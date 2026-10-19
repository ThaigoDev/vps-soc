// Package sender batches events and delivers them to the SOC backend,
// buffering in memory and retrying with backoff while the backend is down.
package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"vps-soc/agent/internal/event"
)

const (
	maxBuffer  = 10_000
	batchSize  = 500
	flushEvery = 2 * time.Second
)

type Sender struct {
	ServerURL string
	Token     string
	HostID    string
	DryRun    bool
	// OnDelivered receives the journald cursor of the last delivered event.
	OnDelivered func(cursor string)

	client  *http.Client
	queue   chan event.Event
	buf     []event.Event
	dropped atomic.Int64 // written by collector goroutines
}

func New(serverURL, token, hostID string, dryRun bool) *Sender {
	return &Sender{
		ServerURL: serverURL, Token: token, HostID: hostID, DryRun: dryRun,
		client: &http.Client{Timeout: 15 * time.Second},
		queue:  make(chan event.Event, 1000),
	}
}

// Enqueue never blocks the collectors; if the queue is full the event is dropped.
func (s *Sender) Enqueue(e event.Event) {
	select {
	case s.queue <- e:
	default:
		s.dropped.Add(1)
	}
}

func (s *Sender) Run(ctx context.Context) {
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	backoff := time.Duration(0)
	nextTry := time.Time{}

	for {
		select {
		case e := <-s.queue:
			s.add(e)
			if len(s.buf) < batchSize {
				continue
			}
		case <-ticker.C:
		case <-ctx.Done():
			s.drainQueue()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.flush(shutdownCtx)
			cancel()
			return
		}

		if time.Now().Before(nextTry) {
			continue
		}
		if err := s.flush(ctx); err != nil {
			backoff = min(max(backoff*2, 2*time.Second), 2*time.Minute)
			nextTry = time.Now().Add(backoff)
			log.Printf("delivery failed (%d buffered, retry in %s): %v", len(s.buf), backoff, err)
		} else {
			backoff = 0
		}
	}
}

func (s *Sender) add(e event.Event) {
	if len(s.buf) >= maxBuffer {
		s.buf = s.buf[1:] // keep the newest events
		s.dropped.Add(1)
	}
	s.buf = append(s.buf, e)
}

func (s *Sender) drainQueue() {
	for {
		select {
		case e := <-s.queue:
			s.add(e)
		default:
			return
		}
	}
}

func (s *Sender) flush(ctx context.Context) error {
	for len(s.buf) > 0 {
		n := min(len(s.buf), batchSize)
		batch := s.buf[:n]
		if err := s.send(ctx, batch); err != nil {
			return err
		}
		if s.OnDelivered != nil {
			for i := n - 1; i >= 0; i-- {
				if batch[i].Cursor != "" {
					s.OnDelivered(batch[i].Cursor)
					break
				}
			}
		}
		s.buf = s.buf[n:]
	}
	if n := s.dropped.Swap(0); n > 0 {
		log.Printf("warning: %d events were dropped because the buffer was full", n)
	}
	return nil
}

func (s *Sender) send(ctx context.Context, batch []event.Event) error {
	if s.DryRun {
		for _, e := range batch {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
		}
		return nil
	}
	return s.post(ctx, "/api/v1/ingest/events", map[string]any{"hostId": s.HostID, "events": batch})
}

// SendHeartbeat posts host metrics and open ports directly (not buffered:
// a stale heartbeat has no value).
func (s *Sender) SendHeartbeat(ctx context.Context, hb any) error {
	if s.DryRun {
		b, _ := json.Marshal(hb)
		fmt.Println("heartbeat:", string(b))
		return nil
	}
	return s.post(ctx, "/api/v1/ingest/heartbeat", hb)
}

func (s *Sender) post(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ServerURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}
