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
	"vps-soc/agent/internal/state"
)

const (
	maxBuffer  = 10_000
	batchSize  = 500
	flushEvery = 2 * time.Second
	// After an event arrives, wait this long for others before sending, so a burst
	// (e.g. a brute force) goes in one request but a single event still leaves at once.
	coalesce = 150 * time.Millisecond
)

type Sender struct {
	ServerURL string
	Token     string
	HostID    string
	DryRun    bool
	// OnDelivered receives the journald cursor of the last delivered event.
	OnDelivered func(cursor string)
	// Spool, when set, keeps undelivered events on disk while the SOC is unreachable, so an
	// agent restart (or a reboot of the VPS) does not lose them.
	Spool *state.Store

	spooled   bool      // the spool file holds events not yet delivered
	spooledAt time.Time // last write of the spool

	client     *http.Client
	pollClient *http.Client
	queue      chan event.Event
	buf        []event.Event
	dropped    atomic.Int64 // written by collector goroutines
}

func New(serverURL, token, hostID string, dryRun bool) *Sender {
	return &Sender{
		ServerURL: serverURL, Token: token, HostID: hostID, DryRun: dryRun,
		client: &http.Client{Timeout: 15 * time.Second},
		// Action polls stay open up to 25 s on the SOC side (long polling).
		pollClient: &http.Client{Timeout: 40 * time.Second},
		queue:      make(chan event.Event, 1000),
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

const spoolFile = "pending-events.json"

// spoolEvery limits how often the buffer is rewritten to disk while the SOC is down.
const spoolEvery = 30 * time.Second

// loadSpool puts the events saved by a previous run back in the buffer.
func (s *Sender) loadSpool() {
	if s.Spool == nil {
		return
	}
	var saved []event.Event
	found, err := s.Spool.LoadJSON(spoolFile, &saved)
	if err != nil {
		log.Printf("spool unreadable, ignored: %v", err)
		return
	}
	if found && len(saved) > 0 {
		log.Printf("%d undelivered events recovered from disk", len(saved))
		for _, e := range saved {
			s.add(e)
		}
		s.spooled = true
	}
}

// saveSpool writes the undelivered events to disk. Events read from journald are left out:
// the journal cursor is only saved after delivery, so those are read again on restart.
func (s *Sender) saveSpool() {
	if s.Spool == nil || (len(s.buf) == 0 && !s.spooled) {
		return
	}
	keep := make([]event.Event, 0, len(s.buf))
	for _, e := range s.buf {
		if e.Cursor == "" {
			keep = append(keep, e)
		}
	}
	if err := s.Spool.SaveJSON(spoolFile, keep); err != nil {
		log.Printf("save spool: %v", err)
		return
	}
	s.spooled = len(keep) > 0
	s.spooledAt = time.Now()
}

func (s *Sender) Run(ctx context.Context) {
	s.loadSpool()
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	backoff := time.Duration(0)
	nextTry := time.Time{}

	var soon <-chan time.Time // fires shortly after the first event of a burst
	for {
		select {
		case e := <-s.queue:
			s.add(e)
			if len(s.buf) < batchSize {
				if soon == nil {
					soon = time.After(coalesce)
				}
				continue
			}
		case <-soon:
		case <-ticker.C:
		case <-ctx.Done():
			s.drainQueue()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.flush(shutdownCtx)
			cancel()
			s.saveSpool() // whatever could not be delivered survives the restart
			return
		}

		soon = nil
		if len(s.buf) == 0 || time.Now().Before(nextTry) {
			continue
		}
		if err := s.flush(ctx); err != nil {
			backoff = min(max(backoff*2, 2*time.Second), 2*time.Minute)
			nextTry = time.Now().Add(backoff)
			log.Printf("delivery failed (%d buffered, retry in %s): %v", len(s.buf), backoff, err)
			if time.Since(s.spooledAt) >= spoolEvery {
				s.saveSpool() // survives a crash or reboot, not only a clean stop
			}
		} else {
			backoff = 0
			if s.spooled {
				s.saveSpool() // everything delivered: empty the spool
			}
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

// SendInventory uploads an app's installed packages (names and versions only).
func (s *Sender) SendInventory(ctx context.Context, inv any) error {
	if s.DryRun {
		b, _ := json.Marshal(inv)
		fmt.Printf("inventory: %.300s\n", b)
		return nil
	}
	return s.post(ctx, "/api/v1/ingest/inventory", inv)
}

// PollActions asks the backend for response actions queued for this host.
func (s *Sender) PollActions(ctx context.Context, out any) error {
	if s.DryRun {
		return nil
	}
	// wait=25: the SOC holds the request until an action is queued (or 25 s pass), so a
	// block decided on the SOC reaches this host immediately. Older SOCs ignore it.
	return s.postJSONWith(ctx, s.pollClient, "/api/v1/ingest/actions/poll?wait=25", map[string]any{"hostId": s.HostID}, out)
}

// ReportAction sends the outcome of one response action.
func (s *Sender) ReportAction(ctx context.Context, id int64, result any) error {
	if s.DryRun {
		b, _ := json.Marshal(result)
		fmt.Printf("action %d result: %s\n", id, b)
		return nil
	}
	// The token is shared by all agents, so the host id travels with the result and the
	// SOC checks the action belongs to that host.
	var body map[string]any
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return err
	}
	body["hostId"] = s.HostID
	return s.post(ctx, fmt.Sprintf("/api/v1/ingest/actions/%d/result", id), body)
}

func (s *Sender) post(ctx context.Context, path string, body any) error {
	return s.postJSON(ctx, path, body, nil)
}

// postJSON posts body and, when out is non-nil, decodes the JSON response into it.
func (s *Sender) postJSON(ctx context.Context, path string, body any, out any) error {
	return s.postJSONWith(ctx, s.client, path, body, out)
}

func (s *Sender) postJSONWith(ctx context.Context, client *http.Client, path string, body any, out any) error {
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
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}
