package sender

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

// Events queued while the SOC is down survive an agent restart; journald events are left
// to the journal cursor (they are read again), so they are not duplicated.
func TestUndeliveredEventsSurviveRestart(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var up atomic.Bool
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		var body struct {
			Events []event.Event `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got.Add(int64(len(body.Events)))
	}))
	defer srv.Close()

	// First run: SOC down, then the agent stops.
	s1 := New(srv.URL, "t", "h", false)
	s1.Spool = store
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s1.Run(ctx); close(done) }()
	s1.Enqueue(event.Event{Type: event.FileModified, OccurredAt: time.Now(), Message: "sudoers changed"})
	s1.Enqueue(event.Event{Type: event.SSHFailedLogin, OccurredAt: time.Now(), Cursor: "c1"})
	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done

	// Second run: SOC back.
	up.Store(true)
	s2 := New(srv.URL, "t", "h", false)
	s2.Spool = store
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go s2.Run(ctx2)
	deadline := time.Now().Add(5 * time.Second)
	for got.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got.Load() != 1 {
		t.Fatalf("delivered %d events after restart, want 1 (the journald one is replayed by cursor)", got.Load())
	}
	var left []event.Event
	if _, err := store.LoadJSON(spoolFile, &left); err != nil || len(left) != 0 {
		t.Fatalf("spool not emptied: %v %v", left, err)
	}
}
