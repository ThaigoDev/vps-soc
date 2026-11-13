package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

func TestFileMonitorSeesChangeImmediately(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(target, []byte("root ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan event.Event, 10)
	m := &FileMonitor{Interval: time.Hour, Patterns: []string{target, filepath.Join(dir, "cron.d", "*")}, State: store,
		Emit: func(e event.Event) { events <- e }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	if e := <-events; e.Type != event.FileBaseline {
		t.Fatalf("first event = %s, want baseline", e.Type)
	}
	time.Sleep(50 * time.Millisecond)
	// Atomic replace, like visudo or an editor does.
	tmp := filepath.Join(dir, "sudoers.tmp")
	if err := os.WriteFile(tmp, []byte("root ALL=(ALL) ALL\nevil ALL=(ALL) NOPASSWD: ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e.Type != event.FileModified {
			t.Fatalf("got %s, want %s", e.Type, event.FileModified)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("took %s", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("change not seen without waiting for the (1 h) interval")
	}
}

func TestWatchDirsAndMatch(t *testing.T) {
	dirs := watchDirsFor([]string{"/etc/passwd", "/etc/cron.d/*", "/etc/group"})
	if len(dirs) != 2 || dirs[0] != "/etc" || dirs[1] != "/etc/cron.d" {
		t.Fatalf("dirs = %v", dirs)
	}
	pats := []string{"/etc/passwd", "/etc/cron.d/*"}
	for path, want := range map[string]bool{"/etc/passwd": true, "/etc/cron.d/job": true, "/etc/hosts": false, "/etc/cron.d": true} {
		if got := matchesAny(pats, path); got != want {
			t.Errorf("matchesAny(%s) = %v", path, got)
		}
	}
}
