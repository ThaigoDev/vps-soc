package collector

import (
	"context"
	"slices"
	"sync"
	"time"
)

// UnitWatcher keeps the list of failed systemd services fresh: `systemctl list-units
// --state=failed` is cheap, so it runs every few seconds instead of with the slow posture
// checks, and OnChange fires as soon as a unit fails or recovers.
type UnitWatcher struct {
	Interval time.Duration
	OnChange func()

	trigOnce sync.Once
	trig     chan struct{}

	mu     sync.RWMutex
	failed []string // nil until systemctl answered
}

// Current is the last list of failed units, or nil when systemctl could not be asked.
func (w *UnitWatcher) Current() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.failed
}

// Trigger asks for a check now (after an action restarted a unit, for instance).
func (w *UnitWatcher) Trigger() {
	select {
	case w.trigger() <- struct{}{}:
	default:
	}
}

func (w *UnitWatcher) trigger() chan struct{} {
	w.trigOnce.Do(func() { w.trig = make(chan struct{}, 1) })
	return w.trig
}

func (w *UnitWatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		w.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-w.trigger():
		}
	}
}

func (w *UnitWatcher) check(ctx context.Context) {
	units := failedUnits(ctx)
	if units == nil {
		return // keep the last known list
	}
	w.mu.Lock()
	changed := w.failed != nil && !slices.Equal(w.failed, units)
	w.failed = units
	w.mu.Unlock()
	if changed && w.OnChange != nil {
		w.OnChange()
	}
}
