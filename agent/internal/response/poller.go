package response

import (
	"context"
	"log"
	"time"
)

// Backend is the part of the sender the poller needs.
type Backend interface {
	PollActions(ctx context.Context, out any) error
	ReportAction(ctx context.Context, id int64, result any) error
}

// Poll asks the SOC for queued actions, runs them one by one and reports each result.
// The SOC holds the request open until there is something to do (long polling), so the
// loop asks again right away; it only pauses after an error, or when an old SOC answers
// immediately with nothing (then it falls back to asking every interval).
func Poll(ctx context.Context, b Backend, x *Executor, interval time.Duration) {
	for {
		var resp struct {
			Actions []Action `json:"actions"`
		}
		started := time.Now()
		pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := b.PollActions(pctx, &resp)
		cancel()
		if err == nil {
			for _, a := range resp.Actions {
				actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				res := x.Execute(actx, a)
				cancel()
				log.Printf("action #%d %s: %s %s", a.ID, a.Type, res.Status, res.Output)
				rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				if err := b.ReportAction(rctx, a.ID, res); err != nil {
					log.Printf("report action #%d: %v", a.ID, err)
				}
				cancel()
			}
		}
		pause := time.Duration(0)
		if err != nil || (len(resp.Actions) == 0 && time.Since(started) < time.Second) {
			pause = interval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
	}
}
