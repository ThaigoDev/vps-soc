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

// Poll fetches queued actions from the SOC every interval, runs them one by one and
// reports each result. While the backend is unreachable it just keeps trying.
func Poll(ctx context.Context, b Backend, x *Executor, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		var resp struct {
			Actions []Action `json:"actions"`
		}
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
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
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
