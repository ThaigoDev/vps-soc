package response

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

const knownGoodFile = "known-good-ips.json"

// Guard is the agent's own brute-force defense. It works without the SOC backend (the
// backend may be a PC that is switched off), like fail2ban: N SSH failures from one
// address inside a window block it for a while. It refuses to block an address that
// logged in successfully before (most likely the owner mistyping a password) and anything
// on the allowlist; those cases are left for the SOC to raise as incidents.
type Guard struct {
	Enabled   bool
	Threshold int
	Window    time.Duration
	TTL       time.Duration
	Firewall  *Firewall
	Allowlist *Allowlist
	State     *state.Store
	Emit      func(event.Event)

	mu        sync.Mutex
	failures  map[string][]time.Time
	knownGood map[string]time.Time
}

// knownGoodFor is how long a clean successful login keeps an address trusted.
const knownGoodFor = 30 * 24 * time.Hour

func (g *Guard) Load() {
	g.failures = map[string][]time.Time{}
	g.knownGood = map[string]time.Time{}
	if g.State != nil {
		if _, err := g.State.LoadJSON(knownGoodFile, &g.knownGood); err != nil {
			log.Printf("known-good state unreadable: %v", err)
		}
	}
}

// Observe is called for every event before it is shipped.
func (g *Guard) Observe(e event.Event) {
	if !g.Enabled || e.SourceIP == "" {
		return
	}
	switch e.Type {
	case event.SSHFailedLogin, event.SSHInvalidUser:
		g.onFailure(e)
	case event.SSHLoginSuccess:
		g.onSuccess(e)
	}
}

func (g *Guard) onSuccess(e event.Event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	// A login right after a burst of failures is the attack succeeding, not the owner.
	if len(g.recent(e.SourceIP, e.OccurredAt)) >= 3 {
		return
	}
	g.knownGood[e.SourceIP] = e.OccurredAt
	if g.State != nil {
		_ = g.State.SaveJSON(knownGoodFile, g.knownGood)
	}
}

func (g *Guard) onFailure(e event.Event) {
	if time.Since(e.OccurredAt) > g.Window {
		return // old lines replayed from the journal after a restart
	}
	g.mu.Lock()
	times := append(g.recent(e.SourceIP, e.OccurredAt), e.OccurredAt)
	g.failures[e.SourceIP] = times
	trigger := len(times) >= g.Threshold
	good, isGood := g.knownGood[e.SourceIP]
	if isGood && time.Since(good) > knownGoodFor {
		isGood = false
	}
	if trigger {
		delete(g.failures, e.SourceIP) // one decision per burst
	}
	g.mu.Unlock()

	if !trigger || isGood || g.Firewall.IsBlocked(e.SourceIP) {
		return
	}
	ip := net.ParseIP(e.SourceIP)
	if ip == nil {
		return
	}
	if ok, _ := g.Allowlist.Protected(ip); ok {
		return
	}
	reason := fmt.Sprintf("%d falhas de login SSH em %s", len(times), g.Window)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := g.Firewall.Block(ctx, ip, g.TTL, reason, "agent")
	status, out := StatusSucceeded, fmt.Sprintf("%s bloqueado automaticamente pelo agente até %s", ip, b.Until.UTC().Format(time.RFC3339))
	if err != nil {
		status, out = StatusFailed, "bloqueio automático falhou: "+err.Error()
	}
	log.Printf("guard: %s (%s)", out, reason)
	g.Emit(event.Event{
		Type: event.ResponseExecuted, OccurredAt: time.Now(), SourceIP: ip.String(), Message: out,
		Metadata: map[string]any{
			"action": BlockIP, "origin": "agent", "status": status, "reason": reason,
			"ip": ip.String(), "ttlSeconds": int(g.TTL.Seconds()), "until": b.Until.UTC(), "failures": len(times),
		},
	})
}

// recent returns the failures from ip still inside the window. Caller holds mu.
func (g *Guard) recent(ip string, now time.Time) []time.Time {
	cutoff := now.Add(-g.Window)
	var keep []time.Time
	for _, t := range g.failures[ip] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	return keep
}

// Sweep drops idle counters so memory stays bounded under a large distributed attack.
func (g *Guard) Sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for ip := range g.failures {
		if r := g.recent(ip, now); len(r) == 0 {
			delete(g.failures, ip)
		} else {
			g.failures[ip] = r
		}
	}
}
