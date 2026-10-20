package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"vps-soc/agent/internal/collector"
	"vps-soc/agent/internal/config"
	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/response"
	"vps-soc/agent/internal/sender"
	"vps-soc/agent/internal/state"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	dryRun := flag.Bool("dry-run", false, "print events and heartbeats to stdout instead of sending them")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if !*dryRun {
		if err := cfg.ValidateRemote(); err != nil {
			log.Fatal(err)
		}
	}
	store, err := state.New(cfg.StateDir)
	if err != nil {
		log.Fatalf("state dir %s: %v", cfg.StateDir, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	snd := sender.New(cfg.ServerURL, cfg.AgentToken, cfg.HostID, *dryRun)
	snd.OnDelivered = func(cursor string) {
		if err := store.SaveCursor(cursor); err != nil {
			log.Printf("save cursor: %v", err)
		}
	}

	hostname, _ := os.Hostname()
	osName := collector.OSName()
	log.Printf("vps-soc-agent %s starting: host=%s os=%q server=%s dryRun=%v", version, cfg.HostID, osName, cfg.ServerURL, *dryRun)

	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}

	run(func() { snd.Run(ctx) })

	// Active response: nftables blocks, the local brute-force guard and the action poller.
	allow, err := response.NewAllowlist(cfg.ResponseAllowlist, cfg.ServerURL)
	if err != nil {
		log.Fatalf("SOC_RESPONSE_ALLOWLIST: %v", err)
	}
	fw := response.NewFirewall(store)
	fwErr := error(nil)
	if cfg.ResponseEnabled && !*dryRun {
		if fwErr = fw.Init(ctx); fwErr != nil {
			log.Printf("firewall disabled: %v", fwErr)
		}
	}
	guard := &response.Guard{
		Enabled: cfg.AutoBlock && !*dryRun && fwErr == nil, Threshold: cfg.AutoBlockThreshold, Window: cfg.AutoBlockWindow,
		TTL: cfg.AutoBlockTTL, Firewall: fw, Allowlist: allow, State: store, Emit: snd.Enqueue,
	}
	guard.Load()
	emit := func(e event.Event) {
		guard.Observe(e)
		snd.Enqueue(e)
	}
	executor := &response.Executor{
		Enabled: cfg.ResponseEnabled && !*dryRun, Firewall: fw, Allowlist: allow,
		QuarantineDir: filepath.Join(cfg.StateDir, "quarantine"), Run: response.DefaultRunner, Self: os.Getpid(),
	}
	run(func() { response.Poll(ctx, snd, executor, cfg.ActionPollInterval) })

	snd.Enqueue(event.Event{
		Type: event.AgentStarted, OccurredAt: time.Now(),
		Message: "agent " + version + " started",
		Metadata: map[string]any{"version": version, "os": osName, "responseEnabled": executor.Enabled,
			"autoBlock": guard.Enabled, "firewallError": errString(fwErr)},
	})

	auth := &collector.AuthLogSource{Mode: cfg.LogSource, Path: cfg.AuthLogPath, Cursor: store.LoadCursor(), Emit: emit}
	run(func() {
		if err := auth.Run(ctx); err != nil {
			log.Printf("auth log collector stopped: %v", err)
		}
	})

	ports := &collector.PortMonitor{Interval: cfg.PortScanInterval, State: store, Emit: snd.Enqueue}
	run(func() { ports.Run(ctx) })

	files := &collector.FileMonitor{Interval: cfg.FIMInterval, State: store, Emit: snd.Enqueue}
	run(func() { files.Run(ctx) })

	procs := &collector.ProcessMonitor{Interval: cfg.ProcScanInterval, Emit: snd.Enqueue}
	run(func() { procs.Run(ctx) })

	pm2 := &collector.PM2Monitor{Interval: cfg.PM2Interval, State: store, Emit: snd.Enqueue,
		Enricher: &collector.Enricher{Ports: func() []collector.Listener { return ports.Current() }}}
	run(func() { pm2.Run(ctx) })
	run(func() { uploadInventories(ctx, pm2, snd, store, cfg.HostID) })

	run(func() {
		metrics := &collector.MetricsReader{}
		metrics.Read() // prime CPU and network counters
		posture := &collector.PostureReader{}
		ticker := time.NewTicker(cfg.HeartbeatInterval)
		defer ticker.Stop()
		sweep := time.NewTicker(time.Minute)
		defer sweep.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-sweep.C:
				guard.Sweep(now)
				continue
			case <-ticker.C:
			}
			p := posture.Read(ctx)
			listeners := ports.Current()
			services, pm2Status := pm2.Current()
			p.Firewall = fw.Stats(ctx)
			hb := map[string]any{
				"hostId": cfg.HostID, "hostname": hostname, "os": osName, "agentVersion": version,
				"heartbeatIntervalSeconds": int(cfg.HeartbeatInterval.Seconds()),
				"metrics":                  metrics.Read(),
				"openPorts":                listeners,
				"services":                 services,
				"pm2":                      pm2Status,
				"posture":                  p,
				"response":                 map[string]any{"enabled": executor.Enabled, "autoBlock": guard.Enabled},
			}
			hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := snd.SendHeartbeat(hctx, hb); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}
			cancel()
		}
	})

	<-ctx.Done()
	log.Printf("shutting down")
	wg.Wait()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// uploadInventories sends each PM2 app's installed packages to the SOC when its lockfile
// changes (and once a day, so new advisories are matched against fresh data).
func uploadInventories(ctx context.Context, pm2 *collector.PM2Monitor, snd *sender.Sender, store *state.Store, hostID string) {
	const stateFile = "inventory.json"
	type sent struct {
		Hash string    `json:"hash"`
		At   time.Time `json:"at"`
	}
	last := map[string]sent{}
	_, _ = store.LoadJSON(stateFile, &last)
	timer := time.NewTimer(time.Minute) // let the first PM2 scan finish
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		services, _ := pm2.Current()
		done := map[string]bool{}
		for _, s := range services {
			key := s.PM2Home + "#" + s.Name
			if done[key] || s.Security.Lockfile == "" {
				continue
			}
			done[key] = true
			prev := last[key]
			if prev.Hash == s.Security.DepsHash && time.Since(prev.At) < 24*time.Hour {
				continue
			}
			inv, err := collector.ReadInventory(s.Security.Lockfile)
			if err != nil {
				log.Printf("inventory %s: %v", s.Name, err)
				continue
			}
			body := map[string]any{"hostId": hostID, "service": s.Name, "pm2Home": s.PM2Home,
				"lockfile": inv.Lockfile, "hash": inv.Hash, "packages": inv.Packages}
			uctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err = snd.SendInventory(uctx, body)
			cancel()
			if err != nil {
				log.Printf("upload inventory %s: %v", s.Name, err)
				continue
			}
			last[key] = sent{Hash: inv.Hash, At: time.Now()}
			_ = store.SaveJSON(stateFile, last)
			log.Printf("inventory %s: %d packages sent", s.Name, len(inv.Packages))
		}
		timer.Reset(10 * time.Minute)
	}
}
