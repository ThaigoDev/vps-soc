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
			p.Firewall = fw.Stats(ctx)
			hb := map[string]any{
				"hostId": cfg.HostID, "hostname": hostname, "os": osName, "agentVersion": version,
				"heartbeatIntervalSeconds": int(cfg.HeartbeatInterval.Seconds()),
				"metrics":                  metrics.Read(),
				"openPorts":                ports.Current(),
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
