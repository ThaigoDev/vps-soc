package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"vps-soc/agent/internal/collector"
	"vps-soc/agent/internal/config"
	"vps-soc/agent/internal/event"
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
	snd.Enqueue(event.Event{
		Type: event.AgentStarted, OccurredAt: time.Now(),
		Message:  "agent " + version + " started",
		Metadata: map[string]any{"version": version, "os": osName},
	})

	auth := &collector.AuthLogSource{Mode: cfg.LogSource, Path: cfg.AuthLogPath, Cursor: store.LoadCursor(), Emit: snd.Enqueue}
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
		metrics.Read() // prime CPU counters
		ticker := time.NewTicker(cfg.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			hb := map[string]any{
				"hostId": cfg.HostID, "hostname": hostname, "os": osName, "agentVersion": version,
				"heartbeatIntervalSeconds": int(cfg.HeartbeatInterval.Seconds()),
				"metrics":                  metrics.Read(),
				"openPorts":                ports.Current(),
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
