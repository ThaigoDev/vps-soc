// Package config loads the agent configuration from environment variables
// (systemd reads them from /etc/vps-soc-agent/agent.env).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	ServerURL         string
	AgentToken        string
	HostID            string
	LogSource         string // auto | journald | file
	AuthLogPath       string
	StateDir          string
	HeartbeatInterval time.Duration
	PortScanInterval  time.Duration
	FIMInterval       time.Duration
	ProcScanInterval  time.Duration
	AllowInsecureHTTP bool
}

func Load() (Config, error) {
	hostname, _ := os.Hostname()
	c := Config{
		ServerURL:   strings.TrimRight(os.Getenv("SOC_SERVER_URL"), "/"),
		AgentToken:  os.Getenv("SOC_AGENT_TOKEN"),
		HostID:      env("SOC_HOST_ID", hostname),
		LogSource:   env("SOC_LOG_SOURCE", "auto"),
		AuthLogPath: os.Getenv("SOC_AUTH_LOG_PATH"),
		StateDir:    env("SOC_STATE_DIR", "/var/lib/vps-soc-agent"),
	}
	var err error
	if c.HeartbeatInterval, err = duration("SOC_HEARTBEAT_INTERVAL", 30*time.Second); err != nil {
		return c, err
	}
	if c.PortScanInterval, err = duration("SOC_PORT_SCAN_INTERVAL", 30*time.Second); err != nil {
		return c, err
	}
	if c.FIMInterval, err = duration("SOC_FIM_INTERVAL", 60*time.Second); err != nil {
		return c, err
	}
	if c.ProcScanInterval, err = duration("SOC_PROCESS_SCAN_INTERVAL", 15*time.Second); err != nil {
		return c, err
	}
	c.AllowInsecureHTTP = os.Getenv("SOC_ALLOW_INSECURE_HTTP") == "true"

	switch c.LogSource {
	case "auto", "journald", "file":
	default:
		return c, fmt.Errorf("SOC_LOG_SOURCE must be auto, journald or file (got %q)", c.LogSource)
	}
	if c.HostID == "" {
		return c, errors.New("SOC_HOST_ID is empty and hostname could not be read")
	}
	return c, nil
}

// ValidateRemote checks the settings needed to ship events (skipped in dry-run).
func (c Config) ValidateRemote() error {
	if c.ServerURL == "" {
		return errors.New("SOC_SERVER_URL is required")
	}
	if c.AgentToken == "" {
		return errors.New("SOC_AGENT_TOKEN is required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid SOC_SERVER_URL: %w", err)
	}
	if u.Scheme == "http" && !c.AllowInsecureHTTP {
		return errors.New("SOC_SERVER_URL uses plain http; use https, or set SOC_ALLOW_INSECURE_HTTP=true " +
			"only when the link is already encrypted (e.g. Tailscale/WireGuard)")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("SOC_SERVER_URL must be http(s), got %q", u.Scheme)
	}
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func duration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("%s must be a duration >= 1s like 30s (got %q)", key, v)
	}
	return d, nil
}
