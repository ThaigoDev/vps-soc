package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

// Service is one process managed by PM2, the same row `pm2 list` shows. Only these fields
// are read from `pm2 jlist`: its output also carries every app's environment variables
// (database passwords, API keys), which never leave the agent.
type Service struct {
	Source           string    `json:"source"` // "pm2"
	Name             string    `json:"name"`
	Namespace        string    `json:"namespace,omitempty"`
	PmID             int       `json:"pmId"`
	PID              int       `json:"pid"`
	Status           string    `json:"status"` // online | stopping | stopped | launching | errored | one-launch-status
	Restarts         int       `json:"restarts"`
	UnstableRestarts int       `json:"unstableRestarts"`
	StartedAt        time.Time `json:"startedAt,omitempty"`
	CreatedAt        time.Time `json:"createdAt,omitempty"`
	CPUPercent       float64   `json:"cpuPercent"`
	MemoryBytes      uint64    `json:"memoryBytes"`
	Mode             string    `json:"mode,omitempty"` // fork | cluster
	ExecPath         string    `json:"execPath,omitempty"`
	Cwd              string    `json:"cwd,omitempty"`
	Version          string    `json:"version,omitempty"`
	NodeVersion      string    `json:"nodeVersion,omitempty"`
	User             string    `json:"user,omitempty"`
	PM2Home          string    `json:"pm2Home"`
	ErrLogPath       string    `json:"errLogPath,omitempty"`
	OutLogPath       string    `json:"outLogPath,omitempty"`
	Ports            []int     `json:"ports,omitempty"`
}

func (s Service) key() string { return s.PM2Home + "#" + strconv.Itoa(s.PmID) }

// PM2Daemon is a running "PM2 vX: God Daemon (<PM2_HOME>)" process.
type PM2Daemon struct {
	PID     int
	Home    string
	UID     int
	GID     int
	User    string
	NodeExe string
	Version string
}

// PM2Status is shipped with the heartbeat next to the services.
type PM2Status struct {
	Daemons []string `json:"daemons"`
	Error   string   `json:"error,omitempty"`
}

// PM2Monitor lists PM2 apps every interval and emits an event when one changes status,
// restarts, appears or disappears. It never starts a PM2 daemon: the CLI is only called
// for daemons that are already running, as the user that owns them.
type PM2Monitor struct {
	Interval time.Duration
	State    *state.Store
	Emit     func(event.Event)

	mu       sync.RWMutex
	current  []Service
	status   PM2Status
	previous map[string]serviceMark
	baseline bool
}

type serviceMark struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Restarts int    `json:"restarts"`
}

const pm2StateFile = "pm2.json"

func (m *PM2Monitor) Current() ([]Service, PM2Status) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current, m.status
}

func (m *PM2Monitor) Run(ctx context.Context) {
	m.previous = map[string]serviceMark{}
	if found, err := m.State.LoadJSON(pm2StateFile, &m.previous); err == nil && found {
		m.baseline = true
	}
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		m.scan(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *PM2Monitor) scan(ctx context.Context) {
	daemons := FindPM2Daemons()
	var services []Service
	st := PM2Status{Daemons: []string{}}
	var errs []string
	for _, d := range daemons {
		st.Daemons = append(st.Daemons, fmt.Sprintf("%s (%s, %s)", d.Home, d.User, d.Version))
		list, err := ListPM2(ctx, d)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", d.Home, err))
			continue
		}
		services = append(services, list...)
	}
	st.Error = strings.Join(errs, "; ")
	sort.Slice(services, func(i, j int) bool {
		if services[i].PM2Home != services[j].PM2Home {
			return services[i].PM2Home < services[j].PM2Home
		}
		return services[i].PmID < services[j].PmID
	})

	if st.Error == "" || len(services) > 0 {
		m.diff(services)
	}
	m.mu.Lock()
	m.current, m.status = services, st
	m.mu.Unlock()
}

func (m *PM2Monitor) diff(services []Service) {
	now := time.Now()
	seen := map[string]serviceMark{}
	for _, s := range services {
		mark := serviceMark{Name: s.Name, Status: s.Status, Restarts: s.Restarts}
		seen[s.key()] = mark
		if !m.baseline {
			continue
		}
		prev, existed := m.previous[s.key()]
		switch {
		case !existed:
			m.Emit(serviceEvent(event.ServiceAdded, s, now, fmt.Sprintf("PM2: app %s (id %d) adicionado, status %s", s.Name, s.PmID, s.Status), nil))
		default:
			if prev.Status != s.Status {
				meta := map[string]any{"from": prev.Status, "to": s.Status}
				if s.Status != "online" {
					meta["errLogTail"] = tailLines(s.ErrLogPath, 15)
				}
				m.Emit(serviceEvent(event.ServiceStatusChanged, s, now,
					fmt.Sprintf("PM2: %s mudou de %s para %s", s.Name, prev.Status, s.Status), meta))
			}
			if s.Restarts > prev.Restarts {
				delta := s.Restarts - prev.Restarts
				m.Emit(serviceEvent(event.ServiceRestarted, s, now,
					fmt.Sprintf("PM2: %s reiniciou %d vez(es) (total %d)", s.Name, delta, s.Restarts),
					map[string]any{"delta": delta, "errLogTail": tailLines(s.ErrLogPath, 15)}))
			}
		}
	}
	if m.baseline {
		for k, prev := range m.previous {
			if _, ok := seen[k]; !ok {
				m.Emit(event.Event{Type: event.ServiceRemoved, OccurredAt: now,
					Message:  fmt.Sprintf("PM2: app %s removido da lista", prev.Name),
					Metadata: map[string]any{"service": prev.Name, "source": "pm2", "lastStatus": prev.Status}})
			}
		}
	}
	m.previous = seen
	m.baseline = true
	if err := m.State.SaveJSON(pm2StateFile, seen); err != nil {
		log.Printf("save pm2 state: %v", err)
	}
}

func serviceEvent(typ string, s Service, ts time.Time, msg string, extra map[string]any) event.Event {
	meta := map[string]any{
		"service": s.Name, "source": "pm2", "pmId": s.PmID, "pid": s.PID, "status": s.Status,
		"restarts": s.Restarts, "unstableRestarts": s.UnstableRestarts, "memoryBytes": s.MemoryBytes,
		"cpuPercent": s.CPUPercent, "execPath": s.ExecPath, "pm2Home": s.PM2Home, "user": s.User,
	}
	for k, v := range extra {
		meta[k] = v
	}
	return event.Event{Type: typ, OccurredAt: ts, Username: s.User, Message: msg, Metadata: meta}
}

// FindPM2Daemons scans /proc for PM2 God Daemons and where their PM2_HOME is.
func FindPM2Daemons() []PM2Daemon {
	var out []PM2Daemon
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		cmd, err := os.ReadFile(dir + "/cmdline")
		if err != nil {
			continue
		}
		d, ok := ParsePM2DaemonCmdline(string(bytes.TrimRight(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '}), " ")))
		if !ok {
			continue
		}
		d.PID, _ = strconv.Atoi(filepath.Base(dir))
		if status, err := os.ReadFile(dir + "/status"); err == nil {
			d.UID, _ = strconv.Atoi(ParseStatusUID(string(status)))
			d.GID, _ = strconv.Atoi(parseStatusGID(string(status)))
		}
		d.User = lookupUser(strconv.Itoa(d.UID))
		d.NodeExe, _ = os.Readlink(dir + "/exe")
		out = append(out, d)
	}
	return out
}

// ParsePM2DaemonCmdline reads "PM2 v5.4.3: God Daemon (/root/.pm2)".
func ParsePM2DaemonCmdline(cmd string) (PM2Daemon, bool) {
	if !strings.HasPrefix(cmd, "PM2 v") || !strings.Contains(cmd, "God Daemon") {
		return PM2Daemon{}, false
	}
	open, end := strings.Index(cmd, "("), strings.LastIndex(cmd, ")")
	if open < 0 || end <= open+1 {
		return PM2Daemon{}, false
	}
	version, _, _ := strings.Cut(strings.TrimPrefix(cmd, "PM2 v"), ":")
	return PM2Daemon{Home: cmd[open+1 : end], Version: version}, true
}

func parseStatusGID(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if rest, ok := strings.CutPrefix(line, "Gid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// PM2Command runs the pm2 CLI against a running daemon, as the daemon's owner, with
// the daemon's node first in PATH. Arguments are passed as argv: no shell is involved.
func PM2Command(ctx context.Context, d PM2Daemon, args ...string) ([]byte, error) {
	bin, nodeDir := findPM2Binary(d)
	if bin == "" {
		return nil, errors.New("pm2 CLI not found (looked next to the daemon's node, in PATH, /usr/local/bin, /usr/bin and nvm)")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	home := filepath.Dir(d.Home)
	if u, err := user.LookupId(strconv.Itoa(d.UID)); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	path := "/usr/local/bin:/usr/bin:/bin"
	if nodeDir != "" {
		path = nodeDir + ":" + path
	}
	cmd.Env = []string{"PM2_HOME=" + d.Home, "HOME=" + home, "PATH=" + path, "LANG=C"}
	cmd.Dir = "/"
	if d.UID != os.Getuid() {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(d.UID), Gid: uint32(d.GID)}}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(lastN(stderr.String(), 300)))
	}
	return out, nil
}

// ListPM2 runs `pm2 jlist` for one daemon.
func ListPM2(ctx context.Context, d PM2Daemon) ([]Service, error) {
	out, err := PM2Command(ctx, d, "jlist")
	if err != nil {
		return nil, err
	}
	return ParsePM2JList(out, d.Home)
}

type jlistEntry struct {
	Name  string `json:"name"`
	PmID  int    `json:"pm_id"`
	PID   int    `json:"pid"`
	Monit struct {
		Memory uint64  `json:"memory"`
		CPU    float64 `json:"cpu"`
	} `json:"monit"`
	Env struct {
		Status           string `json:"status"`
		RestartTime      int    `json:"restart_time"`
		UnstableRestarts int    `json:"unstable_restarts"`
		PmUptime         int64  `json:"pm_uptime"`
		CreatedAt        int64  `json:"created_at"`
		ExecMode         string `json:"exec_mode"`
		ExecPath         string `json:"pm_exec_path"`
		Cwd              string `json:"pm_cwd"`
		Version          string `json:"version"`
		NodeVersion      string `json:"node_version"`
		Username         string `json:"username"`
		Namespace        string `json:"namespace"`
		ErrLog           string `json:"pm_err_log_path"`
		OutLog           string `json:"pm_out_log_path"`
	} `json:"pm2_env"`
}

// ParsePM2JList keeps only the operational fields of `pm2 jlist` (never the env).
func ParsePM2JList(out []byte, home string) ([]Service, error) {
	// pm2 may print "[PM2] ..." warnings before the JSON array, so look for the array itself.
	for _, start := range [][]byte{[]byte("[{"), []byte("[]")} {
		if i := bytes.Index(out, start); i >= 0 {
			out = out[i:]
			break
		}
	}
	var entries []jlistEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse pm2 jlist: %w", err)
	}
	services := make([]Service, 0, len(entries))
	for _, e := range entries {
		s := Service{
			Source: "pm2", Name: e.Name, PmID: e.PmID, PID: e.PID, Status: e.Env.Status,
			Restarts: e.Env.RestartTime, UnstableRestarts: e.Env.UnstableRestarts,
			CPUPercent: e.Monit.CPU, MemoryBytes: e.Monit.Memory,
			Mode: strings.TrimSuffix(e.Env.ExecMode, "_mode"), ExecPath: e.Env.ExecPath, Cwd: e.Env.Cwd,
			Version: e.Env.Version, NodeVersion: e.Env.NodeVersion, User: e.Env.Username, Namespace: e.Env.Namespace,
			PM2Home: home, ErrLogPath: e.Env.ErrLog, OutLogPath: e.Env.OutLog,
		}
		if s.Version == "N/A" {
			s.Version = ""
		}
		if e.Env.PmUptime > 0 {
			s.StartedAt = time.UnixMilli(e.Env.PmUptime).UTC()
		}
		if e.Env.CreatedAt > 0 {
			s.CreatedAt = time.UnixMilli(e.Env.CreatedAt).UTC()
		}
		if s.Status != "online" {
			s.PID = 0 // pm2 keeps the last pid of a dead process
		}
		services = append(services, s)
	}
	return services, nil
}

func findPM2Binary(d PM2Daemon) (bin, nodeDir string) {
	if d.NodeExe != "" {
		nodeDir = filepath.Dir(strings.TrimSuffix(d.NodeExe, " (deleted)"))
	}
	candidates := []string{}
	if nodeDir != "" {
		candidates = append(candidates, filepath.Join(nodeDir, "pm2"))
	}
	if p, err := exec.LookPath("pm2"); err == nil {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, "/usr/local/bin/pm2", "/usr/bin/pm2",
		"/usr/local/lib/node_modules/pm2/bin/pm2", "/usr/lib/node_modules/pm2/bin/pm2")
	nvm, _ := filepath.Glob("/root/.nvm/versions/node/*/bin/pm2")
	homeNvm, _ := filepath.Glob("/home/*/.nvm/versions/node/*/bin/pm2")
	candidates = append(candidates, nvm...)
	candidates = append(candidates, homeNvm...)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			if nodeDir == "" {
				nodeDir = filepath.Dir(c)
			}
			return c, nodeDir
		}
	}
	return "", nodeDir
}

// tailLines returns the last n lines of a log file (reading at most 8 KB).
func tailLines(path string, n int) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	const max = 8 << 10
	if st, err := f.Stat(); err == nil && st.Size() > max {
		_, _ = f.Seek(-max, io.SeekEnd)
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() {
		lines = append(lines, truncate(sc.Text(), 300))
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// AttachPorts fills each service's listening ports from the port monitor's snapshot.
func AttachPorts(services []Service, listeners []Listener) []Service {
	byPID := map[int][]int{}
	for _, l := range listeners {
		if l.PID > 0 && !containsInt(byPID[l.PID], l.Port) {
			byPID[l.PID] = append(byPID[l.PID], l.Port)
		}
	}
	out := make([]Service, len(services))
	for i, s := range services {
		s.Ports = byPID[s.PID]
		out[i] = s
	}
	return out
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
