package collector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vps-soc/agent/internal/event"
)

// Reasons a process is reported as PROCESS_SUSPICIOUS.
const (
	ReasonTempExe    = "TEMP_EXE"    // binary runs from /tmp, /var/tmp or /dev/shm
	ReasonDeletedExe = "DELETED_EXE" // binary was removed from disk (or is a memfd)
	ReasonWebShell   = "WEB_SHELL"   // shell spawned by a web server / app runtime or as www-data
)

var (
	tempExeDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	shells      = map[string]bool{"sh": true, "bash": true, "dash": true}
	webParents  = []string{"nginx", "apache", "apache2", "httpd", "php-fpm", "node", "next-server", "bun", "deno",
		"java", "gunicorn", "uvicorn", "uwsgi"}
	webUsers = map[string]bool{"www-data": true}
)

// ProcInfo is what the monitor reads about a process from /proc.
type ProcInfo struct {
	PID       int
	PPID      int
	StartTime uint64 // clock ticks since boot; with PID identifies one process
	Comm      string
	Exe       string
	Cmdline   string
	UID       string
	User      string
}

// ProcessMonitor scans /proc and emits one PROCESS_SUSPICIOUS event per
// suspicious process (identified by pid + start time) while it runs.
type ProcessMonitor struct {
	Interval time.Duration
	Emit     func(event.Event)

	seen map[string]bool
}

func (m *ProcessMonitor) Run(ctx context.Context) {
	m.seen = map[string]bool{}
	self := os.Getpid()
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		m.scan(self)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *ProcessMonitor) scan(self int) {
	procs := ListProcesses()
	exposed := PublicListenerPIDs()
	alive := map[string]bool{}
	ts := time.Now()
	for _, p := range procs {
		if p.PID == self {
			continue
		}
		parent := procs[p.PPID]
		for _, reason := range ClassifyProcess(p, parent, exposed[p.PPID]) {
			key := fmt.Sprintf("%d/%d/%s", p.PID, p.StartTime, reason)
			alive[key] = true
			if !m.seen[key] {
				m.Emit(processEvent(p, parent, reason, ts))
			}
		}
	}
	m.seen = alive // forget processes that exited
}

// ClassifyProcess returns why a process is suspicious (empty if it is not).
// parentExposed says the parent holds a socket listening on a public address:
// whatever it is called, a shell under it is a shell under an internet-facing service.
func ClassifyProcess(p ProcInfo, parent ProcInfo, parentExposed bool) []string {
	var reasons []string
	exe := p.Exe
	deleted := strings.HasSuffix(exe, " (deleted)")
	path := strings.TrimSuffix(exe, " (deleted)")
	for _, dir := range tempExeDirs {
		if strings.HasPrefix(path, dir) {
			reasons = append(reasons, ReasonTempExe)
			break
		}
	}
	if deleted {
		reasons = append(reasons, ReasonDeletedExe)
	}

	name := p.Comm
	if exe != "" {
		name = filepath.Base(path)
	}
	if shells[name] || shells[p.Comm] {
		if webUsers[p.User] || parentExposed || isWebParent(parent.Comm) {
			reasons = append(reasons, ReasonWebShell)
		}
	}
	return reasons
}

// isWebParent matches a runtime name followed by nothing or a non-letter, so
// "php-fpm8.3", "nginx: worker" and "next-server (v15" match but "nodemon" does not.
func isWebParent(comm string) bool {
	for _, w := range webParents {
		if !strings.HasPrefix(comm, w) {
			continue
		}
		if len(comm) == len(w) {
			return true
		}
		if c := comm[len(w)]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

func processEvent(p, parent ProcInfo, reason string, ts time.Time) event.Event {
	return event.Event{
		Type: event.ProcessSuspicious, OccurredAt: ts, Username: p.User,
		Message: fmt.Sprintf("suspicious process (%s): %s pid %d exe %s parent %s pid %d",
			reason, p.Comm, p.PID, p.Exe, parent.Comm, p.PPID),
		Metadata: map[string]any{
			"reason": reason, "pid": p.PID, "ppid": p.PPID, "comm": p.Comm, "exe": p.Exe,
			"cmdline": p.Cmdline, "uid": p.UID, "user": p.User,
			"parentComm": parent.Comm, "parentExe": parent.Exe, "parentUser": parent.User,
		},
	}
}

// ListProcesses reads every process in /proc, keyed by pid.
func ListProcesses() map[int]ProcInfo {
	out := map[int]ProcInfo{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(dir + "/stat")
		if err != nil {
			continue // exited
		}
		comm, ppid, start, ok := ParseProcStat(string(stat))
		if !ok {
			continue
		}
		p := ProcInfo{PID: pid, PPID: ppid, StartTime: start, Comm: comm}
		p.Exe, _ = os.Readlink(dir + "/exe") // empty for kernel threads
		if status, err := os.ReadFile(dir + "/status"); err == nil {
			p.UID = ParseStatusUID(string(status))
			if p.UID != "" {
				p.User = lookupUser(p.UID)
			}
		}
		if cmd, err := os.ReadFile(dir + "/cmdline"); err == nil {
			p.Cmdline = truncate(string(bytes.TrimRight(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '}), " ")), 512)
		}
		out[pid] = p
	}
	return out
}

// ParseProcStat extracts comm, ppid and starttime from /proc/<pid>/stat.
// comm is wrapped in parentheses and may itself contain spaces or ')'.
func ParseProcStat(s string) (comm string, ppid int, start uint64, ok bool) {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return "", 0, 0, false
	}
	comm = s[open+1 : end]
	// Fields after comm: state(3) ppid(4) ... starttime(22).
	f := strings.Fields(s[end+1:])
	if len(f) < 20 {
		return "", 0, 0, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	start, err2 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	return comm, ppid, start, true
}

// ParseStatusUID returns the real UID from /proc/<pid>/status.
func ParseStatusUID(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
