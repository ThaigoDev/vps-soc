package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ListenAddr is one socket an app listens on.
type ListenAddr struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// Probe is the result of the agent calling the app on its own port.
type Probe struct {
	OK        bool      `json:"ok"`
	Port      int       `json:"port"`
	Status    int       `json:"status,omitempty"` // HTTP status; 0 when the port speaks something else
	LatencyMs int64     `json:"latencyMs"`
	TCPOnly   bool      `json:"tcpOnly,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

// Security-relevant facts about an app, gathered without reading its secrets.
type ServiceSecurity struct {
	Inspect      string `json:"inspect,omitempty"`     // --inspect flag found in node/interpreter args
	NodeEnv      string `json:"nodeEnv,omitempty"`     // only NODE_ENV is read from the environment
	EnvFile      string `json:"envFile,omitempty"`     // path of a .env next to the app
	EnvFileMode  string `json:"envFileMode,omitempty"` // e.g. -rw-r--r--
	EnvFileOwner string `json:"envFileOwner,omitempty"`
	Lockfile     string `json:"lockfile,omitempty"`
	DepsHash     string `json:"depsHash,omitempty"`
}

// InspectFlag finds --inspect / --inspect-brk in pm2's node_args (array or string).
func InspectFlag(raws ...json.RawMessage) string {
	for _, raw := range raws {
		var args []string
		var one string
		if json.Unmarshal(raw, &args) != nil {
			if json.Unmarshal(raw, &one) == nil {
				args = strings.Fields(one)
			}
		}
		for _, a := range args {
			if strings.HasPrefix(a, "--inspect") {
				return a
			}
		}
	}
	return ""
}

// Enricher adds listeners, probes, error-log growth, security facts and nginx sites to
// the PM2 list. It keeps small caches so each scan stays cheap.
type Enricher struct {
	Ports func() []Listener

	mu        sync.Mutex
	logSizes  map[string]int64
	hashCache map[string]hashEntry
	sites     []Site
	sitesAt   time.Time
	client    *http.Client
}

type hashEntry struct {
	mtime time.Time
	size  int64
	hash  string
}

func (e *Enricher) Enrich(ctx context.Context, services []Service) []Service {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logSizes == nil {
		e.logSizes = map[string]int64{}
		e.hashCache = map[string]hashEntry{}
		e.client = &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if time.Since(e.sitesAt) > 5*time.Minute {
		e.sites = ReadNginxSites()
		e.sitesAt = time.Now()
	}
	var listeners []Listener
	if e.Ports != nil {
		listeners = e.Ports()
	}
	out := make([]Service, len(services))
	for i, s := range services {
		for _, l := range listeners {
			if s.PID > 0 && l.PID == s.PID {
				s.Listeners = append(s.Listeners, ListenAddr{Address: l.Address, Port: l.Port})
				if !containsInt(s.Ports, l.Port) {
					s.Ports = append(s.Ports, l.Port)
				}
			}
		}
		for _, site := range e.sites {
			for _, p := range site.ProxyPorts {
				if containsInt(s.Ports, p) {
					s.Sites = append(s.Sites, site)
					break
				}
			}
		}
		s.ErrorLines = e.errorLines(s.ErrLogPath)
		s.Security.EnvFile, s.Security.EnvFileMode, s.Security.EnvFileOwner = envFile(s.Cwd, s.ExecPath)
		if lf := FindLockfile(s.Cwd, s.ExecPath); lf != "" {
			s.Security.Lockfile = lf
			s.Security.DepsHash = e.fileHash(lf)
		}
		if s.Status == "online" && len(s.Listeners) > 0 {
			p := e.probe(ctx, probeOrder(s))
			s.Probe = &p
		}
		out[i] = s
	}
	return out
}

// errorLines counts lines appended to the error log since the previous scan.
func (e *Enricher) errorLines(path string) int {
	if path == "" || path == "/dev/null" {
		return 0
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	prev, seen := e.logSizes[path]
	e.logSizes[path] = st.Size()
	if !seen || st.Size() <= prev {
		return 0 // first look, or rotated/truncated
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	start := prev
	if st.Size()-prev > 4<<20 {
		start = st.Size() - 4<<20 // a huge burst: count the last 4 MB
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return 0
	}
	b, _ := io.ReadAll(io.LimitReader(f, 4<<20))
	return bytes.Count(b, []byte{'\n'})
}

func (e *Enricher) fileHash(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if h, ok := e.hashCache[path]; ok && h.mtime.Equal(st.ModTime()) && h.size == st.Size() {
		return h.hash
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	e.hashCache[path] = hashEntry{mtime: st.ModTime(), size: st.Size(), hash: h}
	return h
}

// probe calls the app on its first listening port: HTTP GET /, or a plain TCP connect if
// the port does not speak HTTP. Wildcard binds are reached through loopback.
func (e *Enricher) probe(ctx context.Context, ls []ListenAddr) Probe {
	l := ls[0]
	host := l.Address
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	addr := net.JoinHostPort(host, fmt.Sprint(l.Port))
	p := Probe{Port: l.Port, CheckedAt: time.Now().UTC()}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
	req.Header.Set("User-Agent", "vps-soc-agent/health")
	resp, err := e.client.Do(req)
	p.LatencyMs = time.Since(start).Milliseconds()
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		p.Status = resp.StatusCode
		p.OK = resp.StatusCode < 500
		if !p.OK {
			p.Error = resp.Status
		}
		return p
	}
	// Not HTTP (websocket server, gRPC, raw TCP): being able to connect is the check.
	start = time.Now()
	conn, derr := net.DialTimeout("tcp", addr, 3*time.Second)
	if derr != nil {
		p.Error = derr.Error()
		return p
	}
	conn.Close()
	p.OK, p.TCPOnly, p.LatencyMs = true, true, time.Since(start).Milliseconds()
	return p
}

// probeOrder puts first the port nginx forwards to, then any port that is not Node's
// inspector (9229/9230), so the check hits the app itself.
func probeOrder(s Service) []ListenAddr {
	rank := func(l ListenAddr) int {
		for _, site := range s.Sites {
			if containsInt(site.ProxyPorts, l.Port) {
				return 0
			}
		}
		if l.Port == 9229 || l.Port == 9230 {
			return 2
		}
		return 1
	}
	out := append([]ListenAddr(nil), s.Listeners...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

// envFile finds a .env next to the app and reports its permissions (never its content).
func envFile(cwd, execPath string) (path, mode, owner string) {
	for _, d := range []string{cwd, filepath.Dir(execPath)} {
		if d == "" || d == "/" || d == "." {
			continue
		}
		p := filepath.Join(d, ".env")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, st.Mode().Perm().String(), fileOwner(st)
		}
	}
	return "", "", ""
}
