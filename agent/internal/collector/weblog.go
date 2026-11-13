package collector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"vps-soc/agent/internal/event"
)

// Web request categories. Exploit categories are attempts to break the application; probe
// categories are scanners looking for files and panels that should not be public.
const (
	WebSQLi          = "SQLI"
	WebTraversal     = "PATH_TRAVERSAL"
	WebCmdInjection  = "COMMAND_INJECTION"
	WebJNDI          = "LOG4SHELL"
	WebXSS           = "XSS"
	WebSensitiveFile = "SENSITIVE_FILE"
	WebAdminProbe    = "ADMIN_PROBE"
)

// ExploitCategories are the ones that try to break the application.
var ExploitCategories = map[string]bool{WebSQLi: true, WebTraversal: true, WebCmdInjection: true, WebJNDI: true, WebXSS: true}

var webRules = []struct {
	category string
	re       *regexp.Regexp
}{
	{WebJNDI, regexp.MustCompile(`\$\{(jndi|\$\{lower|\$\{::-j|env:)`)},
	{WebSQLi, regexp.MustCompile(`union(\s|/\*.*?\*/)+(all\s+)?select|select\s.+\sfrom\s|information_schema|\bor\s+'?\d+'?\s*=\s*'?\d+|'\s*(or|and)\s+'|\b(sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay|;\s*(drop|insert|update|delete)\s|extractvalue\s*\(|updatexml\s*\(`)},
	{WebTraversal, regexp.MustCompile(`\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|/proc/self/|c:\\windows|boot\.ini`)},
	{WebCmdInjection, regexp.MustCompile("(;|\\||&&|`|\\$\\()\\s*(cat|wget|curl|nc|bash|sh|id|whoami|uname|chmod|python|perl)\\b|/bin/(ba)?sh|cmd\\.exe|powershell")},
	{WebXSS, regexp.MustCompile(`<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+\s*=|alert\s*\(|document\.cookie`)},
	{WebSensitiveFile, regexp.MustCompile(`/\.env(\.|$|/|\?)|/\.git/|/\.svn/|/\.aws/|/\.ssh/|/\.htpasswd|/\.ds_store|wp-config\.php|/id_rsa|/config\.(json|yml|yaml|php)(\?|$)|\.(sql|bak|old|backup|swp)(\?|$)|/web\.config|/\.vscode/|/docker-compose\.ya?ml`)},
	{WebAdminProbe, regexp.MustCompile(`/wp-login\.php|/wp-admin|/xmlrpc\.php|/phpmyadmin|/pma/|/adminer|/cgi-bin/|/phpunit|eval-stdin\.php|/actuator|/server-status|/solr/|/boaform|/hnap1|/shell\?|/vendor/|/\.well-known/security|/console/|/manager/html|/owa/|/ecp/`)},
}

// scannerTools are user agents of attack and scanning tools.
var scannerTools = regexp.MustCompile(`(?i)\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|acunetix|nessus|openvas|hydra|whatweb|jaeles|xray|zmeu|commix)\b`)

// combined log format: ip - user [time] "METHOD target PROTO" status bytes "referer" "user-agent"
var accessLine = regexp.MustCompile(`^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?`)

// WebRequest is one parsed access log line.
type WebRequest struct {
	IP, Method, Target, UserAgent string
	Status                        int
}

// ParseAccessLine reads a line in nginx's default "combined" format.
func ParseAccessLine(line string) (WebRequest, bool) {
	m := accessLine.FindStringSubmatch(line)
	if m == nil {
		return WebRequest{}, false
	}
	var status int
	fmt.Sscanf(m[4], "%d", &status)
	return WebRequest{IP: m[1], Method: m[2], Target: m[3], Status: status, UserAgent: m[5]}, true
}

// ClassifyRequest returns the attack categories a request matches and the attack tool in its
// user agent, if any. The target is URL-decoded twice (attackers double-encode) and lower-cased.
func ClassifyRequest(r WebRequest) (categories []string, tool string) {
	target := r.Target
	for i := 0; i < 2; i++ {
		if d, err := url.QueryUnescape(target); err == nil {
			target = d
		}
	}
	target = strings.ToLower(target)
	for _, rule := range webRules {
		if rule.re.MatchString(target) {
			categories = append(categories, rule.category)
		}
	}
	if strings.Contains(r.UserAgent, "${") && !containsStr(categories, WebJNDI) {
		if webRules[0].re.MatchString(strings.ToLower(r.UserAgent)) {
			categories = append(categories, WebJNDI) // Log4Shell is mostly sent in headers
		}
	}
	if m := scannerTools.FindString(r.UserAgent); m != "" {
		tool = strings.ToLower(m)
	}
	return categories, tool
}

// WebLogMonitor follows web server access logs and reports, per client IP and per window,
// the requests that look like attacks (one WEB_ATTACK event per IP and window, not per line).
type WebLogMonitor struct {
	Patterns []string // access log globs
	Window   time.Duration
	Emit     func(event.Event)

	files map[string]*tailedFile
	aggs  map[string]*webAgg
}

type tailedFile struct {
	ino     uint64
	offset  int64
	partial []byte
}

type webAgg struct {
	ip         string
	first      time.Time
	requests   int
	categories map[string]int
	statuses   map[int]int
	samples    []string
	tool       string
	userAgent  string
	files      map[string]bool
}

func (m *WebLogMonitor) Run(ctx context.Context) {
	m.files = map[string]*tailedFile{}
	m.aggs = map[string]*webAgg{}
	if m.Window == 0 {
		m.Window = 10 * time.Second
	}
	m.poll(true) // start at the end: history before the agent started is not replayed
	read := time.NewTicker(time.Second)
	defer read.Stop()
	flush := time.NewTicker(m.Window)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			m.flush()
			return
		case <-read.C:
			m.poll(false)
		case <-flush.C:
			m.flush()
		}
	}
}

func (m *WebLogMonitor) poll(skipToEnd bool) {
	seen := map[string]bool{}
	for _, pattern := range m.Patterns {
		paths, _ := filepath.Glob(pattern)
		for _, path := range paths {
			seen[path] = true
			m.readNew(path, skipToEnd)
		}
	}
	for path := range m.files {
		if !seen[path] {
			delete(m.files, path)
		}
	}
}

const maxReadPerTick = 8 << 20

func (m *WebLogMonitor) readNew(path string, skipToEnd bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	var ino uint64
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = s.Ino
	}
	t, known := m.files[path]
	switch {
	case !known:
		t = &tailedFile{ino: ino}
		if skipToEnd {
			t.offset = st.Size()
		}
		m.files[path] = t
	case t.ino != ino || st.Size() < t.offset: // rotated or truncated: read the new file from the start
		*t = tailedFile{ino: ino}
	}
	if st.Size() == t.offset {
		return
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxReadPerTick))
	if err != nil {
		return
	}
	t.offset += int64(len(buf))
	data := append(t.partial, buf...)
	last := bytes.LastIndexByte(data, '\n')
	if last < 0 {
		t.partial = data
		if len(t.partial) > 64<<10 {
			t.partial = nil // not a log line
		}
		return
	}
	t.partial = append([]byte(nil), data[last+1:]...)
	for _, line := range bytes.Split(data[:last], []byte{'\n'}) {
		m.observe(path, string(line))
	}
}

func (m *WebLogMonitor) observe(path, line string) {
	r, ok := ParseAccessLine(line)
	if !ok {
		return
	}
	if ip := net.ParseIP(r.IP); ip == nil || ip.IsLoopback() {
		return
	}
	cats, tool := ClassifyRequest(r)
	if len(cats) == 0 && tool == "" {
		return
	}
	a := m.aggs[r.IP]
	if a == nil {
		if len(m.aggs) >= 5000 {
			return // flood of distinct sources: keep memory bounded until the next flush
		}
		a = &webAgg{ip: r.IP, first: time.Now(), categories: map[string]int{}, statuses: map[int]int{}, files: map[string]bool{}}
		m.aggs[r.IP] = a
	}
	a.requests++
	a.files[path] = true
	a.statuses[r.Status]++
	for _, c := range cats {
		a.categories[c]++
	}
	if tool != "" {
		a.tool = tool
	}
	if a.userAgent == "" {
		a.userAgent = truncate(r.UserAgent, 200)
	}
	if len(a.samples) < 5 {
		a.samples = append(a.samples, fmt.Sprintf("%s %s → %d", r.Method, truncate(r.Target, 200), r.Status))
	}
}

func (m *WebLogMonitor) flush() {
	now := time.Now()
	for ip, a := range m.aggs {
		exploits := 0
		var cats []string
		for c, n := range a.categories {
			cats = append(cats, c)
			if ExploitCategories[c] {
				exploits += n
			}
		}
		sort.Strings(cats)
		success := 0
		for s, n := range a.statuses {
			if s >= 200 && s < 300 {
				success += n
			}
		}
		files := make([]string, 0, len(a.files))
		for f := range a.files {
			files = append(files, f)
		}
		sort.Strings(files)
		msg := fmt.Sprintf("web: %d requisições suspeitas de %s (%s)", a.requests, ip, strings.Join(cats, ", "))
		if a.tool != "" {
			msg += ", ferramenta " + a.tool
		}
		m.Emit(event.Event{Type: event.WebAttack, OccurredAt: a.first, SourceIP: ip, Message: msg,
			Metadata: map[string]any{
				"requests": a.requests, "exploitRequests": exploits, "categories": a.categories, "statuses": a.statuses,
				"successfulRequests": success, "samples": a.samples, "tool": a.tool, "userAgent": a.userAgent,
				"logs": files, "windowSeconds": int(now.Sub(a.first).Seconds()) + 1,
			}})
	}
	m.aggs = map[string]*webAgg{}
}
