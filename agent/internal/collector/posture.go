package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session is an interactive login read from /run/utmp (what `who` shows).
type Session struct {
	User    string    `json:"user"`
	TTY     string    `json:"tty"`
	Host    string    `json:"host,omitempty"`
	LoginAt time.Time `json:"loginAt"`
}

type SSHSettings struct {
	PermitRootLogin        string `json:"permitRootLogin,omitempty"`
	PasswordAuthentication string `json:"passwordAuthentication,omitempty"`
	MaxAuthTries           string `json:"maxAuthTries,omitempty"`
}

// Posture is the hardening state of the host: things that are not attacks but make one
// easier (pending security patches, a failed service, password SSH logins...).
type Posture struct {
	Sessions        []Session    `json:"sessions"`
	PendingUpdates  int          `json:"pendingUpdates"`  // -1 = unknown
	SecurityUpdates int          `json:"securityUpdates"` // -1 = unknown
	RebootRequired  bool         `json:"rebootRequired"`
	FailedUnits     []string     `json:"failedUnits"` // null = unknown, [] = none failed
	SSH             *SSHSettings `json:"ssh,omitempty"`
	Firewall        any          `json:"firewall,omitempty"`
	Certificates    []*CertInfo  `json:"certificates,omitempty"` // TLS certs of certbot and nginx
}

// PostureReader caches the slow checks (systemctl, sshd -T) for a few minutes.
type PostureReader struct {
	mu     sync.Mutex
	slowAt time.Time
	failed []string
	ssh    *SSHSettings
	certs  []*CertInfo
}

const slowPostureEvery = 5 * time.Minute

func (r *PostureReader) Read(ctx context.Context) Posture {
	p := Posture{Sessions: ReadSessions("/run/utmp")}
	p.PendingUpdates, p.SecurityUpdates = readUpdates("/var/lib/update-notifier/updates-available")
	_, err := os.Stat("/var/run/reboot-required")
	p.RebootRequired = err == nil

	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.slowAt) > slowPostureEvery {
		r.failed = failedUnits(ctx)
		r.ssh = sshSettings(ctx)
		r.certs = allCertificates()
		r.slowAt = time.Now()
	}
	p.FailedUnits = r.failed // nil (sent as null) when systemctl could not be asked: the SOC then keeps its findings
	p.SSH = r.ssh
	p.Certificates = r.certs
	return p
}

func failedUnits(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--state=failed", "--type=service",
		"--plain", "--no-legend", "--no-pager").Output()
	if err != nil {
		return nil
	}
	return ParseFailedUnits(string(out))
}

// ParseFailedUnits takes the first column of `systemctl list-units --plain --no-legend`.
func ParseFailedUnits(out string) []string {
	units := []string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			units = append(units, f[0])
		}
	}
	return units
}

func sshSettings(ctx context.Context) *SSHSettings {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sshd", "-T").Output()
	if err != nil {
		if path, lookErr := exec.LookPath("/usr/sbin/sshd"); lookErr == nil {
			out, err = exec.CommandContext(ctx, path, "-T").Output()
		}
		if err != nil {
			return nil
		}
	}
	return ParseSSHDEffective(string(out))
}

// ParseSSHDEffective reads the lowercase "key value" lines printed by `sshd -T`.
func ParseSSHDEffective(out string) *SSHSettings {
	s := &SSHSettings{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch k {
		case "permitrootlogin":
			s.PermitRootLogin = v
		case "passwordauthentication":
			s.PasswordAuthentication = v
		case "maxauthtries":
			s.MaxAuthTries = v
		}
	}
	return s
}

var reUpdates = regexp.MustCompile(`(\d+) (?:updates?|atualizaç\S+) (?:can be applied|pode)`)
var reSecurity = regexp.MustCompile(`(\d+) (?:of these )?updates? (?:is|are) (?:a )?(?:standard )?security`)

// readUpdates parses Ubuntu's update-notifier summary, e.g.
// "12 updates can be applied immediately.\n5 of these updates are standard security updates."
func readUpdates(path string) (pending, security int) {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1, -1
	}
	return ParseUpdates(string(b))
}

func ParseUpdates(s string) (pending, security int) {
	pending, security = 0, 0
	if m := reUpdates.FindStringSubmatch(s); m != nil {
		pending, _ = strconv.Atoi(m[1])
	}
	if m := reSecurity.FindStringSubmatch(s); m != nil {
		security, _ = strconv.Atoi(m[1])
	}
	return pending, security
}

// utmp record layout on Linux (glibc, x86_64 and arm64): 384 bytes.
const (
	utmpSize        = 384
	utmpUserProcess = 7
)

// ReadSessions parses utmp and returns the logged-in users.
func ReadSessions(path string) []Session {
	b, err := os.ReadFile(path)
	if err != nil {
		return []Session{}
	}
	return ParseUtmp(b)
}

func ParseUtmp(b []byte) []Session {
	out := []Session{}
	for off := 0; off+utmpSize <= len(b); off += utmpSize {
		r := b[off : off+utmpSize]
		if int16(binary.LittleEndian.Uint16(r[0:2])) != utmpUserProcess {
			continue
		}
		pid := int32(binary.LittleEndian.Uint32(r[4:8]))
		if pid > 0 {
			if _, err := os.Stat("/proc/" + strconv.Itoa(int(pid))); err != nil {
				continue // stale record left by a crashed session
			}
		}
		sec := int64(int32(binary.LittleEndian.Uint32(r[340:344])))
		out = append(out, Session{
			TTY:     cstr(r[8:40]),
			User:    cstr(r[44:76]),
			Host:    cstr(r[76:332]),
			LoginAt: time.Unix(sec, 0).UTC(),
		})
	}
	return out
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// netCounters sums received/transmitted bytes of all non-loopback interfaces.
func netCounters() (rx, tx uint64, ok bool) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, rest, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx, true
}

// tcpEstablished counts sockets in state ESTABLISHED (01).
func tcpEstablished() int {
	n := 0
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if f := strings.Fields(line); len(f) > 3 && f[3] == "01" {
				n++
			}
		}
	}
	return n
}

func processCount() int {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	return len(dirs)
}

// allCertificates merges certbot's certificates with any other cert nginx serves.
func allCertificates() []*CertInfo {
	seen := map[string]bool{}
	var out []*CertInfo
	for _, c := range ReadLetsEncryptCerts() {
		seen[c.Path] = true
		seen[filepath.Dir(c.Path)] = true // nginx points at fullchain.pem in the same live/ dir
		out = append(out, c)
	}
	for _, s := range ReadNginxSites() {
		if c := s.Certificate; c != nil && !seen[c.Path] && !seen[filepath.Dir(c.Path)] {
			seen[c.Path] = true
			out = append(out, c)
		}
	}
	return out
}
