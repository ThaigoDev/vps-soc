package collector

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"vps-soc/agent/internal/event"
)

var (
	// Failed password for root from 1.2.3.4 port 51234 ssh2
	// Failed password for invalid user admin from 1.2.3.4 port 51234 ssh2
	reSSHFailed = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)`)
	// Accepted publickey for thiago from 1.2.3.4 port 51234 ssh2: ED25519 SHA256:...
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	// Invalid user admin from 1.2.3.4 port 51234
	reSSHInvalid = regexp.MustCompile(`^Invalid user (\S*) from (\S+) port (\d+)`)

	// thiago : TTY=pts/0 ; PWD=/home/thiago ; USER=root ; COMMAND=/usr/bin/apt update
	// thiago : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/thiago ; USER=root ; COMMAND=/bin/ls
	// thiago : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/thiago ; USER=root ; COMMAND=/bin/ls
	reSudo = regexp.MustCompile(`^\s*(\S+) : (.*)$`)

	// Classic syslog:  Oct 19 13:40:21 vps sshd[1234]: message
	// RFC3339 syslog:  2026-10-19T13:40:21.123456+00:00 vps sshd[1234]: message
	reSyslogLine = regexp.MustCompile(
		`^(?:\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|(\d{4}-\d{2}-\d{2}T\S+)) \S+ ([^\s\[:]+)(?:\[\d+\])?: (.*)$`)
)

// isSSHProgram covers sshd and the per-session binaries split off in OpenSSH 9.8+.
func isSSHProgram(p string) bool {
	return p == "sshd" || p == "sshd-session" || p == "sshd-auth"
}

// ParseAuthMessage turns one sshd/sudo log message into an event.
// It returns false for lines that carry no security signal we track.
func ParseAuthMessage(program, msg string, ts time.Time) (event.Event, bool) {
	msg = strings.TrimSpace(msg)
	switch {
	case isSSHProgram(program):
		return parseSSH(msg, ts)
	case program == "sudo":
		return parseSudo(msg, ts)
	}
	return event.Event{}, false
}

func parseSSH(msg string, ts time.Time) (event.Event, bool) {
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		return event.Event{
			Type: event.SSHFailedLogin, OccurredAt: ts, SourceIP: m[4], Username: m[3], Message: msg,
			Metadata: map[string]any{"method": m[1], "invalidUser": m[2] != "", "port": atoi(m[5])},
		}, true
	}
	if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
		return event.Event{
			Type: event.SSHLoginSuccess, OccurredAt: ts, SourceIP: m[3], Username: m[2], Message: msg,
			Metadata: map[string]any{"method": m[1], "port": atoi(m[4])},
		}, true
	}
	if m := reSSHInvalid.FindStringSubmatch(msg); m != nil {
		return event.Event{
			Type: event.SSHInvalidUser, OccurredAt: ts, SourceIP: m[2], Username: m[1], Message: msg,
			Metadata: map[string]any{"port": atoi(m[3])},
		}, true
	}
	return event.Event{}, false
}

func parseSudo(msg string, ts time.Time) (event.Event, bool) {
	m := reSudo.FindStringSubmatch(msg)
	if m == nil || !strings.Contains(m[2], "COMMAND=") {
		return event.Event{}, false
	}
	user, rest := m[1], m[2]
	fields := sudoFields(rest)
	meta := map[string]any{"runAs": fields["USER"], "command": fields["COMMAND"], "tty": fields["TTY"], "pwd": fields["PWD"]}

	typ := event.SudoCommand
	switch {
	case strings.Contains(rest, "NOT in sudoers"):
		typ = event.SudoDenied
	case strings.Contains(rest, "incorrect password attempt"):
		typ = event.SudoAuthFailure
	}
	return event.Event{Type: typ, OccurredAt: ts, Username: user, Message: msg, Metadata: meta}, true
}

// sudoFields splits "TTY=pts/0 ; PWD=/x ; USER=root ; COMMAND=/bin/ls -la".
// COMMAND is always last and may itself contain " ; ", so it takes the remainder.
func sudoFields(s string) map[string]string {
	out := map[string]string{}
	if i := strings.Index(s, "COMMAND="); i >= 0 {
		out["COMMAND"] = s[i+len("COMMAND="):]
		s = s[:i]
	}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

// ParseSyslogLine extracts program and message from an auth.log/secure line.
// Lines with an RFC3339 timestamp keep it; classic lines get now (we tail live).
func ParseSyslogLine(line string, now time.Time) (program, msg string, ts time.Time, ok bool) {
	m := reSyslogLine.FindStringSubmatch(line)
	if m == nil {
		return "", "", time.Time{}, false
	}
	ts = now
	if m[1] != "" {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			ts = t
		}
	}
	return m[2], m[3], ts, true
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
