package collector

import (
	"testing"
	"time"

	"vps-soc/agent/internal/event"
)

func TestParseSSH(t *testing.T) {
	ts := time.Now()
	cases := []struct {
		program, msg       string
		wantType, ip, user string
	}{
		{"sshd", "Failed password for root from 185.10.20.30 port 51234 ssh2", event.SSHFailedLogin, "185.10.20.30", "root"},
		{"sshd-session", "Failed password for invalid user admin from 2001:db8::1 port 40000 ssh2", event.SSHFailedLogin, "2001:db8::1", "admin"},
		{"sshd", "Accepted publickey for thiago from 10.0.0.5 port 60000 ssh2: ED25519 SHA256:abc", event.SSHLoginSuccess, "10.0.0.5", "thiago"},
		{"sshd", "Invalid user oracle from 45.1.2.3 port 1111", event.SSHInvalidUser, "45.1.2.3", "oracle"},
		{"sshd", "Invalid user  from 45.1.2.3 port 1111", event.SSHInvalidUser, "45.1.2.3", ""},
	}
	for _, c := range cases {
		e, ok := ParseAuthMessage(c.program, c.msg, ts)
		if !ok {
			t.Fatalf("not parsed: %q", c.msg)
		}
		if e.Type != c.wantType || e.SourceIP != c.ip || e.Username != c.user {
			t.Errorf("%q => %s ip=%s user=%s", c.msg, e.Type, e.SourceIP, e.Username)
		}
	}

	ignored := []string{
		"Connection closed by authenticating user root 1.2.3.4 port 22 [preauth]",
		"pam_unix(sshd:session): session opened for user thiago(uid=1000) by (uid=0)",
		"Received disconnect from 1.2.3.4 port 22:11: Bye Bye [preauth]",
	}
	for _, msg := range ignored {
		if _, ok := ParseAuthMessage("sshd", msg, ts); ok {
			t.Errorf("should ignore %q", msg)
		}
	}
}

func TestParseSudo(t *testing.T) {
	ts := time.Now()
	e, ok := ParseAuthMessage("sudo", "thiago : TTY=pts/0 ; PWD=/home/thiago ; USER=root ; COMMAND=/usr/bin/apt update ; echo x", ts)
	if !ok || e.Type != event.SudoCommand || e.Username != "thiago" {
		t.Fatalf("got %+v", e)
	}
	if e.Metadata["command"] != "/usr/bin/apt update ; echo x" || e.Metadata["runAs"] != "root" {
		t.Errorf("metadata %+v", e.Metadata)
	}

	e, _ = ParseAuthMessage("sudo", "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh", ts)
	if e.Type != event.SudoDenied {
		t.Errorf("want denied, got %s", e.Type)
	}
	e, _ = ParseAuthMessage("sudo", "bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh", ts)
	if e.Type != event.SudoAuthFailure {
		t.Errorf("want auth failure, got %s", e.Type)
	}
	if _, ok := ParseAuthMessage("sudo", "pam_unix(sudo:session): session opened for user root", ts); ok {
		t.Error("pam line should be ignored")
	}
}

func TestParseSyslogLine(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	p, msg, ts, ok := ParseSyslogLine("Oct 19 13:40:21 vps sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2", now)
	if !ok || p != "sshd" || ts != now || msg != "Failed password for root from 1.2.3.4 port 22 ssh2" {
		t.Errorf("classic: %v %q %q %v", ok, p, msg, ts)
	}
	p, _, ts, ok = ParseSyslogLine("2026-10-19T13:40:21.123456+00:00 vps sudo: thiago : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", now)
	if !ok || p != "sudo" || ts.Hour() != 13 {
		t.Errorf("rfc3339: %v %q %v", ok, p, ts)
	}
}
