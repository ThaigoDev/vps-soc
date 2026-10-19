package collector

import (
	"reflect"
	"testing"
)

func TestParseProcStat(t *testing.T) {
	comm, ppid, start, ok := ParseProcStat("1234 (my (evil) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000000 200 18446744073709551615")
	if !ok || comm != "my (evil) proc" || ppid != 1 || start != 98765 {
		t.Fatalf("got %q %d %d %v", comm, ppid, start, ok)
	}
	if _, _, _, ok := ParseProcStat("garbage"); ok {
		t.Error("garbage must not parse")
	}
}

func TestParseStatusUID(t *testing.T) {
	if uid := ParseStatusUID("Name:\tbash\nPPid:\t1\nUid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\n"); uid != "33" {
		t.Errorf("uid %q", uid)
	}
}

func TestClassifyProcess(t *testing.T) {
	systemd := ProcInfo{Comm: "systemd", Exe: "/usr/lib/systemd/systemd"}
	cases := []struct {
		name   string
		p      ProcInfo
		parent ProcInfo
		want   []string
	}{
		{"binary in /tmp", ProcInfo{Comm: "kworkerd", Exe: "/tmp/.x/kworkerd", User: "root"}, systemd, []string{ReasonTempExe}},
		{"deleted from /dev/shm", ProcInfo{Comm: "x", Exe: "/dev/shm/x (deleted)"}, systemd, []string{ReasonTempExe, ReasonDeletedExe}},
		{"memfd", ProcInfo{Comm: "3", Exe: "/memfd: (deleted)"}, systemd, []string{ReasonDeletedExe}},
		{"shell under nginx", ProcInfo{Comm: "sh", Exe: "/usr/bin/dash", User: "nginx"}, ProcInfo{Comm: "nginx"}, []string{ReasonWebShell}},
		{"bash under php-fpm", ProcInfo{Comm: "bash", Exe: "/usr/bin/bash", User: "app"}, ProcInfo{Comm: "php-fpm8.3"}, []string{ReasonWebShell}},
		{"shell as www-data", ProcInfo{Comm: "sh", Exe: "/usr/bin/dash", User: "www-data"}, ProcInfo{Comm: "python3"}, []string{ReasonWebShell}},
		{"shell under node", ProcInfo{Comm: "sh", Exe: "/bin/sh", User: "app"}, ProcInfo{Comm: "node"}, []string{ReasonWebShell}},
		{"admin shell under sshd", ProcInfo{Comm: "bash", Exe: "/usr/bin/bash", User: "thiago"}, ProcInfo{Comm: "sshd"}, nil},
		{"nginx worker itself", ProcInfo{Comm: "nginx", Exe: "/usr/sbin/nginx", User: "www-data"}, ProcInfo{Comm: "nginx"}, nil},
		{"kernel thread", ProcInfo{Comm: "kthreadd"}, ProcInfo{}, nil},
		{"tmpfs lookalike", ProcInfo{Comm: "x", Exe: "/tmpfoo/x"}, systemd, nil},
	}
	for _, c := range cases {
		if got := ClassifyProcess(c.p, c.parent, false); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestClassifyShellUnderExposedService(t *testing.T) {
	shell := ProcInfo{Comm: "sh", Exe: "/usr/bin/dash", User: "root"}
	// Next.js apps show up as "next-server (v15" (comm is cut at 15 chars).
	if got := ClassifyProcess(shell, ProcInfo{Comm: "next-server (v1"}, false); !reflect.DeepEqual(got, []string{ReasonWebShell}) {
		t.Errorf("next-server parent: got %v", got)
	}
	// Any parent listening on a public address counts, whatever its name.
	if got := ClassifyProcess(shell, ProcInfo{Comm: "myapi"}, true); !reflect.DeepEqual(got, []string{ReasonWebShell}) {
		t.Errorf("exposed parent: got %v", got)
	}
	if got := ClassifyProcess(shell, ProcInfo{Comm: "myapi"}, false); got != nil {
		t.Errorf("internal parent: got %v", got)
	}
}

func TestIsWebParent(t *testing.T) {
	for _, comm := range []string{"nginx", "nginx: worker", "php-fpm8.3", "apache2", "next-server (v1", "node", "bun"} {
		if !isWebParent(comm) {
			t.Errorf("%q should be a web parent", comm)
		}
	}
	for _, comm := range []string{"nodemon", "bundle", "javac", "sshd", "cron"} {
		if isWebParent(comm) {
			t.Errorf("%q should not be a web parent", comm)
		}
	}
}

func TestIsExposedAddress(t *testing.T) {
	for addr, want := range map[string]bool{"0.0.0.0": true, "::": true, "203.0.113.5": true, "100.64.0.10": true,
		"127.0.0.1": false, "127.0.0.53": false, "::1": false, "bogus": false} {
		if got := isExposedAddress(addr); got != want {
			t.Errorf("%s: got %v want %v", addr, got, want)
		}
	}
}
