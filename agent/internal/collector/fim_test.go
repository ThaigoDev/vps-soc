package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vps-soc/agent/internal/event"
)

func TestSSHDDirectives(t *testing.T) {
	got := SSHDDirectives("# comment\n\nPort 22\n  PermitRootLogin   no \n\t# indented comment\nMatch User git\n    X11Forwarding no\n")
	want := []string{"Port 22", "PermitRootLogin no", "Match User git", "X11Forwarding no"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestDiffLines(t *testing.T) {
	added, removed := DiffLines(
		[]string{"Port 22", "PermitRootLogin no", "PasswordAuthentication no", "AllowUsers a"},
		[]string{"Port 22", "PermitRootLogin yes", "PasswordAuthentication no", "AllowUsers a", "AllowUsers a"})
	if !reflect.DeepEqual(added, []string{"PermitRootLogin yes", "AllowUsers a"}) {
		t.Errorf("added %q", added)
	}
	if !reflect.DeepEqual(removed, []string{"PermitRootLogin no"}) {
		t.Errorf("removed %q", removed)
	}
	if a, r := DiffLines([]string{"x"}, []string{"x"}); a != nil || r != nil {
		t.Errorf("identical => %q %q", a, r)
	}
}

func TestDiffFiles(t *testing.T) {
	ts := time.Now()
	prev := map[string]FileState{
		"/etc/passwd":          {Hash: "a", Size: 10, Owner: "root:root", Mode: "-rw-r--r--"},
		"/etc/cron.d/old":      {Hash: "b", Size: 5},
		"/etc/ssh/sshd_config": {Hash: "c", Directives: []string{"Port 22", "PermitRootLogin no"}},
		"/etc/group":           {Hash: "d", Owner: "root:root", Mode: "-rw-r--r--"},
	}
	now := map[string]FileState{
		"/etc/passwd":                {Hash: "a2", Size: 50, Owner: "root:root", Mode: "-rw-r--r--"},
		"/etc/ssh/sshd_config":       {Hash: "c2", Directives: []string{"Port 22", "PermitRootLogin yes"}},
		"/root/.ssh/authorized_keys": {Hash: "e", Size: 100, Owner: "root:root"},
		"/etc/group":                 {Hash: "d", Owner: "root:root", Mode: "-rw-rw-rw-"},
	}
	byPath := map[string]event.Event{}
	for _, e := range DiffFiles(prev, now, ts) {
		byPath[e.Metadata["path"].(string)] = e
	}
	if len(byPath) != 5 {
		t.Fatalf("want 5 events, got %d: %+v", len(byPath), byPath)
	}
	if e := byPath["/etc/passwd"]; e.Type != event.FileModified || e.Metadata["oldHash"] != "a" || e.Metadata["newHash"] != "a2" || e.Metadata["oldSize"] != int64(10) {
		t.Errorf("passwd %+v", e)
	}
	if e := byPath["/etc/cron.d/old"]; e.Type != event.FileDeleted || e.Metadata["oldHash"] != "b" {
		t.Errorf("cron %+v", e)
	}
	if e := byPath["/root/.ssh/authorized_keys"]; e.Type != event.FileCreated || e.Metadata["newHash"] != "e" {
		t.Errorf("keys %+v", e)
	}
	sshd := byPath["/etc/ssh/sshd_config"]
	if sshd.Type != event.FileModified ||
		!reflect.DeepEqual(sshd.Metadata["addedLines"], []string{"PermitRootLogin yes"}) ||
		!reflect.DeepEqual(sshd.Metadata["removedLines"], []string{"PermitRootLogin no"}) {
		t.Errorf("sshd %+v", sshd.Metadata)
	}
	if e := byPath["/etc/group"]; e.Type != event.FileModified || e.Metadata["oldMode"] != "-rw-r--r--" {
		t.Errorf("group chmod %+v", e)
	}
	if _, ok := byPath["/etc/passwd"].Metadata["addedLines"]; ok {
		t.Error("non-sshd files must not carry line diffs")
	}

	if got := DiffFiles(now, now, ts); len(got) != 0 {
		t.Errorf("no change must emit nothing, got %+v", got)
	}
}

func TestSnapshotFilesHashesWithoutKeepingContents(t *testing.T) {
	dir := t.TempDir()
	secret := "root:$6$verysecrethash:19000:0:99999:7:::"
	if err := os.WriteFile(filepath.Join(dir, "shadow"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cron-job"), []byte("* * * * * root /tmp/x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "shadow"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	snap := SnapshotFiles([]string{filepath.Join(dir, "*"), filepath.Join(dir, "missing")})
	if len(snap) != 2 {
		t.Fatalf("want 2 regular files, got %v", snap)
	}
	fs := snap[filepath.Join(dir, "shadow")]
	// sha256 of the secret line above
	if len(fs.Hash) != 64 || fs.Size != int64(len(secret)) || fs.Mode != "-rw-------" || fs.Directives != nil {
		t.Errorf("shadow state %+v", fs)
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "verysecrethash") || strings.Contains(string(b), "/tmp/x") {
		t.Fatalf("file contents leaked into state: %s", b)
	}
}

func TestHashOnlyNeverParsed(t *testing.T) {
	for _, p := range []string{"/etc/shadow", "/etc/gshadow"} {
		if !hashOnly(p) {
			t.Errorf("%s must be hash-only", p)
		}
	}
	if !isSSHDConfig("/etc/ssh/sshd_config.d/50-cloud-init.conf") || isSSHDConfig("/etc/ssh/ssh_config") {
		t.Error("isSSHDConfig")
	}
}
