package collector

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fast fingerprint (kernel list of children) sees the same thing as the full /proc
// walk, and changes when an app process dies.
func TestPM2FingerprintFollowsChildren(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	self := map[int]bool{os.Getpid(): true}
	fast := PM2Fingerprint(self)
	if !strings.Contains(fast, strconv.Itoa(cmd.Process.Pid)+":") {
		t.Fatalf("child %d not in %q", cmd.Process.Pid, fast)
	}
	if slow := pm2FingerprintSlow(self); slow != fast {
		t.Fatalf("fast %q != slow %q", fast, slow)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if after := PM2Fingerprint(self); after == fast {
		t.Fatal("fingerprint did not change after the child exited")
	}
}

func TestRefreshUsageReadsProc(t *testing.T) {
	m := &PM2Monitor{current: []Service{{Name: "me", PID: os.Getpid(), Status: "online"}, {Name: "stopped", Status: "stopped"}}}
	m.RefreshUsage()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) { // burn some CPU
	}
	m.RefreshUsage()
	s, _ := m.Current()
	if s[0].MemoryBytes == 0 {
		t.Fatal("memory not read")
	}
	if s[0].CPUPercent <= 0 {
		t.Fatalf("cpu = %v", s[0].CPUPercent)
	}
	if s[1].MemoryBytes != 0 || s[1].CPUPercent != 0 {
		t.Fatal("a stopped app got usage")
	}
}
