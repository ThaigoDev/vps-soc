package collector

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"vps-soc/agent/internal/event"
)

func TestParseExecEvents(t *testing.T) {
	le := binary.LittleEndian
	msg := func(what, tgid uint32) []byte {
		b := make([]byte, nlmsgHdrLen+cnMsgLen+24)
		le.PutUint32(b[0:], uint32(len(b)))
		le.PutUint32(b[nlmsgHdrLen:], cnIdxProc)
		le.PutUint32(b[nlmsgHdrLen+cnMsgLen:], what)
		le.PutUint32(b[nlmsgHdrLen+cnMsgLen+16:], tgid+1) // pid (thread)
		le.PutUint32(b[nlmsgHdrLen+cnMsgLen+20:], tgid)
		return b
	}
	b := append(msg(procEventExec, 4242), msg(0x1 /* fork */, 7)...)
	b = append(b, msg(procEventExec, 99)...)
	got := ParseExecEvents(b)
	if len(got) != 2 || got[0] != 4242 || got[1] != 99 {
		t.Fatalf("got %v", got)
	}
	if got := ParseExecEvents([]byte{1, 2, 3}); len(got) != 0 {
		t.Fatalf("garbage parsed as %v", got)
	}
}

// A binary that lives for a fraction of a second in /tmp is caught although the periodic
// scan runs only once an hour. Needs root (CAP_NET_ADMIN) and the process connector.
func TestShortLivedTempBinaryIsCaught(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := watchExecs(ctx, func(int) {}); err != nil {
		t.Skipf("process connector unavailable here: %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "soc-exec-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	bin := dir + "/kworker-fake"
	src, err := os.Open("/bin/sleep")
	if err != nil {
		t.Skip("no /bin/sleep")
	}
	dst, _ := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY, 0o755)
	_, _ = io.Copy(dst, src)
	src.Close()
	dst.Close()

	events := make(chan event.Event, 10)
	m := &ProcessMonitor{Interval: time.Hour, Emit: func(e event.Event) { events <- e }}
	go m.Run(ctx)
	time.Sleep(300 * time.Millisecond) // first scan done, connector listening

	if err := exec.Command(bin, "0.3").Run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Metadata["exe"] == bin && e.Metadata["reason"] == ReasonTempExe {
				return
			}
		case <-deadline:
			t.Fatal("short-lived /tmp binary not reported")
		}
	}
}
