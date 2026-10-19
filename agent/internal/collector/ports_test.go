package collector

import "testing"

func TestParseProcNetLine(t *testing.T) {
	l, inode, uid, ok := parseProcNetLine(
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18291 1 0000000000000000 100 0 0 10 0", "tcp")
	if !ok || l.Address != "0.0.0.0" || l.Port != 22 || inode != "18291" || uid != "0" {
		t.Fatalf("got %+v inode=%s uid=%s ok=%v", l, inode, uid, ok)
	}

	l, _, _, ok = parseProcNetLine(
		"   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2222 1 0000000000000000 100 0 0 10 0", "tcp")
	if !ok || l.Address != "127.0.0.1" || l.Port != 3306 {
		t.Fatalf("got %+v", l)
	}

	l, _, _, ok = parseProcNetLine(
		"   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3333 1 0000000000000000 100 0 0 10 0", "tcp6")
	if !ok || l.Address != "::" || l.Port != 443 {
		t.Fatalf("got %+v", l)
	}

	// ESTABLISHED (01) connections are not listeners.
	if _, _, _, ok := parseProcNetLine(
		"   2: 0100007F:0016 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 4444 1 0000000000000000 20 4 30 10 -1", "tcp"); ok {
		t.Fatal("established socket must be ignored")
	}
}
