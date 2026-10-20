package collector

import (
	"encoding/binary"
	"testing"
)

func TestParseUpdates(t *testing.T) {
	p, s := ParseUpdates("\n12 updates can be applied immediately.\n5 of these updates are standard security updates.\nTo see these additional updates run: apt list --upgradable\n")
	if p != 12 || s != 5 {
		t.Errorf("got %d/%d", p, s)
	}
	p, s = ParseUpdates("\n1 update can be applied immediately.\n1 of these updates is a standard security update.\n")
	if p != 1 || s != 1 {
		t.Errorf("singular: got %d/%d", p, s)
	}
	p, s = ParseUpdates("\n0 updates can be applied immediately.\n")
	if p != 0 || s != 0 {
		t.Errorf("zero: got %d/%d", p, s)
	}
}

func TestParseFailedUnitsAndSSHD(t *testing.T) {
	u := ParseFailedUnits("nginx.service loaded failed failed A high performance web server\nfoo.service loaded failed failed Foo\n")
	if len(u) != 2 || u[0] != "nginx.service" {
		t.Errorf("units %v", u)
	}
	if u := ParseFailedUnits(""); len(u) != 0 {
		t.Errorf("empty %v", u)
	}
	s := ParseSSHDEffective("port 22\npermitrootlogin without-password\npasswordauthentication yes\nmaxauthtries 6\n")
	if s.PermitRootLogin != "without-password" || s.PasswordAuthentication != "yes" || s.MaxAuthTries != "6" {
		t.Errorf("sshd %+v", s)
	}
}

func TestParseUtmp(t *testing.T) {
	rec := func(typ int16, user, tty, host string, sec int32) []byte {
		r := make([]byte, utmpSize)
		binary.LittleEndian.PutUint16(r[0:2], uint16(typ))
		copy(r[8:40], tty)
		copy(r[44:76], user)
		copy(r[76:332], host)
		binary.LittleEndian.PutUint32(r[340:344], uint32(sec))
		return r
	}
	var b []byte
	b = append(b, rec(2, "reboot", "~", "6.8.0", 1700000000)...) // BOOT_TIME
	b = append(b, rec(7, "thiago", "pts/0", "100.111.247.53", 1760000000)...)
	b = append(b, rec(8, "", "pts/1", "", 1760000100)...) // DEAD_PROCESS
	s := ParseUtmp(b)
	if len(s) != 1 || s[0].User != "thiago" || s[0].TTY != "pts/0" || s[0].Host != "100.111.247.53" || s[0].LoginAt.Unix() != 1760000000 {
		t.Errorf("sessions %+v", s)
	}
}
