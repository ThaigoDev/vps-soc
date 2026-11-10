package collector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"testing"
	"time"
)

func TestParseLockfileV3AndV1(t *testing.T) {
	v3 := `{"lockfileVersion":3,"packages":{"":{"name":"app"},
	"node_modules/express":{"version":"4.17.1"},
	"node_modules/@nestjs/core":{"version":"10.0.0"},
	"node_modules/express/node_modules/qs":{"version":"6.7.0"},
	"node_modules/jest":{"version":"29.0.0","dev":true},
	"packages/lib":{"version":"1.0.0"},
	"node_modules/lib":{"link":true}}}`
	p, err := ParseLockfile([]byte(v3))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, x := range p {
		got[x.Name+"@"+x.Version] = x.Dev
	}
	for _, want := range []string{"express@4.17.1", "@nestjs/core@10.0.0", "qs@6.7.0", "jest@29.0.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if !got["jest@29.0.0"] || len(p) != 4 {
		t.Errorf("dev flag / count wrong: %v", p)
	}
	v1 := `{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.15"},"a":{"version":"1.0.0","dependencies":{"minimist":{"version":"0.0.8"}}}}}`
	p, err = ParseLockfile([]byte(v1))
	if err != nil || len(p) != 3 {
		t.Fatalf("v1: %v %v", p, err)
	}
}

func TestParseNginxServers(t *testing.T) {
	conf := `
# comment { not a block }
server {
    listen 80;
    server_name api.example.com www.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name api.example.com;
    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
    location /ws { proxy_pass http://localhost:3001/socket; }
}
server { listen 80; server_name _; location / { proxy_pass http://upstream_pool; } }`
	sites := ParseNginxServers(conf, "/etc/nginx/sites-enabled/app")
	if len(sites) != 2 {
		t.Fatalf("got %d sites: %+v", len(sites), sites)
	}
	s := sites[1]
	if !s.TLS || s.Certificate == nil || s.Certificate.Path != "/etc/letsencrypt/live/api.example.com/fullchain.pem" ||
		len(s.ProxyPorts) != 2 || s.ProxyPorts[0] != 3000 || s.ProxyPorts[1] != 3001 || s.Domains[0] != "api.example.com" {
		t.Errorf("site %+v", s)
	}
}

func TestReadCert(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.example.com"},
		Issuer: pkix.Name{CommonName: "R11", Organization: []string{"Let's Encrypt"}}, DNSNames: []string{"api.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	p := filepath.Join(t.TempDir(), "fullchain.pem")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	c := ReadCert(p)
	if c.Error != "" || c.Subject != "api.example.com" || c.NotAfter.Before(time.Now()) || len(c.DNSNames) != 1 {
		t.Errorf("cert %+v", c)
	}
	if ReadCert("/nope").Error == "" {
		t.Error("missing file must report an error")
	}
}

func TestInspectFlag(t *testing.T) {
	if InspectFlag(json.RawMessage(`["--max-old-space-size=512","--inspect=0.0.0.0:9229"]`)) != "--inspect=0.0.0.0:9229" {
		t.Error("array form")
	}
	if InspectFlag(json.RawMessage(`null`), json.RawMessage(`"--inspect-brk"`)) != "--inspect-brk" {
		t.Error("string form")
	}
	if InspectFlag(json.RawMessage(`[]`)) != "" {
		t.Error("no flag")
	}
}

func TestEnricherProbeErrorsAndEnv(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"packages":{"node_modules/a":{"version":"1.0.0"}}}`), 0o644)
	errLog := filepath.Join(dir, "err.log")
	_ = os.WriteFile(errLog, []byte("old\n"), 0o644)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer ln.Close()

	e := &Enricher{Ports: func() []Listener { return []Listener{{Address: "0.0.0.0", Port: port, PID: 42}} }}
	svc := []Service{{Name: "api", PID: 42, Status: "online", Cwd: dir, ErrLogPath: errLog}}
	out := e.Enrich(context.Background(), svc)
	s := out[0]
	if s.Probe == nil || !s.Probe.OK || s.Probe.Status != 204 || s.Probe.Port != port {
		t.Errorf("probe %+v", s.Probe)
	}
	if s.Security.EnvFileMode != "-rw-r--r--" || s.Security.Lockfile == "" || s.Security.DepsHash == "" {
		t.Errorf("security %+v", s.Security)
	}
	if len(s.Listeners) != 1 || s.Listeners[0].Address != "0.0.0.0" {
		t.Errorf("listeners %+v", s.Listeners)
	}
	f, _ := os.OpenFile(errLog, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("e1\ne2\ne3\n")
	f.Close()
	s = e.Enrich(context.Background(), svc)[0]
	if s.ErrorLines != 3 {
		t.Errorf("error lines %d", s.ErrorLines)
	}

}

func TestProbeOrderPrefersProxiedPortAndSkipsInspector(t *testing.T) {
	s := Service{Listeners: []ListenAddr{{Port: 9229}, {Port: 4000}, {Port: 3000}}, Sites: []Site{{ProxyPorts: []int{3000}}}}
	if got := probeOrder(s); got[0].Port != 3000 || got[len(got)-1].Port != 9229 {
		t.Errorf("order %+v", got)
	}
	s.Sites = nil
	if got := probeOrder(s); got[0].Port != 4000 {
		t.Errorf("without nginx: %+v", got)
	}
}
