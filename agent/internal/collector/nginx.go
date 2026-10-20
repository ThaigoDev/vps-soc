package collector

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Site is an nginx server block: the domains it answers, the local port it proxies to,
// and the TLS certificate it presents.
type Site struct {
	Domains     []string  `json:"domains"`
	ProxyPorts  []int     `json:"proxyPorts,omitempty"`
	TLS         bool      `json:"tls"`
	Certificate *CertInfo `json:"certificate,omitempty"`
	ConfigFile  string    `json:"configFile"`
}

// CertInfo is what matters about a certificate for monitoring (never the key).
type CertInfo struct {
	Path      string    `json:"path"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dnsNames,omitempty"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Error     string    `json:"error,omitempty"`
}

var (
	reComment   = regexp.MustCompile(`(?m)#.*$`)
	reProxyPort = regexp.MustCompile(`^https?://(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(?::(\d+))?`)
)

// ReadNginxSites parses the enabled nginx configs. It is a small tokenizer, not a full
// nginx parser: enough to pair server_name, ssl_certificate and proxy_pass per server.
func ReadNginxSites() []Site {
	var files []string
	for _, pat := range []string{"/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf"} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	var sites []Site
	certs := map[string]*CertInfo{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, s := range ParseNginxServers(string(b), f) {
			if s.Certificate != nil {
				c, ok := certs[s.Certificate.Path]
				if !ok {
					c = ReadCert(s.Certificate.Path)
					certs[s.Certificate.Path] = c
				}
				s.Certificate = c
			}
			sites = append(sites, s)
		}
	}
	return sites
}

// ParseNginxServers extracts server blocks from one config file.
func ParseNginxServers(conf, file string) []Site {
	tokens := tokenizeNginx(reComment.ReplaceAllString(conf, ""))
	var out []Site
	depth := 0
	serverDepth := -1
	var cur *Site
	stmt := []string{}
	for _, t := range tokens {
		switch t {
		case "{":
			if len(stmt) == 1 && stmt[0] == "server" && cur == nil {
				cur = &Site{ConfigFile: file}
				serverDepth = depth
			}
			depth++
			stmt = stmt[:0]
		case "}":
			depth--
			if cur != nil && depth == serverDepth {
				if len(cur.Domains) > 0 || len(cur.ProxyPorts) > 0 {
					sort.Ints(cur.ProxyPorts)
					out = append(out, *cur)
				}
				cur = nil
				serverDepth = -1
			}
			stmt = stmt[:0]
		case ";":
			if cur != nil && len(stmt) > 0 {
				applyDirective(cur, stmt)
			}
			stmt = stmt[:0]
		default:
			stmt = append(stmt, t)
		}
	}
	return out
}

func applyDirective(s *Site, d []string) {
	switch d[0] {
	case "server_name":
		for _, n := range d[1:] {
			if n != "_" && n != "" && !containsStr(s.Domains, n) {
				s.Domains = append(s.Domains, n)
			}
		}
	case "listen":
		for _, a := range d[1:] {
			if a == "ssl" || strings.HasSuffix(a, ":443") || a == "443" {
				s.TLS = true
			}
		}
	case "ssl_certificate":
		if len(d) > 1 {
			s.TLS = true
			s.Certificate = &CertInfo{Path: strings.Trim(d[1], `"'`)}
		}
	case "proxy_pass":
		if len(d) > 1 {
			if m := reProxyPort.FindStringSubmatch(d[1]); m != nil {
				port := 80
				if m[1] != "" {
					port, _ = strconv.Atoi(m[1])
				}
				if !containsInt(s.ProxyPorts, port) {
					s.ProxyPorts = append(s.ProxyPorts, port)
				}
			}
		}
	}
}

func tokenizeNginx(s string) []string {
	var out []string
	var cur strings.Builder
	quote := byte(0)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '{' || c == '}' || c == ';':
			flush()
			out = append(out, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// ReadCert parses the first certificate of a PEM file (the leaf).
func ReadCert(path string) *CertInfo {
	info := &CertInfo{Path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	block, _ := pem.Decode(b)
	if block == nil {
		info.Error = "not a PEM certificate"
		return info
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Subject = c.Subject.CommonName
	info.Issuer = c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		info.Issuer = c.Issuer.Organization[0] + " " + c.Issuer.CommonName
	}
	info.DNSNames = c.DNSNames
	info.NotBefore, info.NotAfter = c.NotBefore.UTC(), c.NotAfter.UTC()
	return info
}

// ReadLetsEncryptCerts lists certificates managed by certbot, whether nginx uses them or not.
func ReadLetsEncryptCerts() []*CertInfo {
	dirs, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem")
	var out []*CertInfo
	for _, p := range dirs {
		out = append(out, ReadCert(p))
	}
	return out
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
