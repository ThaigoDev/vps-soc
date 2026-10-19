package collector

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
	"time"
)

// AuthKey describes one authorized_keys entry the way `ssh-keygen -lf` does.
// Only the fingerprint is kept, never the key blob.
type AuthKey struct {
	Type        string     `json:"type"`
	Bits        int        `json:"bits,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	Comment     string     `json:"comment,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"` // from the expiry-time="..." option
	Options     bool       `json:"hasOptions,omitempty"`
}

func isAuthorizedKeys(path string) bool {
	return strings.HasSuffix(path, "/.ssh/authorized_keys")
}

// ParseAuthorizedKeys reads every valid key line; comments, blanks and garbage are skipped.
func ParseAuthorizedKeys(content string) []AuthKey {
	var out []AuthKey
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, ok := parseAuthKeyLine(line); ok {
			out = append(out, k)
		}
	}
	return out
}

func parseAuthKeyLine(line string) (AuthKey, bool) {
	tokens := splitOptions(line)
	for i, tok := range tokens {
		if !isKeyType(tok) || i+1 >= len(tokens) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(tokens[i+1])
		if err != nil || len(blob) == 0 {
			continue
		}
		sum := sha256.Sum256(blob)
		k := AuthKey{
			Type:        tok,
			Bits:        keyBits(tok, blob),
			Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
			Comment:     strings.Join(tokens[i+2:], " "),
			Options:     i > 0,
		}
		if i > 0 {
			k.ExpiresAt = expiryOption(strings.Join(tokens[:i], " "))
		}
		return k, true
	}
	return AuthKey{}, false
}

// splitOptions splits on spaces outside double quotes, so options such as
// command="a b" or expiry-time="2026..." stay one token.
func splitOptions(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func isKeyType(s string) bool {
	return s == "ssh-rsa" || s == "ssh-dss" || s == "ssh-ed25519" ||
		strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-ssh-ed25519") || strings.HasPrefix(s, "sk-ecdsa-")
}

func keyBits(typ string, blob []byte) int {
	switch {
	case typ == "ssh-ed25519" || strings.HasPrefix(typ, "sk-ssh-ed25519"):
		return 256
	case strings.HasSuffix(typ, "nistp256") || strings.Contains(typ, "nistp256@"):
		return 256
	case strings.HasSuffix(typ, "nistp384"):
		return 384
	case strings.HasSuffix(typ, "nistp521"):
		return 521
	case typ == "ssh-rsa":
		// string "ssh-rsa", mpint e, mpint n
		fields := sshFields(blob, 3)
		if len(fields) == 3 {
			return new(big.Int).SetBytes(fields[2]).BitLen()
		}
	}
	return 0
}

// sshFields reads up to n length-prefixed fields of the SSH wire format.
func sshFields(b []byte, n int) [][]byte {
	var out [][]byte
	for len(out) < n && len(b) >= 4 {
		l := binary.BigEndian.Uint32(b)
		if uint64(l) > uint64(len(b)-4) {
			return nil
		}
		out = append(out, b[4:4+l])
		b = b[4+l:]
	}
	return out
}

// expiryOption parses expiry-time="YYYYMMDD[HHMM[SS]][Z]" (local time without Z, like sshd).
func expiryOption(opts string) *time.Time {
	for _, o := range strings.Split(opts, ",") {
		v, ok := strings.CutPrefix(strings.TrimSpace(o), "expiry-time=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		loc := time.Local
		if strings.HasSuffix(v, "Z") {
			loc = time.UTC
			v = strings.TrimSuffix(v, "Z")
		}
		for _, layout := range []string{"20060102150405", "200601021504", "20060102"} {
			if len(v) == len(layout) {
				if t, err := time.ParseInLocation(layout, v, loc); err == nil {
					t = t.UTC()
					return &t
				}
			}
		}
	}
	return nil
}

// DiffKeys returns the keys only in next (added) and only in prev (removed), by fingerprint.
func DiffKeys(prev, next []AuthKey) (added, removed []AuthKey) {
	in := func(list []AuthKey, fp string) bool {
		for _, k := range list {
			if k.Fingerprint == fp {
				return true
			}
		}
		return false
	}
	for _, k := range next {
		if !in(prev, k.Fingerprint) {
			added = append(added, k)
		}
	}
	for _, k := range prev {
		if !in(next, k.Fingerprint) {
			removed = append(removed, k)
		}
	}
	return added, removed
}
