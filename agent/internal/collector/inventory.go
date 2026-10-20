package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Package is one installed npm dependency (name@version) from a lockfile.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev,omitempty"`
}

// Inventory is what an app has installed, read from its lockfile. Only names and versions
// leave the VPS: they are matched against public vulnerability databases by the SOC.
type Inventory struct {
	Lockfile string    `json:"lockfile"`
	Hash     string    `json:"hash"`
	Packages []Package `json:"packages"`
}

const maxLockfile = 32 << 20
const maxPackages = 8000

// FindLockfile looks for package-lock.json in the app's cwd and up to three directories
// above its script, then for node_modules/.package-lock.json (written by npm 7+).
func FindLockfile(cwd, execPath string) string {
	var dirs []string
	if cwd != "" && cwd != "/" {
		dirs = append(dirs, cwd)
	}
	if execPath != "" {
		d := filepath.Dir(execPath)
		for i := 0; i < 4 && d != "/" && d != "."; i++ {
			dirs = append(dirs, d)
			d = filepath.Dir(d)
		}
	}
	for _, name := range []string{"package-lock.json", "node_modules/.package-lock.json", "npm-shrinkwrap.json"} {
		for _, d := range dirs {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() <= maxLockfile {
				return p
			}
		}
	}
	return ""
}

// ReadInventory parses an npm lockfile (v1, v2 or v3).
func ReadInventory(path string) (Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, err
	}
	pkgs, err := ParseLockfile(b)
	if err != nil {
		return Inventory{}, err
	}
	sum := sha256.Sum256(b)
	return Inventory{Lockfile: path, Hash: hex.EncodeToString(sum[:]), Packages: pkgs}, nil
}

type lockfile struct {
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
		Link    bool   `json:"link"`
	} `json:"packages"`
	Dependencies map[string]lockDep `json:"dependencies"`
}

type lockDep struct {
	Version      string             `json:"version"`
	Dev          bool               `json:"dev"`
	Dependencies map[string]lockDep `json:"dependencies"`
}

// ParseLockfile returns the unique name@version pairs of the installed packages.
func ParseLockfile(b []byte) ([]Package, error) {
	var lf lockfile
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, err
	}
	seen := map[string]Package{}
	add := func(name, version string, dev bool) {
		if name == "" || version == "" || strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "link:") {
			return
		}
		k := name + "@" + version
		if p, ok := seen[k]; ok {
			if p.Dev && !dev { // needed in production somewhere: not dev-only
				p.Dev = false
				seen[k] = p
			}
			return
		}
		seen[k] = Package{Name: name, Version: version, Dev: dev}
	}
	if len(lf.Packages) > 0 { // lockfileVersion 2 and 3
		for key, p := range lf.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if key == "" || i < 0 || p.Link {
				continue // the root project or a workspace link
			}
			add(key[i+len("node_modules/"):], p.Version, p.Dev)
		}
	} else { // lockfileVersion 1
		var walk func(map[string]lockDep)
		walk = func(deps map[string]lockDep) {
			for name, d := range deps {
				add(name, d.Version, d.Dev)
				walk(d.Dependencies)
			}
		}
		walk(lf.Dependencies)
	}
	if len(seen) == 0 {
		return nil, errors.New("lockfile has no packages")
	}
	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	if len(out) > maxPackages {
		out = out[:maxPackages]
	}
	return out, nil
}
