package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

// FIMPatterns are the files whose integrity is watched. Globs are expanded on
// every scan, so files that appear later (a new cron job, a new user's
// authorized_keys) are picked up as FILE_CREATED.
var FIMPatterns = []string{
	"/etc/passwd",
	"/etc/group",
	"/etc/shadow", // hash only, see hashOnly
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/crontab",
	"/etc/cron.d/*",
	"/var/spool/cron/crontabs/*",
	"/root/.ssh/authorized_keys",
	"/home/*/.ssh/authorized_keys",
}

const fimStateFile = "fim.json"

// maxDirectiveFileSize caps how much of an sshd config is parsed for the diff.
const maxDirectiveFileSize = 1 << 20

// FileState is what the baseline remembers about a watched file. Contents are
// never stored, except the effective directive lines of sshd config files and
// the fingerprints of authorized_keys entries, so a change can say what changed.
type FileState struct {
	Hash       string    `json:"hash"`
	Size       int64     `json:"size"`
	Mtime      time.Time `json:"mtime"`
	Owner      string    `json:"owner"`
	Mode       string    `json:"mode"`
	Directives []string  `json:"directives,omitempty"`
	Keys       []AuthKey `json:"keys,omitempty"`
	KeysParsed bool      `json:"keysParsed,omitempty"` // false in baselines from older agents
}

// FileMonitor periodically hashes FIMPatterns and emits FILE_* events for
// every difference against the persisted baseline.
type FileMonitor struct {
	Interval time.Duration
	Patterns []string
	State    *state.Store
	Emit     func(event.Event)
}

func (m *FileMonitor) Run(ctx context.Context) {
	patterns := m.Patterns
	if patterns == nil {
		patterns = FIMPatterns
	}
	var prev map[string]FileState
	found, err := m.State.LoadJSON(fimStateFile, &prev)
	if err != nil {
		log.Printf("fim state unreadable, rebuilding baseline: %v", err)
		found = false
	}

	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		now := SnapshotFiles(patterns)
		if !found {
			paths := make([]string, 0, len(now))
			for p := range now {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			m.Emit(event.Event{
				Type: event.FileBaseline, OccurredAt: time.Now(),
				Message:  fmt.Sprintf("baseline of %d monitored files recorded", len(paths)),
				Metadata: map[string]any{"files": paths},
			})
			found = true
		} else {
			for _, e := range DiffFiles(prev, now, time.Now()) {
				m.Emit(e)
			}
		}
		prev = now
		if err := m.State.SaveJSON(fimStateFile, now); err != nil {
			log.Printf("save fim state: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SnapshotFiles hashes every regular file matching the patterns.
func SnapshotFiles(patterns []string) map[string]FileState {
	out := map[string]FileState{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			fs, err := statFile(path)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Printf("fim %s: %v", path, err)
				}
				continue
			}
			out[path] = fs
		}
	}
	return out
}

func statFile(path string) (FileState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileState{}, err
	}
	if !info.Mode().IsRegular() {
		return FileState{}, os.ErrNotExist // symlinks and dirs are not tracked
	}
	f, err := os.Open(path)
	if err != nil {
		return FileState{}, err
	}
	defer f.Close()

	h := sha256.New()
	// Directive lines are only kept for sshd config files; everything else
	// (notably /etc/shadow) is streamed straight into the hash.
	var buf strings.Builder
	var w io.Writer = h
	keep := (isSSHDConfig(path) || isAuthorizedKeys(path)) && !hashOnly(path)
	if keep {
		w = io.MultiWriter(h, &limitedBuilder{b: &buf, max: maxDirectiveFileSize})
	}
	if _, err := io.Copy(w, f); err != nil {
		return FileState{}, err
	}
	fs := FileState{
		Hash:  hex.EncodeToString(h.Sum(nil)),
		Size:  info.Size(),
		Mtime: info.ModTime().UTC(),
		Owner: fileOwner(info),
		Mode:  info.Mode().Perm().String(),
	}
	switch {
	case keep && isAuthorizedKeys(path):
		fs.Keys = ParseAuthorizedKeys(buf.String())
		fs.KeysParsed = true
	case keep:
		fs.Directives = SSHDDirectives(buf.String())
	}
	return fs, nil
}

// hashOnly lists files whose contents must never be parsed or stored.
func hashOnly(path string) bool {
	switch path {
	case "/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-":
		return true
	}
	return false
}

func isSSHDConfig(path string) bool {
	return path == "/etc/ssh/sshd_config" || strings.HasPrefix(path, "/etc/ssh/sshd_config.d/")
}

type limitedBuilder struct {
	b   *strings.Builder
	max int
}

func (l *limitedBuilder) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

func fileOwner(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return lookupUser(strconv.FormatUint(uint64(st.Uid), 10)) + ":" + lookupGroup(strconv.FormatUint(uint64(st.Gid), 10))
}

var groupCache sync.Map

func lookupGroup(gid string) string {
	if v, ok := groupCache.Load(gid); ok {
		return v.(string)
	}
	name := gid
	if g, err := user.LookupGroupId(gid); err == nil {
		name = g.Name
	}
	groupCache.Store(gid, name)
	return name
}

// SSHDDirectives returns the effective lines of an sshd config: comments and
// blank lines dropped, whitespace collapsed.
func SSHDDirectives(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Join(strings.Fields(line), " "))
	}
	return out
}

// DiffLines returns the lines only in next (added) and only in prev (removed),
// treating both as multisets and keeping their original order.
func DiffLines(prev, next []string) (added, removed []string) {
	count := map[string]int{}
	for _, l := range prev {
		count[l]++
	}
	for _, l := range next {
		if count[l] > 0 {
			count[l]--
		} else {
			added = append(added, l)
		}
	}
	for _, l := range prev {
		if count[l] > 0 {
			count[l]--
			removed = append(removed, l)
		}
	}
	return added, removed
}

// DiffFiles compares two snapshots and returns one event per change.
func DiffFiles(prev, now map[string]FileState, ts time.Time) []event.Event {
	var out []event.Event
	paths := make([]string, 0, len(now)+len(prev))
	for p := range now {
		paths = append(paths, p)
	}
	for p := range prev {
		if _, ok := now[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	for _, path := range paths {
		old, hadOld := prev[path]
		cur, hasCur := now[path]
		switch {
		case !hadOld:
			meta := fileMeta(path, cur)
			meta["newHash"] = cur.Hash
			if len(cur.Directives) > 0 {
				meta["addedLines"] = cur.Directives
			}
			if len(cur.Keys) > 0 {
				meta["addedKeys"] = cur.Keys
			}
			out = append(out, event.Event{Type: event.FileCreated, OccurredAt: ts,
				Message: fmt.Sprintf("monitored file created: %s (%d bytes, owner %s)", path, cur.Size, cur.Owner), Metadata: meta})
		case !hasCur:
			meta := fileMeta(path, old)
			meta["oldHash"] = old.Hash
			if len(old.Keys) > 0 {
				meta["removedKeys"] = old.Keys
			}
			out = append(out, event.Event{Type: event.FileDeleted, OccurredAt: ts,
				Message: "monitored file deleted: " + path, Metadata: meta})
		case old.Hash != cur.Hash || old.Owner != cur.Owner || old.Mode != cur.Mode:
			meta := fileMeta(path, cur)
			meta["oldHash"], meta["newHash"] = old.Hash, cur.Hash
			meta["oldSize"] = old.Size
			if old.Owner != cur.Owner {
				meta["oldOwner"] = old.Owner
			}
			if old.Mode != cur.Mode {
				meta["oldMode"] = old.Mode
			}
			if isSSHDConfig(path) {
				added, removed := DiffLines(old.Directives, cur.Directives)
				if len(added) > 0 {
					meta["addedLines"] = added
				}
				if len(removed) > 0 {
					meta["removedLines"] = removed
				}
			}
			if isAuthorizedKeys(path) && old.KeysParsed {
				added, removed := DiffKeys(old.Keys, cur.Keys)
				if len(added) > 0 {
					meta["addedKeys"] = added
				}
				if len(removed) > 0 {
					meta["removedKeys"] = removed
				}
			}
			out = append(out, event.Event{Type: event.FileModified, OccurredAt: ts,
				Message: fmt.Sprintf("monitored file modified: %s (%d -> %d bytes)", path, old.Size, cur.Size), Metadata: meta})
		}
	}
	return out
}

func fileMeta(path string, fs FileState) map[string]any {
	return map[string]any{
		"path": path, "size": fs.Size, "mtime": fs.Mtime, "owner": fs.Owner, "mode": fs.Mode,
	}
}
