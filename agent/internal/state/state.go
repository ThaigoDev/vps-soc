// Package state persists the little the agent must remember across restarts:
// the journald cursor and the last snapshot of listening ports.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Store struct {
	dir string
	mu  sync.Mutex
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) LoadCursor() string {
	b, err := os.ReadFile(filepath.Join(s.dir, "journal.cursor"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (s *Store) SaveCursor(cursor string) error {
	return s.write("journal.cursor", []byte(cursor))
}

// LoadJSON reads a JSON state file. found is false when it does not exist yet.
func (s *Store) LoadJSON(name string, v any) (found bool, err error) {
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func (s *Store) SaveJSON(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.write(name, b)
}

// write replaces the file atomically so a crash never leaves it half-written.
func (s *Store) write(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp := filepath.Join(s.dir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, name))
}
