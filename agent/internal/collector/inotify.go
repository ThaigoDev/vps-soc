package collector

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// dirWatcher wakes the caller the instant something changes in a set of directories, using
// inotify (no polling). It only signals; the caller re-reads what it cares about.
type dirWatcher struct {
	file    *os.File
	fd      int
	mu      sync.Mutex
	watched map[string]bool
	wds     map[int32]string
}

const watchMask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_MOVED_FROM | syscall.IN_CREATE |
	syscall.IN_DELETE | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

func newDirWatcher() (*dirWatcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	// Non-blocking fd: os.File uses the runtime poller, so Close unblocks a pending Read.
	return &dirWatcher{file: os.NewFile(uintptr(fd), "inotify"), fd: fd, watched: map[string]bool{}, wds: map[int32]string{}}, nil
}

// Watch adds directories (missing ones are skipped; call again later to pick them up).
func (w *dirWatcher) Watch(dirs []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, d := range dirs {
		if w.watched[d] {
			continue
		}
		wd, err := syscall.InotifyAddWatch(w.fd, d, watchMask)
		if err != nil {
			continue
		}
		w.watched[d] = true
		w.wds[int32(wd)] = d
	}
}

// Run calls onChange with the full path of every changed entry until ctx ends.
func (w *dirWatcher) Run(ctx context.Context, onChange func(path string)) {
	go func() { <-ctx.Done(); w.file.Close() }()
	buf := make([]byte, 64<<10)
	for {
		n, err := w.file.Read(buf)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, os.ErrClosed) {
				log.Printf("inotify: %v", err)
			}
			return
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			nameBytes := buf[off+syscall.SizeofInotifyEvent : off+syscall.SizeofInotifyEvent+int(ev.Len)]
			off += syscall.SizeofInotifyEvent + int(ev.Len)
			name := strings.TrimRight(string(nameBytes), "\x00")
			w.mu.Lock()
			dir := w.wds[ev.Wd]
			if ev.Mask&(syscall.IN_IGNORED|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0 {
				// The directory is gone: forget it so it is watched again if it comes back.
				delete(w.watched, dir)
				delete(w.wds, ev.Wd)
			}
			w.mu.Unlock()
			if dir == "" {
				continue
			}
			if name == "" {
				onChange(dir)
			} else {
				onChange(filepath.Join(dir, name))
			}
		}
	}
}

// watchDirsFor returns the directories that hold files matching the patterns (with globs in
// directory names expanded), so a change, creation or atomic rename is seen there.
func watchDirsFor(patterns []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range patterns {
		dir := filepath.Dir(p)
		dirs := []string{dir}
		if strings.ContainsAny(dir, "*?[") {
			dirs, _ = filepath.Glob(dir)
		}
		for _, d := range dirs {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// matchesAny reports whether path is one of the watched files (or the directory itself).
func matchesAny(patterns []string, path string) bool {
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, path); ok {
			return true
		}
		if filepath.Dir(p) == path {
			return true
		}
	}
	return false
}
