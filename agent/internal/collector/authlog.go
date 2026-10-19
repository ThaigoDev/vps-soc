package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"

	"vps-soc/agent/internal/event"
)

// AuthLogSource streams sshd/sudo events from journald or a syslog file.
type AuthLogSource struct {
	Mode   string // auto | journald | file
	Path   string // auth.log path for file mode; auto-detected when empty
	Cursor string // journald cursor to resume after
	Emit   func(event.Event)
}

func (s *AuthLogSource) Run(ctx context.Context) error {
	mode := s.Mode
	if mode == "auto" {
		if _, err := exec.LookPath("journalctl"); err == nil {
			mode = "journald"
		} else {
			mode = "file"
		}
	}
	if mode == "journald" {
		log.Printf("auth source: journald")
		return s.runJournald(ctx)
	}
	path := s.Path
	if path == "" {
		path = detectAuthLog()
	}
	if path == "" {
		return errors.New("no journalctl and no /var/log/auth.log or /var/log/secure found; set SOC_AUTH_LOG_PATH")
	}
	log.Printf("auth source: file %s", path)
	return tailFile(ctx, path, func(line string) {
		program, msg, ts, ok := ParseSyslogLine(line, time.Now())
		if !ok {
			return
		}
		if e, ok := ParseAuthMessage(program, msg, ts); ok {
			s.Emit(e)
		}
	})
}

func detectAuthLog() string {
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

type journalEntry struct {
	Message    any    `json:"MESSAGE"` // string, or a byte array for non-UTF-8 messages
	Identifier string `json:"SYSLOG_IDENTIFIER"`
	Comm       string `json:"_COMM"`
	Realtime   string `json:"__REALTIME_TIMESTAMP"`
	Cursor     string `json:"__CURSOR"`
}

// runJournald follows journalctl and restarts it with backoff if it exits.
func (s *AuthLogSource) runJournald(ctx context.Context) error {
	backoff := time.Second
	for ctx.Err() == nil {
		err := s.followJournal(ctx)
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("journalctl exited (%v); restarting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
	return nil
}

func (s *AuthLogSource) followJournal(ctx context.Context) error {
	args := []string{"--follow", "--output=json", "--no-pager"}
	if s.Cursor != "" {
		args = append(args, "--after-cursor="+s.Cursor)
	} else {
		args = append(args, "--lines=0")
	}
	args = append(args, "_COMM=sshd", "+", "_COMM=sshd-session", "+", "_COMM=sshd-auth", "+", "_COMM=sudo")

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var je journalEntry
		if json.Unmarshal(sc.Bytes(), &je) != nil {
			continue
		}
		s.Cursor = je.Cursor // resume point if journalctl gets restarted
		msg, ok := je.Message.(string)
		if !ok {
			continue
		}
		program := je.Identifier
		if program == "" {
			program = je.Comm
		}
		ts := time.Now()
		if us, err := strconv.ParseInt(je.Realtime, 10, 64); err == nil {
			ts = time.UnixMicro(us)
		}
		if e, ok := ParseAuthMessage(program, msg, ts); ok {
			e.Cursor = je.Cursor
			s.Emit(e)
		}
	}
	return cmd.Wait()
}

// tailFile follows a log file from its current end, reopening it after rotation.
func tailFile(ctx context.Context, path string, onLine func(string)) error {
	var (
		f      *os.File
		reader *bufio.Reader
		err    error
	)
	open := func(seekEnd bool) error {
		if f != nil {
			f.Close()
		}
		if f, err = os.Open(path); err != nil {
			return err
		}
		if seekEnd {
			if _, err = f.Seek(0, io.SeekEnd); err != nil {
				return err
			}
		}
		reader = bufio.NewReader(f)
		return nil
	}
	if err := open(true); err != nil {
		return err
	}
	defer func() { f.Close() }()

	partial := ""
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		for {
			chunk, err := reader.ReadString('\n')
			if err != nil {
				partial += chunk
				break
			}
			onLine(partial + chunk[:len(chunk)-1])
			partial = ""
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		// Rotation: the path now points to a new file, or the file was truncated.
		cur, statErr := os.Stat(path)
		open1, _ := f.Stat()
		pos, _ := f.Seek(0, io.SeekCurrent)
		if statErr == nil && open1 != nil && (!os.SameFile(cur, open1) || cur.Size() < pos) {
			if err := open(false); err != nil {
				log.Printf("reopen %s: %v", path, err)
				continue
			}
			partial = ""
		}
	}
}
