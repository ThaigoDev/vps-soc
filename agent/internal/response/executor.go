package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"vps-soc/agent/internal/collector"
)

// Action types the agent accepts. Anything else is rejected.
const (
	BlockIP        = "BLOCK_IP"
	UnblockIP      = "UNBLOCK_IP"
	KillProcess    = "KILL_PROCESS"
	DiskCleanup    = "DISK_CLEANUP"
	RestartService = "RESTART_SERVICE"
)

// Result statuses reported back to the SOC.
const (
	StatusSucceeded = "SUCCEEDED"
	StatusFailed    = "FAILED"
	StatusRejected  = "REJECTED" // refused by the agent's own safety checks
)

type Action struct {
	ID     int64          `json:"id"`
	Type   string         `json:"type"`
	Params map[string]any `json:"params"`
}

type Result struct {
	Status  string         `json:"status"`
	Output  string         `json:"output"`
	Details map[string]any `json:"details,omitempty"`
}

const maxEvidenceBytes = 64 << 20

var unitName = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,200}\.service$`)

// Executor validates and runs actions. Every action re-checks the facts on the host
// itself (the IP is not protected, the process is still the suspicious one, the unit is
// still failed) instead of trusting the request.
type Executor struct {
	Enabled       bool
	Firewall      *Firewall
	Allowlist     *Allowlist
	QuarantineDir string
	Run           Runner
	Self          int
}

func (x *Executor) Execute(ctx context.Context, a Action) Result {
	if !x.Enabled {
		return Result{Status: StatusRejected, Output: "resposta ativa desligada no agente (SOC_RESPONSE_ENABLED=false)"}
	}
	switch a.Type {
	case BlockIP:
		return x.blockIP(ctx, a)
	case UnblockIP:
		return x.unblockIP(ctx, a)
	case KillProcess:
		return x.killProcess(a)
	case DiskCleanup:
		return x.diskCleanup(ctx)
	case RestartService:
		return x.restartService(ctx, a)
	default:
		return Result{Status: StatusRejected, Output: "ação desconhecida: " + a.Type}
	}
}

func (x *Executor) blockIP(ctx context.Context, a Action) Result {
	ip := net.ParseIP(str(a.Params["ip"]))
	if ip == nil {
		return Result{Status: StatusRejected, Output: "IP inválido"}
	}
	if ok, why := x.Allowlist.Protected(ip); ok {
		return Result{Status: StatusRejected, Output: fmt.Sprintf("%s está na lista de proteção do agente (%s); não bloqueado", ip, why)}
	}
	ttl := time.Duration(num(a.Params["ttlSeconds"])) * time.Second
	b, err := x.Firewall.Block(ctx, ip, ttl, str(a.Params["reason"]), "soc")
	if err != nil {
		return Result{Status: StatusFailed, Output: err.Error()}
	}
	return Result{
		Status:  StatusSucceeded,
		Output:  fmt.Sprintf("%s bloqueado no firewall (nftables) até %s", ip, b.Until.UTC().Format(time.RFC3339)),
		Details: map[string]any{"ip": b.IP, "until": b.Until.UTC()},
	}
}

func (x *Executor) unblockIP(ctx context.Context, a Action) Result {
	ip := net.ParseIP(str(a.Params["ip"]))
	if ip == nil {
		return Result{Status: StatusRejected, Output: "IP inválido"}
	}
	if err := x.Firewall.Unblock(ctx, ip); err != nil {
		return Result{Status: StatusFailed, Output: err.Error()}
	}
	return Result{Status: StatusSucceeded, Output: fmt.Sprintf("%s desbloqueado", ip), Details: map[string]any{"ip": ip.String()}}
}

// killProcess only kills a process that is still the same one (pid + start time + exe)
// and that the agent itself still classifies as suspicious. Before killing, it copies the
// binary (readable through /proc even when deleted from disk) to quarantine as evidence.
func (x *Executor) killProcess(a Action) Result {
	pid := int(num(a.Params["pid"]))
	if pid <= 1 || pid == x.Self {
		return Result{Status: StatusRejected, Output: fmt.Sprintf("pid %d não pode ser encerrado", pid)}
	}
	procs := collector.ListProcesses()
	p, ok := procs[pid]
	if !ok {
		return Result{Status: StatusSucceeded, Output: fmt.Sprintf("processo %d já não está rodando", pid)}
	}
	if st := uint64(num(a.Params["startTime"])); st != 0 && st != p.StartTime {
		return Result{Status: StatusRejected, Output: fmt.Sprintf("pid %d agora é outro processo (%s); nada encerrado", pid, p.Comm)}
	}
	if exe := str(a.Params["exe"]); exe != "" && exe != p.Exe {
		return Result{Status: StatusRejected, Output: fmt.Sprintf("executável do pid %d mudou (%s); nada encerrado", pid, p.Exe)}
	}
	reasons := collector.ClassifyProcess(p, procs[p.PPID], collector.PublicListenerPIDs()[p.PPID])
	if len(reasons) == 0 {
		return Result{Status: StatusRejected, Output: fmt.Sprintf("pid %d (%s) não é mais classificado como suspeito; nada encerrado", pid, p.Comm)}
	}

	details := map[string]any{"pid": pid, "comm": p.Comm, "exe": p.Exe, "cmdline": p.Cmdline, "user": p.User, "reasons": reasons}
	evidence, sum, err := x.quarantine(pid, p)
	if err != nil {
		details["evidenceError"] = err.Error()
	} else {
		details["evidence"], details["sha256"] = evidence, sum
	}

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return Result{Status: StatusFailed, Output: "falha ao encerrar: " + err.Error(), Details: details}
	}
	msg := fmt.Sprintf("processo %d (%s, %s) encerrado com SIGKILL", pid, p.Comm, p.Exe)
	if sum != "" {
		msg += fmt.Sprintf("; binário preservado em %s (sha256 %s)", evidence, sum[:16])
	}
	return Result{Status: StatusSucceeded, Output: msg, Details: details}
}

func (x *Executor) quarantine(pid int, p collector.ProcInfo) (path, sum string, err error) {
	if x.QuarantineDir == "" {
		return "", "", errors.New("quarantine disabled")
	}
	if err := os.MkdirAll(x.QuarantineDir, 0o700); err != nil {
		return "", "", err
	}
	src, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", "", err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(x.QuarantineDir, "incoming-*")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxEvidenceBytes))
	tmp.Close()
	if copyErr != nil {
		os.Remove(tmp.Name())
		return "", "", copyErr
	}
	sum = hex.EncodeToString(h.Sum(nil))
	path = filepath.Join(x.QuarantineDir, sum+".bin")
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return "", "", err
	}
	_ = os.Chmod(path, 0o400) // evidence: never executable
	meta, _ := json.MarshalIndent(map[string]any{
		"capturedAt": time.Now().UTC(), "pid": pid, "comm": p.Comm, "exe": p.Exe, "cmdline": p.Cmdline,
		"user": p.User, "bytes": n, "truncated": n == maxEvidenceBytes,
	}, "", "  ")
	_ = os.WriteFile(filepath.Join(x.QuarantineDir, sum+".json"), meta, 0o400)
	return path, sum, nil
}

// diskCleanup frees space that is safe to drop: old journal files beyond 500 MB and the
// apt package cache. It never deletes application data or rotated security logs.
func (x *Executor) diskCleanup(ctx context.Context) Result {
	before := freeBytes("/")
	var steps []string
	if _, err := exec.LookPath("journalctl"); err == nil {
		if out, err := x.Run(ctx, "", "journalctl", "--vacuum-size=500M"); err != nil {
			steps = append(steps, "journalctl: "+firstLine(err.Error()))
		} else {
			steps = append(steps, "journald: "+lastLine(out))
		}
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		if _, err := x.Run(ctx, "", "apt-get", "clean"); err != nil {
			steps = append(steps, "apt-get clean: "+firstLine(err.Error()))
		} else {
			steps = append(steps, "cache do apt limpo")
		}
	}
	freed := int64(freeBytes("/")) - int64(before)
	if freed < 0 {
		freed = 0
	}
	return Result{
		Status:  StatusSucceeded,
		Output:  fmt.Sprintf("limpeza concluída, %.1f MB liberados (%s)", float64(freed)/(1<<20), strings.Join(steps, "; ")),
		Details: map[string]any{"freedBytes": freed},
	}
}

func (x *Executor) restartService(ctx context.Context, a Action) Result {
	unit := str(a.Params["unit"])
	if !unitName.MatchString(unit) {
		return Result{Status: StatusRejected, Output: "nome de serviço inválido"}
	}
	state, _ := x.Run(ctx, "", "systemctl", "is-failed", unit)
	if strings.TrimSpace(state) != "failed" {
		return Result{Status: StatusRejected, Output: fmt.Sprintf("%s não está em falha (estado: %s); nada feito", unit, strings.TrimSpace(state))}
	}
	if _, err := x.Run(ctx, "", "systemctl", "restart", unit); err != nil {
		return Result{Status: StatusFailed, Output: firstLine(err.Error())}
	}
	time.Sleep(3 * time.Second)
	active, _ := x.Run(ctx, "", "systemctl", "is-active", unit)
	active = strings.TrimSpace(active)
	if active != "active" {
		return Result{Status: StatusFailed, Output: fmt.Sprintf("%s reiniciado mas está %s; veja journalctl -u %s", unit, active, unit)}
	}
	return Result{Status: StatusSucceeded, Output: unit + " reiniciado e ativo", Details: map[string]any{"unit": unit}}
}

func freeBytes(path string) uint64 {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize)
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
