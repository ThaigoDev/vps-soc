package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Metrics struct {
	CPUPercent     float64 `json:"cpuPercent"`
	MemPercent     float64 `json:"memPercent"`
	MemTotalBytes  uint64  `json:"memTotalBytes"`
	MemUsedBytes   uint64  `json:"memUsedBytes"`
	DiskPercent    float64 `json:"diskPercent"`
	DiskTotalBytes uint64  `json:"diskTotalBytes"`
	DiskUsedBytes  uint64  `json:"diskUsedBytes"`
	Load1          float64 `json:"load1"`
	Load5          float64 `json:"load5"`
	Load15         float64 `json:"load15"`
	UptimeSeconds  int64   `json:"uptimeSeconds"`
	SwapPercent    float64 `json:"swapPercent"`
	NetRxBps       float64 `json:"netRxBps"` // bytes per second, all interfaces but lo
	NetTxBps       float64 `json:"netTxBps"`
	TCPEstablished int     `json:"tcpEstablished"`
	Processes      int     `json:"processes"`
}

// MetricsReader computes CPU usage as the delta between two consecutive reads.
type MetricsReader struct {
	prevIdle, prevTotal uint64
	prevRx, prevTx      uint64
	prevNetAt           time.Time
}

func (r *MetricsReader) Read() Metrics {
	var m Metrics
	if idle, total, ok := readCPU(); ok {
		if r.prevTotal > 0 && total > r.prevTotal {
			dt, di := float64(total-r.prevTotal), float64(idle-r.prevIdle)
			m.CPUPercent = round1(100 * (dt - di) / dt)
		}
		r.prevIdle, r.prevTotal = idle, total
	}

	mem := readMeminfo()
	if total := mem["MemTotal"]; total > 0 {
		m.MemTotalBytes = total
		m.MemUsedBytes = total - mem["MemAvailable"]
		m.MemPercent = round1(100 * float64(m.MemUsedBytes) / float64(total))
	}
	if st := mem["SwapTotal"]; st > 0 {
		m.SwapPercent = round1(100 * float64(st-mem["SwapFree"]) / float64(st))
	}
	if rx, tx, ok := netCounters(); ok {
		now := time.Now()
		if !r.prevNetAt.IsZero() && rx >= r.prevRx && tx >= r.prevTx {
			secs := now.Sub(r.prevNetAt).Seconds()
			m.NetRxBps = round1(float64(rx-r.prevRx) / secs)
			m.NetTxBps = round1(float64(tx-r.prevTx) / secs)
		}
		r.prevRx, r.prevTx, r.prevNetAt = rx, tx, now
	}
	m.TCPEstablished = tcpEstablished()
	m.Processes = processCount()

	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		total := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		used := total - st.Bfree*uint64(st.Bsize)
		m.DiskTotalBytes, m.DiskUsedBytes = total, used
		if used+free > 0 {
			m.DiskPercent = round1(100 * float64(used) / float64(used+free)) // same formula as df
		}
	}

	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			m.Load1, _ = strconv.ParseFloat(f[0], 64)
			m.Load5, _ = strconv.ParseFloat(f[1], 64)
			m.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			up, _ := strconv.ParseFloat(f[0], 64)
			m.UptimeSeconds = int64(up)
		}
	}
	return m
}

func readCPU() (idle, total uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text()) // cpu user nice system idle iowait irq softirq steal ...
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, v := range fields[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		if i >= 8 { // guest time is already counted in user
			break
		}
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return idle, total, true
}

func readMeminfo() map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fields[0], 10, 64)
		out[k] = n * 1024 // values are in kB
	}
	return out
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

// OSName returns PRETTY_NAME from /etc/os-release.
func OSName() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "linux"
}
