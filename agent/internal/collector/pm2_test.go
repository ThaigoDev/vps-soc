package collector

import (
	"testing"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

const sampleJList = `[PM2] warning line
[{"pid":44,"name":"api-web","pm2_env":{"status":"online","restart_time":0,"unstable_restarts":0,"pm_uptime":1792497717766,"created_at":1792497717000,"exec_mode":"fork_mode","pm_exec_path":"/app/web.js","pm_cwd":"/app","version":"N/A","node_version":"20.20.2","username":"node","namespace":"default","pm_err_log_path":"/pm2home/logs/api-web-error.log","pm_out_log_path":"/pm2home/logs/api-web-out.log","DATABASE_PASSWORD":"s3cret","env":{"API_KEY":"k"}},"pm_id":0,"monit":{"memory":56008704,"cpu":1.5}},
 {"pid":811,"name":"worker","pm2_env":{"status":"errored","restart_time":68,"unstable_restarts":3,"exec_mode":"cluster_mode","username":"node"},"pm_id":1,"monit":{"memory":0,"cpu":0}}]`

func TestParsePM2JList(t *testing.T) {
	s, err := ParsePM2JList([]byte(sampleJList), "/pm2home")
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 {
		t.Fatalf("got %d services", len(s))
	}
	a := s[0]
	if a.Name != "api-web" || a.PmID != 0 || a.PID != 44 || a.Status != "online" || a.MemoryBytes != 56008704 ||
		a.CPUPercent != 1.5 || a.Mode != "fork" || a.Version != "" || a.NodeVersion != "20.20.2" || a.StartedAt.IsZero() {
		t.Errorf("api-web parsed as %+v", a)
	}
	w := s[1]
	if w.Status != "errored" || w.Restarts != 68 || w.UnstableRestarts != 3 || w.PID != 0 || w.Mode != "cluster" {
		t.Errorf("worker parsed as %+v", w)
	}
}

func TestParsePM2DaemonCmdline(t *testing.T) {
	d, ok := ParsePM2DaemonCmdline("PM2 v5.4.3: God Daemon (/root/.pm2)")
	if !ok || d.Home != "/root/.pm2" || d.Version != "5.4.3" {
		t.Errorf("got %+v %v", d, ok)
	}
	if _, ok := ParsePM2DaemonCmdline("node /app/web.js"); ok {
		t.Error("app process must not be a daemon")
	}
}

func TestPM2DiffEmitsStatusRestartAddRemove(t *testing.T) {
	st, _ := state.New(t.TempDir())
	var got []event.Event
	m := &PM2Monitor{State: st, Emit: func(e event.Event) { got = append(got, e) }, previous: map[string]serviceMark{}}

	api := Service{Name: "api", PmID: 0, PID: 10, Status: "online", PM2Home: "/h"}
	worker := Service{Name: "worker", PmID: 1, PID: 11, Status: "online", PM2Home: "/h"}
	m.diff([]Service{api, worker}) // baseline: no events
	if len(got) != 0 {
		t.Fatalf("baseline emitted %v", got)
	}

	worker.Status, worker.Restarts = "errored", 4
	cron := Service{Name: "cron", PmID: 2, Status: "online", PM2Home: "/h"}
	m.diff([]Service{worker, cron}) // api removed, worker crashed, cron added
	types := map[string]int{}
	for _, e := range got {
		types[e.Type]++
	}
	if types[event.ServiceStatusChanged] != 1 || types[event.ServiceRestarted] != 1 || types[event.ServiceAdded] != 1 || types[event.ServiceRemoved] != 1 {
		t.Errorf("events %v", types)
	}
	for _, e := range got {
		if e.Type == event.ServiceRestarted && e.Metadata["delta"] != 4 {
			t.Errorf("restart delta %v", e.Metadata["delta"])
		}
	}

	// A new agent process resumes from the saved state instead of starting a new baseline.
	got = nil
	m2 := &PM2Monitor{State: st, Emit: func(e event.Event) { got = append(got, e) }, previous: map[string]serviceMark{}}
	found, _ := st.LoadJSON(pm2StateFile, &m2.previous)
	m2.baseline = found
	worker.Restarts = 5
	m2.diff([]Service{worker, cron})
	if len(got) != 1 || got[0].Type != event.ServiceRestarted {
		t.Errorf("after restart got %v", got)
	}
}

func TestAttachPorts(t *testing.T) {
	s := AttachPorts([]Service{{Name: "api", PID: 10}, {Name: "w", PID: 0}},
		[]Listener{{Port: 3000, PID: 10}, {Port: 3000, PID: 10, Proto: "tcp6"}, {Port: 22, PID: 1}})
	if len(s[0].Ports) != 1 || s[0].Ports[0] != 3000 || len(s[1].Ports) != 0 {
		t.Errorf("ports %+v", s)
	}
}
