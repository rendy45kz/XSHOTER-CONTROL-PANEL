package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type hostingResourceLimits struct {
	User       string `json:"user"`
	CPUPercent int64  `json:"cpu_percent"`
	MemoryMB   int64  `json:"memory_mb"`
	Processes  int64  `json:"processes"`
	UpdatedAt  int64  `json:"updated_at"`
}

func hostingResourceStatePath(u string) string {
	return filepath.Join(state, "hosting", "resources", u+".json")
}

func hostingResourceSlice(u string) string { return "xshoter-hosting-" + u + ".slice" }
func validHostingResources(cpu, mem, proc int64) bool {
	return cpu >= 10 && cpu <= 6400 && mem >= 64 && mem <= 1048576 && proc >= 8 && proc <= 100000
}

func loadHostingResourceLimits(u string) hostingResourceLimits {
	x := hostingResourceLimits{User: u, CPUPercent: 100, MemoryMB: 512, Processes: 64}
	if b, e := os.ReadFile(hostingResourceStatePath(u)); e == nil {
		_ = json.Unmarshal(b, &x)
	}
	x.User = u
	if !validHostingResources(x.CPUPercent, x.MemoryMB, x.Processes) {
		x.CPUPercent, x.MemoryMB, x.Processes = 100, 512, 64
	}
	return x
}

func resourcePHPValues(u string) (children int64, memoryPerChild int64) {
	x := loadHostingResourceLimits(u)
	children = x.Processes
	if children > 8 {
		children = 8
	}
	byMem := x.MemoryMB / 64
	if byMem < 1 {
		byMem = 1
	}
	if children > byMem {
		children = byMem
	}
	if children < 1 {
		children = 1
	}
	memoryPerChild = x.MemoryMB / children
	if memoryPerChild < 32 {
		memoryPerChild = 32
	}
	if memoryPerChild > 512 {
		memoryPerChild = 512
	}
	return
}
func writeHostingSlice(x hostingResourceLimits) error {
	unit := hostingResourceSlice(x.User)
	p := filepath.Join("/etc/systemd/system", unit)
	body := fmt.Sprintf("[Unit]\nDescription=Xshoter Hosting Resource Slice %s\n\n[Slice]\nCPUAccounting=yes\nMemoryAccounting=yes\nTasksAccounting=yes\nCPUQuota=%d%%\nMemoryMax=%dM\nTasksMax=%d\n", x.User, x.CPUPercent, x.MemoryMB, x.Processes)
	if e := os.WriteFile(p, []byte(body), 0644); e != nil {
		return e
	}
	if _, e := cmd("systemctl", "daemon-reload"); e != nil {
		return e
	}
	if _, e := cmd("systemctl", "start", unit); e != nil {
		return e
	}
	if _, e := cmd("systemctl", "set-property", "--runtime", unit,
		fmt.Sprintf("CPUQuota=%d%%", x.CPUPercent),
		fmt.Sprintf("MemoryMax=%dM", x.MemoryMB),
		fmt.Sprintf("TasksMax=%d", x.Processes)); e != nil {
		return e
	}
	return nil
}

func writeHostingPamLimits(x hostingResourceLimits) error {
	p := filepath.Join("/etc/security/limits.d", "90-xshoter-"+x.User+".conf")
	asKB := x.MemoryMB * 1024
	body := fmt.Sprintf("# Managed by Xshoter Control\n%s soft nproc %d\n%s hard nproc %d\n%s soft as %d\n%s hard as %d\n", x.User, x.Processes, x.User, x.Processes, x.User, asKB, x.User, asKB)
	return os.WriteFile(p, []byte(body), 0644)
}

func replaceResourceLine(lines []string, prefix, value string) []string {
	found := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			lines[i] = value
			found = true
		}
	}
	if !found {
		lines = append(lines, value)
	}
	return lines
}
func reconcileHostingPHPResources(u string) error {
	children, memPer := resourcePHPValues(u)
	fs, _ := filepath.Glob(filepath.Join(state, "sites", "*.json"))
	changed := map[string]bool{}
	for _, metaPath := range fs {
		b, e := os.ReadFile(metaPath)
		if e != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil || fmt.Sprint(m["owner"]) != u {
			continue
		}
		pp := fmt.Sprint(m["php_pool"])
		ver := fmt.Sprint(m["php"])
		if !strings.HasPrefix(pp, "/etc/php/") || !phpRE.MatchString(ver) {
			continue
		}
		pb, e := os.ReadFile(pp)
		if e != nil {
			continue
		}
		lines := strings.Split(string(pb), "\n")
		lines = replaceResourceLine(lines, "pm.max_children=", fmt.Sprintf("pm.max_children=%d", children))
		lines = replaceResourceLine(lines, "php_admin_value[memory_limit]=", fmt.Sprintf("php_admin_value[memory_limit]=%dM", memPer))
		if e = os.WriteFile(pp, []byte(strings.Join(lines, "\n")), 0644); e != nil {
			return e
		}
		changed[ver] = true
	}
	for ver := range changed {
		if _, e := cmd("systemctl", "reload", "php"+ver+"-fpm"); e != nil {
			return e
		}
	}
	return nil
}

func hostingCronCommand(x hostingResourceLimits, id, schedule, command string) string {
	unitPrefix := "xshoter-cron-" + x.User + "-" + id
	run := "/usr/bin/systemd-run --quiet --wait --collect --service-type=exec --slice=" + hostingResourceSlice(x.User) +
		" --uid=" + x.User + " --gid=" + x.User + " --working-directory=/home/" + x.User +
		" --unit=" + unitPrefix + " --property=RuntimeMaxSec=3600 /bin/bash -lc " + cronShellQuote(command)
	return "SHELL=/bin/bash\nPATH=/usr/local/bin:/usr/bin:/bin\nHOME=/root\n" + schedule + " root " + run + "\n"
}
func reconcileHostingCronResources(u string) error {
	x := loadHostingResourceLimits(u)
	dir := filepath.Join(state, "hosting-cron", u)
	fs, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, p := range fs {
		b, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		id := fmt.Sprint(m["id"])
		schedule := fmt.Sprint(m["schedule"])
		command := fmt.Sprint(m["command"])
		if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(id) || !cronRE.MatchString(schedule) || command == "" {
			continue
		}
		cp := "/etc/cron.d/xshoter-client-" + u + "-" + id
		if e = os.WriteFile(cp, []byte(hostingCronCommand(x, id, schedule, command)), 0644); e != nil {
			return e
		}
	}
	return nil
}

func reconcileHostingAppResources(u string) error {
	fs, _ := filepath.Glob("/etc/systemd/system/xshoter-app-*.service")
	changed := []string{}
	for _, p := range fs {
		b, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		txt := string(b)
		if !strings.Contains(txt, "User="+u+"\n") {
			continue
		}
		want := "Slice=" + hostingResourceSlice(u)
		lines := strings.Split(txt, "\n")
		lines = replaceResourceLine(lines, "Slice=", want)
		next := strings.Join(lines, "\n")
		if next == txt {
			continue
		}
		if e = os.WriteFile(p, []byte(next), 0644); e != nil {
			return e
		}
		changed = append(changed, filepath.Base(p))
	}
	if len(changed) == 0 {
		return nil
	}
	if _, e := cmd("systemctl", "daemon-reload"); e != nil {
		return e
	}
	for _, unit := range changed {
		if b, _ := cmd("systemctl", "is-active", unit); strings.TrimSpace(string(b)) == "active" {
			if _, e := cmd("systemctl", "restart", unit); e != nil {
				return e
			}
		}
	}
	return nil
}

func applyHostingResourceLimits(u string, cpu, mem, proc int64) (hostingResourceLimits, error) {
	x := hostingResourceLimits{User: u, CPUPercent: cpu, MemoryMB: mem, Processes: proc, UpdatedAt: time.Now().Unix()}
	if !hostingUserName(u) || !validHostingResources(cpu, mem, proc) {
		return x, fmt.Errorf("invalid hosting resource limits")
	}
	if _, e := user.Lookup(u); e != nil {
		return x, fmt.Errorf("hosting user not provisioned")
	}
	if e := writeHostingSlice(x); e != nil {
		return x, e
	}
	if e := writeHostingPamLimits(x); e != nil {
		return x, e
	}
	if e := writeStateJSON(hostingResourceStatePath(u), x); e != nil {
		return x, e
	}
	if e := reconcileHostingPHPResources(u); e != nil {
		return x, e
	}
	if e := reconcileHostingCronResources(u); e != nil {
		return x, e
	}
	if e := reconcileHostingAppResources(u); e != nil {
		return x, e
	}
	return x, nil
}

func hostingResources(w http.ResponseWriter, r *http.Request) {
	u := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	x := loadHostingResourceLimits(u)
	if r.Method == "POST" {
		var v struct {
			User       string `json:"user"`
			CPUPercent int64  `json:"cpu_percent"`
			MemoryMB   int64  `json:"memory_mb"`
			Processes  int64  `json:"processes"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		u = strings.ToLower(strings.TrimSpace(v.User))
		var e error
		x, e = applyHostingResourceLimits(u, v.CPUPercent, v.MemoryMB, v.Processes)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
	} else if r.Method != "GET" {
		fail(w, 405, "method not allowed")
		return
	}
	if !hostingUserName(u) {
		fail(w, 400, "invalid hosting user")
		return
	}
	x = loadHostingResourceLimits(u)
	out(w, 200, R{"ok": true, "user": u, "cpu_percent": x.CPUPercent, "memory_mb": x.MemoryMB, "processes": x.Processes, "slice": hostingResourceSlice(u), "updated_at": x.UpdatedAt})
}
