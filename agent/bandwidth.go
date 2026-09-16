package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type bandwidthFileCursor struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

type hostingBandwidthState struct {
	User       string                         `json:"user"`
	Month      string                         `json:"month"`
	UsedBytes  int64                          `json:"used_bytes"`
	LimitBytes int64                          `json:"limit_bytes"`
	Over       bool                           `json:"over"`
	UpdatedAt  int64                          `json:"updated_at"`
	Files      map[string]bandwidthFileCursor `json:"files"`
}

var bandwidthLineRE = regexp.MustCompile(`\[([^]]+)\] "[^"]*" [0-9]{3} ([0-9]+) `)

func hostingBandwidthStatePath(u string) string {
	return filepath.Join(state, "hosting", "bandwidth", u+".json")
}
func hostingBandwidthGatePath(u string) string {
	return filepath.Join("/etc/nginx/xshoter/bandwidth", u+".conf")
}
func bandwidthMonth(t time.Time) string    { return t.Format("2006-01") }
func bandwidthLogMonth(t time.Time) string { return "/" + t.Format("Jan/2006") + ":" }

func loadHostingBandwidth(u string) hostingBandwidthState {
	st := hostingBandwidthState{User: u, Month: bandwidthMonth(time.Now()), Files: map[string]bandwidthFileCursor{}}
	b, e := os.ReadFile(hostingBandwidthStatePath(u))
	if e == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Files == nil {
		st.Files = map[string]bandwidthFileCursor{}
	}
	st.User = u
	return st
}

func saveHostingBandwidth(st hostingBandwidthState) error {
	b, e := json.MarshalIndent(st, "", "  ")
	if e != nil {
		return e
	}
	return writeStateJSON(hostingBandwidthStatePath(st.User), json.RawMessage(b))
}

func safeBandwidthLog(path string) (*os.File, os.FileInfo, error) {
	li, e := os.Lstat(path)
	if e != nil {
		return nil, nil, e
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("unsafe bandwidth log")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	fi, e := f.Stat()
	if e != nil {
		_ = f.Close()
		return nil, nil, e
	}
	return f, fi, nil
}

func scanBandwidthLog(path string, cur bandwidthFileCursor, monthNeedle string) (int64, bandwidthFileCursor, error) {
	f, fi, e := safeBandwidthLog(path)
	if e != nil {
		return 0, cur, e
	}
	defer f.Close()
	inode := uint64(0)
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		inode = st.Ino
	}
	start := cur.Offset
	if cur.Inode != inode || start < 0 || fi.Size() < start {
		start = 0
	}
	if _, e = f.Seek(start, 0); e != nil {
		return 0, cur, e
	}
	rd := bufio.NewReaderSize(f, 64*1024)
	pos, added := start, int64(0)
	const maxPerPass = int64(64 << 20)
	for pos-start < maxPerPass {
		line, er := rd.ReadString('\n')
		if strings.HasSuffix(line, "\n") {
			pos += int64(len(line))
			if m := bandwidthLineRE.FindStringSubmatch(line); len(m) == 3 && strings.Contains(m[1], monthNeedle) {
				if n, x := strconv.ParseInt(m[2], 10, 64); x == nil && n > 0 {
					added += n
				}
			}
		}
		if er != nil {
			break
		}
	}
	return added, bandwidthFileCursor{Offset: pos, Inode: inode}, nil
}

func refreshHostingBandwidth(u string, limitMB int64) (hostingBandwidthState, error) {
	now := time.Now()
	st := loadHostingBandwidth(u)
	month := bandwidthMonth(now)
	if st.Month != month {
		st.Month = month
		st.UsedBytes = 0
		st.Over = false
		st.Files = map[string]bandwidthFileCursor{}
	}
	logs, _ := filepath.Glob(filepath.Join("/home", u, "web", "*", "logs", "access.log"))
	prefix := filepath.Join("/home", u, "web") + string(os.PathSeparator)
	live := map[string]bool{}
	for _, p := range logs {
		clean := filepath.Clean(p)
		if !strings.HasPrefix(clean, prefix) {
			continue
		}
		live[clean] = true
		added, next, e := scanBandwidthLog(clean, st.Files[clean], bandwidthLogMonth(now))
		if e != nil {
			continue
		}
		st.UsedBytes += added
		st.Files[clean] = next
	}
	for p := range st.Files {
		if !live[p] {
			delete(st.Files, p)
		}
	}
	st.LimitBytes = limitMB * 1024 * 1024
	st.Over = st.LimitBytes > 0 && st.UsedBytes >= st.LimitBytes
	st.UpdatedAt = now.Unix()
	if e := saveHostingBandwidth(st); e != nil {
		return st, e
	}
	if e := applyHostingBandwidthGate(u, st.Over); e != nil {
		return st, e
	}
	return st, nil
}

func ensureHostingBandwidthGate(u string) error {
	p := hostingBandwidthGatePath(u)
	if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
		return e
	}
	if _, e := os.Stat(p); os.IsNotExist(e) {
		return os.WriteFile(p, []byte("# Xshoter bandwidth: within quota\n"), 0644)
	}
	return nil
}

func ensureHostingBandwidthVhosts(u string) error {
	if e := ensureHostingBandwidthGate(u); e != nil {
		return e
	}
	gateLine := "include " + hostingBandwidthGatePath(u) + ";"
	metaFiles, _ := filepath.Glob(filepath.Join(state, "sites", "*.json"))
	backups := map[string][]byte{}
	for _, mp := range metaFiles {
		b, e := os.ReadFile(mp)
		if e != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil || strings.TrimSpace(fmt.Sprint(m["owner"])) != u {
			continue
		}
		vhost := filepath.Clean(strings.TrimSpace(fmt.Sprint(m["vhost"])))
		if !strings.HasPrefix(vhost, "/etc/nginx/xshoter/sites-enabled/") || !strings.HasSuffix(vhost, ".conf") {
			continue
		}
		old, e := os.ReadFile(vhost)
		if e != nil || strings.Contains(string(old), gateLine) {
			continue
		}
		text := string(old)
		if !strings.Contains(text, "server {") {
			continue
		}
		backups[vhost] = old
		text = strings.Replace(text, "server {", "server {\n "+gateLine, 1)
		if e := os.WriteFile(vhost, []byte(text), 0644); e != nil {
			for p, x := range backups {
				_ = os.WriteFile(p, x, 0644)
			}
			return e
		}
	}
	if len(backups) == 0 {
		return nil
	}
	if _, e := cmd("nginx", "-t"); e != nil {
		for p, x := range backups {
			_ = os.WriteFile(p, x, 0644)
		}
		return fmt.Errorf("bandwidth vhost nginx validation failed: %w", e)
	}
	if _, e := cmd("systemctl", "reload", "nginx"); e != nil {
		for p, x := range backups {
			_ = os.WriteFile(p, x, 0644)
		}
		_, _ = cmd("systemctl", "reload", "nginx")
		return e
	}
	return nil
}

func applyHostingBandwidthGate(u string, blocked bool) error {
	if e := ensureHostingBandwidthGate(u); e != nil {
		return e
	}
	p := hostingBandwidthGatePath(u)
	want := "# Xshoter bandwidth: within quota\n"
	if blocked {
		want = "# Xshoter bandwidth: limit exceeded\nreturn 509 \"Bandwidth limit exceeded\\n\";\n"
	}
	old, _ := os.ReadFile(p)
	if string(old) == want {
		return nil
	}
	if e := os.WriteFile(p, []byte(want), 0644); e != nil {
		return e
	}
	if _, e := cmd("nginx", "-t"); e != nil {
		_ = os.WriteFile(p, old, 0644)
		return fmt.Errorf("bandwidth gate nginx validation failed: %w", e)
	}
	_, e := cmd("systemctl", "reload", "nginx")
	return e
}

func hostingBandwidth(w http.ResponseWriter, r *http.Request) {
	u := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	limit := int64(-1)
	if r.Method == "POST" {
		var v struct {
			User    string `json:"user"`
			LimitMB int64  `json:"limit_mb"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		u = strings.ToLower(strings.TrimSpace(v.User))
		limit = v.LimitMB
		if limit < 0 || limit > 1073741824 {
			fail(w, 400, "invalid bandwidth limit")
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
	if _, e := user.Lookup(u); e != nil {
		fail(w, 404, "hosting user not provisioned")
		return
	}
	if limit < 0 {
		limit = loadHostingBandwidth(u).LimitBytes / 1024 / 1024
	}
	if e := ensureHostingBandwidthVhosts(u); e != nil {
		fail(w, 500, e.Error())
		return
	}
	st, e := refreshHostingBandwidth(u, limit)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	out(w, 200, R{"ok": true, "user": u, "month": st.Month, "used_bytes": st.UsedBytes, "limit_bytes": st.LimitBytes, "limit_mb": limit, "over": st.Over, "updated_at": st.UpdatedAt})
}
