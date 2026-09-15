package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var sock = envOr("XSHOTER_AGENT_SOCKET", "/run/xshoter-agent.sock")
var state = envOr("XSHOTER_STATE_DIR", "/var/lib/xshoter-control")

var domainRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var phpRE = regexp.MustCompile(`^8\.(2|3)$`)
var cronRE = regexp.MustCompile(`^[0-9*/?,\-]+\s+[0-9*/?,\-]+\s+[0-9*/?,\-]+\s+[0-9*/?,\-]+\s+[0-9*/?,\-]+$`)
var serviceList = []string{"nginx", "mariadb", "cloudflared", "ssh", "fail2ban", "php8.2-fpm", "php8.3-fpm", "xshoter-control", "xshoter-agent", "xshoter-firewall"}
var servicesOK = map[string]bool{
	"nginx": true, "mariadb": true, "cloudflared": true, "ssh": true,
	"fail2ban": true, "php8.2-fpm": true, "php8.3-fpm": true,
	"xshoter-control": true, "xshoter-agent": true, "xshoter-firewall": true,
}
var servicesReload = map[string]bool{"nginx": true, "mariadb": true, "ssh": true, "fail2ban": true, "php8.2-fpm": true, "php8.3-fpm": true}

type R map[string]any

func main() {
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	must(err)
	g, err := user.LookupGroup("www-data")
	must(err)
	gid, _ := strconv.Atoi(g.Gid)
	must(os.Chown(sock, 0, gid))
	must(os.Chmod(sock, 0660))
	m := http.NewServeMux()
	m.HandleFunc("/v1/health", only("GET", health))
	m.HandleFunc("/v1/stats", only("GET", stats))
	m.HandleFunc("/v1/services", services)
	m.HandleFunc("/v1/websites", websites)
	m.HandleFunc("/v1/databases", databases)
	m.HandleFunc("/v1/pma-token", only("POST", pmaToken))
	m.HandleFunc("/v1/ssl", only("POST", sslIssue))
	m.HandleFunc("/v1/firewall", firewall)
	m.HandleFunc("/v1/cron", cron)
	m.HandleFunc("/v1/backups", backups)
	m.HandleFunc("/v1/logs", only("GET", logs))
	m.HandleFunc("/v1/files", filesAPI)
	m.HandleFunc("/v1/sshkeys", sshKeys)
	m.HandleFunc("/v1/system", only("GET", systemInfo))
	m.HandleFunc("/v1/processes", only("GET", processes))
	m.HandleFunc("/v1/packages", packageUpdates)
	m.HandleFunc("/v1/ssl-status", only("GET", sslStatus))
	m.HandleFunc("/v1/web-logs", only("GET", webLogs))
	m.HandleFunc("/v1/php-settings", phpSettings)
	m.HandleFunc("/v1/file-actions", fileActions)
	m.HandleFunc("/v1/file-upload", fileUpload)
	m.HandleFunc("/v1/backup-actions", backupActions)
	m.HandleFunc("/v1/dns", dnsRecords)
	m.HandleFunc("/v1/cloudflare", cloudflareConfigHandler)
	m.HandleFunc("/v1/cloudflare-test", cloudflareTestHandler)
	m.HandleFunc("/v1/cloudflare-zones", cloudflareZonesHandler)
	m.HandleFunc("/v1/cloudflare-zone-settings", cloudflareZoneSettingsHandler)
	m.HandleFunc("/v1/cloudflare-cache", cloudflareCacheHandler)
	m.HandleFunc("/v1/cloudflare-tunnels", cloudflareTunnelsHandler)
	m.HandleFunc("/v1/cloudflare-tunnel-routes", cloudflareTunnelRoutesHandler)
	m.HandleFunc("/v1/security", only("GET", securityOverview))
	m.HandleFunc("/v1/server-users", only("GET", serverUsers))
	s := &http.Server{Handler: m, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second}
	must(s.Serve(ln))
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func only(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			fail(w, 405, "method not allowed")
			return
		}
		h(w, r)
	}
}
func out(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, msg string) { out(w, code, R{"ok": false, "error": msg}) }
func body(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func cmd(n string, a ...string) (string, error) {
	c := exec.Command(n, a...)
	b, e := c.CombinedOutput()
	if e != nil {
		return string(b), fmt.Errorf("%s: %w", strings.TrimSpace(string(b)), e)
	}
	return string(b), nil
}
func hexRand(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func exists(p string) bool { _, e := os.Stat(p); return e == nil }

func siteMetaPath(d string) string { return state + "/sites/" + d + ".json" }
func siteMeta(d string) map[string]any {
	b, e := os.ReadFile(siteMetaPath(d))
	if e != nil {
		return nil
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	return v
}
func writeStateJSON(p string, v any) error {
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(p, append(b, '\n'), 0600)
}
func health(w http.ResponseWriter, r *http.Request) {
	out(w, 200, R{"ok": true, "service": "xshoter-agent", "version": "1.0.0"})
}
func host() string { h, _ := os.Hostname(); return h }
func firstFloat(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}
func memInfo() map[string]uint64 {
	b, _ := os.ReadFile("/proc/meminfo")
	m := map[string]uint64{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 1 {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			m[strings.TrimSuffix(f[0], ":")] = v * 1024
		}
	}
	return m
}
func cpuSnap() (uint64, uint64) {
	b, _ := os.ReadFile("/proc/stat")
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	var t, i uint64
	for x := 1; x < len(f); x++ {
		v, _ := strconv.ParseUint(f[x], 10, 64)
		t += v
		if x == 4 || x == 5 {
			i += v
		}
	}
	return t, i
}
func cpuPercent() float64 {
	t1, i1 := cpuSnap()
	time.Sleep(120 * time.Millisecond)
	t2, i2 := cpuSnap()
	if t2 == t1 {
		return 0
	}
	return float64((t2-t1)-(i2-i1)) * 100 / float64(t2-t1)
}
func netBytes() (uint64, uint64) {
	b, _ := os.ReadFile("/proc/net/dev")
	var rx, tx uint64
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.Contains(l, ":") {
			continue
		}
		f := strings.Fields(strings.Replace(l, ":", " ", 1))
		if len(f) < 10 || f[0] == "lo" {
			continue
		}
		a, _ := strconv.ParseUint(f[1], 10, 64)
		z, _ := strconv.ParseUint(f[9], 10, 64)
		rx += a
		tx += z
	}
	return rx, tx
}
func stats(w http.ResponseWriter, r *http.Request) {
	load, _ := os.ReadFile("/proc/loadavg")
	up, _ := os.ReadFile("/proc/uptime")
	m := memInfo()
	var st syscall.Statfs_t
	_ = syscall.Statfs("/", &st)
	rx, tx := netBytes()
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	lf := strings.Fields(string(load))
	if len(lf) < 3 {
		lf = []string{"0", "0", "0"}
	}
	out(w, 200, R{"ok": true, "hostname": host(), "cpu_percent": cpuPercent(), "load": lf[:3], "uptime_seconds": firstFloat(string(up)), "memory_total": m["MemTotal"], "memory_available": m["MemAvailable"], "disk_total": total, "disk_free": free, "net_rx": rx, "net_tx": tx})
}
func services(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		a := []R{}
		for _, n := range serviceList {
			s, _ := cmd("systemctl", "is-active", n)
			en, _ := cmd("systemctl", "is-enabled", n)
			a = append(a, R{"name": n, "active": strings.TrimSpace(s) == "active", "enabled": strings.TrimSpace(en) == "enabled", "can_reload": servicesReload[n]})
		}
		out(w, 200, R{"ok": true, "items": a})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var v struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	if !servicesOK[v.Name] || !map[string]bool{"start": true, "stop": true, "restart": true, "reload": true}[v.Action] || (v.Action == "reload" && !servicesReload[v.Name]) {
		fail(w, 400, "service/action not allowed")
		return
	}
	if _, e := cmd("systemctl", v.Action, v.Name); e != nil {
		fail(w, 500, e.Error())
		return
	}
	out(w, 200, R{"ok": true})
}
func websites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		listWebsites(w)
	case "POST":
		createWebsite(w, r)
	case "DELETE":
		deleteWebsite(w, r)
	default:
		fail(w, 405, "method not allowed")
	}
}
func listWebsites(w http.ResponseWriter) {
	p, _ := filepath.Glob("/home/*/web/*/public_html")
	a := []R{}
	for _, root := range p {
		f := strings.Split(root, "/")
		if len(f) >= 6 {
			d := f[4]
			m := siteMeta(d)
			managed := m != nil || exists("/etc/nginx/xshoter/sites-enabled/"+d+".conf")
			pool, ver := managedPool(d)
			tlsMode := "local"
			kind := "native"
			if m != nil {
				if x := fmt.Sprint(m["tls_mode"]); x != "<nil>" && x != "" {
					tlsMode = x
				}
				if x := fmt.Sprint(m["kind"]); x != "<nil>" && x != "" {
					kind = x
				}
			}
			a = append(a, R{"owner": f[2], "domain": d, "root": root, "managed": managed, "php": ver, "php_configurable": pool != "", "tls_mode": tlsMode, "kind": kind})
		}
	}
	out(w, 200, R{"ok": true, "items": a})
}
func createWebsite(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Owner      string `json:"owner"`
		Domain     string `json:"domain"`
		PHP        string `json:"php"`
		Cloudflare bool   `json:"cloudflare"`
		TunnelID   string `json:"tunnel_id"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	v.Domain = strings.ToLower(v.Domain)
	if !userRE.MatchString(v.Owner) || !domainRE.MatchString(v.Domain) || !phpRE.MatchString(v.PHP) {
		fail(w, 400, "invalid owner/domain/php")
		return
	}
	if _, e := user.Lookup(v.Owner); e != nil {
		if _, e = cmd("useradd", "-m", "-s", "/bin/bash", v.Owner); e != nil {
			fail(w, 500, e.Error())
			return
		}
	}
	webdir := fmt.Sprintf("/home/%s/web", v.Owner)
	webdirNew := !exists(webdir)
	base := fmt.Sprintf("%s/%s", webdir, v.Domain)
	root := base + "/public_html"
	logs := base + "/logs"
	_ = os.MkdirAll(root, 0755)
	_ = os.MkdirAll(logs, 0750)
	if webdirNew {
		_, _ = cmd("chown", v.Owner+":"+v.Owner, webdir)
		_ = os.Chmod(webdir, 0755)
	}
	_, _ = cmd("chown", "-R", v.Owner+":"+v.Owner, base)
	_ = os.Chmod(base, 0751)
	_ = os.Chmod(root, 0755)
	_ = os.Chmod(logs, 0750)
	safe := strings.ReplaceAll(v.Domain, ".", "_")
	socket := fmt.Sprintf("/run/php/php%s-fpm-xshoter-%s.sock", v.PHP, safe)
	pool := fmt.Sprintf("[xshoter-%s]\nuser=%s\ngroup=%s\nlisten=%s\nlisten.owner=www-data\nlisten.group=www-data\nlisten.mode=0660\npm=ondemand\npm.max_children=8\npm.process_idle_timeout=15s\npm.max_requests=500\nphp_admin_value[open_basedir]=%s:/tmp\n", safe, v.Owner, v.Owner, socket, base)
	pp := fmt.Sprintf("/etc/php/%s/fpm/pool.d/xshoter-%s.conf", v.PHP, safe)
	if e := os.WriteFile(pp, []byte(pool), 0644); e != nil {
		fail(w, 500, e.Error())
		return
	}
	np := "/etc/nginx/xshoter/sites-enabled/" + v.Domain + ".conf"
	if e := os.WriteFile(np, []byte(nginxSite(v.Domain, root, logs, socket)), 0644); e != nil {
		fail(w, 500, e.Error())
		return
	}
	if _, e := cmd("nginx", "-t"); e != nil {
		_ = os.Remove(np)
		_ = os.Remove(pp)
		fail(w, 500, e.Error())
		return
	}
	_, _ = cmd("systemctl", "reload", "php"+v.PHP+"-fpm")
	_, _ = cmd("systemctl", "reload", "nginx")
	idx := root + "/index.html"
	if !exists(idx) {
		_ = os.WriteFile(idx, []byte("<!doctype html><title>"+v.Domain+"</title><h1>"+v.Domain+"</h1>"), 0644)
		_, _ = cmd("chown", v.Owner+":"+v.Owner, idx)
		_ = os.Chmod(idx, 0644)
	}
	meta := R{"owner": v.Owner, "domain": v.Domain, "root": root, "vhost": np, "php": v.PHP, "php_pool": pp, "access_log": logs + "/access.log", "error_log": logs + "/error.log", "tls_mode": "local", "kind": "native"}
	_ = writeStateJSON(siteMetaPath(v.Domain), meta)
	cf := R{"requested": v.Cloudflare, "ok": false}
	if v.Cloudflare {
		cfg := effectiveCloudflareConfig()
		if strings.TrimSpace(v.TunnelID) != "" {
			cfg.TunnelID = strings.TrimSpace(v.TunnelID)
		}
		cfg, tunnelID, e := cfPickTunnel(cfg)
		if e == nil {
			var zoneID, zoneName, zoneStatus string
			var ns []string
			cfg, zoneID, zoneName, zoneStatus, ns, e = cfEnsureZoneForHostname(cfg, v.Domain)
			_ = zoneID
			if e == nil {
				listen := envOr("XSHOTER_WEB_LISTEN", "80")
				service := "http://127.0.0.1:" + listen
				if strings.Contains(listen, ":") {
					service = "http://" + listen
				}
				e = cfUpsertTunnelRoute(cfg, tunnelID, v.Domain, "", service, false)
			}
			if e == nil {
				meta["tls_mode"] = "cloudflare"
				meta["cloudflare_zone"] = zoneName
				meta["cloudflare_tunnel_id"] = tunnelID
				_ = writeStateJSON(siteMetaPath(v.Domain), meta)
				cf = R{"requested": true, "ok": true, "zone": zoneName, "zone_status": zoneStatus, "name_servers": ns, "tunnel_id": tunnelID, "hostname": v.Domain}
			}
		}
		if e != nil {
			cf = R{"requested": true, "ok": false, "error": e.Error()}
		}
	}
	out(w, 201, R{"ok": true, "domain": v.Domain, "root": root, "cloudflare": cf})
}
func nginxSite(d, root, logs, socket string) string {
	return fmt.Sprintf("server {\n listen %s;\n server_name %s;\n root %s;\n index index.php index.html;\n access_log %s/access.log;\n error_log %s/error.log;\n client_max_body_size 128m;\n location / { try_files $uri $uri/ /index.php?$query_string; }\n location ~ \\.php$ { try_files $uri =404; include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:%s; }\n location ~ /\\. { deny all; }\n}\n", envOr("XSHOTER_WEB_LISTEN", "80"), d, root, logs, logs, socket)
}
func deleteWebsite(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(r.URL.Query().Get("domain"))
	if !domainRE.MatchString(d) {
		fail(w, 400, "invalid domain")
		return
	}
	m := siteMeta(d)
	vhost := "/etc/nginx/xshoter/sites-enabled/" + d + ".conf"
	pool := ""
	ver := ""
	if m != nil {
		if x := fmt.Sprint(m["vhost"]); strings.HasPrefix(x, "/etc/nginx/xshoter/") {
			vhost = x
		}
		if x := fmt.Sprint(m["php_pool"]); strings.HasPrefix(x, "/etc/php/") && strings.Contains(x, "/pool.d/xshoter-") {
			pool = x
		}
		if x := fmt.Sprint(m["php"]); phpRE.MatchString(x) {
			ver = x
		}
	}
	_ = os.Remove(vhost)
	if pool != "" {
		_ = os.Remove(pool)
	}
	if ver != "" {
		_, _ = cmd("systemctl", "reload", "php"+ver+"-fpm")
	}
	if _, e := cmd("nginx", "-t"); e != nil {
		fail(w, 500, e.Error())
		return
	}
	_, _ = cmd("systemctl", "reload", "nginx")
	_ = os.Remove(siteMetaPath(d))
	if r.URL.Query().Get("purge") == "1" {
		p, _ := filepath.Glob("/home/*/web/" + d)
		for _, x := range p {
			if strings.HasPrefix(x, "/home/") {
				_ = os.RemoveAll(x)
			}
		}
	}
	out(w, 200, R{"ok": true})
}
func databases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		listDB(w)
	case "POST":
		createDB(w, r)
	case "DELETE":
		deleteDB(w, r)
	default:
		fail(w, 405, "method not allowed")
	}
}
func pmaReady() bool {
	if _, err := os.Stat("/usr/share/phpmyadmin/xshoter-sso.php"); err != nil {
		return false
	}
	_, err := user.Lookup("xshoterpma")
	return err == nil
}

func listDB(w http.ResponseWriter) {
	q := "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys','phpmyadmin') ORDER BY SCHEMA_NAME"
	s, e := cmd("mariadb", "-NBe", q)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	a := []R{}
	for _, n := range strings.Fields(s) {
		sec := dbSecret(n)
		u := ""
		if sec != nil {
			u = fmt.Sprint(sec["user"])
		}
		st, _ := cmd("mariadb", "-NBe", fmt.Sprintf("SELECT COUNT(*),COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='%s'", n))
		f := strings.Fields(st)
		tables, size := 0, int64(0)
		if len(f) >= 2 {
			tables, _ = strconv.Atoi(f[0])
			size, _ = strconv.ParseInt(f[1], 10, 64)
		}
		a = append(a, R{"name": n, "managed": sec != nil, "user": u, "tables": tables, "size": size, "sso": sec != nil && pmaReady()})
	}
	out(w, 200, R{"ok": true, "items": a})
}
func createDB(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Name string `json:"name"`
		User string `json:"user"`
	}
	if body(r, &v) != nil || !nameRE.MatchString(v.Name) || !nameRE.MatchString(v.User) {
		fail(w, 400, "invalid database/user")
		return
	}
	p := hexRand(18)
	sql := fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'; GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';", v.Name, v.User, p, v.Name, v.User)
	if pmaReady() {
		sql += fmt.Sprintf(" GRANT ALL PRIVILEGES ON `%s`.* TO 'xshoterpma'@'localhost';", v.Name)
	}
	sql += " FLUSH PRIVILEGES;"
	if _, e := cmd("mariadb", "-e", sql); e != nil {
		fail(w, 500, e.Error())
		return
	}
	sec := R{"database": v.Name, "user": v.User, "password": p}
	b, _ := json.Marshal(sec)
	_ = os.WriteFile(state+"/secrets/db/"+v.Name+".json", b, 0600)
	out(w, 201, R{"ok": true, "name": v.Name, "user": v.User, "password": p})
}
func deleteDB(w http.ResponseWriter, r *http.Request) {
	n := r.URL.Query().Get("name")
	if !nameRE.MatchString(n) {
		fail(w, 400, "invalid database")
		return
	}
	sec := dbSecret(n)
	sql := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", n)
	if sec != nil {
		u := fmt.Sprint(sec["user"])
		if nameRE.MatchString(u) {
			sql += fmt.Sprintf(" DROP USER IF EXISTS '%s'@'localhost';", u)
		}
	}
	sql += " FLUSH PRIVILEGES;"
	if _, e := cmd("mariadb", "-e", sql); e != nil {
		fail(w, 500, e.Error())
		return
	}
	_ = os.Remove(state + "/secrets/db/" + n + ".json")
	out(w, 200, R{"ok": true})
}
func dbSecret(n string) map[string]any {
	b, e := os.ReadFile(state + "/secrets/db/" + n + ".json")
	if e != nil {
		return nil
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	return v
}
func pmaToken(w http.ResponseWriter, r *http.Request) {
	if !pmaReady() {
		fail(w, 503, "phpMyAdmin integration is not configured")
		return
	}
	var v struct {
		Name string `json:"name"`
	}
	if body(r, &v) != nil || !nameRE.MatchString(v.Name) {
		fail(w, 400, "invalid database")
		return
	}
	if dbSecret(v.Name) == nil {
		fail(w, 404, "database not managed")
		return
	}
	q := fmt.Sprintf("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='%s'", v.Name)
	x, e := cmd("mariadb", "-NBe", q)
	if e != nil || strings.TrimSpace(x) != "1" {
		fail(w, 404, "database not found")
		return
	}
	t := hexRand(32)
	dir := "/run/xshoter-control/pma-tokens"
	_ = os.MkdirAll(dir, 0770)
	g, _ := user.LookupGroup("www-data")
	gid, _ := strconv.Atoi(g.Gid)
	_ = os.Chown(dir, 0, gid)
	b, _ := json.Marshal(R{"database": v.Name, "expires": time.Now().Add(60 * time.Second).Unix()})
	p := dir + "/" + t + ".json"
	_ = os.WriteFile(p, b, 0640)
	_ = os.Chown(p, 0, gid)
	_ = os.Chmod(p, 0640)
	out(w, 200, R{"ok": true, "token": t})
}
func firewall(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s, _ := cmd("iptables", "-S", "INPUT")
		items := []R{}
		files, _ := filepath.Glob(state + "/firewall/*.json")
		for _, p := range files {
			b, e := os.ReadFile(p)
			if e != nil {
				continue
			}
			var v map[string]any
			if json.Unmarshal(b, &v) != nil {
				continue
			}
			items = append(items, R{"id": v["id"], "protocol": v["protocol"], "port": v["port"], "source": v["source"], "action": v["action"]})
		}
		out(w, 200, R{"ok": true, "raw": strings.Split(strings.TrimSpace(s), "\n"), "items": items})
	case "POST":
		addFW(w, r)
	case "DELETE":
		delFW(w, r)
	default:
		fail(w, 405, "method not allowed")
	}
}
func syncFirewallSnapshot() {
	p := "/etc/xshoter-control/firewall/iptables.rules"
	b, e := os.ReadFile(p)
	if e != nil {
		return
	}
	lines := []string{}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "--comment xshoter:") || strings.Contains(l, "--comment \"xshoter:") {
			continue
		}
		if strings.TrimSpace(l) == "COMMIT" {
			files, _ := filepath.Glob(state + "/firewall/*.json")
			for _, f := range files {
				bb, ee := os.ReadFile(f)
				if ee != nil {
					continue
				}
				var v struct {
					ID, Protocol, Source, Action string
					Port                         int
				}
				if json.Unmarshal(bb, &v) != nil || v.ID == "" {
					continue
				}
				lines = append(lines, fmt.Sprintf("-A INPUT -p %s --dport %d -s %s -m comment --comment xshoter:%s -j %s", v.Protocol, v.Port, v.Source, v.ID, v.Action))
			}
		}
		lines = append(lines, l)
	}
	_ = os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0640)
}
func addFW(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Source   string `json:"source"`
		Action   string `json:"action"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	if (v.Protocol != "tcp" && v.Protocol != "udp") || v.Port < 1 || v.Port > 65535 || (v.Action != "ACCEPT" && v.Action != "DROP") {
		fail(w, 400, "invalid rule")
		return
	}
	if v.Source == "" {
		v.Source = "0.0.0.0/0"
	}
	if !regexp.MustCompile(`^(?:[0-9a-fA-F:.]+)(?:/[0-9]{1,3})?$`).MatchString(v.Source) {
		fail(w, 400, "invalid source")
		return
	}
	id := hexRand(8)
	a := []string{"-I", "INPUT", "1", "-p", v.Protocol, "--dport", strconv.Itoa(v.Port), "-s", v.Source, "-m", "comment", "--comment", "xshoter:" + id, "-j", v.Action}
	if _, e := cmd("iptables", a...); e != nil {
		fail(w, 500, e.Error())
		return
	}
	_ = os.MkdirAll(state+"/firewall", 0700)
	bb, _ := json.Marshal(R{"id": id, "protocol": v.Protocol, "port": v.Port, "source": v.Source, "action": v.Action})
	_ = os.WriteFile(state+"/firewall/"+id+".json", bb, 0600)
	syncFirewallSnapshot()
	out(w, 201, R{"ok": true, "id": id})
}
func delFW(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(id) {
		fail(w, 400, "invalid id")
		return
	}
	b, e := os.ReadFile(state + "/firewall/" + id + ".json")
	if e != nil {
		fail(w, 404, "rule not found")
		return
	}
	var v struct {
		ID, Protocol, Source, Action string
		Port                         int
	}
	if json.Unmarshal(b, &v) != nil {
		fail(w, 500, "invalid stored rule")
		return
	}
	a := []string{"-D", "INPUT", "-p", v.Protocol, "--dport", strconv.Itoa(v.Port), "-s", v.Source, "-m", "comment", "--comment", "xshoter:" + id, "-j", v.Action}
	_, _ = cmd("iptables", a...)
	_ = os.Remove(state + "/firewall/" + id + ".json")
	syncFirewallSnapshot()
	out(w, 200, R{"ok": true})
}
func cron(w http.ResponseWriter, r *http.Request) {
	idRE := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	parse := func(p string) R {
		b, _ := os.ReadFile(p)
		id := strings.TrimPrefix(filepath.Base(p), "xshoter-")
		schedule, usr, command := "", "", ""
		for _, l := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || (!strings.Contains(t, " ") && strings.Contains(t, "=")) {
				continue
			}
			f := strings.Fields(t)
			if len(f) >= 7 {
				schedule = strings.Join(f[:5], " ")
				usr = f[5]
				command = strings.Join(f[6:], " ")
				break
			}
		}
		return R{"id": id, "schedule": schedule, "user": usr, "command": command, "content": strings.TrimSpace(string(b))}
	}
	if r.Method == "GET" {
		f, _ := filepath.Glob("/etc/cron.d/xshoter-*")
		a := []R{}
		for _, p := range f {
			a = append(a, parse(p))
		}
		out(w, 200, R{"ok": true, "items": a})
		return
	}
	if r.Method == "POST" || r.Method == "PATCH" {
		var v struct {
			Schedule string `json:"schedule"`
			User     string `json:"user"`
			Command  string `json:"command"`
		}
		if body(r, &v) != nil || !cronRE.MatchString(v.Schedule) || (!userRE.MatchString(v.User) && v.User != "root") || len(v.Command) < 1 || len(v.Command) > 500 || strings.Contains(v.Command, "\n") {
			fail(w, 400, "invalid cron")
			return
		}
		id := hexRand(8)
		if r.Method == "PATCH" {
			id = r.URL.Query().Get("id")
			if !idRE.MatchString(id) || !exists("/etc/cron.d/xshoter-"+id) {
				fail(w, 404, "cron not found")
				return
			}
		}
		path := "/etc/cron.d/xshoter-" + id
		env := []string{"SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
		if b, e := os.ReadFile(path); e == nil {
			for _, l := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(l)
				if strings.HasPrefix(t, "MAILTO=") || strings.HasPrefix(t, "CONTENT_TYPE=") {
					env = append(env, t)
				}
			}
		}
		c := strings.Join(env, "\n") + "\n" + fmt.Sprintf("%s %s %s\n", v.Schedule, v.User, v.Command)
		if e := os.WriteFile(path, []byte(c), 0644); e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, map[bool]int{true: 200, false: 201}[r.Method == "PATCH"], R{"ok": true, "id": id})
		return
	}
	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if !idRE.MatchString(id) {
			fail(w, 400, "invalid id")
			return
		}
		p := "/etc/cron.d/xshoter-" + id
		if !exists(p) {
			fail(w, 404, "cron not found")
			return
		}
		_ = os.Remove(p)
		out(w, 200, R{"ok": true})
		return
	}
	fail(w, 405, "method not allowed")
}
func backups(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		root := filepath.Join(state, "backups")
		a := []R{}
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			rel, e := filepath.Rel(root, p)
			if e != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			parts := strings.Split(rel, "/")
			if len(parts) > 2 || strings.Contains(rel, "..") {
				return nil
			}
			scope := "manual"
			if len(parts) == 2 {
				scope = parts[0]
			}
			base := filepath.Base(p)
			typ, target, restore := "archive", "", false
			if m := regexp.MustCompile(`^db-([A-Za-z0-9_]+)-[0-9]{8}-[0-9]{6}\.sql(?:\.gz)?$`).FindStringSubmatch(base); len(m) == 2 {
				typ, target, restore = "database", m[1], true
			} else if m := regexp.MustCompile(`^web-([a-z0-9.-]+)-[0-9]{8}-[0-9]{6}\.tar\.gz$`).FindStringSubmatch(base); len(m) == 2 && domainRE.MatchString(m[1]) {
				typ, target, restore = "website", m[1], true
			} else if strings.HasPrefix(base, "control-") && strings.HasSuffix(base, ".tar.gz") {
				typ = "system"
			}
			a = append(a, R{"name": rel, "file": base, "scope": scope, "type": typ, "target": target, "restorable": restore, "size": info.Size(), "time": info.ModTime()})
			return nil
		})
		out(w, 200, R{"ok": true, "items": a})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var v struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	ts := time.Now().Format("20060102-150405")
	if v.Type == "database" {
		if !nameRE.MatchString(v.Name) {
			fail(w, 400, "invalid database")
			return
		}
		p := fmt.Sprintf("%s/backups/db-%s-%s.sql", state, v.Name, ts)
		f, e := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		c := exec.Command("mysqldump", v.Name)
		c.Stdout = f
		e = c.Run()
		_ = f.Close()
		if e != nil {
			_ = os.Remove(p)
			fail(w, 500, e.Error())
			return
		}
		out(w, 201, R{"ok": true, "file": filepath.Base(p)})
		return
	}
	if v.Type == "website" {
		if !domainRE.MatchString(v.Name) {
			fail(w, 400, "invalid domain")
			return
		}
		m, _ := filepath.Glob("/home/*/web/" + v.Name)
		if len(m) == 0 {
			fail(w, 404, "website not found")
			return
		}
		p := fmt.Sprintf("%s/backups/web-%s-%s.tar.gz", state, v.Name, ts)
		if _, e := cmd("tar", "-czf", p, "-C", filepath.Dir(m[0]), filepath.Base(m[0])); e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 201, R{"ok": true, "file": filepath.Base(p)})
		return
	}
	fail(w, 400, "invalid backup type")
}
func logs(w http.ResponseWriter, r *http.Request) {
	n := r.URL.Query().Get("name")
	if !servicesOK[n] && n != "xshoter-agent" {
		fail(w, 400, "log not allowed")
		return
	}
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines < 10 || lines > 500 {
		lines = 100
	}
	s, e := cmd("journalctl", "-u", n, "-n", strconv.Itoa(lines), "--no-pager", "--output=short-iso")
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	out(w, 200, R{"ok": true, "text": s})
}
func safePath(p string) (string, error) {
	return secureWebPath(p, false)
}
func filesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		p, e := safePath(r.URL.Query().Get("path"))
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		s, e := os.Stat(p)
		if e != nil {
			fail(w, 404, "not found")
			return
		}
		if s.IsDir() {
			d, _ := os.ReadDir(p)
			a := []R{}
			for _, x := range d {
				i, _ := x.Info()
				sz := int64(0)
				if i != nil {
					sz = i.Size()
				}
				a = append(a, R{"name": x.Name(), "dir": x.IsDir(), "size": sz})
			}
			out(w, 200, R{"ok": true, "path": p, "items": a})
			return
		}
		if s.Size() > 2<<20 {
			fail(w, 413, "file too large")
			return
		}
		b, _ := os.ReadFile(p)
		out(w, 200, R{"ok": true, "path": p, "content": string(b)})
		return
	}
	if r.Method == "POST" {
		var v struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		p, e := safePath(v.Path)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		if len(v.Content) > 2<<20 {
			fail(w, 413, "file too large")
			return
		}
		if e = os.WriteFile(p, []byte(v.Content), 0644); e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 200, R{"ok": true})
		return
	}
	fail(w, 405, "method not allowed")
}
func sshKeys(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("user")
	if !userRE.MatchString(u) && u != "root" {
		fail(w, 400, "invalid user")
		return
	}
	home := "/home/" + u
	if u == "root" {
		home = "/root"
	}
	p := home + "/.ssh/authorized_keys"
	if r.Method == "GET" {
		b, _ := os.ReadFile(p)
		a := []R{}
		for i, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			h := sha256.Sum256([]byte(l))
			a = append(a, R{"index": i, "fingerprint": hex.EncodeToString(h[:8]), "key": l})
		}
		out(w, 200, R{"ok": true, "items": a})
		return
	}
	if r.Method == "POST" {
		var v struct {
			Key string `json:"key"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		k := strings.TrimSpace(v.Key)
		if !(strings.HasPrefix(k, "ssh-ed25519 ") || strings.HasPrefix(k, "ssh-rsa ") || strings.HasPrefix(k, "ecdsa-sha2-")) || strings.Contains(k, "\n") {
			fail(w, 400, "invalid ssh key")
			return
		}
		_ = os.MkdirAll(filepath.Dir(p), 0700)
		f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		_, _ = f.WriteString(k + "\n")
		_ = f.Close()
		if u != "root" {
			_, _ = cmd("chown", "-R", u+":"+u, filepath.Dir(p))
		}
		out(w, 201, R{"ok": true})
		return
	}
	if r.Method == "DELETE" {
		idx, e := strconv.Atoi(r.URL.Query().Get("index"))
		if e != nil {
			fail(w, 400, "invalid index")
			return
		}
		b, _ := os.ReadFile(p)
		l := strings.Split(strings.TrimSpace(string(b)), "\n")
		if idx < 0 || idx >= len(l) {
			fail(w, 404, "key not found")
			return
		}
		l = append(l[:idx], l[idx+1:]...)
		_ = os.WriteFile(p, []byte(strings.Join(l, "\n")+"\n"), 0600)
		out(w, 200, R{"ok": true})
		return
	}
	fail(w, 405, "method not allowed")
}
func serverUsers(w http.ResponseWriter, r *http.Request) {
	wanted := map[string]bool{"root": true, "xshoter": true, "admin": true}
	b, e := os.ReadFile("/etc/passwd")
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	items := []R{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || !wanted[f[0]] {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		home := f[5]
		shell := f[6]
		webs, _ := filepath.Glob("/home/" + f[0] + "/web/*/public_html")
		keys := 0
		if kb, ee := os.ReadFile(home + "/.ssh/authorized_keys"); ee == nil {
			for _, x := range strings.Split(string(kb), "\n") {
				if strings.TrimSpace(x) != "" && !strings.HasPrefix(strings.TrimSpace(x), "#") {
					keys++
				}
			}
		}
		jail := exists("/etc/systemd/system/srv-jail-" + f[0] + "-home-" + f[0] + ".mount")
		items = append(items, R{"username": f[0], "uid": uid, "gid": gid, "home": home, "shell": shell, "websites": len(webs), "ssh_keys": keys, "sftp_jail": jail})
	}
	out(w, 200, R{"ok": true, "items": items})
}

func sslIssue(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Domain string `json:"domain"`
		Email  string `json:"email"`
	}
	if body(r, &v) != nil || !domainRE.MatchString(v.Domain) {
		fail(w, 400, "invalid domain")
		return
	}
	if m := siteMeta(v.Domain); m != nil && fmt.Sprint(m["tls_mode"]) == "cloudflare" {
		out(w, 200, R{"ok": true, "mode": "cloudflare", "output": "TLS is managed by Cloudflare edge"})
		return
	}
	roots, _ := filepath.Glob("/home/*/web/" + v.Domain + "/public_html")
	if len(roots) == 0 {
		fail(w, 404, "website not found")
		return
	}
	a := []string{"certonly", "--webroot", "-w", roots[0], "-d", v.Domain, "--non-interactive", "--agree-tos"}
	if strings.Contains(v.Email, "@") {
		a = append(a, "--email", v.Email)
	} else {
		a = append(a, "--register-unsafely-without-email")
	}
	s, e := cmd("certbot", a...)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	out(w, 200, R{"ok": true, "mode": "local", "output": s})
}
