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
	"sort"
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
var phpRE = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
var cronRE = regexp.MustCompile(`^[0-9*/?,\-]+\s+[0-9*/?,\-]+\s+[0-9*/?,\-]+\s+[0-9*/?,\-]+\s+[0-9*/?,\-]+$`)
var serviceList = []string{"nginx", "mariadb", "cloudflared", "ssh", "fail2ban", "xshoter-control", "xshoter-agent", "xshoter-firewall"}
var servicesOK = map[string]bool{
	"nginx": true, "mariadb": true, "cloudflared": true, "ssh": true,
	"fail2ban": true, "xshoter-control": true, "xshoter-agent": true, "xshoter-firewall": true,
}
var servicesReload = map[string]bool{"nginx": true, "mariadb": true, "ssh": true, "fail2ban": true}

func discoveredServices() []string {
	a := append([]string{}, serviceList...)
	seen := map[string]bool{}
	for _, n := range a {
		seen[n] = true
	}
	rows, _ := filepath.Glob("/etc/php/*/fpm")
	for _, x := range rows {
		v := filepath.Base(filepath.Dir(x))
		if !phpRE.MatchString(v) {
			continue
		}
		n := "php" + v + "-fpm"
		if !seen[n] {
			seen[n] = true
			a = append(a, n)
		}
	}
	sort.Strings(a)
	return a
}
func serviceAllowed(n string) bool {
	if servicesOK[n] {
		return true
	}
	m := regexp.MustCompile(`^php([0-9]+\.[0-9]+)-fpm$`).FindStringSubmatch(n)
	if len(m) != 2 {
		return false
	}
	_, e := os.Stat(filepath.Join("/etc/php", m[1], "fpm"))
	return e == nil
}
func serviceCanReload(n string) bool {
	return servicesReload[n] || (strings.HasPrefix(n, "php") && strings.HasSuffix(n, "-fpm") && serviceAllowed(n))
}

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
	m.HandleFunc("/v1/hosting-provision", only("POST", hostingProvision))
	m.HandleFunc("/v1/hosting-usage", only("GET", hostingUsage))
	m.HandleFunc("/v1/hosting-sftp", hostingSFTP)
	m.HandleFunc("/v1/hosting-backups", hostingBackups)
	m.HandleFunc("/v1/hosting-cron", hostingCron)
	m.HandleFunc("/v1/hosting-installer", hostingInstaller)
	m.HandleFunc("/v1/hosting-control", only("POST", hostingControl))
	m.HandleFunc("/v1/hosting-quota-status", only("GET", hostingQuotaStatus))
	m.HandleFunc("/v1/hosting-bandwidth", hostingBandwidth)
	m.HandleFunc("/v1/hosting-resources", hostingResources)
	m.HandleFunc("/v1/runtimes", only("GET", runtimeInventory))
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
	out(w, 200, R{"ok": true, "service": "xshoter-agent", "version": "1.0.2"})
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
		for _, n := range discoveredServices() {
			s, _ := cmd("systemctl", "is-active", n)
			en, _ := cmd("systemctl", "is-enabled", n)
			a = append(a, R{"name": n, "active": strings.TrimSpace(s) == "active", "enabled": strings.TrimSpace(en) == "enabled", "can_reload": serviceCanReload(n)})
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
	if !serviceAllowed(v.Name) || !map[string]bool{"start": true, "stop": true, "restart": true, "reload": true}[v.Action] || (v.Action == "reload" && !serviceCanReload(v.Name)) {
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
		Owner        string `json:"owner"`
		Domain       string `json:"domain"`
		PHP          string `json:"php"`
		Cloudflare   bool   `json:"cloudflare"`
		TunnelID     string `json:"tunnel_id"`
		WebListen    string `json:"web_listen"`
		TunnelOrigin string `json:"tunnel_origin"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	v.Domain = strings.ToLower(v.Domain)
	v.WebListen = strings.TrimSpace(v.WebListen)
	if v.WebListen == "" {
		v.WebListen = envOr("XSHOTER_WEB_LISTEN", "80")
	}
	v.TunnelOrigin = strings.TrimSpace(v.TunnelOrigin)
	if v.TunnelOrigin == "" {
		v.TunnelOrigin = envOr("XSHOTER_TUNNEL_ORIGIN", "http://127.0.0.1:80")
	}
	listenOK := regexp.MustCompile(`^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}:)?[0-9]{1,5}$`).MatchString(v.WebListen)
	if !userRE.MatchString(v.Owner) || !domainRE.MatchString(v.Domain) || !phpRE.MatchString(v.PHP) || !exists("/etc/php/"+v.PHP+"/fpm") || !listenOK || !cfServiceOK(v.TunnelOrigin) {
		fail(w, 400, "invalid owner/domain/php/listener/origin")
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
	children, memPer := resourcePHPValues(v.Owner)
	pool := fmt.Sprintf("[xshoter-%s]\nuser=%s\ngroup=%s\nlisten=%s\nlisten.owner=www-data\nlisten.group=www-data\nlisten.mode=0660\npm=ondemand\npm.max_children=%d\npm.process_idle_timeout=15s\npm.max_requests=500\nphp_admin_value[memory_limit]=%dM\nphp_admin_value[open_basedir]=%s:/tmp\n", safe, v.Owner, v.Owner, socket, children, memPer, base)
	pp := fmt.Sprintf("/etc/php/%s/fpm/pool.d/xshoter-%s.conf", v.PHP, safe)
	if e := os.WriteFile(pp, []byte(pool), 0644); e != nil {
		fail(w, 500, e.Error())
		return
	}
	np := "/etc/nginx/xshoter/sites-enabled/" + v.Domain + ".conf"
	if e := os.WriteFile(np, []byte(nginxSite(v.Domain, root, logs, socket, v.WebListen, v.Owner)), 0644); e != nil {
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
				e = cfUpsertTunnelRoute(cfg, tunnelID, v.Domain, "", v.TunnelOrigin, false)
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
func nginxSite(d, root, logs, socket, listen, owner string) string {
	gate := ""
	if hostingUserName(owner) && exists(hostingStatePath(owner)) {
		_ = ensureHostingBandwidthGate(owner)
		gate = " include " + hostingBandwidthGatePath(owner) + ";\n"
	}
	return fmt.Sprintf("server {\n listen %s;\n server_name %s;\n%s root %s;\n index index.php index.html;\n access_log %s/access.log;\n error_log %s/error.log;\n client_max_body_size 128m;\n location / { try_files $uri $uri/ /index.php?$query_string; }\n location ~ \\.php$ { try_files $uri =404; include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:%s; }\n location ~ /\\. { deny all; }\n}\n", listen, d, gate, root, logs, logs, socket)
}
func deleteWebsite(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(r.URL.Query().Get("domain"))
	if !domainRE.MatchString(d) {
		fail(w, 400, "invalid domain")
		return
	}
	m := siteMeta(d)
	cfwarn := ""
	if m != nil {
		tid := strings.ToLower(strings.TrimSpace(fmt.Sprint(m["cloudflare_tunnel_id"])))
		if cfID(tid) {
			if e := cfDeleteTunnelRoute(effectiveCloudflareConfig(), tid, d, true); e != nil {
				cfwarn = e.Error()
			}
		}
	}
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
	if m != nil {
		if unit := fmt.Sprint(m["service"]); strings.HasPrefix(unit, "xshoter-app-") && strings.HasSuffix(unit, ".service") {
			_, _ = cmd("systemctl", "disable", "--now", unit)
			_ = os.Remove(filepath.Join("/etc/systemd/system", unit))
			_, _ = cmd("systemctl", "daemon-reload")
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
		if m != nil {
			if owner := fmt.Sprint(m["owner"]); hostingUserName(owner) {
				_ = os.RemoveAll(filepath.Join("/home", owner, "apps", d))
			}
		}
	}
	out(w, 200, R{"ok": true, "cloudflare_warning": cfwarn})
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
		if u := webPathOwner(p); u != "" {
			_, _ = cmd("chown", u+":"+u, p)
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
func hostingUserName(v string) bool {
	return regexp.MustCompile(`^[a-z_][a-z0-9_-]{2,30}$`).MatchString(v)
}

func runtimeInventory(w http.ResponseWriter, r *http.Request) {
	php := []string{}
	if rows, _ := filepath.Glob("/etc/php/*/fpm"); len(rows) > 0 {
		seen := map[string]bool{}
		for _, x := range rows {
			v := filepath.Base(filepath.Dir(x))
			if phpRE.MatchString(v) && !seen[v] {
				seen[v] = true
				php = append(php, v)
			}
		}
	}
	get := func(n string, a ...string) string {
		x, e := cmd(n, a...)
		if e != nil {
			return ""
		}
		return strings.TrimSpace(x)
	}
	out(w, 200, R{"ok": true, "php": php, "node": get("node", "--version"), "npm": get("npm", "--version"), "python": get("python3", "--version"), "composer": get("composer", "--version")})
}

func hostingQuotaEnabled() (bool, string) {
	b, e := os.ReadFile("/proc/mounts")
	if e != nil {
		return false, "unknown"
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[1] != "/" {
			continue
		}
		for _, o := range strings.Split(f[3], ",") {
			if o == "usrquota" || o == "quota" {
				return true, "filesystem"
			}
		}
		return false, "soft"
	}
	return false, "unknown"
}
func hostingStatePath(u string) string { return state + "/hosting/users/" + u + ".json" }
func hostingState(u string) map[string]any {
	b, e := os.ReadFile(hostingStatePath(u))
	if e != nil {
		return map[string]any{}
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return map[string]any{}
	}
	return v
}
func applyHostingQuota(u string, diskMB int64) (bool, error) {
	hard, _ := hostingQuotaEnabled()
	if !hard {
		return false, nil
	}
	blocks := diskMB * 1024
	if _, e := cmd("setquota", "-u", u, strconv.FormatInt(blocks, 10), strconv.FormatInt(blocks, 10), "0", "0", "/"); e != nil {
		return true, e
	}
	return true, nil
}
func hostingQuotaStatus(w http.ResponseWriter, r *http.Request) {
	hard, mode := hostingQuotaEnabled()
	out(w, 200, R{"ok": true, "hard_quota": hard, "mode": mode, "filesystem": "/", "message": map[bool]string{true: "OS filesystem quota enabled", false: "Soft quota enforcement active; enable usrquota during a maintenance window for OS-level hard limits"}[hard]})
}
func hostingUsage(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimSpace(r.URL.Query().Get("user"))
	if !hostingUserName(u) {
		fail(w, 400, "invalid hosting user")
		return
	}
	home := "/home/" + u
	if _, e := user.Lookup(u); e != nil {
		fail(w, 404, "hosting user not provisioned")
		return
	}
	used := int64(0)
	if b, e := cmd("du", "-sb", home); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			used, _ = strconv.ParseInt(f[0], 10, 64)
		}
	}
	st := hostingState(u)
	limit := int64(0)
	if x, ok := st["disk_limit_bytes"].(float64); ok {
		limit = int64(x)
	}
	hard, mode := hostingQuotaEnabled()
	over := limit > 0 && used > limit
	out(w, 200, R{"ok": true, "user": u, "home": home, "used_bytes": used, "disk_limit_bytes": limit, "over_quota": over, "hard_quota": hard, "quota_mode": mode, "status": fmt.Sprint(st["status"])})
}
func hostingProvision(w http.ResponseWriter, r *http.Request) {
	var v struct {
		User        string `json:"user"`
		DiskMB      int64  `json:"disk_mb"`
		SFTPEnabled bool   `json:"sftp_enabled"`
		Status      string `json:"status"`
		CPUPercent  int64  `json:"cpu_percent"`
		MemoryMB    int64  `json:"memory_mb"`
		Processes   int64  `json:"processes"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	v.User = strings.ToLower(strings.TrimSpace(v.User))
	v.Status = strings.ToLower(strings.TrimSpace(v.Status))
	if v.Status == "" {
		v.Status = "active"
	}
	if v.CPUPercent == 0 {
		v.CPUPercent = 100
	}
	if v.MemoryMB == 0 {
		v.MemoryMB = 512
	}
	if v.Processes == 0 {
		v.Processes = 64
	}
	if !hostingUserName(v.User) || v.DiskMB < 50 || v.DiskMB > 1048576 || !validHostingResources(v.CPUPercent, v.MemoryMB, v.Processes) || (v.Status != "active" && v.Status != "suspended") {
		fail(w, 400, "invalid hosting provision request")
		return
	}
	if _, e := user.LookupGroup("xshoter-hosting"); e != nil {
		if _, e = cmd("groupadd", "--system", "xshoter-hosting"); e != nil {
			fail(w, 500, "cannot create hosting group: "+e.Error())
			return
		}
	}
	if _, e := user.Lookup(v.User); e != nil {
		if _, e = cmd("useradd", "-m", "-U", "-s", "/usr/sbin/nologin", v.User); e != nil {
			fail(w, 500, "cannot create hosting user: "+e.Error())
			return
		}
	}
	if v.SFTPEnabled {
		_, _ = cmd("usermod", "-a", "-G", "xshoter-hosting", v.User)
	} else {
		_, _ = cmd("gpasswd", "-d", v.User, "xshoter-hosting")
	}
	home := "/home/" + v.User
	for _, d := range []string{home, home + "/web", home + "/backups", home + "/apps", home + "/tmp", home + "/logs"} {
		if e := os.MkdirAll(d, 0750); e != nil {
			fail(w, 500, e.Error())
			return
		}
	}
	_, _ = cmd("chown", "-R", v.User+":"+v.User, home)
	_, _ = cmd("chown", "root:root", home)
	_ = os.Chmod(home, 0755)
	_ = os.Chmod(home+"/web", 0711)
	for _, d := range []string{home + "/backups", home + "/apps", home + "/tmp", home + "/logs"} {
		_ = os.Chmod(d, 0750)
	}
	if e := ensureHostingBandwidthGate(v.User); e != nil {
		fail(w, 500, "cannot prepare bandwidth gate: "+e.Error())
		return
	}
	hard, e := applyHostingQuota(v.User, v.DiskMB)
	if e != nil {
		fail(w, 500, "cannot apply filesystem quota: "+e.Error())
		return
	}
	if v.Status == "suspended" {
		_ = os.Chmod(home, 0700)
		_, _ = cmd("chage", "-E", "1", v.User)
		_, _ = cmd("pkill", "-KILL", "-u", v.User)
	} else {
		_ = os.Chmod(home, 0755)
		_, _ = cmd("chage", "-E", "-1", v.User)
	}
	st := R{"user": v.User, "disk_limit_bytes": v.DiskMB * 1024 * 1024, "status": v.Status, "cpu_percent": v.CPUPercent, "memory_mb": v.MemoryMB, "processes": v.Processes, "updated_at": time.Now().Unix()}
	_ = writeStateJSON(hostingStatePath(v.User), st)
	resources, e := applyHostingResourceLimits(v.User, v.CPUPercent, v.MemoryMB, v.Processes)
	if e != nil {
		fail(w, 500, "cannot apply hosting resource limits: "+e.Error())
		return
	}
	uu, _ := user.Lookup(v.User)
	uid, gid := "", ""
	if uu != nil {
		uid, gid = uu.Uid, uu.Gid
	}
	used := int64(0)
	if b, e := cmd("du", "-sb", home); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			used, _ = strconv.ParseInt(f[0], 10, 64)
		}
	}
	out(w, 200, R{"ok": true, "user": v.User, "uid": uid, "gid": gid, "home": home, "used_bytes": used, "disk_limit_bytes": v.DiskMB * 1024 * 1024, "hard_quota": hard, "quota_mode": map[bool]string{true: "filesystem", false: "soft"}[hard], "isolation": "dedicated-linux-user", "status": v.Status, "resources": resources})
}
func hostingControl(w http.ResponseWriter, r *http.Request) {
	var v struct {
		User   string `json:"user"`
		Status string `json:"status"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	v.User = strings.ToLower(strings.TrimSpace(v.User))
	v.Status = strings.ToLower(strings.TrimSpace(v.Status))
	if !hostingUserName(v.User) || (v.Status != "active" && v.Status != "suspended") {
		fail(w, 400, "invalid hosting control request")
		return
	}
	if _, e := user.Lookup(v.User); e != nil {
		fail(w, 404, "hosting user not provisioned")
		return
	}
	home := "/home/" + v.User
	st := hostingState(v.User)
	st["user"] = v.User
	st["status"] = v.Status
	st["updated_at"] = time.Now().Unix()
	_ = writeStateJSON(hostingStatePath(v.User), st)
	if v.Status == "suspended" {
		_ = os.Chmod(home, 0700)
		_, _ = cmd("chage", "-E", "1", v.User)
		_, _ = cmd("pkill", "-KILL", "-u", v.User)
	} else {
		_ = os.Chmod(home, 0755)
		_, _ = cmd("chage", "-E", "-1", v.User)
	}
	out(w, 200, R{"ok": true, "user": v.User, "status": v.Status})
}

func ensureHostingSFTPConfig() error {
	p := "/etc/ssh/sshd_config.d/90-xshoter-hosting.conf"
	want := "# Managed by Xshoter Control\nMatch Group xshoter-hosting\n    ChrootDirectory %h\n    ForceCommand internal-sftp -d /\n    PasswordAuthentication yes\n    PubkeyAuthentication yes\n    X11Forwarding no\n    AllowTcpForwarding no\n    PermitTTY no\nMatch all\n"
	if b, e := os.ReadFile(p); e == nil && string(b) == want {
		return nil
	}
	old, _ := os.ReadFile(p)
	if e := os.WriteFile(p, []byte(want), 0644); e != nil {
		return e
	}
	if _, e := cmd("sshd", "-t"); e != nil {
		if len(old) > 0 {
			_ = os.WriteFile(p, old, 0644)
		} else {
			_ = os.Remove(p)
		}
		return e
	}
	if _, e := cmd("systemctl", "reload", "ssh"); e != nil {
		return e
	}
	return nil
}

func hostingSFTP(w http.ResponseWriter, r *http.Request) {
	u := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	if r.Method == "POST" {
		var v struct {
			User   string `json:"user"`
			Action string `json:"action"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		u = strings.ToLower(strings.TrimSpace(v.User))
		if !hostingUserName(u) {
			fail(w, 400, "invalid hosting user")
			return
		}
		if _, e := user.Lookup(u); e != nil {
			fail(w, 404, "hosting user not provisioned")
			return
		}
		if e := ensureHostingSFTPConfig(); e != nil {
			fail(w, 500, "cannot configure sftp: "+e.Error())
			return
		}
		home := "/home/" + u
		_ = os.Chown(home, 0, 0)
		_ = os.Chmod(home, 0755)
		if v.Action == "enable" {
			_, _ = cmd("chage", "-E", "-1", u)
			out(w, 200, R{"ok": true, "user": u, "enabled": true})
			return
		}
		if v.Action == "disable" {
			_, _ = cmd("chage", "-E", "1", u)
			out(w, 200, R{"ok": true, "user": u, "enabled": false})
			return
		}
		if v.Action == "reset_password" {
			pass := hexRand(12)
			c := exec.Command("chpasswd")
			c.Stdin = strings.NewReader(u + ":" + pass + "\n")
			if b, e := c.CombinedOutput(); e != nil {
				fail(w, 500, "cannot set sftp password: "+strings.TrimSpace(string(b)))
				return
			}
			_, _ = cmd("chage", "-E", "-1", u)
			out(w, 200, R{"ok": true, "user": u, "password": pass, "host": host(), "port": 22})
			return
		}
		fail(w, 400, "invalid sftp action")
		return
	}
	if r.Method != "GET" {
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
	st, _ := cmd("passwd", "-S", u)
	enabled := !strings.Contains(st, " L ")
	out(w, 200, R{"ok": true, "user": u, "enabled": enabled, "host": host(), "port": 22, "chroot": "/", "password_auth": true})
}

func hostingBackups(w http.ResponseWriter, r *http.Request) {
	u := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	if r.Method == "POST" {
		var v struct {
			User, Type, Name string
			LimitMB          int64 `json:"limit_mb"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		u = strings.ToLower(strings.TrimSpace(v.User))
		if !hostingUserName(u) {
			fail(w, 400, "invalid hosting user")
			return
		}
		if _, e := user.Lookup(u); e != nil {
			fail(w, 404, "hosting user not provisioned")
			return
		}
		dir := "/home/" + u + "/backups"
		_ = os.MkdirAll(dir, 0750)
		ts := time.Now().Format("20060102-150405")
		file := ""
		if v.Type == "website" {
			h := strings.ToLower(strings.TrimSpace(v.Name))
			if !domainRE.MatchString(h) {
				fail(w, 400, "invalid website")
				return
			}
			base := "/home/" + u + "/web/" + h
			if !exists(base) {
				fail(w, 404, "website not found")
				return
			}
			file = "web-" + h + "-" + ts + ".tar.gz"
			if _, e := cmd("tar", "-czf", filepath.Join(dir, file), "-C", filepath.Dir(base), filepath.Base(base)); e != nil {
				fail(w, 500, e.Error())
				return
			}
		} else if v.Type == "database" {
			n := strings.TrimSpace(v.Name)
			if !nameRE.MatchString(n) || !strings.HasPrefix(n, u+"_") {
				fail(w, 400, "invalid database")
				return
			}
			file = "db-" + n + "-" + ts + ".sql"
			f, e := os.OpenFile(filepath.Join(dir, file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if e != nil {
				fail(w, 500, e.Error())
				return
			}
			c := exec.Command("mariadb-dump", n)
			c.Stdout = f
			e = c.Run()
			_ = f.Close()
			if e != nil {
				_ = os.Remove(filepath.Join(dir, file))
				fail(w, 500, "database backup failed")
				return
			}
		} else {
			fail(w, 400, "invalid backup type")
			return
		}
		p := filepath.Join(dir, file)
		_, _ = cmd("chown", u+":"+u, p)
		_ = os.Chmod(p, 0640)
		used := int64(0)
		if b, e := cmd("du", "-sb", "/home/"+u); e == nil {
			f := strings.Fields(b)
			if len(f) > 0 {
				used, _ = strconv.ParseInt(f[0], 10, 64)
			}
		}
		if v.LimitMB > 0 && used > v.LimitMB*1024*1024 {
			_ = os.Remove(p)
			fail(w, 409, "disk quota exceeded by backup")
			return
		}
		st, _ := os.Stat(p)
		sz := int64(0)
		if st != nil {
			sz = st.Size()
		}
		out(w, 201, R{"ok": true, "file": file, "size": sz, "type": v.Type, "target": v.Name})
		return
	}
	if !hostingUserName(u) {
		fail(w, 400, "invalid hosting user")
		return
	}
	dir := "/home/" + u + "/backups"
	if r.Method == "GET" {
		a := []R{}
		es, _ := os.ReadDir(dir)
		for _, e := range es {
			if e.IsDir() {
				continue
			}
			i, _ := e.Info()
			if i != nil {
				a = append(a, R{"file": e.Name(), "size": i.Size(), "time": i.ModTime()})
			}
		}
		out(w, 200, R{"ok": true, "items": a})
		return
	}
	if r.Method == "DELETE" {
		raw := strings.TrimSpace(r.URL.Query().Get("file"))
		f := filepath.Base(raw)
		hostingBackupRE := regexp.MustCompile(`^(?:web-[a-z0-9.-]+-[0-9]{8}-[0-9]{6}\.tar\.gz|db-[A-Za-z0-9_]+-[0-9]{8}-[0-9]{6}\.sql)$`)
		if raw != f || !hostingBackupRE.MatchString(f) {
			fail(w, 400, "invalid backup file")
			return
		}
		p := filepath.Join(dir, f)
		if !exists(p) {
			fail(w, 404, "backup not found")
			return
		}
		if e := os.Remove(p); e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 200, R{"ok": true})
		return
	}
	fail(w, 405, "method not allowed")
}

func cronShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func hostingCron(w http.ResponseWriter, r *http.Request) {
	u := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	if r.Method == "POST" || r.Method == "PATCH" {
		var v struct{ User, ID, Schedule, Command string }
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		u = strings.ToLower(strings.TrimSpace(v.User))
		if !hostingUserName(u) || !cronRE.MatchString(v.Schedule) || len(v.Command) < 1 || len(v.Command) > 400 || strings.Contains(v.Command, "\n") {
			fail(w, 400, "invalid hosting cron")
			return
		}
		if _, e := user.Lookup(u); e != nil {
			fail(w, 404, "hosting user not provisioned")
			return
		}
		id := v.ID
		if r.Method == "POST" {
			id = hexRand(8)
		}
		if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(id) {
			fail(w, 400, "invalid cron id")
			return
		}
		p := "/etc/cron.d/xshoter-client-" + u + "-" + id
		content := hostingCronCommand(loadHostingResourceLimits(u), id, v.Schedule, v.Command)
		if e := os.WriteFile(p, []byte(content), 0644); e != nil {
			fail(w, 500, e.Error())
			return
		}
		meta := R{"id": id, "user": u, "schedule": v.Schedule, "command": v.Command}
		_ = writeStateJSON(state+"/hosting-cron/"+u+"/"+id+".json", meta)
		out(w, map[bool]int{true: 200, false: 201}[r.Method == "PATCH"], R{"ok": true, "id": id})
		return
	}
	if !hostingUserName(u) {
		fail(w, 400, "invalid hosting user")
		return
	}
	dir := state + "/hosting-cron/" + u
	if r.Method == "GET" {
		a := []R{}
		fs, _ := filepath.Glob(dir + "/*.json")
		for _, p := range fs {
			b, e := os.ReadFile(p)
			if e != nil {
				continue
			}
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				a = append(a, R{"id": m["id"], "schedule": m["schedule"], "command": m["command"]})
			}
		}
		out(w, 200, R{"ok": true, "items": a})
		return
	}
	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(id) {
			fail(w, 400, "invalid cron id")
			return
		}
		_ = os.Remove("/etc/cron.d/xshoter-client-" + u + "-" + id)
		_ = os.Remove(dir + "/" + id + ".json")
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
