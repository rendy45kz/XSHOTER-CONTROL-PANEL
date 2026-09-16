package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var packageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
var backupRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,220}$`)
var sizeRE = regexp.MustCompile(`^[0-9]{1,6}[KMG]?$`)

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

var cfZoneID = envOr("XSHOTER_CF_ZONE_ID", "")
var cfZoneName = strings.TrimSuffix(strings.ToLower(envOr("XSHOTER_CF_ZONE_NAME", "")), ".")
var cfTokenFile = envOr("XSHOTER_CF_TOKEN_FILE", "/etc/xshoter-control/cloudflare.token")

func systemInfo(w http.ResponseWriter, r *http.Request) {
	osName := "Debian"
	if b, e := os.ReadFile("/etc/os-release"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
			}
		}
	}
	kernel, _ := cmd("uname", "-r")
	arch, _ := cmd("uname", "-m")
	phpv, _ := cmd("php", "-r", "echo PHP_VERSION;")
	nodev, _ := cmd("node", "--version")
	nginxv, _ := cmd("nginx", "-v")
	mariav, _ := cmd("mariadb", "--version")
	out(w, 200, R{"ok": true, "os": osName, "kernel": strings.TrimSpace(kernel), "arch": strings.TrimSpace(arch), "php": strings.TrimSpace(phpv), "node": strings.TrimSpace(nodev), "nginx": strings.TrimSpace(nginxv), "mariadb": strings.TrimSpace(mariav), "hostname": host()})
}

func processes(w http.ResponseWriter, r *http.Request) {
	s, e := cmd("ps", "-eo", "pid,user,pcpu,pmem,etimes,comm", "--sort=-pcpu")
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	rows := []R{}
	ls := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range ls {
		if i == 0 {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		cpu, _ := strconv.ParseFloat(f[2], 64)
		mem, _ := strconv.ParseFloat(f[3], 64)
		age, _ := strconv.Atoi(f[4])
		rows = append(rows, R{"pid": pid, "user": f[1], "cpu": cpu, "memory": mem, "seconds": age, "command": f[5]})
		if len(rows) >= 80 {
			break
		}
	}
	out(w, 200, R{"ok": true, "items": rows})
}
func packageUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s, _ := cmd("apt", "list", "--upgradable")
		items := []R{}
		for _, l := range strings.Split(s, "\n") {
			if !strings.Contains(l, "/") || strings.HasPrefix(l, "Listing") {
				continue
			}
			p := strings.SplitN(l, "/", 2)[0]
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			old := ""
			if i := strings.Index(l, "upgradable from:"); i >= 0 {
				old = strings.Trim(strings.TrimSuffix(l[i+16:], "]"), " []")
			}
			items = append(items, R{"name": p, "candidate": f[1], "installed": old})
		}
		out(w, 200, R{"ok": true, "zone": cfZoneName, "items": items})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var v struct {
		Action string `json:"action"`
		Name   string `json:"name"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	if v.Action == "refresh" {
		s, e := cmd("apt-get", "update")
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 200, R{"ok": true, "output": tailText(s, 40)})
		return
	}
	if v.Action == "upgrade" && packageRE.MatchString(v.Name) {
		s, e := cmd("apt-get", "install", "-y", "--only-upgrade", v.Name)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 200, R{"ok": true, "output": tailText(s, 60)})
		return
	}
	fail(w, 400, "package/action not allowed")
}
func sslStatus(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(r.URL.Query().Get("domain"))
	if !domainRE.MatchString(d) {
		fail(w, 400, "invalid domain")
		return
	}
	if m := siteMeta(d); m != nil && fmt.Sprint(m["tls_mode"]) == "cloudflare" {
		out(w, 200, R{"ok": true, "domain": d, "installed": true, "mode": "cloudflare", "expires": "Managed by Cloudflare", "subject": d})
		return
	}
	cert := "/etc/letsencrypt/live/" + d + "/fullchain.pem"
	if !exists(cert) {
		out(w, 200, R{"ok": true, "domain": d, "installed": false, "mode": "local"})
		return
	}
	end, _ := cmd("openssl", "x509", "-in", cert, "-noout", "-enddate")
	sub, _ := cmd("openssl", "x509", "-in", cert, "-noout", "-subject")
	out(w, 200, R{"ok": true, "domain": d, "installed": true, "mode": "local", "expires": strings.TrimSpace(strings.TrimPrefix(end, "notAfter=")), "subject": strings.TrimSpace(sub)})
}

func webLogs(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(r.URL.Query().Get("domain"))
	typ := r.URL.Query().Get("type")
	if !domainRE.MatchString(d) || (typ != "access" && typ != "error") {
		fail(w, 400, "invalid domain/log type")
		return
	}
	logPath := ""
	if m := siteMeta(d); m != nil {
		logPath = fmt.Sprint(m[typ+"_log"])
		if logPath == "<nil>" {
			logPath = ""
		}
	}
	if logPath == "" {
		m, _ := filepath.Glob("/home/*/web/" + d + "/logs/" + typ + ".log")
		if len(m) > 0 {
			logPath = m[0]
		}
	}
	if logPath == "" || (!strings.HasPrefix(logPath, "/home/") && !strings.HasPrefix(logPath, "/var/log/xshoter-control/")) {
		out(w, 200, R{"ok": true, "text": ""})
		return
	}
	s, _ := cmd("tail", "-n", "250", logPath)
	out(w, 200, R{"ok": true, "text": s})
}

func managedPool(domain string) (string, string) {
	if m := siteMeta(domain); m != nil {
		p := fmt.Sprint(m["php_pool"])
		v := fmt.Sprint(m["php"])
		if p != "<nil>" && p != "" && exists(p) && phpRE.MatchString(v) {
			return p, v
		}
	}
	if !exists("/etc/nginx/xshoter/sites-enabled/" + domain + ".conf") {
		return "", ""
	}
	safe := strings.ReplaceAll(domain, ".", "_")
	for _, v := range []string{"8.3", "8.2"} {
		p := fmt.Sprintf("/etc/php/%s/fpm/pool.d/xshoter-%s.conf", v, safe)
		if exists(p) {
			return p, v
		}
	}
	return "", ""
}
func phpSettings(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(r.URL.Query().Get("domain"))
	if r.Method != "GET" {
		var v struct {
			Domain    string `json:"domain"`
			Memory    string `json:"memory_limit"`
			Upload    string `json:"upload_max_filesize"`
			Post      string `json:"post_max_size"`
			Execution int    `json:"max_execution_time"`
			InputVars int    `json:"max_input_vars"`
		}
		if body(r, &v) != nil {
			fail(w, 400, "invalid json")
			return
		}
		d = strings.ToLower(v.Domain)
		p, ver := managedPool(d)
		if p == "" {
			fail(w, 404, "managed PHP pool not found")
			return
		}
		if !sizeRE.MatchString(v.Memory) || !sizeRE.MatchString(v.Upload) || !sizeRE.MatchString(v.Post) || v.Execution < 1 || v.Execution > 3600 || v.InputVars < 100 || v.InputVars > 100000 {
			fail(w, 400, "invalid PHP settings")
			return
		}
		b, _ := os.ReadFile(p)
		lines := []string{}
		keys := []string{"memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time", "max_input_vars"}
		for _, l := range strings.Split(string(b), "\n") {
			keep := true
			for _, k := range keys {
				if strings.HasPrefix(strings.TrimSpace(l), "php_admin_value["+k+"]") {
					keep = false
				}
			}
			if keep {
				lines = append(lines, l)
			}
		}
		lines = append(lines, fmt.Sprintf("php_admin_value[memory_limit]=%s", v.Memory), fmt.Sprintf("php_admin_value[upload_max_filesize]=%s", v.Upload), fmt.Sprintf("php_admin_value[post_max_size]=%s", v.Post), fmt.Sprintf("php_admin_value[max_execution_time]=%d", v.Execution), fmt.Sprintf("php_admin_value[max_input_vars]=%d", v.InputVars))
		if e := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0644); e != nil {
			fail(w, 500, e.Error())
			return
		}
		if _, e := cmd("systemctl", "reload", "php"+ver+"-fpm"); e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 200, R{"ok": true})
		return
	}
	if !domainRE.MatchString(d) {
		fail(w, 400, "invalid domain")
		return
	}
	p, ver := managedPool(d)
	if p == "" {
		fail(w, 404, "managed PHP pool not found")
		return
	}
	b, _ := os.ReadFile(p)
	vals := map[string]string{}
	re := regexp.MustCompile(`^php_admin_value\[([^]]+)\]=(.*)$`)
	for _, l := range strings.Split(string(b), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) == 3 {
			vals[m[1]] = m[2]
		}
	}
	out(w, 200, R{"ok": true, "domain": d, "version": ver, "settings": vals})
}

func secureWebPath(p string, allowNew bool) (string, error) {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) || !strings.HasPrefix(p, "/home/") {
		return "", fmt.Errorf("path outside website roots")
	}
	parts := strings.Split(p, "/")
	if len(parts) < 6 || parts[1] != "home" || parts[3] != "web" || parts[5] != "public_html" {
		return "", fmt.Errorf("path outside website roots")
	}
	root := filepath.Join("/home", parts[2], "web", parts[4], "public_html")
	eroot, e := filepath.EvalSymlinks(root)
	if e != nil {
		return "", e
	}
	target := p
	etarget, e := filepath.EvalSymlinks(target)
	if e != nil && allowNew {
		ep, pe := filepath.EvalSymlinks(filepath.Dir(target))
		if pe != nil {
			return "", pe
		}
		etarget = filepath.Join(ep, filepath.Base(target))
		e = nil
	}
	if e != nil {
		return "", e
	}
	if etarget != eroot && !strings.HasPrefix(etarget, eroot+string(os.PathSeparator)) {
		return "", fmt.Errorf("path outside website root")
	}
	return etarget, nil
}
func webPathOwner(p string) string {
	parts := strings.Split(filepath.Clean(p), "/")
	if len(parts) > 2 && parts[1] == "home" && userRE.MatchString(parts[2]) {
		return parts[2]
	}
	return ""
}

func fileActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var v struct {
		Action string `json:"action"`
		Path   string `json:"path"`
		Target string `json:"target"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	switch v.Action {
	case "mkdir":
		p, e := secureWebPath(v.Path, true)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		if e = os.Mkdir(p, 0755); e != nil {
			fail(w, 500, e.Error())
			return
		}
		_ = os.Chmod(p, 0755)
		if u := webPathOwner(p); u != "" {
			_, _ = cmd("chown", u+":"+u, p)
		}
	case "touch":
		p, e := secureWebPath(v.Path, true)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		_ = f.Close()
		_ = os.Chmod(p, 0644)
		if u := webPathOwner(p); u != "" {
			_, _ = cmd("chown", u+":"+u, p)
		}
	case "rename":
		src, e := secureWebPath(v.Path, false)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		dst, e := secureWebPath(v.Target, true)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		if strings.Split(src, "/public_html")[0] != strings.Split(dst, "/public_html")[0] {
			fail(w, 400, "cross-site move not allowed")
			return
		}
		if e = os.Rename(src, dst); e != nil {
			fail(w, 500, e.Error())
			return
		}
		if u := webPathOwner(dst); u != "" {
			_, _ = cmd("chown", u+":"+u, dst)
		}
	case "delete":
		p, e := secureWebPath(v.Path, false)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		if strings.HasSuffix(p, "/public_html") {
			fail(w, 400, "cannot delete website root")
			return
		}
		if e = os.RemoveAll(p); e != nil {
			fail(w, 500, e.Error())
			return
		}
	default:
		fail(w, 400, "file action not allowed")
		return
	}
	out(w, 200, R{"ok": true})
}
func safeBackupFile(rel string) (string, string, bool) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") || strings.Contains(rel, "..") {
		return "", "", false
	}
	parts := strings.Split(rel, "/")
	if len(parts) > 2 {
		return "", "", false
	}
	if len(parts) == 2 && parts[0] != "production" && parts[0] != "system" {
		return "", "", false
	}
	base := parts[len(parts)-1]
	if !backupRE.MatchString(base) {
		return "", "", false
	}
	root := filepath.Join(state, "backups")
	p := filepath.Join(root, filepath.FromSlash(rel))
	cleanRoot, _ := filepath.Abs(root)
	cleanPath, _ := filepath.Abs(p)
	if cleanPath == cleanRoot || !strings.HasPrefix(cleanPath, cleanRoot+string(os.PathSeparator)) {
		return "", "", false
	}
	return cleanPath, base, true
}

func backupActions(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if r.Method == "DELETE" {
		p, _, ok := safeBackupFile(name)
		if !ok {
			fail(w, 400, "invalid backup name")
			return
		}
		st, e := os.Stat(p)
		if e != nil || st.IsDir() {
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
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var v struct {
		File string `json:"file"`
	}
	if body(r, &v) != nil {
		fail(w, 400, "invalid backup file")
		return
	}
	p, base, ok := safeBackupFile(v.File)
	if !ok {
		fail(w, 400, "invalid backup file")
		return
	}
	st, e := os.Stat(p)
	if e != nil || st.IsDir() {
		fail(w, 404, "backup not found")
		return
	}
	if m := regexp.MustCompile(`^db-([A-Za-z0-9_]+)-[0-9]{8}-[0-9]{6}\.sql$`).FindStringSubmatch(base); len(m) == 2 {
		f, e := os.Open(p)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		defer f.Close()
		c := exec.Command("mariadb", m[1])
		c.Stdin = f
		b, e := c.CombinedOutput()
		if e != nil {
			fail(w, 500, strings.TrimSpace(string(b)))
			return
		}
		out(w, 200, R{"ok": true, "type": "database", "name": m[1]})
		return
	}
	if m := regexp.MustCompile(`^db-([A-Za-z0-9_]+)-[0-9]{8}-[0-9]{6}\.sql\.gz$`).FindStringSubmatch(base); len(m) == 2 {
		gz := exec.Command("gzip", "-dc", p)
		db := exec.Command("mariadb", m[1])
		pipe, e := gz.StdoutPipe()
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
		db.Stdin = pipe
		var dbOut strings.Builder
		db.Stdout = &dbOut
		db.Stderr = &dbOut
		if e = db.Start(); e != nil {
			fail(w, 500, e.Error())
			return
		}
		if e = gz.Start(); e != nil {
			_ = db.Process.Kill()
			fail(w, 500, e.Error())
			return
		}
		gzErr := gz.Wait()
		dbErr := db.Wait()
		if gzErr != nil || dbErr != nil {
			fail(w, 500, strings.TrimSpace(dbOut.String()))
			return
		}
		out(w, 200, R{"ok": true, "type": "database", "name": m[1]})
		return
	}
	if m := regexp.MustCompile(`^web-([a-z0-9.-]+)-[0-9]{8}-[0-9]{6}\.tar\.gz$`).FindStringSubmatch(base); len(m) == 2 && domainRE.MatchString(m[1]) {
		roots, _ := filepath.Glob("/home/*/web/" + m[1])
		if len(roots) == 0 {
			fail(w, 404, "website target not found")
			return
		}
		if _, e := cmd("tar", "-xzf", p, "-C", filepath.Dir(roots[0])); e != nil {
			fail(w, 500, e.Error())
			return
		}
		out(w, 200, R{"ok": true, "type": "website", "name": m[1]})
		return
	}
	fail(w, 400, "backup is not restorable from panel")
}

func tailText(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}

func cfRequest(method, endpoint string, payload any) (map[string]any, error) {
	c := effectiveCloudflareConfig()
	if c.APIToken == "" {
		return nil, fmt.Errorf("cloudflare API token is not configured")
	}
	return cfZoneRequest(c, method, endpoint, payload)
}

func dnsRecords(w http.ResponseWriter, r *http.Request) {
	if mode := r.URL.Query().Get("mode"); mode == "config" {
		cloudflareConfigHandler(w, r)
		return
	} else if mode == "test" {
		cloudflareTestHandler(w, r)
		return
	}
	cfg := effectiveCloudflareConfig()
	if z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("zone"))), "."); z != "" {
		if !domainRE.MatchString(z) {
			fail(w, 400, "invalid Cloudflare zone")
			return
		}
		cfg.ZoneName = z
	}
	if cfg.APIToken == "" || cfg.ZoneName == "" {
		fail(w, 503, "cloudflare DNS is not configured")
		return
	}
	zoneID, zoneName, e := resolveCFZone(cfg)
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	base := "/zones/" + zoneID + "/dns_records"
	if r.Method == "GET" {
		v, e := cfRequest("GET", base+"?per_page=200", nil)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		items := []R{}
		if a, ok := v["result"].([]any); ok {
			for _, x := range a {
				m, _ := x.(map[string]any)
				if m == nil {
					continue
				}
				n, _ := m["name"].(string)
				if n != zoneName && !strings.HasSuffix(n, "."+zoneName) {
					continue
				}
				items = append(items, R{"id": m["id"], "type": m["type"], "name": n, "content": m["content"], "proxied": m["proxied"], "ttl": m["ttl"], "priority": m["priority"]})
			}
		}
		out(w, 200, R{"ok": true, "zone": zoneName, "items": items})
		return
	}
	if r.Method == "POST" || r.Method == "PATCH" {
		var x struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Content  string `json:"content"`
			Proxied  bool   `json:"proxied"`
			TTL      int    `json:"ttl"`
			Priority int    `json:"priority"`
		}
		if body(r, &x) != nil {
			fail(w, 400, "invalid json")
			return
		}
		x.Type = strings.ToUpper(x.Type)
		x.Name = strings.ToLower(strings.TrimSpace(x.Name))
		x.Content = strings.TrimSpace(x.Content)
		if x.Name == "@" {
			x.Name = zoneName
		} else if !strings.Contains(x.Name, ".") {
			x.Name += "." + zoneName
		}
		allowed := map[string]bool{"A": true, "AAAA": true, "CNAME": true, "TXT": true, "MX": true}
		if !allowed[x.Type] || (x.Name != zoneName && !strings.HasSuffix(x.Name, "."+zoneName)) || len(x.Content) < 1 || len(x.Content) > 2048 {
			fail(w, 400, "invalid DNS record")
			return
		}
		if x.TTL == 0 {
			x.TTL = 1
		}
		if x.Priority < 0 || x.Priority > 65535 {
			fail(w, 400, "invalid MX priority")
			return
		}
		payload := map[string]any{"type": x.Type, "name": x.Name, "content": x.Content, "ttl": x.TTL}
		if x.Type == "A" || x.Type == "AAAA" || x.Type == "CNAME" {
			payload["proxied"] = x.Proxied
		}
		if x.Type == "MX" {
			if x.Priority == 0 {
				x.Priority = 10
			}
			payload["priority"] = x.Priority
		}
		path := base
		code := 201
		if r.Method == "PATCH" {
			id := r.URL.Query().Get("id")
			if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
				fail(w, 400, "invalid record id")
				return
			}
			path = base + "/" + id
			code = 200
		}
		v, e := cfRequest(r.Method, path, payload)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		out(w, code, R{"ok": true, "result": v["result"]})
		return
	}
	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(id) {
			fail(w, 400, "invalid record id")
			return
		}
		_, e := cfRequest("DELETE", base+"/"+id, nil)
		if e != nil {
			fail(w, 502, e.Error())
			return
		}
		out(w, 200, R{"ok": true})
		return
	}
	fail(w, 405, "method not allowed")
}

func securityOverview(w http.ResponseWriter, r *http.Request) {
	sshd, _ := cmd("sshd", "-T")
	picks := []string{}
	for _, l := range strings.Split(sshd, "\n") {
		if strings.HasPrefix(l, "permitrootlogin ") || strings.HasPrefix(l, "passwordauthentication ") || strings.HasPrefix(l, "pubkeyauthentication ") || strings.HasPrefix(l, "maxauthtries ") {
			picks = append(picks, l)
		}
	}
	f2b, _ := cmd("fail2ban-client", "status")
	fw, _ := cmd("iptables", "-S", "INPUT")
	out(w, 200, R{"ok": true, "ssh": picks, "fail2ban": tailText(f2b, 40), "firewall": strings.Split(strings.TrimSpace(fw), "\n")})
}

func fileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	target, e := secureWebPath(r.URL.Query().Get("path"), true)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	const maxUpload = int64(1024 << 20)
	dir := filepath.Dir(target)
	f, e := os.CreateTemp(dir, ".xc-upload-*")
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	n, e := io.Copy(f, io.LimitReader(r.Body, maxUpload+1))
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	if n > maxUpload {
		fail(w, 413, "upload too large")
		return
	}
	if e = f.Sync(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	if e = f.Close(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	_ = os.Chmod(tmp, 0644)
	if u := webPathOwner(target); u != "" {
		_, _ = cmd("chown", u+":"+u, tmp)
	}
	if e = os.Rename(tmp, target); e != nil {
		fail(w, 500, e.Error())
		return
	}
	ok = true
	out(w, 201, R{"ok": true, "path": target, "size": n})
}
