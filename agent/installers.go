package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func installerSite(userName, domain string) (map[string]any, string, error) {
	userName = strings.ToLower(strings.TrimSpace(userName))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !hostingUserName(userName) || !domainRE.MatchString(domain) {
		return nil, "", fmt.Errorf("invalid installer target")
	}
	m := siteMeta(domain)
	if m == nil || fmt.Sprint(m["owner"]) != userName {
		return nil, "", fmt.Errorf("website not owned by hosting user")
	}
	root := "/home/" + userName + "/web/" + domain + "/public_html"
	if !exists(root) {
		return nil, "", fmt.Errorf("website root not found")
	}
	return m, root, nil
}

func installerRootReady(root string) error {
	es, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	for _, x := range es {
		if x.Name() != "index.html" && x.Name() != ".well-known" {
			return fmt.Errorf("website root is not empty")
		}
	}
	return nil
}
func installerClearDefault(root string) error {
	if e := installerRootReady(root); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(root, "index.html"))
	return nil
}

func rollbackInstallerTarget(userName, domain, root, listen string, meta map[string]any) {
	unit := safeUnitForDomain(domain)
	_, _ = cmd("systemctl", "disable", "--now", unit)
	_ = os.Remove(filepath.Join("/etc/systemd/system", unit))
	_, _ = cmd("systemctl", "daemon-reload")
	_ = os.RemoveAll(filepath.Join("/home", userName, "apps", domain))
	if es, e := os.ReadDir(root); e == nil {
		for _, x := range es {
			if x.Name() != ".well-known" {
				_ = os.RemoveAll(filepath.Join(root, x.Name()))
			}
		}
	}
	idx := filepath.Join(root, "index.html")
	_ = os.WriteFile(idx, []byte("<!doctype html><title>"+domain+"</title><h1>"+domain+"</h1>"), 0644)
	_, _ = cmd("chown", "-R", userName+":"+userName, root)
	ver := fmt.Sprint(meta["php"])
	if phpRE.MatchString(ver) {
		logs := filepath.Dir(fmt.Sprint(meta["access_log"]))
		safe := strings.ReplaceAll(domain, ".", "_")
		socket := fmt.Sprintf("/run/php/php%s-fpm-xshoter-%s.sock", ver, safe)
		vhost := "/etc/nginx/xshoter/sites-enabled/" + domain + ".conf"
		_ = os.WriteFile(vhost, []byte(nginxSite(domain, root, logs, socket, listen, userName)), 0644)
		if _, e := cmd("nginx", "-t"); e == nil {
			_, _ = cmd("systemctl", "reload", "nginx")
		}
	}
}

func runAs(userName string, args ...string) (string, error) {
	a := append([]string{"-u", userName, "--"}, args...)
	c := exec.Command("runuser", a...)
	c.Dir = "/home/" + userName
	b, e := c.CombinedOutput()
	if e != nil {
		return string(b), fmt.Errorf("%s: %w", strings.TrimSpace(string(b)), e)
	}
	return string(b), nil
}

func ensureComposer() (string, error) {
	dir := envOr("XSHOTER_RUNTIME_DIR", "/opt/xshoter-runtime")
	if e := os.MkdirAll(dir, 0755); e != nil {
		return "", e
	}
	phar := filepath.Join(dir, "composer.phar")
	if exists(phar) {
		return phar, nil
	}
	setup := filepath.Join(dir, "composer-setup.php")
	if _, e := cmd("curl", "-fsSL", "https://getcomposer.org/installer", "-o", setup); e != nil {
		return "", e
	}
	sig, e := cmd("curl", "-fsSL", "https://composer.github.io/installer.sig")
	if e != nil {
		return "", e
	}
	actual, e := cmd("php", "-r", "echo hash_file('sha384', '"+setup+"');")
	if e != nil {
		return "", e
	}
	if strings.TrimSpace(sig) != strings.TrimSpace(actual) {
		_ = os.Remove(setup)
		return "", fmt.Errorf("composer installer signature mismatch")
	}
	if _, e = cmd("php", setup, "--install-dir="+dir, "--filename=composer.phar", "--quiet"); e != nil {
		return "", e
	}
	_ = os.Chmod(phar, 0755)
	_ = os.Remove(setup)
	return phar, nil
}
func updateEnvFile(p string, vals map[string]string) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	lines := strings.Split(string(b), "\n")
	seen := map[string]bool{}
	for i, l := range lines {
		for k, v := range vals {
			if strings.HasPrefix(l, k+"=") {
				lines[i] = k + "=" + v
				seen[k] = true
			}
		}
	}
	for k, v := range vals {
		if !seen[k] {
			lines = append(lines, k+"="+v)
		}
	}
	return os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0640)
}

func proxyVhost(domain, listen string, port int, owner string) string {
	gate := ""
	if hostingUserName(owner) && exists(hostingStatePath(owner)) {
		_ = ensureHostingBandwidthGate(owner)
		gate = " include " + hostingBandwidthGatePath(owner) + ";\n"
	}
	logs := filepath.Join("/home", owner, "web", domain, "logs")
	return fmt.Sprintf("server {\n listen %s;\n server_name %s;\n%s access_log %s/access.log;\n error_log %s/error.log;\n client_max_body_size 128m;\n location / { proxy_pass http://127.0.0.1:%d; proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \\\"upgrade\\\"; }\n}\n", listen, domain, gate, logs, logs, port)
}

func freeAppPort() (int, error) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func safeUnitForDomain(domain string) string {
	x := regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(strings.ReplaceAll(strings.ToLower(domain), ".", "-"), "-")
	return "xshoter-app-" + x + ".service"
}

func writeProxyAndService(userName, domain, appDir, listen, execStart string, port int) (string, error) {
	unit := safeUnitForDomain(domain)
	up := filepath.Join("/etc/systemd/system", unit)
	vhost := "/etc/nginx/xshoter/sites-enabled/" + domain + ".conf"
	old, _ := os.ReadFile(vhost)
	uc := "[Unit]\nDescription=Xshoter App " + domain + "\nAfter=network.target\n\n[Service]\nType=simple\nUser=" + userName + "\nGroup=" + userName + "\nSlice=" + hostingResourceSlice(userName) + "\nWorkingDirectory=" + appDir + "\nEnvironment=PORT=" + strconv.Itoa(port) + "\nExecStart=" + execStart + "\nRestart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n"
	if e := os.WriteFile(up, []byte(uc), 0644); e != nil {
		return "", e
	}
	if e := os.WriteFile(vhost, []byte(proxyVhost(domain, listen, port, userName)), 0644); e != nil {
		return "", e
	}
	if _, e := cmd("nginx", "-t"); e != nil {
		_ = os.WriteFile(vhost, old, 0644)
		_ = os.Remove(up)
		return "", e
	}
	_, _ = cmd("systemctl", "daemon-reload")
	if _, e := cmd("systemctl", "enable", "--now", unit); e != nil {
		_ = os.WriteFile(vhost, old, 0644)
		_ = os.Remove(up)
		_, _ = cmd("systemctl", "daemon-reload")
		_, _ = cmd("systemctl", "reload", "nginx")
		return "", e
	}
	ready := false
	for i := 0; i < 50; i++ {
		c, de := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 150*time.Millisecond)
		if de == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		st, _ := cmd("systemctl", "status", unit, "--no-pager", "-n", "20")
		_, _ = cmd("systemctl", "disable", "--now", unit)
		_ = os.Remove(up)
		_ = os.WriteFile(vhost, old, 0644)
		_, _ = cmd("systemctl", "daemon-reload")
		_, _ = cmd("systemctl", "reload", "nginx")
		return "", fmt.Errorf("application did not become ready: %s", strings.TrimSpace(st))
	}
	_, _ = cmd("systemctl", "reload", "nginx")
	origin := listen
	if !strings.Contains(origin, ":") {
		origin = "127.0.0.1:" + origin
	} else if strings.HasPrefix(origin, "0.0.0.0:") {
		origin = "127.0.0.1:" + strings.TrimPrefix(origin, "0.0.0.0:")
	}
	nginxReady := false
	for i := 0; i < 30; i++ {
		if _, ce := cmd("curl", "-fsS", "--max-time", "2", "-H", "Host: "+domain, "http://"+origin+"/"); ce == nil {
			nginxReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !nginxReady {
		return "", fmt.Errorf("application service is ready but nginx route did not become ready")
	}
	return unit, nil
}

func installNodeApp(userName, domain, root, listen string) (R, error) {
	if e := installerClearDefault(root); e != nil {
		return nil, e
	}
	appDir := "/home/" + userName + "/apps/" + domain
	if e := os.MkdirAll(appDir, 0750); e != nil {
		return nil, e
	}
	code := "const http=require('http');const port=Number(process.env.PORT||3000);http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html; charset=utf-8'});res.end('<h1>Node.js on " + domain + "</h1>');}).listen(port,'127.0.0.1');\n"
	if e := os.WriteFile(filepath.Join(appDir, "app.js"), []byte(code), 0640); e != nil {
		return nil, e
	}
	_, _ = cmd("chown", "-R", userName+":"+userName, appDir)
	port, e := freeAppPort()
	if e != nil {
		return nil, e
	}
	unit, e := writeProxyAndService(userName, domain, appDir, listen, "/usr/bin/node "+filepath.Join(appDir, "app.js"), port)
	if e != nil {
		return nil, e
	}
	return R{"kind": "node", "service": unit, "port": port, "app_dir": appDir}, nil
}

func installPythonApp(userName, domain, root, listen string) (R, error) {
	if e := installerClearDefault(root); e != nil {
		return nil, e
	}
	appDir := "/home/" + userName + "/apps/" + domain
	if e := os.MkdirAll(appDir, 0750); e != nil {
		return nil, e
	}
	code := "import os\nfrom http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  b=b'<h1>Python on " + domain + "</h1>'; self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)\nThreadingHTTPServer(('127.0.0.1',int(os.environ.get('PORT','8000'))),H).serve_forever()\n"
	if e := os.WriteFile(filepath.Join(appDir, "app.py"), []byte(code), 0640); e != nil {
		return nil, e
	}
	_, _ = cmd("chown", "-R", userName+":"+userName, appDir)
	port, e := freeAppPort()
	if e != nil {
		return nil, e
	}
	unit, e := writeProxyAndService(userName, domain, appDir, listen, "/usr/bin/python3 "+filepath.Join(appDir, "app.py"), port)
	if e != nil {
		return nil, e
	}
	return R{"kind": "python", "service": unit, "port": port, "app_dir": appDir}, nil
}
func installWordPress(userName, domain, root, dbName, dbUser, dbPass, title, adminUser, adminEmail string) (R, error) {
	if e := installerClearDefault(root); e != nil {
		return nil, e
	}
	tmpBase := "/home/" + userName + "/tmp/wp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if e := os.MkdirAll(tmpBase, 0750); e != nil {
		return nil, e
	}
	defer os.RemoveAll(tmpBase)
	arc := filepath.Join(tmpBase, "wordpress.tar.gz")
	if _, e := cmd("curl", "-fsSL", "https://wordpress.org/latest.tar.gz", "-o", arc); e != nil {
		return nil, e
	}
	if _, e := cmd("tar", "-xzf", arc, "-C", tmpBase); e != nil {
		return nil, e
	}
	if _, e := cmd("cp", "-a", filepath.Join(tmpBase, "wordpress")+"/.", root+"/"); e != nil {
		return nil, e
	}
	cfg := filepath.Join(root, "wp-config.php")
	sample := filepath.Join(root, "wp-config-sample.php")
	b, e := os.ReadFile(sample)
	if e != nil {
		return nil, e
	}
	x := string(b)
	repl := map[string]string{"database_name_here": dbName, "username_here": dbUser, "password_here": dbPass}
	for a, z := range repl {
		x = strings.ReplaceAll(x, a, z)
	}
	keys := []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
	for _, k := range keys {
		re := regexp.MustCompile(`define\(\s*'` + k + `'\s*,\s*'put your unique phrase here'\s*\);`)
		x = re.ReplaceAllString(x, "define( '"+k+"', '"+hexRand(32)+"' );")
	}
	if e = os.WriteFile(cfg, []byte(x), 0640); e != nil {
		return nil, e
	}
	_, _ = cmd("chown", "-R", userName+":"+userName, root)
	if title == "" {
		title = domain
	}
	if adminUser == "" {
		adminUser = "admin"
	}
	if adminEmail == "" {
		adminEmail = "admin@" + domain
	}
	adminPass := hexRand(12)
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	php := `<?php define('WP_INSTALLING',true);$_SERVER['HTTP_HOST']='` + domain + `';$_SERVER['HTTPS']='on';require __DIR__.'/wp-load.php';require_once ABSPATH.'wp-admin/includes/upgrade.php';wp_install(base64_decode('` + enc(title) + `'),base64_decode('` + enc(adminUser) + `'),base64_decode('` + enc(adminEmail) + `'),true,'',base64_decode('` + enc(adminPass) + `'),'');update_option('siteurl','https://` + domain + `');update_option('home','https://` + domain + `');`
	inst := filepath.Join(root, ".xshoter-install.php")
	if e = os.WriteFile(inst, []byte(php), 0600); e != nil {
		return nil, e
	}
	_, _ = cmd("chown", userName+":"+userName, inst)
	_, e = runAs(userName, "php", inst)
	_ = os.Remove(inst)
	if e != nil {
		return nil, e
	}
	return R{"kind": "wordpress", "admin_user": adminUser, "admin_password": adminPass, "admin_email": adminEmail}, nil
}
func installLaravel(userName, domain, root, dbName, dbUser, dbPass, listen string, meta map[string]any) (R, error) {
	if e := installerClearDefault(root); e != nil {
		return nil, e
	}
	composer, e := ensureComposer()
	if e != nil {
		return nil, e
	}
	tmp := "/home/" + userName + "/tmp/laravel-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_ = os.MkdirAll(filepath.Dir(tmp), 0750)
	_, e = runAs(userName, "env", "HOME=/home/"+userName+"/tmp", "COMPOSER_HOME=/home/"+userName+"/tmp/composer", "php", composer, "create-project", "laravel/laravel", tmp, "--no-interaction", "--prefer-dist")
	if e != nil {
		_ = os.RemoveAll(tmp)
		return nil, e
	}
	defer os.RemoveAll(tmp)
	if _, e = cmd("cp", "-a", tmp+"/.", root+"/"); e != nil {
		return nil, e
	}
	_, _ = cmd("chown", "-R", userName+":"+userName, root)
	env := filepath.Join(root, ".env")
	vals := map[string]string{"APP_URL": "https://" + domain, "DB_CONNECTION": "mysql", "DB_HOST": "127.0.0.1", "DB_PORT": "3306", "DB_DATABASE": dbName, "DB_USERNAME": dbUser, "DB_PASSWORD": dbPass}
	if e = updateEnvFile(env, vals); e != nil {
		return nil, e
	}
	_, _ = cmd("chown", userName+":"+userName, env)
	if _, e = runAs(userName, "php", filepath.Join(root, "artisan"), "key:generate", "--force"); e != nil {
		return nil, e
	}
	if _, e = runAs(userName, "php", filepath.Join(root, "artisan"), "migrate", "--force"); e != nil {
		return nil, e
	}
	logs := fmt.Sprint(meta["access_log"])
	logs = filepath.Dir(logs)
	ver := fmt.Sprint(meta["php"])
	safe := strings.ReplaceAll(domain, ".", "_")
	socket := fmt.Sprintf("/run/php/php%s-fpm-xshoter-%s.sock", ver, safe)
	vhost := "/etc/nginx/xshoter/sites-enabled/" + domain + ".conf"
	old, _ := os.ReadFile(vhost)
	if e = os.WriteFile(vhost, []byte(nginxSite(domain, filepath.Join(root, "public"), logs, socket, listen, userName)), 0644); e != nil {
		return nil, e
	}
	if _, e = cmd("nginx", "-t"); e != nil {
		_ = os.WriteFile(vhost, old, 0644)
		return nil, e
	}
	_, _ = cmd("systemctl", "reload", "nginx")
	_ = ver
	return R{"kind": "laravel", "app_root": root, "web_root": filepath.Join(root, "public")}, nil
}

func installerCatalog() []R {
	return []R{{"id": "wordpress", "name": "WordPress", "needs_database": true}, {"id": "laravel", "name": "Laravel", "needs_database": true}, {"id": "node", "name": "Node.js", "needs_database": false}, {"id": "python", "name": "Python", "needs_database": false}}
}
func hostingInstaller(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		out(w, 200, R{"ok": true, "items": installerCatalog()})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method not allowed")
		return
	}
	var v struct{ User, Domain, App, DBName, DBUser, DBPassword, Title, AdminUser, AdminEmail, WebListen string }
	if body(r, &v) != nil {
		fail(w, 400, "invalid json")
		return
	}
	v.User = strings.ToLower(strings.TrimSpace(v.User))
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	v.App = strings.ToLower(strings.TrimSpace(v.App))
	if v.WebListen == "" {
		v.WebListen = envOr("XSHOTER_WEB_LISTEN", "80")
	}
	meta, root, e := installerSite(v.User, v.Domain)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if e = installerRootReady(root); e != nil {
		fail(w, 409, e.Error())
		return
	}
	var result R
	switch v.App {
	case "wordpress":
		if !nameRE.MatchString(v.DBName) || !nameRE.MatchString(v.DBUser) || v.DBPassword == "" {
			fail(w, 400, "database credentials required")
			return
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,60}$`).MatchString(v.AdminUser) && v.AdminUser != "" {
			fail(w, 400, "invalid wordpress admin user")
			return
		}
		result, e = installWordPress(v.User, v.Domain, root, v.DBName, v.DBUser, v.DBPassword, v.Title, v.AdminUser, v.AdminEmail)
	case "laravel":
		if !nameRE.MatchString(v.DBName) || !nameRE.MatchString(v.DBUser) || v.DBPassword == "" {
			fail(w, 400, "database credentials required")
			return
		}
		result, e = installLaravel(v.User, v.Domain, root, v.DBName, v.DBUser, v.DBPassword, v.WebListen, meta)
	case "node":
		result, e = installNodeApp(v.User, v.Domain, root, v.WebListen)
	case "python":
		result, e = installPythonApp(v.User, v.Domain, root, v.WebListen)
	default:
		fail(w, 400, "unsupported installer")
		return
	}
	if e != nil {
		rollbackInstallerTarget(v.User, v.Domain, root, v.WebListen, meta)
		fail(w, 500, e.Error())
		return
	}
	for k, z := range result {
		meta[k] = z
	}
	meta["kind"] = v.App
	_ = writeStateJSON(siteMetaPath(v.Domain), meta)
	out(w, 201, R{"ok": true, "domain": v.Domain, "app": v.App, "result": result})
}
