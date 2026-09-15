#!/usr/bin/env bash
set -Eeuo pipefail

[ "${EUID}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$ROOT/control/server.js" ] || { echo "Run this installer from the Xshoter Control repository." >&2; exit 1; }

if [ -f /var/lib/xshoter-control/control.db ] && [ "${XSHOTER_ALLOW_EXISTING:-0}" != "1" ]; then
  echo "Existing Xshoter Control database found. Set XSHOTER_ALLOW_EXISTING=1 only when intentionally upgrading." >&2
  exit 1
fi

. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) echo "Supported: Debian/Ubuntu." >&2; exit 1;; esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg openssl nginx mariadb-server php-fpm php-cli php-mysql fail2ban python3-systemd iptables openssh-server golang-go

node_ok=0
if command -v node >/dev/null 2>&1; then
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "$major" -ge 22 ] && node_ok=1
fi
if [ "$node_ok" -ne 1 ]; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
  apt-get update
  apt-get install -y nodejs
fi
node -e 'if(Number(process.versions.node.split(".")[0])<22)process.exit(1)'

install -d -m 0755 /opt/xshoter-control /opt/xshoter-agent
rm -rf /opt/xshoter-control/web
cp -a "$ROOT/control/server.js" /opt/xshoter-control/server.js
cp -a "$ROOT/control/web" /opt/xshoter-control/web
chmod -R a+rX /opt/xshoter-control

( cd "$ROOT/agent" && go build -trimpath -ldflags="-s -w" -o /opt/xshoter-agent/xshoter-agent . )
chmod 0755 /opt/xshoter-agent/xshoter-agent

install -d -o www-data -g www-data -m 0750 /var/lib/xshoter-control
install -d -m 0700 /var/lib/xshoter-control/secrets /var/lib/xshoter-control/secrets/db
install -d -m 0750 /var/lib/xshoter-control/backups /var/log/xshoter-control
install -d -m 0750 /etc/xshoter-control /etc/xshoter-control/tls /etc/xshoter-control/firewall
if [ ! -f /etc/xshoter-control/xshoter.env ]; then
  cp "$ROOT/config/xshoter.env.example" /etc/xshoter-control/xshoter.env
  chmod 0640 /etc/xshoter-control/xshoter.env
fi

if [ ! -f /var/lib/xshoter-control/control.db ] && [ ! -f /var/lib/xshoter-control/setup.token ]; then
  openssl rand -hex 24 > /var/lib/xshoter-control/setup.token
  chown www-data:www-data /var/lib/xshoter-control/setup.token
  chmod 0600 /var/lib/xshoter-control/setup.token
fi

cp "$ROOT/systemd/xshoter-control.service" /etc/systemd/system/
cp "$ROOT/systemd/xshoter-agent.service" /etc/systemd/system/
cp "$ROOT/systemd/xshoter-firewall.service" /etc/systemd/system/
cp "$ROOT/config/xshoter-control.tmpfiles" /etc/tmpfiles.d/xshoter-control.conf
systemd-tmpfiles --create /etc/tmpfiles.d/xshoter-control.conf

PANEL_PORT="${XSHOTER_PANEL_PORT:-8443}"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
if [ ! -s /etc/xshoter-control/tls/panel.key ] || [ ! -s /etc/xshoter-control/tls/panel.pem ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -subj "/CN=${HOSTNAME_FQDN}" \
    -keyout /etc/xshoter-control/tls/panel.key \
    -out /etc/xshoter-control/tls/panel.pem >/dev/null 2>&1
  chmod 0600 /etc/xshoter-control/tls/panel.key
fi
cat > /etc/nginx/conf.d/xshoter-control.conf <<NGINX
server {
    listen ${PANEL_PORT} ssl;
    server_name _;
    ssl_certificate /etc/xshoter-control/tls/panel.pem;
    ssl_certificate_key /etc/xshoter-control/tls/panel.key;
    client_max_body_size 1024m;
    # XSHOTER_PMA_INCLUDE
    location / {
        proxy_pass http://127.0.0.1:9100;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 75s;
        proxy_send_timeout 75s;
    }
}
NGINX

mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/xshoter-sshd.conf <<'FAIL2BAN'
[sshd]
enabled = true
backend = systemd
FAIL2BAN
fail2ban-client -t

nginx -t
systemctl daemon-reload
systemctl enable --now mariadb nginx fail2ban xshoter-agent xshoter-control
systemctl restart xshoter-agent xshoter-control nginx

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "Xshoter Control installed."
echo "URL: https://${IP:-server}:${PANEL_PORT}/"
echo "The first visit uses a self-signed TLS certificate."
echo "Setup token: sudo cat /var/lib/xshoter-control/setup.token"
echo "Optional phpMyAdmin integration: sudo $ROOT/scripts/install-phpmyadmin.sh"
echo "Firewall rules are NOT enabled automatically. Review them before enabling xshoter-firewall.service."
