#!/usr/bin/env bash
set -Eeuo pipefail

[ "${EUID}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$ROOT/control/server.js" ] || { echo "Invalid Xshoter release source." >&2; exit 1; }

BUILD="$(mktemp -d /tmp/xshoter-upgrade.XXXXXX)"
trap 'rm -rf "$BUILD"' EXIT

node --check "$ROOT/control/server.js"
node --check "$ROOT/control/web/app.js"
node --check "$ROOT/control/web/features.js"
node --check "$ROOT/control/web/i18n.js"
bash -n "$ROOT/scripts/upgrade.sh" "$ROOT/scripts/xshoter-updater.sh"
( cd "$ROOT/agent" && go build -trimpath -ldflags="-s -w" -o "$BUILD/xshoter-agent" . )

install -d -m 0755 /opt/xshoter-control /opt/xshoter-agent /opt/xshoter-updater
cp -a "$ROOT/control/web" "$BUILD/web"
install -m 0644 "$ROOT/control/server.js" "$BUILD/server.js"
install -m 0755 "$ROOT/scripts/xshoter-updater.sh" "$BUILD/update.sh"
systemctl stop xshoter-control.service xshoter-agent.service || true

rm -rf /opt/xshoter-control/web.new
mv "$BUILD/web" /opt/xshoter-control/web.new
install -m 0644 "$BUILD/server.js" /opt/xshoter-control/server.js.new
install -m 0755 "$BUILD/xshoter-agent" /opt/xshoter-agent/xshoter-agent.new
install -m 0755 "$BUILD/update.sh" /opt/xshoter-updater/update.sh.new

rm -rf /opt/xshoter-control/web.old
[ ! -d /opt/xshoter-control/web ] || mv /opt/xshoter-control/web /opt/xshoter-control/web.old
mv /opt/xshoter-control/web.new /opt/xshoter-control/web
mv /opt/xshoter-control/server.js.new /opt/xshoter-control/server.js
mv /opt/xshoter-agent/xshoter-agent.new /opt/xshoter-agent/xshoter-agent
mv /opt/xshoter-updater/update.sh.new /opt/xshoter-updater/update.sh
chmod -R a+rX /opt/xshoter-control

install -m 0644 "$ROOT/systemd/xshoter-control.service" /etc/systemd/system/xshoter-control.service
install -m 0644 "$ROOT/systemd/xshoter-agent.service" /etc/systemd/system/xshoter-agent.service
install -m 0644 "$ROOT/systemd/xshoter-updater.service" /etc/systemd/system/xshoter-updater.service
install -m 0644 "$ROOT/systemd/xshoter-updater-auto.service" /etc/systemd/system/xshoter-updater-auto.service
install -m 0644 "$ROOT/systemd/xshoter-updater.timer" /etc/systemd/system/xshoter-updater.timer
install -m 0644 "$ROOT/systemd/xshoter-updater.path" /etc/systemd/system/xshoter-updater.path
systemctl daemon-reload
systemctl reset-failed xshoter-updater.service xshoter-updater-auto.service 2>/dev/null || true
systemctl enable xshoter-updater.path xshoter-updater.timer >/dev/null
systemctl start xshoter-agent.service
systemctl start xshoter-control.service
systemctl start xshoter-updater.path
systemctl start xshoter-updater.timer

rm -rf /opt/xshoter-control/web.old
printf 'Xshoter application upgrade installed.\n'
