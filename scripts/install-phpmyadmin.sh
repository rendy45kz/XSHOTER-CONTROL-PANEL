#!/usr/bin/env bash
set -Eeuo pipefail
[ "${EUID}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y phpmyadmin
[ -d /usr/share/phpmyadmin ] || { echo "phpMyAdmin installation not found." >&2; exit 1; }

PHPV="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
POOL_DIR="/etc/php/${PHPV}/fpm/pool.d"
[ -d "$POOL_DIR" ] || { echo "PHP-FPM ${PHPV} not found." >&2; exit 1; }

if ! id xshoterpma >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --gid www-data xshoterpma
fi
mariadb -e "CREATE USER IF NOT EXISTS 'xshoterpma'@'localhost' IDENTIFIED VIA unix_socket; ALTER USER 'xshoterpma'@'localhost' IDENTIFIED VIA unix_socket;"

install -m 0644 "$ROOT/phpmyadmin/xshoter-sso.php" /usr/share/phpmyadmin/xshoter-sso.php
cat > "$POOL_DIR/xshoter-phpmyadmin.conf" <<POOL
[xshoter-phpmyadmin]
user = xshoterpma
group = www-data
listen = /run/php/xshoter-pma.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 20s
pm.max_requests = 500
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
php_admin_value[max_execution_time] = 300
php_admin_value[memory_limit] = 256M
POOL

CFG=/etc/phpmyadmin/config.inc.php
if ! grep -q 'XSHOTER_CONTROL_SSO_BEGIN' "$CFG"; then
  { echo; cat "$ROOT/phpmyadmin/config-append.php"; } >> "$CFG"
fi
install -d -m 0755 /etc/nginx/xshoter-control
install -m 0644 "$ROOT/nginx/phpmyadmin.inc" /etc/nginx/xshoter-control/phpmyadmin.inc
if grep -q '# XSHOTER_PMA_INCLUDE' /etc/nginx/conf.d/xshoter-control.conf; then
  sed -i 's|# XSHOTER_PMA_INCLUDE|include /etc/nginx/xshoter-control/phpmyadmin.inc;|' /etc/nginx/conf.d/xshoter-control.conf
fi
systemd-tmpfiles --create /etc/tmpfiles.d/xshoter-control.conf

python3 - <<'PY'
from pathlib import Path
import json,re,subprocess
for p in Path('/var/lib/xshoter-control/secrets/db').glob('*.json'):
    try: db=str(json.loads(p.read_text()).get('database',''))
    except Exception: continue
    if re.fullmatch(r'[A-Za-z0-9_]{1,64}',db):
        subprocess.run(['mariadb','-e',f"GRANT ALL PRIVILEGES ON `{db}`.* TO 'xshoterpma'@'localhost'; FLUSH PRIVILEGES;"],check=False)
PY

php-fpm${PHPV} -t
nginx -t
systemctl restart "php${PHPV}-fpm" nginx xshoter-agent
printf 'phpMyAdmin integration installed.\n'
