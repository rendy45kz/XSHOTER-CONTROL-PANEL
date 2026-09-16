#!/usr/bin/env bash
set -Eeuo pipefail

[ "${EUID}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
TRIGGER="${1:-manual}"
STATE_ROOT="${XSHOTER_STATE_DIR:-/var/lib/xshoter-control}"
STATUS_DIR="$STATE_ROOT/update"
MODE_FILE="${XSHOTER_UPDATE_MODE_FILE:-$STATUS_DIR/mode}"
STATUS_FILE="$STATUS_DIR/status.json"
BACKUP_DIR="$STATUS_DIR/backups"
REPO="${XSHOTER_UPDATE_REPO:-rendy45kz/XSHOTER-CONTROL-PANEL}"
API="${XSHOTER_UPDATE_API:-https://api.github.com/repos/${REPO}/releases/latest}"
CONTROL_PORT="${XSHOTER_PORT:-9100}"
AGENT_SOCKET="${XSHOTER_AGENT_SOCKET:-/run/xshoter-agent.sock}"
CURRENT=""
LATEST=""
MODE="notify"
BACKUP=""
WORK=""
METADATA_FILE="${XSHOTER_UPDATE_METADATA_FILE:-}"
ARCHIVE_FILE="${XSHOTER_UPDATE_ARCHIVE_FILE:-}"

install -d -o www-data -g www-data -m 0750 "$STATUS_DIR"
install -d -m 0700 "$BACKUP_DIR"
exec 9>/run/xshoter-updater.lock
flock -n 9 || exit 0
[ ! -r "$MODE_FILE" ] || MODE="$(tr -d '[:space:]' < "$MODE_FILE")"
case "$MODE" in off|notify|auto) ;; *) MODE=notify;; esac
[ "$TRIGGER" != manual ] || rm -f "$STATUS_DIR/request"
current_version(){
  sed -n "s/^const VERSION = '\([^']*\)';/\1/p" /opt/xshoter-control/server.js 2>/dev/null | head -1
}
write_status(){
  local st="$1" msg="$2"
  python3 - "$STATUS_FILE" "$st" "$msg" "$CURRENT" "$LATEST" "$MODE" "$BACKUP" "$TRIGGER" <<'PY'
import json,os,sys,time,grp
p,state,msg,current,latest,mode,backup,trigger=sys.argv[1:]
data={"state":state,"message":msg,"current":current,"latest":latest,"mode":mode,"backup":backup,"trigger":trigger,"updated_at":int(time.time())}
t=p+'.tmp'
with open(t,'w') as f: json.dump(data,f,separators=(',',':'))
os.chmod(t,0o640); os.chown(t,0,grp.getgrnam('www-data').gr_gid); os.replace(t,p)
PY
}
newer(){
  python3 - "$1" "$2" <<'PY'
import re,sys
def v(x):
 m=re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?',x.strip())
 if not m: raise SystemExit(2)
 return tuple(map(int,m.groups()[:3])), bool(m.group(4))
a,ap=v(sys.argv[1]); b,bp=v(sys.argv[2])
newer=a>b or (a==b and not ap and bp)
raise SystemExit(0 if newer else 1)
PY
}
rollback(){
  write_status rollback "Update failed; restoring previous Xshoter version"
  systemctl stop xshoter-control.service xshoter-agent.service || true
  [ ! -d "$BACKUP/xshoter-control" ] || { rm -rf /opt/xshoter-control; cp -a "$BACKUP/xshoter-control" /opt/xshoter-control; }
  [ ! -d "$BACKUP/xshoter-agent" ] || { rm -rf /opt/xshoter-agent; cp -a "$BACKUP/xshoter-agent" /opt/xshoter-agent; }
  [ ! -d "$BACKUP/xshoter-updater" ] || { rm -rf /opt/xshoter-updater; cp -a "$BACKUP/xshoter-updater" /opt/xshoter-updater; }
  if [ -d "$BACKUP/state" ]; then
    rm -f "$STATE_ROOT"/control.db "$STATE_ROOT"/control.db-wal "$STATE_ROOT"/control.db-shm
    cp -a "$BACKUP/state"/control.db* "$STATE_ROOT/" 2>/dev/null || true
  fi
  if [ -d "$BACKUP/systemd" ]; then
    cp -a "$BACKUP/systemd"/* /etc/systemd/system/ 2>/dev/null || true
  fi
  systemctl daemon-reload
  systemctl start xshoter-agent.service || true
  systemctl start xshoter-control.service || true
  CURRENT="$(current_version || true)"
  write_status failed "Update failed; automatic rollback completed"
}
cleanup(){ [ -z "$WORK" ] || rm -rf "$WORK"; }
on_error(){
  local rc=$?
  trap - ERR
  if [ -n "$BACKUP" ] && [ -d "$BACKUP" ]; then rollback || true; else write_status failed "Update failed unexpectedly" || true; fi
  exit "$rc"
}
trap cleanup EXIT
trap on_error ERR

CURRENT="$(current_version || true)"
[ -n "$CURRENT" ] || { write_status failed "Unable to determine installed Xshoter version"; exit 1; }
if [ "$TRIGGER" = auto ] && [ "$MODE" != auto ]; then
  write_status idle "Automatic installation is disabled"
  exit 0
fi
write_status checking "Checking GitHub stable release"
WORK="$(mktemp -d /tmp/xshoter-update.XXXXXX)"
RELEASE_JSON="$WORK/release.json"
if [ -n "$METADATA_FILE" ]; then
  [ -f "$METADATA_FILE" ] || { write_status failed "Local release metadata file not found"; exit 1; }
  cp "$METADATA_FILE" "$RELEASE_JSON"
else
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 30 \
    -H "Accept: application/vnd.github+json" -H "User-Agent: Xshoter-Updater/${CURRENT}" \
    "$API" -o "$RELEASE_JSON" || { write_status failed "Unable to query GitHub release API"; exit 1; }
fi

LATEST="$(python3 - "$RELEASE_JSON" <<'PY'
import json,re,sys
x=json.load(open(sys.argv[1]))
tag=str(x.get('tag_name',''))
if x.get('draft') or x.get('prerelease') or not re.fullmatch(r'v?\d+\.\d+\.\d+',tag): raise SystemExit(2)
print(tag.lstrip('v'))
PY
)" || { write_status failed "Invalid stable release metadata"; exit 1; }

if ! newer "$LATEST" "$CURRENT"; then
  write_status idle "Xshoter is already up to date"
  exit 0
fi
write_status available "Stable update v${LATEST} is available"

ARCHIVE="$WORK/release.tar.gz"
if [ -n "$ARCHIVE_FILE" ]; then
  [ -f "$ARCHIVE_FILE" ] || { write_status failed "Local release archive file not found"; exit 1; }
  cp "$ARCHIVE_FILE" "$ARCHIVE"
else
  URL="https://github.com/${REPO}/archive/refs/tags/v${LATEST}.tar.gz"
  curl -fL --retry 2 --connect-timeout 10 --max-time 120 \
    --proto '=https' --proto-redir '=https' "$URL" -o "$ARCHIVE" || { write_status failed "Unable to download release archive"; exit 1; }
fi
SRC_DIR="$WORK/src"
mkdir -p "$SRC_DIR"
python3 - "$ARCHIVE" "$SRC_DIR" <<'PY'
import os,sys,tarfile
arc,dst=sys.argv[1:]
with tarfile.open(arc,'r:gz') as t:
 members=t.getmembers()
 if len(members)>20000 or sum(m.size for m in members if m.isfile())>536870912: raise SystemExit('release archive exceeds safety limit')
 for m in members:
  parts=m.name.split('/')
  if m.name.startswith('/') or '..' in parts: raise SystemExit('unsafe archive path')
  if m.issym() or m.islnk() or not (m.isfile() or m.isdir()): raise SystemExit('unsupported archive member')
 t.extractall(dst)
PY
ROOT="$(find "$SRC_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
[ -n "$ROOT" ] && [ -f "$ROOT/control/server.js" ] && [ -f "$ROOT/scripts/upgrade.sh" ] || { write_status failed "Release archive is incomplete"; exit 1; }

SOURCE_VERSION="$(sed -n "s/^const VERSION = '\([^']*\)';/\1/p" "$ROOT/control/server.js" | head -1)"
[ "$SOURCE_VERSION" = "$LATEST" ] || { write_status failed "Release version does not match its tag"; exit 1; }
write_status checking "Validating v${LATEST} before installation"

node --check "$ROOT/control/server.js" >/dev/null
node --check "$ROOT/control/web/app.js" >/dev/null
node --check "$ROOT/control/web/features.js" >/dev/null
node --check "$ROOT/control/web/i18n.js" >/dev/null
node --check "$ROOT/control/web/update-v101.js" >/dev/null
bash -n "$ROOT/scripts/install.sh" "$ROOT/scripts/upgrade.sh" "$ROOT/scripts/xshoter-updater.sh"
( cd "$ROOT/agent" && go build -o "$WORK/agent-check" . )
BACKUP="$BACKUP_DIR/$(date +%Y%m%d-%H%M%S)-v${CURRENT}-to-v${LATEST}"
install -d -m 0700 "$BACKUP" "$BACKUP/state" "$BACKUP/systemd"
cp -a /opt/xshoter-control "$BACKUP/xshoter-control"
cp -a /opt/xshoter-agent "$BACKUP/xshoter-agent"
[ ! -d /opt/xshoter-updater ] || cp -a /opt/xshoter-updater "$BACKUP/xshoter-updater"
for u in xshoter-control.service xshoter-agent.service xshoter-updater.service xshoter-updater-auto.service xshoter-updater.timer xshoter-updater.path; do
  [ ! -f "/etc/systemd/system/$u" ] || cp -a "/etc/systemd/system/$u" "$BACKUP/systemd/$u"
done

systemctl stop xshoter-control.service || true
cp -a "$STATE_ROOT"/control.db* "$BACKUP/state/" 2>/dev/null || true
write_status updating "Installing Xshoter v${LATEST}"

if ! bash "$ROOT/scripts/upgrade.sh"; then
  rollback
  exit 1
fi

HEALTHY=0
for _ in $(seq 1 20); do
  if curl -fsS --connect-timeout 2 --max-time 3 "http://127.0.0.1:${CONTROL_PORT}/api/setup/status" >/dev/null 2>&1 \
     && curl -fsS --unix-socket "$AGENT_SOCKET" --connect-timeout 2 --max-time 3 http://localhost/v1/health >/dev/null 2>&1; then
    HEALTHY=1; break
  fi
  sleep 2
done
INSTALLED="$(current_version || true)"
if [ "$HEALTHY" -ne 1 ] || [ "$INSTALLED" != "$LATEST" ]; then
  rollback
  exit 1
fi

CURRENT="$LATEST"
write_status success "Xshoter updated successfully to v${LATEST}"
printf 'Xshoter updated successfully: v%s\n' "$LATEST"
