# Xshoter Control

Xshoter Control is a free and open-source server control panel for Linux VPS environments. It provides a web UI backed by a restricted Node.js control service and a privileged Go agent connected through a local Unix socket.

**License:** GNU GPL v3.0  
**Current release:** 1.0.1
**Default UI language:** Bahasa Indonesia, with English, Bahasa Melayu, and Tiếng Việt included.

## Features

- Dashboard: CPU, memory, disk, network, uptime, service health
- Website management with Nginx and PHP-FPM
- MariaDB database management and generated credentials
- Optional phpMyAdmin one-time-token integration
- File Manager and website logs
- Backups and restores
- Firewall rule management
- Cron jobs
- Service control and logs
- SSH public-key management
- Process monitor and package updates
- Cloudflare DNS integration (optional)
- SSL status and certificate workflows
- Panel users, roles, sessions, 2FA, and audit log
- Responsive mobile UI and multi-language interface

## Architecture

The control service runs as `www-data` on `127.0.0.1:9100`. Privileged system operations are delegated to `xshoter-agent`, which runs as root and accepts requests only through `/run/xshoter-agent.sock` (`root:www-data`, mode `0660`). The browser never connects directly to the privileged agent.

## Supported systems

The included installer targets Debian and Ubuntu. A full clean-install validation has been completed on Debian 12. The project currently expects:

- Node.js 22 or newer (`node:sqlite` is used)
- Go 1.18 or newer to build the agent
- Nginx
- MariaDB
- PHP-FPM
- Certbot
- systemd
- iptables
- OpenSSH
- Fail2Ban

The installer installs Node.js 22 from the NodeSource APT repository when the system Node.js version is too old. Fresh installs also configure the Xshoter-managed Nginx site include and the Fail2Ban SSH jail to use the systemd journal backend.

## Install

Clone the repository and run:

```bash
sudo ./scripts/install.sh
```

The default panel endpoint is:

```text
https://SERVER_IP:8443/
```

The installer creates a self-signed TLS certificate for the initial connection. Replace it with a trusted certificate or place the panel behind a trusted HTTPS reverse proxy before production use.

Get the one-time first-run token with:

```bash
sudo cat /var/lib/xshoter-control/setup.token
```

The token is deleted by the control service after a successful owner setup.

## Optional phpMyAdmin integration

Core database management works without phpMyAdmin. To enable the phpMyAdmin button and one-time database login:

```bash
sudo ./scripts/install-phpmyadmin.sh
```

The integration uses a local `xshoterpma` service account authenticated through the MariaDB Unix socket. Application database passwords are not sent to the browser for phpMyAdmin login.

## Optional Cloudflare DNS

Edit `/etc/xshoter-control/xshoter.env`:

```ini
XSHOTER_CF_ZONE_ID=your_zone_id
XSHOTER_CF_ZONE_NAME=example.com
XSHOTER_CF_TOKEN_FILE=/etc/xshoter-control/cloudflare.token
```

Write only the API token to the token file and protect it:

```bash
sudo install -m 600 /dev/null /etc/xshoter-control/cloudflare.token
sudo nano /etc/xshoter-control/cloudflare.token
sudo systemctl restart xshoter-agent
```

Use a Cloudflare API token with the minimum permissions required for DNS record management of the selected zone.

## Website listen address

New Nginx website configurations use `XSHOTER_WEB_LISTEN`. The default is:

```ini
XSHOTER_WEB_LISTEN=80
```

It can be changed to a specific interface, for example `10.0.0.10:80`.

## Firewall safety

The installer deliberately does **not** enable `xshoter-firewall.service`. On first install it snapshots the current iptables filter table into `/etc/xshoter-control/firewall/iptables.rules`; panel-managed rules are then synchronized into that snapshot for persistence. Review the resulting rules and confirm SSH/panel access before enabling `xshoter-firewall.service`.

## Updating

Xshoter Control 1.0.1 adds a dedicated application updater under **Updates → Xshoter Update**. It is separate from Debian/Ubuntu package updates. Three modes are available:

- **Off** — no automatic release notification check from the header bell; manual checks remain available from the Updates page.
- **Notify Only** — the default. The panel checks the stable GitHub release and shows a bell badge when a newer version exists.
- **Automatic Stable Updates** — a systemd timer checks daily and installs newer stable releases automatically. Manual updates are queued through a root-owned systemd path trigger, so the web process never runs `systemctl` directly.

Before installation, the updater validates the release in a staging directory, builds the Go agent, creates an application and control-database backup, and then restarts the control plane. If the post-update health check fails, the previous application, agent, systemd units, and control database are restored automatically.

Systems installed from 1.0.0 do not yet contain the self-updater. Upgrade once to 1.0.1 using the repository installer:

```bash
git checkout v1.0.1
sudo XSHOTER_ALLOW_EXISTING=1 ./scripts/install.sh
```

After 1.0.1 is installed, later stable releases can be installed from the panel. Keep independent backups of `/var/lib/xshoter-control`, `/etc/xshoter-control`, and hosted website/database data as part of normal server operations.

## Security

Do not commit any live `.env`, API token, private key, TLS key, database file, database dump, setup token, session file, or production backup. See [SECURITY.md](SECURITY.md).

## Commercial use

GPL-3.0 permits commercial use. You may use Xshoter Control on servers that host paid or commercial services and you may provide the panel to your users at no charge. Distribution and modification must comply with GPL-3.0.

## License

Xshoter Control is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).

Third-party assets and their notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
