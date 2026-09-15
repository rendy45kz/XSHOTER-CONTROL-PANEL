# Xshoter Control

Xshoter Control is a free and open-source server control panel for Linux VPS environments. It provides a web UI backed by a restricted Node.js control service and a privileged Go agent connected through a local Unix socket.

**License:** GNU GPL v3.0  
**Current release:** 1.0.0  
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

The included installer targets Debian and Ubuntu. The project currently expects:

- Node.js 22 or newer (`node:sqlite` is used)
- Go 1.18 or newer to build the agent
- Nginx
- MariaDB
- PHP-FPM
- systemd
- iptables
- OpenSSH
- Fail2Ban

The installer installs Node.js 22 from the NodeSource APT repository when the system Node.js version is too old.

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

The installer deliberately does **not** enable `xshoter-firewall.service`. Review `/etc/xshoter-control/firewall/iptables.rules` and confirm SSH access before enabling persistent firewall rules.

## Updating

Back up `/var/lib/xshoter-control`, `/etc/xshoter-control`, and your web/database data before updating. For an intentional reinstall over an existing control database, the installer requires:

```bash
sudo XSHOTER_ALLOW_EXISTING=1 ./scripts/install.sh
```

## Security

Do not commit any live `.env`, API token, private key, TLS key, database file, database dump, setup token, session file, or production backup. See [SECURITY.md](SECURITY.md).

## Commercial use

GPL-3.0 permits commercial use. You may use Xshoter Control on servers that host paid or commercial services and you may provide the panel to your users at no charge. Distribution and modification must comply with GPL-3.0.

## License

Xshoter Control is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).

Third-party assets and their notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
