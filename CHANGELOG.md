# Changelog

## 1.0.2 - 2026-09-17

- Added commercial Hosting Provider mode with configurable plans and client lifecycle management.
- Added isolated Linux hosting accounts, SFTP chroot, website/database/file/backup/cron controls, and application installers.
- Added monthly bandwidth metering and automatic HTTP 509 enforcement when a plan limit is exceeded.
- Added per-plan CPU, RAM, and process limits using systemd/cgroup v2, including PHP-FPM, cron, and Node/Python app integration.
- Added automatic reconciliation so existing hosted application services move into the correct client resource slice.
- Added configurable File Manager upload limits and package-level resource enforcement.
- Expanded Cloudflare account, zone, DNS, and Tunnel automation without hardcoded production domains.
- Added hosting account expiry, suspend/reactivate, plan upgrade/downgrade, and session revocation workflows.
- Improved mobile layouts and Indonesian, English, Malay, and Vietnamese coverage for hosting/provider workflows.
- Extended release validation to include Provider and Cloudflare modules.

## 1.0.1 - 2026-09-15

- Added Xshoter release notifications with a bell beside the language selector.
- Added stable-release checks against the official GitHub releases feed.
- Added separate Xshoter application updates and Debian/Ubuntu package updates.
- Added update modes: Off, Notify Only, and Automatic Stable Updates.
- Added a root-only updater service and daily systemd timer.
- Added staging validation, application/database backup, health checks, and automatic rollback.
- Added authenticated update status/settings/run APIs in the control service with a root-owned systemd path trigger for manual updates.
- Added archive path, member-type, member-count, and expanded-size safety checks.
- Preserved existing panel database and configuration during application upgrades.

## 1.0.0 - 2026-09-15

- Initial public release preparation.
- Independent Node.js control plane and Go privileged agent.
- Website, database, file, backup, firewall, cron, service, SSH, logs, users, security, DNS, SSL, PHP, process, package, and system modules.
- Responsive mobile UI.
- Indonesian default UI with English, Malay, and Vietnamese translations.
- PNG language flags.
- Optional Cloudflare configuration without hardcoded production zone data.
- Optional phpMyAdmin one-time-token integration.
- Fresh Debian/Ubuntu installs configure Fail2Ban SSH protection with the systemd journal backend.
- Fresh installs include Certbot for local Let's Encrypt certificate issuance.
- Fresh installs load Xshoter-managed Nginx website vhosts from `/etc/nginx/xshoter/sites-enabled/`.
- Fresh installs snapshot the current iptables filter table so panel-managed firewall rules can persist safely.
- GPL-3.0 licensing and GitHub-safe secret exclusions.
