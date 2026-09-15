# Changelog

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
