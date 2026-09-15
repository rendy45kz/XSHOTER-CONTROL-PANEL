# Security Policy

Xshoter Control performs privileged server administration. Treat every installation as security-sensitive.

## Deployment requirements

- Use HTTPS. The self-signed installer certificate is intended only for initial access.
- Prefer a trusted TLS certificate or a protected reverse proxy.
- Keep the control service bound to loopback and the privileged agent on its Unix socket.
- Do not expose `/run/xshoter-agent.sock` through a network service.
- Use SSH public-key authentication for server administration.
- Use least-privilege Cloudflare API tokens.
- Keep Debian/Ubuntu, Node.js, Nginx, MariaDB, PHP, and Go security updates current.
- Back up configuration and application data before panel upgrades.

## Secrets that must never be committed

- Cloudflare/API tokens
- TLS/private keys
- SSH private keys
- setup tokens
- control database files
- database credential JSON files
- database dumps
- session/cookie data
- production backup archives

The repository `.gitignore` blocks common secret and runtime file types, but maintainers must still review every commit before publishing.

## Reporting vulnerabilities

For a public deployment, configure a private security contact in your GitHub repository and use GitHub Private Vulnerability Reporting when available. Do not publish active exploit details in a public issue before a fix is available.
