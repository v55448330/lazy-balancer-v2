# Lazy Balancer V2

English | [简体中文](README.zh-CN.md)

A visual load balancing management platform built on **Caddy v2.11 + caddy-l4** (Go + Vue 3, delivered as a single container), with a full WAF security stack built in.

## Feature Overview

- **Load Balancing**: HTTP/HTTPS reverse proxy and TCP layer-4 proxy; weighted round robin (percentage-interlocked), least connections, IP hash, cookie sticky sessions; active/passive health checks with failover; path-level custom routing; proxy timeouts with global defaults plus per-rule overrides (incl. SSE/LLM streaming); TCP PROXY v2 to pass the real client IP through
- **Security**: Coraza v3 WAF + OWASP CRS v4 (detection/blocking dual modes); IP2Region region control; IP allowlist/blocklist/trusted list; rate limiting; custom rules; customizable block page and status codes; security event collection with an overview dashboard (see the dedicated section below)
- **Free Certificates**: Let's Encrypt / ZeroSSL ACME automatic issuance (DNS-01, DNSPod/Tencent Cloud, accelerated by querying authoritative NS directly), automatic renewal, backoff retries, manual upload
- **Primary-Replica Cluster**: registration approval, incremental sync (rules/certificates/users/keys/settings/security policies), status reporting, one-click promotion; snapshot HMAC-SHA256 signatures against tampering and replay; replicas fully read-only
- **Monitoring**: traffic/rate/latency percentiles (P50/95/99), three-state upstream health, per-rule metrics with historical trends, per-rule access logs (JSON, live view) and TOP statistics
- **Admin Panel HTTPS**: one-click force HTTPS (self-signed or uploaded certificate), automatic HTTP 301 redirect, automatic restart after replica sync
- **MCP Service**: AI agents operate all features via Streamable HTTP + API Key (read-only keys automatically collapse to a read-only toolset, IP allowlist supported), with the operation manual bundled as an MCP resource
- **Multi-user & API**: admin/read-only users, API keys (SHA-256), password changes instantly revoke old JWTs, RESTful v1 API + OpenAPI docs
- **Operations**: operation logs record every action in Chinese; config backup export/import (zero writes on validation failure, compatible with v1 nginx backups); branding (app name/footer/version)

## Quick Start

```bash
# Docker Compose (recommended)
cd web && npm install && npm run build && cd ..
docker compose up -d --build

# Multi-arch image
docker buildx build --platform linux/amd64,linux/arm64 -t <image>:<tag> --push .

# docker run
docker run -d --name lazy-balancer --network host \
  -v $(pwd)/data:/app/data -v $(pwd)/logs:/app/logs \
  -v $(pwd)/certs:/app/certs -v $(pwd)/waf:/app/waf \
  -e LOG_FILE=/app/logs/lazy-balancer.log \
  v55448330/lazy-balancer-v2:v2.1.6
```

> The image must bind host ports 80/443 plus custom listen ports directly; `--network host` is recommended on Linux. On macOS/Windows use `-p 8000:8000 -p 80:80 -p 443:443`. The first visit to `http://<host>:8000` opens an initialization wizard that creates the admin account; there are no default credentials.

## Mounted Directories

| Container Path | Contents | Required |
|---|---|---|
| `/app/data` | Business/audit/metrics databases, branding.json, ACME account keys, IP2Region province cache | **Yes** |
| `/app/certs` | Certificates and private keys (manual uploads and ACME-issued) | **Yes** |
| `/app/logs` | Application logs, Caddy logs, per-rule access logs, rule-set update logs | Recommended |
| `/app/waf` | CRS rule files, IP2Region xdb, Coraza audit logs; preserved across container rebuilds | Recommended |
| `/app/config` | Caddyfile (advanced customization only) | Optional |

> Without `/app/waf` mounted, rebuilding the container rolls CRS back to the version bundled in the image; the system persists an updated rule-tree snapshot to the data volume and reconciles and restores it automatically on startup (recorded in the operation log). Mounting the directory avoids the rollback entirely. The database is the single source of truth for configuration; the Caddy config is rendered from it in real time.

## Environment Variables & Configuration

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | Auto-generated, persisted to `data/jwt_secret` | JWT signing key; recommended to set explicitly in production |
| `LOG_FILE` | Empty | Application log is also written to this file, viewable in the UI |
| `NODE_NAME` | `node-1` | Default node name for cluster registration |
| `APP_VERSION` | Injected at build | Displayed version number |
| `TZ` | Database `timezone` | Process timezone; restart recommended after changing it |

Cluster roles are configured on the "System Settings → Cluster Management" page (not via environment variables). Log level, timezone, log retention, and audit log size are all configured on the "Basic Settings" page.

`data/branding.json` customizes branding (effective immediately after changes; leave `version` empty to show the build version):

```json
{ "app_name": "Lazy Balancer", "footer_text": "Copyright © 2026 XiaoBao.", "version": "" }
```

| Port | Purpose |
|---|---|
| `8000` | Admin UI and REST API (docs at `/api/v1/docs`) |
| `80 / 443` | HTTP/HTTPS proxy traffic |
| `2019` | Caddy Admin API (loopback only) |
| Custom | TCP rule listen ports |

## Security Subsystem

Request processing chain (a block at any stage returns the configured status code and block page immediately):

```
Inbound → GeoIP tagging → Rate limiting (per-IP rate + burst) → WAF (Coraza + CRS + custom rules)
       → IP ACL → Request body size limit → Reverse proxy
```

| Component | Version |
|---|---|
| WAF engine | Coraza v3 (coraza-caddy v2.5.0) |
| Rule set | OWASP CRS v4.28.0 (bundled, online updates supported) |
| GeoIP database | IP2Region v3.17.0 (offline xdb, China province-level) |
| Rate limiting | caddy-ratelimit v0.1.0 |

**Security policies** are managed as standalone entities bound to HTTP rules (one policy can bind multiple rules; one rule binds only one policy):

| Setting | Options |
|---|---|
| WAF mode | Off / Detection (log only) / Blocking (403 once the anomaly score reaches the threshold) |
| Anomaly threshold | 1/3/5/10/20; lower is stricter |
| CRS rule groups & exclusions | Load by attack-type group / exclude by file name |
| Custom rules | Multi-condition chained matching on URI/args/headers/body/User-Agent (contains/regex/exact/prefix), with assignable scores |
| IP access control | Allowlist (allow only) / blocklist (deny) / trusted list (skip inspection), CIDR |
| Region control | Block selected regions / allow only selected regions, based on IP2Region |
| Rate limiting | Per-IP rate cap plus burst allowance |
| Block response | Custom HTML block page + status code (400/401/403/404/429/503, unified across WAF/IP ACL/rate limiting) |

**Security events**: WAF blocks (parsed from Coraza audit logs, covering CRS and custom rules) and IP ACL denials are collected automatically, with trend charts and TOP attack types / source IPs / regions; retention is shared with the operation log. Audit logs rotate automatically by size (default 10 MB × 5 files).

**Rule set updates**: CRS and IP2Region support one-click manual updates and daily automatic updates (progress logged live, automatic rollback on failure, results recorded). Every successful update persists the rule tree (including user customization migration files) as a snapshot on the data volume; if a container rebuild rolls the disk state back, startup reconciliation restores it automatically.

## Primary-Replica Cluster

1. Primary node: Cluster Management → generate a registration token (one-time, valid for 30 minutes)
2. Replica node: choose "Replica", enter the primary address + token to register
3. Primary node: click "Confirm" in the node list; the replica starts syncing and reports periodically
4. Replicas are fully read-only (except Cluster Management) and can "Promote to Primary" to leave the cluster

Configuration changes on the primary auto-increment the cluster version; replicas sync incrementally by section hash. Security policies, CRS/IP2Region versions, and settings are all within the sync scope.

**MFA (v2.1.8)**: TOTP two-step login (Google/Microsoft Authenticator). Self-service binding in Settings → 基础设置 → MFA card (QR + 10 one-time recovery codes, stored as SHA-256). Disable requires password + valid code. Global toggles (default off): write-operation step-up (60s window, 428 + global retry) and verification-failure lockout (5 fails → 10 min). Cluster slave login tickets require admin MFA enabled; users' MFA state syncs via cluster snapshot and full config backup. Admin can reset any user's MFA (audited).

**Security model**: cluster tokens and CA/DNS credentials are stored in plaintext in `data/lazy-balancer.db` (tokens are needed for HMAC signature verification and cannot be hashed; startup forces database `0600` and data directory `0700`), so do not mount that directory shared. Cluster communication defaults to HTTPS with TOFU fingerprint pinning against MITM; plain-HTTP master addresses are allowed for trusted networks (with an audit warning — TOFU pinning does not apply to plain HTTP, so registration tokens and synced certificate keys travel unencrypted). Tokens have no built-in automatic rotation, but regenerating the registration token invalidates all unused tokens (old tokens expire immediately); if you suspect a leak, delete the node record and re-register.

## Configuration Backup & Migration

- **Export/Import**: System Information → Configuration Backup (full JSON, validated before import; zero writes if Caddy validation fails); importing a v2 backup requires a file exported by ≥ v2.1.2
- **Export is a complete backup**: the exported file contains all configuration (including DNS/ACME credentials, certificates and private keys, password hashes) and can fully restore a working deployment; store backup files carefully and guard against leakage
- **v1 migration**: just pick a v1 (nginx-based) backup and load-balancing rules convert automatically (inline certificates included)

## Tech Stack & Image

Go 1.26 · Gin · SQLite · Caddy v2.11.4 + caddy-l4 v0.1.2 + caddy-ratelimit v0.1.0 · Coraza v3 · OWASP CRS v4 · IP2Region v3 · Vue 3 · Element Plus · Vite

```
v55448330/lazy-balancer-v2:v2.1.6
```

## License

[Apache License 2.0](LICENSE). Third-party components: Caddy/caddy-l4/caddy-ratelimit/Coraza/CRS/IP2Region (Apache 2.0), Gin/Vue/Element Plus (MIT), glebarez/sqlite (MIT), golang-jwt (MIT), x/crypto (BSD-3).
