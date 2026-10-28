# Lazy Balancer V2

English | [简体中文](README.md)

A visual load balancing platform built on **Caddy v2.11**, with a full WAF security stack, delivered as a single container.

## Features

| Feature | Description |
|---|---|
| Load Balancing | HTTP/HTTPS/TCP L4 proxy, multiple strategies, health checks, path routing |
| WAF Security | OWASP CRS + custom rules + IP control + GeoIP blocking + rate limiting |
| Crawler Exemption | Verify real search-engine/AI crawlers via UA + reverse DNS or official IP ranges and exempt them from GeoIP blocking; scheduled official crawler IP library updates |
| Free Certificates | ACME auto-issuance (DNS-01), auto-renewal |
| Primary-Replica Cluster | Incremental sync, tamper-proof signatures, read-only replicas, one-click promotion |
| Monitoring | Traffic/latency P50-P99, upstream health, security event dashboard |
| MCP Service | AI agents can operate all major features via MCP tools (tool list follows the runtime `tools/list`) |
| Auto Backup | Scheduled daily/weekly/monthly config backups to the server `backup` directory, one-click restore |

## Quick Start

**Linux (recommended, host network)**:

```bash
docker run -d --name lazy-balancer --network host \
  --restart unless-stopped \
  --pids-limit=4096 \
  --ulimit nproc=4096:4096 \
  --ulimit nofile=1048576:1048576 \
  --stop-timeout 30 \
  -v $(pwd)/data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  -v $(pwd)/backup:/app/backup \
  v55448330/lazy-balancer-v2:latest
```

**Docker Desktop (macOS/Windows, bridge network with port mapping)**:

```bash
docker run -d --name lazy-balancer \
  --restart unless-stopped \
  --pids-limit=4096 \
  --ulimit nproc=4096:4096 \
  --ulimit nofile=1048576:1048576 \
  --stop-timeout 30 \
  -p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp \
  -v lb-data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  -v $(pwd)/backup:/app/backup \
  v55448330/lazy-balancer-v2:latest
```

> Image tags: `latest` points at the most recent **stable** release (no channel suffix); pre-release tags carry a `-beta` suffix (e.g. `:v2.3.9-beta`). Pin that exact tag when you need a pre-release or a reproducible install.
>
> **Container init**: current images ship an init process (reaps abandoned health-check children) and use the binary's built-in health check, so `--init` is no longer needed. If you pin an older image, add `--init`. The examples default to `--pids-limit=4096` (PID cgroup, threads included) and also set `--ulimit nproc=4096:4096` (container `RLIMIT_NPROC`). Both apply only inside the container; the host ulimit needs no change, and the effective task cap is the lower of the two. Tune them to your deployment size.

> **Stop grace period**: the graceful shutdown chain can take up to 25 seconds (in-flight HTTP requests, Caddy draining, task draining, log flush). Docker's default stop grace period is only 10 seconds, after which the container is SIGKILLed — that is why the `docker run` examples pass `--stop-timeout 30` (the compose file already sets `stop_grace_period: 30s`). When using another orchestrator (systemd/Swarm/k8s), keep the stop grace period ≥25 seconds.

Mounts: `/app/data` database, config and IP geolocation data (required — the IP2Region xdb lives at `/app/data/ip2region.xdb` and persists with the data volume), `/app/certs` certificates and private keys (required), `/app/backup` auto-backup output directory (required — without it, backup files are lost when the container is recreated), `/app/logs` logs (recommended), `/app/waf` WAF/CRS rule sets (recommended).

> Host networking is recommended on Linux hosts only. Docker Desktop support for host networking varies by version/settings — use the `-p` command above and keep `/app/data` on the named volume (`lb-data`); bind mounts go through the FUSE sharing layer and risk SQLite WAL page loss (bind mounts on Linux hosts are unaffected). The repository `docker-compose.yml` pins the primary node to host networking and is intended for Linux development/deployment only.

Open `http://localhost:8000` for the admin panel. First visit opens an initialization wizard; no default credentials.

<details>
<summary>Docker Compose / Build from Source</summary>

```bash
# 1) Frontend artifacts (required before an image build: the Dockerfile only
#    copies the pre-built web/dist; skip when running the official image).
#    Frontend needs Node.js >= 22.18: `npm test` runs .ts files directly via
#    node --test, which relies on default type stripping since that version;
#    see the engines field in web/package.json
#    Use `npm ci` (not `npm install`): it installs strictly from
#    package-lock.json instead of rewriting the lock file in place.
cd web && npm ci && npm run build && cd ..

#    Artifact self-proof: web/dist is pre-built and copied into the image as-is,
#    so a stale dist is invisible (the panel version comes from the backend).
#    After building, compare the stamp with the current commit:
git rev-parse HEAD && cat web/dist/build-info.json

# 2) Docker Compose (Linux; the primary node uses host networking)
#    Mind the channel: the checked-in docker-compose.yml pins the current
#    development line's beta tag (e.g. vX.Y.Z-beta, kept in sync with the
#    Dockerfile VERSION by a gate). For a stable release use the `:latest`
#    tag from the example above, or change both image tags to the matching
#    stable tag.
docker compose up -d

# 3) Or build and push the image directly: VERSION is the formal version (what
#    the panel displays); the image tag may carry a -beta channel suffix - they
#    differ on purpose: tag minus suffix == APP_VERSION
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v2.3.9 \
  --provenance=false --sbom=false \
  -t v55448330/lazy-balancer-v2:v2.3.9-beta --push .   # beta channel; drop -beta for a stable release
```
</details>

## Documentation

| Document | Contents |
|---|---|
| [Deployment](docs/deployment.zh-CN.md) (中文) | Mounts, environment variables, ports, production flags |
| [Security](docs/security.zh-CN.md) (中文) | WAF policies, IP control, event collection, rule updates |
| [Cluster](docs/cluster.zh-CN.md) (中文) | Primary-replica architecture, MFA, security model, upgrades |
| [OIDC Login](docs/oidc.zh-CN.md) | Enterprise SSO via OIDC, Entra example (Chinese) |
| [Production Tuning](docs/production-tuning.zh-CN.md) (中文) | Five-layer tuning: kernel/container/LB/WAF/HTTP3 |
| [API Reference](docs/api.zh-CN.md) (中文) | REST endpoints, authentication, error codes |
| [MCP Service](docs/mcp.zh-CN.md) (中文) | AI agent integration, tool permissions, workflows |

## Community

<div align="center">

**LazyBalancer QQ Group** · **303410331**

<img src="docs/qq-group-qr.webp" alt="QQ Group" width="240">

</div>

## Tech Stack

Go 1.26 · Gin · SQLite · Caddy v2.11 · Coraza v3 · OWASP CRS v4 · Vue 3 · Element Plus

## License

[Apache License 2.0](LICENSE)
