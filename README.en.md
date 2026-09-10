# Lazy Balancer V2

[English](README.en.md) | 简体中文

A visual load balancing platform built on **Caddy v2.11**, with a full WAF security stack, delivered as a single container.

## Features

| Feature | Description |
|---|---|
| Load Balancing | HTTP/HTTPS/TCP L4 proxy, multiple strategies, health checks, path routing |
| WAF Security | OWASP CRS + custom rules + IP control + GeoIP blocking + rate limiting |
| Free Certificates | ACME auto-issuance (DNS-01), auto-renewal |
| Primary-Replica Cluster | Incremental sync, tamper-proof signatures, read-only replicas |
| Monitoring | Traffic/latency P50-P99, upstream health, security event dashboard |
| MCP Service | AI agents can operate all features via 127 tools |

## Quick Start

```bash
docker run -d --name lazy-balancer --network host \
  --ulimit nofile=1048576:1048576 \
  -v $(pwd)/data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  v55448330/lazy-balancer-v2:latest
```

Open `http://localhost:8000` for the admin panel. First visit opens an initialization wizard; no default credentials.

<details>
<summary>Docker Compose / Build from Source</summary>

```bash
# Docker Compose
docker compose up -d

# Build from source
cd web && npm install && npm run build && cd ..
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v2.2.7 \
  -t v55448330/lazy-balancer-v2:v2.2.7 --push .
```
</details>

## Documentation

| Document | Contents |
|---|---|
| [Deployment](docs/deployment.zh-CN.md) (中文) | Mounts, environment variables, ports, production flags |
| [Security](docs/security.zh-CN.md) (中文) | WAF policies, IP control, event collection, rule updates |
| [Cluster](docs/cluster.zh-CN.md) (中文) | Primary-replica architecture, MFA, security model, upgrades |
| [Production Tuning](docs/production-tuning.zh-CN.md) (中文) | Five-layer tuning: kernel/container/LB/WAF/HTTP3 |

## Community

<div align="center">

**LazyBalancer QQ Group** · **303410331**

<img src="docs/qq-group-qr.webp" alt="QQ Group" width="240">

</div>

## Tech Stack

Go 1.26 · Gin · SQLite · Caddy v2.11 · Coraza v3 · OWASP CRS v4 · Vue 3 · Element Plus

## License

[Apache License 2.0](LICENSE)
