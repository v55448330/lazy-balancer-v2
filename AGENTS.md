# PROJECT KNOWLEDGE BASE: Lazy Balancer V2

**Generated:** 2026-04-24
**Stack:** Go 1.26, Caddy v2.11.4, Vue 3, TypeScript, Vite, SQLite

## OVERVIEW
Lazy Balancer V2 is a full-stack load balancer management system that orchestrates Caddy server configurations to provide dynamic routing, health checking, and traffic balancing.

## STRUCTURE
```
./
├── cmd/server/    # Backend entry point (main.go)
├── internal/     # Core business logic (DB, Handlers, Services)
├── web/          # Vue 3 + TS frontend source
├── config/       # Caddyfile templates
├── data/         # SQLite persistent storage (lazy-balancer.db)
├── bin/          # Compiled binary (⚠️ NOT committed to git - see ANTI-PATTERNS)
├── docs/         # Project documentation
└── Dockerfile    # Unified build (xcaddy-builder → Go backend; frontend pre-built: `npm run build` first, Dockerfile COPYs web/dist)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Backend Entry | `cmd/server/main.go` | Application startup and config |
| Core Logic | `internal/` | DB schema, API handlers, Caddy orchestration |
| Frontend Source | `web/src/` | Vue components and state management |
| Database Schema | `internal/db/db.go` | SQLite table definitions & migrations |
| Caddy Logic | `internal/services/caddy.go` | Config generation, L4 builder (`buildTCPProxyRoute`/`buildTCPServer`) |

## CONVENTIONS
- **Backend**: Standard Go project layout. Private logic resides in `internal/`.
- **Frontend**: Vue 3 Composition API + Vite. Strict TypeScript mode.
- **Deployment**: Docker Compose orchestration.

## ANTI-PATTERNS (THIS PROJECT)
- **Root Binaries**: Avoid committing compiled binaries to the root `/bin` folder.
- **Direct DB Edits**: Use the provided `internal/db` abstractions for database interactions.

## COMMANDS
```bash
# Build (no Makefile - use docker or Go directly)
docker compose build
go build -o bin/lazy-balancer ./cmd/server

# Orchestration
docker compose up -d
docker compose down -v # Reset DB and containers
```

## NOTES
- **Testing**: Go unit tests exist under `internal/` (run `go test ./...`). No frontend tests.
- **UI Staging**: `/web/dist`（vite 产物）直接由 Dockerfile COPY 进镜像 `/app/ui`；宿主 `ui/` 目录已废弃（gitignored）。
- **Build**: No Makefile - use `docker compose build` or compile Go directly with `go build -o bin/lazy-balancer ./cmd/server`
```
