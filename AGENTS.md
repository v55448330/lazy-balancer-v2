# PROJECT KNOWLEDGE BASE: Lazy Balancer V2

**Generated:** 2026-04-24
**Stack:** Go 1.26, Caddy v2.11.2, Vue 3, TypeScript, Vite, SQLite

## OVERVIEW
Lazy Balancer V2 is a full-stack load balancer management system that orchestrates Caddy server configurations to provide dynamic routing, health checking, and traffic balancing.

## STRUCTURE
```
./
├── cmd/server/    # Backend entry point (main.go)
├── internal/     # Core business logic (DB, Handlers, Services)
├── web/          # Vue 3 + TS frontend source
├── ui/           # Pre-built static assets/staging
├── config/       # Caddyfile templates
├── data/         # SQLite persistent storage (lazy-balancer.db)
├── bin/          # Compiled binary (⚠️ NOT committed to git - see ANTI-PATTERNS)
├── docs/         # Project documentation
└── Dockerfile    # Multi-stage build (xcaddy-builder, Go backend, Node frontend)
    Dockerfile.prebuilt  # Release build: skips frontend stage, COPY web/dist (run `npm run build` first)
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
- **UI Staging**: `/ui` directory is used for staging built assets; `/web` is the source of truth.
- **Build**: No Makefile - use `docker compose build` or compile Go directly with `go build -o bin/lazy-balancer ./cmd/server`
```
