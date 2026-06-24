# PROJECT KNOWLEDGE BASE: Lazy Balancer V2 (Internal)

**Generated:** 2026-04-24
**Scope:** Backend Core Logic

## OVERVIEW
The `internal/` directory contains the private business logic for the load balancer. It manages state via SQLite, exposes the API surface, and orchestrates Caddy server configurations.

## STRUCTURE
```
./
├── caddy/       # Caddy-specific types and helpers
├── config/      # Application configuration logic
├── db/          # SQLite schema and persistence
├── handlers/    # HTTP API request handlers (see handlers/AGENTS.md)
├── middleware/  # Request interceptors (auth, logging)
├── models/      # Shared data structures
└── services/    # Core business services (see services/AGENTS.md)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| DB Schema | `internal/db/db.go` | Table definitions and migrations |
| API Logic | `internal/handlers/handlers.go` | Endpoint implementations |
| Caddy Orchestration | `internal/services/caddy.go` | Config generation and API calls |
| Shared Models | `internal/models/` | Request/Response and DB entities |

## CONVENTIONS
- **Private Logic**: All code here is inaccessible to external packages.
- **Service Pattern**: Handlers delegate business logic to `internal/services`.
- **DB Access**: Use abstractions in `internal/db` for all database operations.
