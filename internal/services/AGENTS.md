# PROJECT KNOWLEDGE BASE: Lazy Balancer V2 (Services)

**Generated:** 2026-04-24
**Scope:** Business Logic Services

## OVERVIEW
Business logic services: Caddy orchestration, metrics collection, node sync, health monitoring.

## STRUCTURE
- `caddy.go` - CaddyService: Caddyfile generation, admin API calls, route management
- `services.go` - MetricsService (traffic/health), NodeService (registration), SyncService (master-slave config sync)

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Caddy config generation | `caddy.go:GenerateCaddyConfig()` |
| Caddy admin API calls | `CaddyService.*` methods |
| Metrics collection | `MetricsService.collect()` |
| Node registration | `NodeService` heartbeat methods |
| Master-slave sync | `SyncService.SyncFromMaster()` |

## CONVENTIONS
- Services called by handlers, NOT by other services (layering)
- CaddyService mutex protects config writes
- MetricsService runs background ticker collection
- SyncService is master-slave only

## ANTI-PATTERNS
- Direct DB edits: use `internal/db` abstractions
- Calling services from other services: use handlers as coordinators

## NOTES
- `CaddyService` owns all Caddy admin API communication
- `GenerateCaddyID()` creates unique LB rule IDs
- `GenerateSingleRuleCaddyConfig()` generates per-rule config
- Health checks via Caddy metrics endpoint parsing
- Sync service reads `global_config` for master URL