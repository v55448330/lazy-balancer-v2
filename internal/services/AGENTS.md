# PROJECT KNOWLEDGE BASE: Lazy Balancer V2 (Services)

**Generated:** 2026-04-24
**Scope:** Business Logic Services

## OVERVIEW
Business logic services: Caddy orchestration, metrics collection, node sync, health monitoring.

## STRUCTURE
- `caddy.go` - CaddyService: Caddyfile generation, admin API calls, route management
- `services.go` - MetricsService (traffic/health)
- `cluster*.go` - ClusterService registration/status/snapshots, transactional slave apply, reporting, lifecycle, and SyncService polling

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Caddy config generation | `caddy.go:GenerateCaddyConfig()` |
| Caddy admin API calls | `CaddyService.*` methods |
| Metrics collection | `MetricsService.collect()` |
| Node registration | `cluster.go` token, registration, and approval methods |
| Master-slave sync | `cluster_sync.go`, `cluster_apply.go` |
| Role lifecycle | `cluster_lifecycle.go` |

## CONVENTIONS
- Services called by handlers, NOT by other services (layering)
- CaddyService mutex protects config writes
- MetricsService runs background ticker collection
- `global_config.is_master` is the role source of truth
- SyncService runs only on slaves; ACME lifecycle runs only on masters

## ANTI-PATTERNS
- Direct DB edits: use `internal/db` abstractions
- Calling services from other services: use handlers as coordinators

## NOTES
- `CaddyService` owns all Caddy admin API communication
- `GenerateCaddyID()` creates unique LB rule IDs
- `GenerateSingleRuleCaddyConfig()` generates per-rule config
- Health checks via Caddy metrics endpoint parsing
- SyncService authenticates with the per-node cluster token and reports after each cycle
