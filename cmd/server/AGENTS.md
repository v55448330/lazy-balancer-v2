# cmd/server AGENTS.md

## OVERVIEW
Backend entry point. Parses flags, loads config, initializes DB, starts HTTP server with background services.

## STRUCTURE
main.go (83 lines)

## WHERE TO LOOK
- Startup: lines 23-40 (flag parse, config load, DB init)
- Service init: lines 42-49 (Caddy, Metrics, Node, Sync)
- Graceful shutdown: lines 64-75 (signal handling, service stop)
- HTTP server: lines 77-81

## CONVENTIONS
- Entry point at `cmd/<app>/main.go`
- Flag parsing with Go standard library

## ANTI-PATTERNS
- Binary stays out of this directory

## NOTES
Main process. Background services started as goroutines:
- CaddyService: Caddy orchestration
- MetricsService: Periodic metrics collection
- NodeService: Health checking via heartbeat
- SyncService: Caddy config sync

Starts on port from config. Applies saved Caddy config on startup if available.