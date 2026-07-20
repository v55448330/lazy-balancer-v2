# Handlers Knowledge Base

**Generated:** 2026-04-24
## OVERVIEW
HTTP API handlers, split by domain across multiple files.

## STRUCTURE
```
internal/handlers/
├── handlers.go            # Handlers struct, shared deps, helpers
├── auth.go / users.go     # auth, user management, first-run setup
├── rules.go               # LB rule CRUD + enable/disable + ACME lifecycle
├── caddy.go               # global config, Caddy control, config preview
├── certificates.go / certjobs.go / caproviders.go
├── cluster_*.go           # cluster registration, mode, sync, status, backup import
├── config_backup.go / config_import_v1.go
├── metrics.go / system.go / branding.go / apidocs.go
└── audit.go / auditlog.go # audit helpers and audit log query
```

## WHERE TO LOOK
| Domain | Handler Methods | Line Range |
|--------|-----------------|------------|
| Auth | Login, Logout, GetCurrentUser | 593, 646, 652 |
| Users | ListUsers, CreateUser, UpdateUser, DeleteUser, ToggleUserStatus, ResetUserPassword | 741-909 |
| API Keys | ListAPIKeys, CreateAPIKey, DeleteAPIKey | 909-985 |
| LB Rules | ListRules, GetRule, CreateRule, UpdateRule, DeleteRule, DuplicateRule, EnableRule, DisableRule | 993-2011 |
| Certificates | ListCertificateConfigs, CreateCertificateConfig, UpdateCertificateConfig, DeleteCertificateConfig | 313-413 |
| ACME | ListCertificates, IssueCertificate | 2818-2840 |
| Metrics | GetMetricsOverview, GetRuleMetrics, GetMetricsHistory | 2484-2571 |
| System | GetSystemInfo, GetSystemMetrics, GetRealtimeTraffic, GetConnectionStats | 2840-2883 |
| Caddy | GetCaddyStatus, GetCaddyConfig, PutCaddyConfig, StartCaddy, StopCaddy, RestartCaddy | 3016-3130 |
| Cluster | Registration, approval, status, mode, snapshot, report, and manual pull | `cluster_*.go` |

## CONVENTIONS
- Handlers delegate to services (internal/services). NOT to db directly.
- Uses Gin context. JWT + API key auth via middleware.
- Helper functions: getOutboundIP, getHostname, getOSInfo, getKernel, getCaddyVersion, getUptime

## ANTI-PATTERNS
- **NEVER delete ports 80/443**: Line 1775: `// HTTP port 80 and HTTPS port 443 servers should never be deleted (default site)`

## NOTES
- Constructor: `NewHandlers(Dependencies)` - cluster, sync, Caddy, metrics, and CA dependencies injected
- Validation: `validatePort`, `validatePortFromDB`, `validateUpstreams`, `validateCaddyConfigBeforeSave`
- Caddy config: `applyCaddyConfig`, `applyCaddyConfigWithRollback` for atomic updates
