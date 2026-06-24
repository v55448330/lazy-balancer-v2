# Handlers Knowledge Base

**Generated:** 2026-04-24
**File:** `internal/handlers/handlers.go` (3260 lines)

## OVERVIEW
All HTTP API handlers in one file (~3260 lines). Single-file anti-pattern.

## STRUCTURE
```
internal/handlers/
└── handlers.go    # ALL handlers + helpers (68 methods, single file)
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
| Nodes | RegisterNode, ListNodes, ListPendingNodes, ApproveNode, RejectNode, DeleteNode, UpdateNode, NodeHeartbeat | 2571-2712 |
| Sync | GetSyncStatus, GetSyncConfig, ManualSync | 2712-2818 |

## CONVENTIONS
- Handlers delegate to services (internal/services). NOT to db directly.
- Uses Gin context. JWT + API key auth via middleware.
- Helper functions: getOutboundIP, getHostname, getOSInfo, getKernel, getCaddyVersion, getUptime

## ANTI-PATTERNS
- **SINGLE FILE**: All 68 handler methods in one file (~3260 lines). Should be split by domain: `auth.go`, `users.go`, `rules.go`, `certs.go`, `nodes.go`, `sync.go`, `metrics.go`, `system.go`.
- **NEVER delete ports 80/443**: Line 1775: `// HTTP port 80 and HTTPS port 443 servers should never be deleted (default site)`

## NOTES
- Constructor: `NewHandlers(cfg, caddy, metrics, node, sync)` - deps injected
- Validation: `validatePort`, `validatePortFromDB`, `validateUpstreams`, `validateCaddyConfigBeforeSave`
- Caddy config: `applyCaddyConfig`, `applyCaddyConfigWithRollback` for atomic updates