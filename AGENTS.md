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
├── caddydeps/    # Local module pinning Caddy dependency floors (grpc/otel/x/net versions)
├── caddygeoip/   # Custom Caddy plugin: IP2Region GeoIP tagging handler
├── web/          # Vue 3 + TS frontend source
├── config/       # Caddyfile templates
├── data/         # SQLite persistent storage (lazy-balancer.db)
├── bin/          # Compiled binary (⚠️ NOT committed to git - see ANTI-PATTERNS)
├── docs/         # Project documentation
├── Dockerfile    # Unified build (xcaddy-builder → Go backend; frontend pre-built: `npm run build` first, Dockerfile COPYs web/dist)
├── docker-compose.yml  # Primary + slave test instance orchestration
└── .dockerignore # Build-context slimming (excludes data/certs/logs/secrets from image layers)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Backend Entry | `cmd/server/main.go` | Application startup and config |
| Core Logic | `internal/` | DB schema, API handlers, Caddy orchestration |
| Frontend Source | `web/src/` | Vue components and state management |
| Database Schema | `internal/db/db.go` | SQLite table definitions & migrations |
| Caddy Logic | `internal/services/caddy.go` | Config generation, L4 builder (`buildTCPProxyRoute`/`buildTCPServer`) |
| MCP Service | `internal/mcpserver/` | MCP tool specs (`tools.go`), server (`server.go`), bundled playbook resource |

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

## 全项目审计标准（用户裁定，长期有效——除非用户当次另行要求）
- **问题分类至少覆盖**：逻辑 bug、不合理逻辑、冗余代码、已弃用代码。
- **每条发现必须**：①读码核实真实有效（file:line + 代码证据，禁止臆测）②判定是否本来就这么设计（区分：有意设计 / 设计漂移 / 缺陷）③评估设计合理性。
- **审查必须结合页面功能、配置项、UI 文案描述**：UI 语义 → 存储 → 消费 → 真实渲染三链对照，不能只判断代码逻辑。
- **按功能域拆分审计任务**：安全模块 / 负载均衡模块 / 集群管理模块 / 证书模块 / 系统模块（认证与权限、日志、系统设置）/ API 与 MCP / 前端基础设施。
- **不过度修复**：发现先进详细报告，拿不准的（尤其涉及改动既有设计/行为契约）必须问用户裁定，不得直接修改。
- **报告必须详尽**：所有设计裁量、行为变更、契约影响、待裁定项在报告中完整可见，不允许只存在于思考过程。
- **认证底线（2026-09 裁定）**：登录后零密码输入（唯一例外=改密验当前密码，纯 bcrypt 不计数）；全系统唯一锁定=登录阶段密码+MFA 验证码同计 5 次/10 分钟、受「登录失败锁定」开关控制；API Key 无密码门、改密不吊销 Key；MFA 验证失败（登录后）只提示不计数。
- **发布底线**：镜像 tag 与 git 提交版本同步发布。
