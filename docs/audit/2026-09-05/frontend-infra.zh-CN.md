# 前端基础设施审计报告（2026-09-05）

> 审计人：fe-infra-audit（全项目再审计 · 前端基础设施域）
> 性质：只读审计，未改动任何源码/配置/测试文件。本报告为唯一产出文件。

## 一、概览

### 1.1 范围文件清单

| 类别 | 文件 | 结果 |
|---|---|---|
| HTTP 客户端 | `web/src/utils/api.ts`（420 行，全文读） | 8 项发现涉及 |
| 横切工具 | `web/src/utils/saveResult.ts`、`restart.ts`、`branding.ts`、`copy.ts`、`date.ts`、`ansi.ts`、`highlight.ts`、`certJobStatus.ts`（全文读） | 各 0–2 项发现 |
| 状态机 | `web/src/stores/auth.ts`（269 行，全文读） | 3 项发现涉及 |
| 入口/骨架 | `web/src/main.ts`、`web/src/App.vue`、`web/src/components/layout/AppLayout.vue`（全文读） | 3 项发现涉及 |
| 路由 | 自研 hash + localStorage 页面切换（无 vue-router；`auth.ts` pages/`setCurrentPage` + `App.vue` v-if 分发 + `Settings.vue` tab 同步），已核实 | 2 项发现 |
| 类型 | `web/src/types/index.ts`、`web/src/types/rules.ts`（全文读），与后端 `internal/models/models.go`、`internal/handlers/branding.go`、`auth.go` 交叉核对 | 2 项发现 |
| composables | `usePollingTask.ts`、`usePollingErrorState.ts`、`useIpListAdd.ts`、`useCrsRuleIndex.ts`（全文读）及全部 8 个消费方核对 | 2 项发现 |
| 公共组件 | `layout/AppLayout.vue`、`CodeEditor.vue`、`SyntaxHighlight.vue`、`LogStorageBar.vue`、`AppLogo.vue`、`views/AsyncPageError.vue`（全文读） | 1 项发现涉及 |
| 样式/构建 | `web/src/styles/main.css`、`web/index.html`、`web/vite.config.ts`、`web/tsconfig.json`、`web/tsconfig.node.json`、`web/package.json`、`web/src/vite-env.d.ts` | 3 项发现 |
| 契约核对 | 根 `Dockerfile`、`docker-compose.yml`、`.dockerignore`、`internal/config/config.go`、`internal/middleware/middleware.go`、`README.md` | 3 项发现涉及 |

### 1.2 方法

1. 全文/分段精读上述文件（`read` 带 anchor，逐段核对，不用摘要转述）。
2. `grep` 引用计数核查每个导出符号/组件/依赖的实际消费方（死代码判定）。
3. 与后端交叉验证：路由权限矩阵（`internal/middleware/middleware.go` SetupRouter）、JSON 模型（`internal/models/models.go`）、`/branding`、`/auth/login` 响应形态、静态目录与 Dockerfile 产物路径。
4. 只读构建检查：`cd web && npx vue-tsc --noEmit` → **退出码 0，无类型错误**（未安装任何依赖、未写任何文件）。
5. 产物契约验证：`web/dist` 存在且 `index.html` mtime 晚于 `src/main.ts`；`.dockerignore` 未排除 `web/dist`。

### 1.3 结论摘要

- **未发现高严重度缺陷**。横切层（401 会话止损、428 MFA step-up 并发去重、轮询任务生命周期、时区回退、Blob 错误解析）经逐行核对设计自洽，注释与实现基本互相印证。
- 核心问题是**三类漂移**：①前端「非管理员全局只读」与后端权限矩阵不一致（规则/证书写操作后端对普通用户放行，中严重度，待裁定）；②版本回退字符串三处漂移（前端 v2.1.12 / config.go 2.1.9 / 实际发版 2.2.4）；③`web/AGENTS.md` 前端约定文档与现状不符（宣称 Tailwind、目录结构过时）。
- 死代码集中在**三个零引用 npm 依赖**与**三个零调用 RequestClient 重载**；另有多处小型重复实现（字节格式化、escapeHtml、轮询错误横幅样板）。
- 构建产物契约（`web/dist → /app/ui`）完整且 README 已文档化预构建步骤；`vue-tsc` 严格模式全绿。

## 二、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| FI-01 | stores/auth.ts:61-73 ↔ middleware.go:374-379/383-385/448-449 | 前后端契约漂移（权限矩阵） | 中 | 设计漂移（待裁定方向） |
| FI-02 | utils/branding.ts:15-16 ↔ Dockerfile:35 / config.go:52 | 已弃用代码（过时回退值） | 低 | 设计漂移 |
| FI-03 | web/package.json:12,14,18-19,24 | 已弃用代码（死依赖） | 低 | 设计漂移 |
| FI-04 | utils/api.ts:66-69 | 冗余代码（死重载） | 低 | 设计漂移 |
| FI-05 | utils/api.ts:27-60 ↔ views/Settings.vue:54-90 | 冗余代码（类型双定义） | 低 | 设计漂移 |
| FI-06 | stores/auth.ts:28-30,224-231 | 不合理逻辑（注释与实现不符：前进后退） | 低 | 设计漂移 |
| FI-07 | stores/auth.ts:237-244 + utils/api.ts:229-233 | 不合理逻辑（对已过期 token 仍发登出请求） | 低 | 缺陷（轻微） |
| FI-08 | components/layout/AppLayout.vue:318-325,351-355,137-147 | 不合理逻辑（看门狗轮询不暂停/从节点空转） | 低 | 设计漂移 |
| FI-09 | utils/api.ts:395-401 ↔ LogStorageBar.vue:44-54；Dashboard.vue:1099 / Rules.vue:3280 / Users.vue:716 | 冗余代码 | 低 | 设计漂移 |
| FI-10 | utils/branding.ts:19-20 ↔ utils/ansi.ts:4-10 | 冗余代码（escapeHtml 双实现） | 低 | 设计漂移 |
| FI-11 | Rules.vue:3156-3181 / CertJobs.vue:421-444 / ClusterSettings.vue:599-629 | 冗余代码（三处逐字样板） | 低 | 有意设计（但已到提取阈值） |
| FI-12 | types/index.ts:7 ↔ models.go:21-29 | 类型漂移（mfa_enabled 可空性） | 低 | 有意设计（宽松防御） |
| FI-13 | web/AGENTS.md:3,10-17,19-26 | 文档漂移 | 低 | 设计漂移 |
| FI-14 | composables/usePollingTask.ts:40-44,64,82 | 不合理逻辑（onError 抛错逃逸） | 低 | 缺陷（防御缺口，无现实触发路径） |
| FI-15 | utils/api.ts:327,347,362 | 不合理逻辑（私有标记属性脱离类型检查） | 低 | 有意设计（权衡） |
| FI-16 | utils/branding.ts:42 + AppLayout.vue:9 + Login.vue:9 | 不合理逻辑（" V2" 后缀硬拼） | 低 | 待裁定 |
| FI-17 | utils/copy.ts:12-19 | 已弃用代码（document.execCommand） | 低 | 有意设计（兼容回退） |
| FI-18 | stores/auth.ts:134-135,160-161 | 逻辑 bug（重入返回假成功形态） | 低 | 缺陷（当前无触发路径） |
| FI-19 | utils/restart.ts:9-23 + api.ts:220-223 | 不合理逻辑（deadline 与单次 30s 超时叠加） | 低 | 有意设计（边界可容忍） |
| FI-20 | App.vue:10 ↔ stores/auth.ts:60 | 冗余代码（isLoggedIn 重复实现） | 低 | 设计漂移 |

统计：共 **20** 项。
- 按分类：逻辑 bug 1（FI-18）；不合理逻辑 8（FI-06/07/08/14/15/16/19 及 FI-01 计入契约漂移单列）；冗余代码 6（FI-04/05/09/10/11/20）；已弃用代码 3（FI-02/03/17）；契约/类型/文档漂移 4（FI-01/12/13 + FI-02 兼）。
- 按严重度：高 0；中 1（FI-01）；低 19。
- 按判定：有意设计 6；设计漂移 12；缺陷 3（FI-07/14/18，均为低）。

## 三、逐条详述

### FI-01 前端「非管理员全局只读」与后端权限矩阵不一致（中 / 设计漂移 / 待裁定）

**位置**：
- `web/src/stores/auth.ts:61-67`
- `internal/middleware/middleware.go:374-379, 383-385, 448-449`（business 组）、`257-335`（admin 组）、`886-897`（adminOnly）

**代码证据**（前端把非管理员一律判只读）：
```ts
// stores/auth.ts:61-67
const readOnlyReason = computed<'slave' | 'non-admin' | 'unknown' | null>(() => {
  if (nodeMode.value === 'slave') return 'slave'
  if (user.value) return user.value.role !== 'admin' ? 'non-admin' : null
  ...
})
```
Rules.vue / FreeCertificates.vue / CertJobs.vue 的全部写按钮均 `:disabled="isReadOnly ..."`（如 `views/Rules.vue:11` `:disabled="isReadOnly || saving"`）。

**代码证据**（后端对普通用户放行规则与证书写操作——挂在 business 组，无 adminOnly）：
```go
// middleware.go:374-379（business 组，仅 readOnlyGuard）
business.POST("/rules", h.CreateRule)
business.PUT("/rules/:caddy_id", h.UpdateRule)
business.DELETE("/rules/:caddy_id", h.DeleteRule)
business.POST("/rules/:caddy_id/enable", h.EnableRule)
...
// middleware.go:383-385
business.POST("/certificate-configs", h.CreateCertificateConfig)
business.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
business.DELETE("/certificate-configs/:id", h.DeleteCertificateConfig)
// middleware.go:448-449
business.POST("/certificates/jobs/:id/retry", h.RetryCertJob)
business.DELETE("/certificates/jobs/:id", h.DeleteCertJob)
```
adminOnly 仅覆盖 admin 组（用户管理、system/restart、config 导入导出、security 写、api-keys 写等）。

**分类**：前后端权限矩阵漂移（接缝问题）。
**判定**：设计漂移。依据：前端注释（auth.ts:63、AppLayout.vue:202-205 A6-S3）明确表达「非管理员只读」是主动策略且与后端自助能力（`PATCH /users/me`、MFA 自助端点）刻意区分；但后端 business 组同时放行了规则/证书写，两侧对 `role=user` 的能力边界没有共同事实源。读侧一致（`GET /users`、`GET /config`、`GET /cluster/*` 后端注释「所有已登录用户可读」，apidocs.go:41），不一致仅在写侧。
**影响**：用普通账号直接调 API（绕过 UI）可创建/修改/删除负载均衡规则与证书配置；前端只读仅为 UI 约束。若产品意图是「普通用户完全只读」，后端属权限缺口（安全相关，建议转 `sec-core-audit`/`lb-rules-audit` 域复核）；若意图是「普通用户可管规则」，则前端过度收紧。
**建议**：裁定产品语义后二选一对齐：后端将 rules/certificate-configs/cert-jobs 写操作迁入 admin 组，或前端放开 non-admin 的规则编辑。至少应在后端 apidocs 的权限矩阵中显式记录当前口径。
**是否待裁定**：是（方向性裁决）。

### FI-02 版本回退字符串三处漂移：前端 v2.1.12 / config.go 2.1.9 / 实际 2.2.4（低 / 设计漂移）

**位置**：`web/src/utils/branding.ts:15-16`、`internal/config/config.go:52`、`Dockerfile:35`、`docker-compose.yml:5,14`

**代码证据**：
```ts
// branding.ts:15-16
// R72 二十九次：发版检查单——发版时需同步 bump 此回退版本。
export const appVersion = ref('v2.1.12')
```
```dockerfile
# Dockerfile:35
ARG VERSION=2.2.4
```
```go
// config.go:52（裸跑 go run 时的兜底）
Version:         getEnv("APP_VERSION", "2.1.9"),
```
另 `views/settings/BasicSettings.vue:274-281` 维持独立的 `appVersion = ref('-')`，从 `/system/info` 读取（该值最终来自 `h.cfg.Version`，可被 branding.json 覆盖，branding.go:95-98）。

**分类**：已弃用代码（过时回退值）。
**判定**：设计漂移。依据：注释自认「发版检查单需同步 bump」，但已落后实际版本两个小版本（2.1.12 → 2.2.4），说明检查单未被执行；config.go 的 2.1.9 又是第三个不一致值。
**影响**：仅当 `/branding` 请求失败时（如 API 网关故障的降级窗口），Login 页（`Login.vue:115` `版本 {{ appVersion }}`）显示过时版本号，误导排障。正常运行时无影响（后端 `/branding` 返回 cfg.Version 或 APP_VERSION）。
**建议**：发版脚本化注入（如 vite `define` + 环境变量），消除手工检查单；或至少本次同步 bump 至 v2.2.4。
**是否待裁定**：否。

### FI-03 三个零引用 npm 依赖 + @types/qrcode 位置错误（低 / 设计漂移）

**位置**：`web/package.json:12,14,18-19,24`

**代码证据**：
```json
"dependencies": {
    "@types/qrcode": "^1.5.5",      // 类型包放错分组
    ...
    "asn1js": "^3.0.10",             // web/src 零引用
    ...
    "pkijs": "^3.4.0",               // web/src 零引用
    ...
    "vue-json-pretty": "^2.6.0"      // web/src 零引用
}
```
**核查**：`grep -rn "asn1js|pkijs|vue-json-pretty" web/src` → 0 命中；证书解析已迁移到后端（`views/Rules.vue:2068` `request.post<APIResponse<CertificateParseResult>>('/certificates/parse', ...)`）；`qrcode` 仅 `Users.vue:203` 使用（MFA 二维码）。
**分类**：已弃用代码（死依赖）。
**判定**：设计漂移。依据：功能移到后端/组件移除后依赖未清理，无任何「保留待用」注释。
**影响**：安装体积与安全面（供应链扫描噪音）增大；`@types/qrcode` 位于 dependencies 虽被打包器忽略但分类失当。
**建议**：`npm uninstall asn1js pkijs vue-json-pretty`；`@types/qrcode` 移入 devDependencies。
**是否待裁定**：否。

### FI-04 RequestClient 三个死重载（/caddy/metrics、/caddy/host-metrics、/metrics/overview）（低 / 设计漂移）

**位置**：`web/src/utils/api.ts:66-69`

**代码证据**：
```ts
get(url: '/caddy/metrics', config?: AxiosRequestConfig): Promise<APIResponse<CaddyMetrics>>
get(url: '/caddy/host-metrics', config?: AxiosRequestConfig): Promise<APIResponse<HostMetrics[]>>
...
get(url: '/metrics/overview', config?: AxiosRequestConfig): Promise<APIResponse<MetricsOverview>>
```
**核查**：全仓 grep 这三个 URL 字符串，除 api.ts 自身外 0 个调用点。Dashboard 实际使用聚合端点（`views/Dashboard.vue:798` `request.get<APIResponse<DashboardMetricsResponse>>('/metrics/dashboard', config)`），`CaddyMetrics/HostMetrics/MetricsOverview` 类型经由组合响应仍被使用，但三条字面量重载本身无调用方。
**分类**：冗余代码。
**判定**：设计漂移。依据：后端确实仍注册这三个独立端点（middleware.go:421,424,438），重载应是聚合端点切换前的遗留；无注释说明保留意图。
**影响**：无运行时影响（类型层死代码）；误导后来者以为页面在用独立端点。
**建议**：删除三条重载（类型可保留，由 DashboardMetricsResponse 引用）。
**是否待裁定**：否。

### FI-05 GET /config 响应类型双定义（低 / 设计漂移）

**位置**：`web/src/utils/api.ts:27-60`（GlobalConfigData）↔ `web/src/views/Settings.vue:54-90`（SettingsConfig + CertificateConfig）

**代码证据**：两处均完整罗列同后端 `GlobalConfig` 响应字段子集（log_level … mfa_lockout_enabled / acme_email … dns_provider），字段名逐一相同。Settings.vue 走 `request.get('/config')`（命中 api.ts 的字面量重载得到 GlobalConfigData），再赋给自己的 `ConfigPayload` 形参——两套结构靠结构兼容隐式对齐。
**分类**：冗余代码。
**判定**：设计漂移。依据：AGENTS.md 约定「Type Definitions | src/types/index.ts | Backend entity mappings」，而 /config 这一核心横切契约却在 api.ts 与 Settings.vue 各写一份；后端加字段时需改两处。
**影响**：维护双份；潜在漂移面（一侧更新另一侧遗漏时靠 `?? 默认值` 掩盖）。
**建议**：合并为 types/ 中单一 `GlobalConfigData`，api.ts 重载与 Settings.vue 共同引用。
**是否待裁定**：否。

### FI-06 hash 路由注释宣称「前进后退可靠」，实现为 replaceState 无历史栈（低 / 设计漂移）

**位置**：`web/src/stores/auth.ts:28-30, 224-231`

**代码证据**：
```ts
// auth.ts:28-29
// URL hash 优先（刷新/多标签页/前进后退可靠）；localStorage 作为后备。
const hashMatch = window.location.hash.match(/^#\/(.+)$/)
```
```ts
// auth.ts:224-231
function setCurrentPage(page: PageId) {
  ...
  if (window.location.hash !== `#/${page}`) {
    window.history.replaceState(null, '', `#/${page}`)
  }
}
```
**核查**：全仓 grep `hashchange|popstate` → 0 命中；导航一律 `replaceState`（不产生历史条目）。
**分类**：不合理逻辑（文档/注释与实现不符）。
**判定**：设计漂移。依据：注释把「前进后退」列为 hash 方案优点，但 replaceState 恰恰使浏览器返回键离开 SPA（回到上一站点）而非回退页面；刷新/多标签页两项确实成立。
**影响**：用户按返回键意外退出管理台；后续维护者会误信注释。
**建议**：要么改 `pushState` + `popstate` 监听（真正支持页间前进后退），要么修正注释为「仅刷新/多标签页可靠」。
**是否待裁定**：否（修注释即可；改 pushState 属产品决策可另立项）。

### FI-07 init() 对客户端已判定过期的 token 仍 POST /auth/logout，必然 401 并计入后端认证拒绝审计（低 / 缺陷·轻微）

**位置**：`web/src/stores/auth.ts:237-244`、`web/src/utils/api.ts:229-233`、`internal/middleware/middleware.go:526-564`

**代码证据**：
```ts
// auth.ts:237-244
async function init() {
  if (!token.value || isTokenExpired(token.value)) {
    await logout()   // → request.post('/auth/logout')（auth.ts:204）
    return
  }
  ...
}
```
```ts
// api.ts:229-233（请求拦截器不区分过期与否，一律附 token）
if (sessionExpiredDetected) throw sessionHaltedRequestError()
const token = localStorage.getItem('token')
if (token && token !== 'null' && token !== 'undefined') {
  config.headers.Authorization = `Bearer ${token}`
}
```
后端 jwtAuth 对过期 token `recordAuthenticationRejection(c, "jwt_expired")`（middleware.go:556-558）后 401。前端侧该 401 因 `intentionalLogout=true` 被静默（api.ts:308），本地清理照常完成。
**分类**：不合理逻辑（边界缺陷）。
**判定**：缺陷（轻微）。依据：客户端已有确定性过期判定（isTokenExpired 为 true），此时服务端吊销一个已失效令牌是纯浪费请求，且每次「带陈旧 token 冷加载」都会在后端认证拒绝审计里多一行 jwt_expired 噪音——与 api.ts:184-187 会话止损注释所防御的「审计刷屏」目标相悖；logout() 的服务端吊销价值仅在 token 仍有效时存在。
**影响**：每次过期会话冷加载产生 1 条无意义审计记录 + 1 次注定失败的请求；无功能损坏。
**建议**：`init()` 的过期分支跳过服务端调用，仅做本地清理（或将 logout 拆为 `revokeServer: boolean` 参数）。
**是否待裁定**：否（低风险小改）。

### FI-08 AppLayout 配置漂移看门狗：不随标签页隐藏暂停，且从节点持续空轮询（低 / 设计漂移）

**位置**：`web/src/components/layout/AppLayout.vue:318-325, 351-355`（对照模板 `137-147`）

**代码证据**：
```ts
// AppLayout.vue:351-355
onMounted(() => {
  syncProfileForm()
  fetchDriftStatus()
  driftTimer = window.setInterval(fetchDriftStatus, 60000)
})
```
```html
<!-- AppLayout.vue:137-138：结果仅在主节点展示 -->
<el-alert v-if="configDrift && authStore.nodeMode === 'master'" ...>
```
**对照**：`usePollingTask.ts:60-86` 为全站轮询建立了「后台标签页暂停 + 可见恢复即刷」的标准（visibilitychange），此看门狗是其外唯一的常驻 `setInterval`（其余裸 setInterval 均为用户显式开启的日志自动刷新，见 Rules/SecurityRules/CertJobs/CaddyGlobalSettings/BasicSettings）。
**分类**：不合理逻辑（体系不一致）。
**判定**：设计漂移。依据：无注释说明豁免 visibility 暂停的原因；从节点分支仅模板层忽略数据，请求照发（60s 一次），与「从节点只读、请到主节点操作」的定位不符；卸载清理（onUnmounted clearInterval, line 357-360）正确，无泄漏。
**影响**：后台标签页持续低频请求；从节点无意义流量。均为轻微资源浪费，无正确性问题。
**建议**：看门狗迁移到 usePollingTask（interval 60s）获得暂停语义；`nodeMode !== 'master'` 时跳过 fetch（或仅在模式变化为 master 后启动）。
**是否待裁定**：否。

### FI-09 字节格式化双实现 + .text-secondary 三处 scoped 重定义（低 / 设计漂移）

**位置**：`web/src/utils/api.ts:395-401` ↔ `web/src/components/LogStorageBar.vue:44-54`；`web/src/styles/main.css:122-125` ↔ `views/Dashboard.vue:1099`、`views/Rules.vue:3280`、`views/Users.vue:716`

**代码证据**：
```ts
// api.ts:395-401
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  ... parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
```
```ts
// LogStorageBar.vue:44-53（截断到 GB、自适应小数位）
const humanSize = (bytes: number): string => {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  ... `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}
```
`.text-secondary` 在 main.css 已有定义（含 font-size:13px），Dashboard/Rules/Users 又在 scoped 内重写（Dashboard 版漏掉 font-size，Users 版补齐——三者口径不一致）。
**分类**：冗余代码。
**判定**：设计漂移。依据：main.css:127-136 对 form-tip-* 明文「禁止组件内重复定义」，说明项目有去重约定，但字节格式化与 text-secondary 未纳入该治理；两套字节格式化输出格式不同（`1.5 MB` vs `1.5 MB`/`153 MB`）。
**影响**：同屏可能出现两种字节精度（Dashboard 用 formatBytes、日志容量条用 humanSize）；维护分散。
**建议**：humanSize 若是为紧凑展示有意差异化，应在两函数注释互指；否则统一收敛到 utils。删除三处 scoped `.text-secondary`（main.css 全局类在 scoped 模板中可直接用）。
**是否待裁定**：否。

### FI-10 escapeHtml 双实现（低 / 设计漂移）

**位置**：`web/src/utils/branding.ts:19-20` ↔ `web/src/utils/ansi.ts:4-10`

**代码证据**：
```ts
// branding.ts:19-20
const escapeHtml = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
```
```ts
// ansi.ts:4-10（导出版，CertJobs.vue:124 亦从此处引用）
export function escapeHtml(text: string): string { /* 同样四个替换 */ }
```
**分类**：冗余代码。
**判定**：设计漂移。依据：逻辑逐字符相同；branding.ts 未复用 ansi.ts 导出版（可能为避免 ansi 模块连带 Prism 无关代码——但 ansi.ts 并不引 Prism，成本为零）。
**影响**：极小；仅治理层面。
**建议**：branding.ts 改为 `import { escapeHtml } from '@/utils/ansi'`。
**是否待裁定**：否。

### FI-11 usePollingErrorState 消费样板三处逐字重复（低 / 有意设计，但已达提取阈值）

**位置**：`web/src/views/Rules.vue:3156-3181`、`web/src/views/settings/CertJobs.vue:421-444`、`web/src/views/settings/ClusterSettings.vue:599-629`

**代码证据**（三处相同的 description 构造，逐字一致）：
```ts
const xxPollingError = usePollingErrorState()
const xxPollingErrorDescription = computed(() => {
  const lastError = formatDate(xxPollingError.lastErrorAt.value)
  const retryAt = formatDate(xxPollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
```
配套的 `canRun() 早退 → 成功 clear() → onError recordError() → 手动重试 resetBackoff()+run()` 接线也在三处复制（仅 retrying 防抖有无差异）。
**分类**：冗余代码。
**判定**：有意设计（向有效设计漂移）。依据：usePollingErrorState 本身是精心抽取的状态机（TypeError 才退避、30s 错误可见节流），消费侧样板是当时最小落地方案；但第三份拷贝出现且文案硬编码三份，继续复制将产生文案漂移面。
**影响**：改提示文案需改三处；已核对当前三处一致、且 `retryAt/lastErrorAt` 的 ISO 串均经 `formatDate` 渲染（无裸 ISO 泄漏）。
**建议**：在 composable 内提供 `usePollingErrorBanner()` 返回 `{description, bind(task)}` 一类组合助手，或至少把文案常量导出共享。
**是否待裁定**：否。

### FI-12 CurrentUser.mfa_enabled 建模为可选，后端恒输出布尔（低 / 有意设计）

**位置**：`web/src/types/index.ts:7` ↔ `internal/models/models.go:21-29`

**代码证据**：
```ts
// types/index.ts:1-8
export interface CurrentUser {
  ...
  mfa_enabled?: boolean     // 可选
}
```
```go
// models.go:21-29（UserResponse，无 omitempty，恒输出）
type UserResponse struct {
  ...
  MFAEnabled  bool        `json:"mfa_enabled"`
```
auth.ts 两处以 `mfa_enabled ?? false` 兜底（auth.ts:105、184），注释（auth.go:237-238 R72 十次）表明后端曾长期漏发该字段、后来补齐——前端的可选建模是该历史时期的防御残留。
**分类**：类型漂移（可空性）。
**判定**：有意设计（历史兼容的宽松防御）。依据：字段曾有恒 false 的 bug 史（auth.go:237-239 注释），前端可选 + 兜底是对旧后端/混部集群（主从版本差）的容错；非缺陷。
**影响**：无运行时影响；类型层面弱于真实契约。
**建议**：若不再支持「主新从旧」的版本窗口可收紧为必填；否则保留并补一行注释说明混部容错意图。
**是否待裁定**：否。

### FI-13 web/AGENTS.md 前端约定文档与现状不符（低 / 设计漂移）

**位置**：`web/AGENTS.md:3, 10-17, 12, 19-26`

**代码证据与核查**：
1. 第 3 行/第 30 行宣称 **Tailwind CSS**：`**Stack:** Vue 3, TypeScript, Vite, Pinia, Element Plus, Tailwind CSS`。核查 `grep -rn tailwind web/`（ts/vue/css/json/js）→ **0 命中**；package.json 无 tailwind 依赖；main.css 是手写 CSS 变量 + 自定义 utility（`.mb-5`、`.page` 等）。
2. 第 12 行 STRUCTURE 树缺 `composables/` 目录（4 个已上线 composable）；第 12 行 `stores/ # Pinia state management (auth, session)` —— **不存在 session store**（stores/ 仅 auth.ts）。
3. 第 19-26 行 WHERE TO LOOK 表缺 composables 行；「Type Definitions | src/types/index.ts」未提 types/rules.ts（已拆分）。
4. 结构层面：`AsyncPageError.vue` 是 App.vue 专用的公共错误组件（`App.vue:36 import ... from '@/views/AsyncPageError.vue'`），按项目自身 components/ 语义应位于 components/，现放 views/。
**分类**：文档漂移（AGENTS.md 遵守性核对结论：Composition API/Element Plus/Pinia/自定义页面切换四项约定与代码一致；Tailwind 与目录描述不符）。
**判定**：设计漂移。依据：文档描述的栈与目录是历史形态，未随 composables 引入与 Tailwind 移除更新。
**影响**：依赖 AGENTS.md 的自动化代理/新人会被误导（尤其「用 Tailwind 写布局」的指示会直接产生不可用代码）。
**建议**：更新 AGENTS.md：删除 Tailwind 表述、补 composables/ 与 types/rules.ts、修正 stores 描述；顺手把 AsyncPageError.vue 迁至 components/。
**是否待裁定**：否。

### FI-14 usePollingTask：onError 回调若抛错将逃逸为 unhandled rejection（低 / 缺陷·防御缺口）

**位置**：`web/src/composables/usePollingTask.ts:40-44, 64, 82`

**代码证据**：
```ts
// usePollingTask.ts:35-45
const drain = async (): Promise<void> => {
  while (!disposed && pending) {
    ...
    try {
      await task({ signal: controller.signal, sequence: taskSequence, isCurrent })
    } catch (error: unknown) {
      if (!controller.signal.aborted) options.onError?.(error)   // 回调在 catch 内执行
    }
  }
}
```
`onError` 抛出的异常不在任何 try 内，经 `drain()` → `run()` 返回的 promise 拒绝；定时器触发处为 `timer = setInterval(() => void run(), options.interval)`（line 64）与可见性恢复处 `void run()`（line 82）——`void` 丢弃 promise，拒绝即 unhandled rejection。
**分类**：不合理逻辑（健壮性边界）。
**判定**：缺陷（防御缺口，当前无现实触发路径）。依据：现有 6 个消费方的 onError 全部是 `console.error(...)`（Rules.vue:3154、Dashboard.vue:984 等），不会抛错；但该 composable 的定位是全站轮询基座，消费方回调属外部输入。
**影响**：未来某消费方在 onError 里做复杂处理（如再发请求）抛错时，仅得到控制台 unhandled rejection，轮询 drain 提前终止（inFlight 复位，下轮 tick 恢复），不影响主流程但掩盖错误来源。
**建议**：`options.onError?.(error)` 外再包一层 try/catch（或 `.catch(() => {})` 吞掉回调异常并 console.error）。
**是否待裁定**：否。

### FI-15 axios 私有标记属性（_mfaRetried / mfaSurfaced）脱离类型检查（低 / 有意设计）

**位置**：`web/src/utils/api.ts:327, 347, 362`（对照 `api.ts:20-25` 的 `declare module 'axios'` 仅扩展了 `silent`）

**代码证据**：
```ts
// api.ts:327
} else if (status === 428 && error.response?.data?.code === 428 && error.config && !error.config._mfaRetried) {
// api.ts:347
  error.config._mfaRetried = true
```
`AxiosRequestConfig` 上并无 `_mfaRetried` 声明；能通过 `vue-tsc`（本会话验证退出码 0）仅因 axios 拦截器错误回调形参为 `any`。`sessionExpiredHalted`（api.ts:216）与 `mfaSurfaced`（api.ts:362）则用了显式交叉类型断言，风格不一。
**分类**：不合理逻辑（类型安全缺口）。
**判定**：有意设计（权衡）。依据：`silent` 走了正式模块扩展，说明作者知道该机制，私有标记属快通道写法；运行时无问题（属性挂在 config/error 对象上随请求生命周期消亡）。
**影响**：`_mfaRetried` 拼写错误不会被编译器捕获（若某天重构改名，静默失去「只重试一次」保护，形成 428 重试循环风险——当前有 `mfaPending` 共享兜底）。
**建议**：把 `_mfaRetried?: boolean` 并入现有 `declare module 'axios'` 扩展，统一三个标记的类型标注方式。
**是否待裁定**：否。

### FI-16 品牌自定义 app_name 时标题/侧栏仍硬拼「V2」后缀（低 / 待裁定）

**位置**：`web/src/utils/branding.ts:42`、`web/src/components/layout/AppLayout.vue:9`、`web/src/views/Login.vue:9`

**代码证据**：
```ts
// branding.ts:42
document.title = `${appName.value} V2`
```
```html
<!-- AppLayout.vue:9 -->
{{ appName }} <span class="v2-badge">V2</span>
```
后端 `/branding` 的 `app_name` 是完整可定制字段（branding.go:31-33 默认 "Lazy Balancer"）。管理员把 app_name 改为 "Acme 均衡器" 后，标题变 "Acme 均衡器 V2"、侧栏显示 "Acme 均衡器 [V2]"。
**分类**：不合理逻辑（品牌定制语义）。
**判定**：待裁定。依据：可解读为有意设计（产品线名即 Lazy Balancer **V2**，版本徽章是产品标识而非 app_name 一部分，默认页脚文案同样内嵌 "V2"）；也可解读为定制能力不彻底。两种解读都有依据，需产品裁决。
**影响**：品牌定制场景下的展示语义歧义；无功能影响。
**建议**：若裁定「V2 属产品名」则在 branding.ts 加注释固化；若属定制不彻底则改为由后端 branding 返回完整显示名。
**是否待裁定**：是。

### FI-17 copy.ts 回退使用已弃用 API document.execCommand（低 / 有意设计）

**位置**：`web/src/utils/copy.ts:12-19`

**代码证据**：
```ts
try {
  return document.execCommand('copy')
} catch {
  // execCommand 仅抛 DOMException（Error 子类）；其余值同样按复制失败处理，不向外抛。
  return false
}
```
**分类**：已弃用代码（W3C 已标记 deprecated）。
**判定**：有意设计。依据：仅当 `navigator.clipboard` 不可用时触发（copy.ts:23）——非安全上下文（HTTP 访问管理台）下 clipboard API 不存在，execCommand 是唯一可行回退；且实现含 readonly textarea、失败不外抛的防御，是成熟的兼容写法。
**影响**：浏览器未来移除该 API 时 HTTP 部署的复制功能退化为返回 false（调用方 Keys.vue 有失败提示分支）；当前可用。
**建议**：维持现状；可在注释标注「execCommand 已弃用，仅非安全上下文回退」。
**是否待裁定**：否。

### FI-18 auth store 登录函数重入时返回「假成功」形态（低 / 缺陷·无触发路径）

**位置**：`web/src/stores/auth.ts:134-135`（login）、`160-161`（verifyMfaLogin）、`190-191`（loginWithTicket）

**代码证据**：
```ts
// auth.ts:134-135
async function login(username: string, password: string): Promise<{ mfaRequired: boolean; mfaToken?: string }> {
  if (loading.value) return { mfaRequired: false }   // 静默放弃，形态与「登录成功（无 MFA）」一致
```
调用方 `Login.vue:249-255` 以 `result.mfaRequired` 分流：重入返回会被当作「密码登录已成功」——但 token 未写入，界面停留在登录页且无任何错误提示。`loginWithTicket` 的重入则直接 return（App.vue:82 的 await 正常结束 → `setCurrentPage('dashboard')`，同样无反馈）。
**分类**：逻辑 bug（重入语义错误）。
**判定**：缺陷（潜在，当前无触发路径）。依据：现网调用方都有外层防抖（Login.vue:240 `if (loading.value) return`；App.vue 挂载期仅调用一次），双保险使重入分支几乎不可达；但 store 层的返回形态与函数契约（成功=已建立会话）相悖，属地雷式接口。
**影响**：未来新增调用方（如另一个组件触发登录）踩中时表现为「点了没反应」。
**建议**：重入分支改为 reject（`throw new Error('登录请求进行中')`）或返回显式 `{ skipped: true }` 形态。
**是否待裁定**：否。

### FI-19 reloadAfterRestart 的 60s 上限可被单次 30s 请求超时突破（低 / 有意设计）

**位置**：`web/src/utils/restart.ts:9-23` + `web/src/utils/api.ts:220-223`

**代码证据**：
```ts
// restart.ts:9-23
const deadline = Date.now() + 60_000
while (Date.now() < deadline) {     // deadline 仅在循环顶检查
  await sleep(2000)
  ...
  try {
    await request.get('/caddy/status', { silent: true })  // axios timeout 30000
    window.location.reload()
```
冷启动期间服务不可达通常表现为连接拒绝（快速失败），但若表现为挂起（如防火墙 DROP），单次请求可耗时 30s；最后一轮在途超时会使总等待达 ~90s，随后才提示「服务重启时间较长，请稍后手动刷新」。
**分类**：不合理逻辑（边界）。
**判定**：有意设计（可容忍边界）。依据：注释明确「与容器冷启动时长无契约」「超过 60s 上限提示手动刷新」，选择轮询而非固定 10s reload 本身就是对该问题的修复（W1）；30s×2 的最坏叠加仍在人工可接受范围。
**影响**：极端网络下提示出现时间比标称 60s 晚最多 30s；功能正确。
**建议**：可选：给就绪探测单独设置更短的 axios timeout（如 5s）以收紧节拍。
**是否待裁定**：否。

### FI-20 App.vue 以 isTokenExpired 重新实现 isLoggedIn 判定（低 / 设计漂移）

**位置**：`web/src/App.vue:10` ↔ `web/src/stores/auth.ts:60`

**代码证据**：
```html
<!-- App.vue:10 -->
<Login v-else-if="!authStore.token || isTokenExpired(authStore.token || '')" />
```
```ts
// auth.ts:60
const isLoggedIn = computed(() => !!token.value && !isTokenExpired(token.value))
```
两者语义完全等价（token 非空 && 未过期）；App.vue 另行 import `isTokenExpired` 组合同一判定，绕开了 store 已导出的单一事实源。
**分类**：冗余代码。
**判定**：设计漂移。依据：无注释解释为何不用 `!authStore.isLoggedIn`；两处实现需同步演化（例如未来加入 token 刷新机制时易漏改模板侧）。
**影响**：极小；纯维护面。
**建议**：改为 `v-else-if="!authStore.isLoggedIn"`。
**是否待裁定**：否。

## 四、待裁定项汇总

| 编号 | 议题 | 需要的裁决 | 关联域 |
|---|---|---|---|
| FI-01 | 非管理员对规则/证书配置/证书任务的写权限：前端禁、后端放 | 产品语义：普通用户应「完全只读」还是「可管规则」？据此决定收紧后端（迁 admin 组）或放开前端 | 后端权限矩阵（建议 sec-core-audit / lb-rules-audit 复核后端侧） |
| FI-16 | app_name 定制后仍硬拼「V2」后缀（标题/侧栏徽章） | 「V2」是否属产品名一部分（不可定制）还是应随品牌定制消化 | 品牌展示语义 |

## 附：核实为无问题的重点链路（本会话逐行验证）

1. **401 会话止损链路**（api.ts:183-188, 227-229, 269-325）：首个 401 弹窗置位 `sessionExpiredDetected` 后请求拦截器拒绝一切出站请求；止损标记经 `sessionExpiredHalted` 打标原样透传，不会被兜底逻辑误映射为「网络连接失败」toast；`intentionalLogout` 防 logout 期误弹；MFA 自助端点（`/auth/mfa/`、`/mfa/reset`）401 正确豁免会话失效流（api.ts:296-304）。
2. **428 step-up 并发去重**（api.ts:83-89, 132-181, 327-365）：`mfaPending` 共享弹窗 Promise、`mfaStepUpRefresh` 共享 verify-step（防同码重放被后端 mfa_last_timestep 拒绝计失败）、`_mfaRetried` 防无限重试、取消路径以中文文案 reject——各分支与注释声明一致。
3. **usePollingTask 生命周期**：`onUnmounted(stop)` + stop 中 abort/removeEventListener/clearInterval（usePollingTask.ts:99-111），无监听器/定时器泄漏；后台暂停-可见恢复即刷逻辑正确（drain 合并 pending 防重入风暴）。
4. **date.ts 时区防御**：非法配置时区经 tzFormatter 回退 Asia/Shanghai 并缓存（含非法键缓存回退实例），Intl RangeError 不会传导到渲染层；`parseDateValue` 对 DB "YYYY-MM-DD HH:MM:SS" 按 UTC 归一、对未知对象形状宽容返回 null。
5. **构建产物契约**：`Dockerfile:45 COPY web/dist /app/ui` ↔ `config.go:46 StaticDir: "/app/ui"`；`.dockerignore` 未排除 web/dist（仅排除 web/node_modules 与根 ui/）；README.md:23 明确要求构建镜像前 `cd web && npm install && npm run build`；当前 web/dist 存在且新于 src/main.ts。dev 代理 `/api → localhost:8000` 与后端默认端口一致（config.go:44）。
6. **类型检查**：`npx vue-tsc --noEmit` 退出码 0（strict + noUnusedLocals + noUnusedParameters 全开）。
7. **票据登录深链**：后端票据链接形态 `URL#login_ticket=<ticket>`（apidocs.go:101）与 App.vue 的 `URLSearchParams(url.hash.slice(1))` 解析及消费后 `replaceState` 清除 fragment 匹配；auth.ts 的页面 hash 正则 `^#\/(.+)$` 不会误吞票据 fragment。
