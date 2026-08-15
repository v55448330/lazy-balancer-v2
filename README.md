# Lazy Balancer V2

基于 **Caddy v2.11 + caddy-l4** 的可视化负载均衡管理平台（Go + Vue 3 单容器交付），内置完整 WAF 安全防护。

## 功能概览

- **负载均衡规则**：HTTP/HTTPS 反向代理与 TCP 四层代理；加权轮询（百分比互锁输入，GCD 归一渲染）、最少连接、IP 哈希、Cookie 粘滞；主动/被动健康检查（HTTP URI、TCP 端口、rise/fall 阈值），失败自动重试转移，5xx 计入被动熔断
- **安全防护**：Coraza v3 WAF 引擎 + OWASP CRS v4 规则集（拦截/检测双模式、异常评分阈值）；IP2Region 离线 GeoIP 区域控制；策略级 IP 白名单/黑名单/信任名单；caddy-ratelimit 限流（速率 + 突发双窗口）；自定义安全规则（多条件链式匹配）；可自定义拦截页面与状态码；安全事件实时采集与总览仪表盘；CRS 与 IP2Region 规则库一键/定时自动更新
- **免费证书**：Let's Encrypt / ZeroSSL ACME 自动签发（DNS-01，支持 DNSPod、腾讯云，权威 NS 直查加速传播确认），到期自动续签、限流退避重试、手动证书上传；证书/私钥原子写盘
- **主从集群**：从节点注册审批、定期同步规则/证书/用户/密钥/设置/安全策略、状态上报、一键提升为主节点；快照指纹 + **HMAC-SHA256 签名（含版本号，防篡改/重放/中间人）**；HTTP/HTTPS 协议自动迁移；从节点全站只读
- **操作日志**：独立审计库，全操作中文留痕（创建/更新/启停/签发/同步/登录/安全自动更新等），保留期可配，按配置时区显示
- **配置备份**：一键导出/导入全量配置（版本与完整性校验后导入，失败零写入），兼容 **Lazy Balancer v1（nginx 版）** 备份的规则迁移
- **监控面板**：实时流量、请求速率与延迟分位数（P50/95/99）、连接统计、上游健康三态（正常/异常/不健康）、规则级指标（仪表盘按请求数/流量 TOP10 排行，口径可切换）
- **管理面板 HTTPS**：一键启用强制 HTTPS（自签名/上传证书），开关与证书选择先暂存、主保存确认后重启生效；HTTP 明文请求 301 自动跳转到 HTTPS（协议嗅探单端口复用）；从节点同步后自动重启
- **MCP 服务**：AI Agent 经 Streamable HTTP + API Key 操作全部功能（只读 Key 自动收敛为只读工具集，支持 IP 白名单），服务端随连接下发挥 scope 与常用流程指引，完整操作手册以 MCP 资源形式内置、支持页面下载
- **规则访问日志与统计**：按规则记录 JSON 访问日志（最近 1000 行查看，5s 实时刷新），日志统计 tab 实时聚合 IP / 客户端 / URI TOP 20（前端本地增量统计，无服务端状态）
- **自定义路由**：HTTP 规则支持路径级路由（前缀/精确匹配、按序命中），可覆盖默认上游指向不同后端（http/https 协议、百分比权重互锁），向导独立步骤编辑与行内即时校验
- **TCP PROXY v2**：TCP 规则可开启向上游发送 PROXY v2 协议头，后端获取真实客户端 IP
- **代理超时**：连接/响应头/读/写/流式（SSE/LLM 长连接）超时，全局默认 + 规则级覆盖（规则优先）
- **规则级历史指标**：HTTP 规则按域名采集请求数/状态码/流量历史，仪表盘规则名点击弹出时间范围（1h/6h/24h/7d）趋势图表
- **多用户与 API 密钥**：管理员/只读用户、自管理 API Key（SHA-256）、密码修改即时吊销旧 JWT、RESTful v1 API + OpenAPI 文档
- **品牌定制**：应用名、页脚、版本号均可通过配置文件修改

## 快速开始

### Docker Compose（推荐）

先构建前端静态资源，再构建镜像：

```bash
cd web && npm install && npm run build && cd ..
docker compose up -d --build
```

### 多架构镜像构建

```bash
cd web && npm install && npm run build && cd ..
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <image>:<tag> --push .
```

### docker run

```bash
docker run -d \
  --name lazy-balancer \
  --network host \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/certs:/app/certs \
  -v $(pwd)/waf:/app/waf \
  -e LOG_FILE=/app/logs/lazy-balancer.log \
  v55448330/lazy-balancer-v2:v2.1.1
```

> 镜像与 Caddy 需要直接绑定宿主机端口（80/443 及自定义监听端口），建议使用 `--network host`（Linux）。macOS/Windows 下可用 `-p 8000:8000 -p 80:80 -p 443:443` 桥接映射。

### 首次登录

首次访问 `http://<host>:8000` 会进入**初始化向导**，创建第一个管理员账号后自动登录。不再有任何默认账号密码。

## 挂载目录

| 容器路径 | 内容 | 是否必须 |
|---|---|---|
| `/app/data` | 业务库（lazy-balancer.db）、审计库、指标库、`branding.json`、ACME 账户密钥（`acme_accounts/`，按 CA+邮箱 复用）、IP2Region 省份缓存 | **必须**（持久化核心数据） |
| `/app/certs` | 证书与私钥文件（手动上传与 ACME 签发） | **必须**（重启后证书不丢） |
| `/app/logs` | 应用日志、Caddy 四类日志、规则级访问日志、CRS/IP2Region 更新日志 | 建议 |
| `/app/waf` | WAF/CRS 规则库（OWASP CRS 规则文件）、IP2Region xdb 数据库、Coraza 审计日志；跨重建保留 | 建议 |
| `/app/config` | Caddyfile（仅高级自定义场景） | 可选 |

> 数据库是所有配置的唯一事实来源；Caddy 配置由数据库实时渲染，无需手工维护 Caddyfile。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| （页面设置） | `info` | 应用日志级别在"基础设置 → 日志级别"配置，即时生效 |
| `JWT_SECRET` | 自动生成并持久化到 `data/jwt_secret` | JWT 签名密钥（crypto/rand 生成，跨重启保持），生产建议显式设置 |
| `LOG_FILE` | （空） | 设置后将应用日志同时写入该文件（如 `/app/logs/lazy-balancer.log`），可在页面"基础设置 → 运行日志"查看 |
| `NODE_NAME` | `node-1` | 集群注册时的默认节点名 |
| `APP_VERSION` | 构建时注入 | 系统信息中显示的版本号（Dockerfile `ARG VERSION`） |
| `TZ` | 数据库 `timezone` 配置 | 进程时区；页面"基础设置 → 时区"为显示/日志统一时区，修改后建议重启容器 |

> 集群角色（主/从）不再通过环境变量设置，请在"系统设置 → 集群管理"页面配置。

## 配置文件

### data/branding.json（品牌文案，改后即时生效）

```json
{
  "app_name": "Lazy Balancer",
  "footer_text": "Copyright © 2026 XiaoBao. All rights reserved.",
  "version": "2.1.1-custom"
}
```

影响页面标题、导航栏、面包屑、登录框与页脚。`version` 留空或省略时显示构建版本号。

### config.json（可选，启动参数覆盖）

通过 `-config /path/config.json` 传入，字段：`port`、`data_dir`、`static_dir`、`caddy_admin_url`、`caddy_metrics_url`、`metrics_interval`。一般无需使用。

## 端口

| 端口 | 用途 |
|---|---|
| `8000` | 管理界面与 REST API（`/api/v1`，文档 `/api/v1/docs`） |
| `80 / 443` | HTTP/HTTPS 代理流量 |
| `2019` | Caddy Admin API（仅监听 loopback，不对外暴露） |
| 自定义 | TCP 规则监听端口（host 网络下直接绑定） |

## 安全防护子系统

Lazy Balancer V2 内置完整的 Web 应用防火墙（WAF）与流量安全控制，无需额外部署 sidecar 或反向代理。

### 请求处理链

```
入站请求
  → GeoIP 标记（IP2Region 解析访客区域）
    → 限流（caddy-ratelimit，per-IP 速率 + 突发双窗口）
      → WAF 检测（Coraza + OWASP CRS + 自定义规则）
        → IP ACL（白名单/黑名单/信任名单）
          → 请求体大小限制
            → 反向代理 → 上游服务
```

拦截发生在任意阶段时，请求不会继续向后传递，直接返回配置的拦截状态码和拦截页面。

### 核心组件

| 组件 | 版本 | 说明 |
|---|---|---|
| WAF 引擎 | Coraza v3（coraza-caddy v2.5.0） | ModSecurity 兼容，原生 Caddy 集成 |
| 规则集 | OWASP CRS v4.14.0 | 内置，支持在线更新 |
| GeoIP 库 | IP2Region v3.17.0 | 离线 xdb，中国省份级精度，支持在线更新 |
| 限流 | caddy-ratelimit v0.1.0 | per-IP 速率 + 突发双窗口 |
| 审计日志 | Coraza Audit Log（JSON） | 实时解析入库为安全事件 |

### 安全策略

安全策略以独立实体管理，通过向导配置后绑定到 HTTP 负载均衡规则。一个策略可绑定多条规则，一条规则只绑定一个策略。

**配置项：**

| 配置 | 选项 | 说明 |
|---|---|---|
| WAF 模式 | 关闭 / 检测 / 拦截 | 检测模式仅记录不阻断；拦截模式达到异常阈值后返回 403 |
| 异常阈值 | 1/3/5/10/20 | 越低越严格；规则异常分值累计达到此值后触发拦截 |
| CRS 规则组 | 按组选择 / 全部 | 可仅加载特定攻击类型规则（SQLi、XSS、LFI 等） |
| 规则排除 | 按文件名 | 排除不需要的 CRS 规则（减少误报） |
| 自定义规则 | 多条件链式匹配 | URI/参数/请求头/请求体/User-Agent，支持包含/正则/精确/前缀运算符，可设异常分值 |
| IP 访问控制 | 白名单/黑名单/信任名单 | CIDR 格式；白名单仅允许列表内 IP，黑名单拒绝列表内 IP，信任名单跳过全部检测 |
| 区域控制 | 拦截所选/仅允许所选 | 基于 IP2Region 的中国省份 + 海外区域控制 |
| 限流 | 速率上限 + 突发余量 | per-IP 粒度；突发余量允许短时超出速率上限 |
| 拦截页面 | 自定义 HTML | 可为不同策略配置不同拦截页面 |
| 返回状态码 | 400/401/403/404/429/503 | WAF、IP ACL、限流拦截统一使用此状态码 |

### 安全事件

WAF 与 IP ACL 拦截行为自动采集为安全事件，存储在独立的指标库中：

- **事件来源**：WAF 拦截（Coraza 审计日志解析，含 CRS 与自定义规则）、IP ACL 拒绝
- **事件字段**：时间、客户端 IP、区域、规则 ID、规则描述、动作（拦截/记录）
- **安全总览**：事件趋势图（按小时/天）、TOP 攻击类型、TOP 源 IP、TOP 区域统计
- **保留策略**：安全事件与操作日志共用保留期（基础设置 → 日志保留月数 × 30 天自动清理）

### 规则库更新

| 规则库 | 内置版本 | 更新方式 | 回滚 |
|---|---|---|---|
| OWASP CRS | v4.14.0 | 手动一键更新 / 每日自动定时更新 | 失败自动回滚到上一版本 |
| IP2Region | v3.17.0 | 手动一键更新 / 每日自动定时更新 | 失败自动回滚到上一版本 |

更新过程实时显示进度日志（检查 → 下载 → 安装 → 重载），完成后自动刷新版本号。自动更新完成（成功或失败）在操作日志中留痕。

### 审计日志轮转

WAF 审计日志（`/app/waf/audit/audit.log`）按配置大小自动轮转（默认 10 MB，保留 5 份）。轮转阈值在"基础设置 → 审计日志大小"配置。

## 主从集群快速部署

1. 主节点：系统设置 → 集群管理 → 生成注册令牌（一次性，30 分钟有效）
2. 从节点：集群管理 → 选择"从节点"，填主节点地址 + 令牌注册
3. 主节点：节点列表点击"确认"，从节点开始同步并周期上报状态
4. 从节点除集群管理外全站只读；需要时可在从节点"提升为主节点"脱离集群

### 集群同步范围

主节点配置变更（规则、证书、用户、安全策略、全局设置等）自动递增集群版本号，从节点定期拉取快照增量同步。安全策略、自定义规则、拦截页面、CRS/IP2Region 版本与设置均在同步范围内。

### 集群安全模型

- **集群令牌存储**：从节点 `data/lazy-balancer.db` 中以**明文**保存 `cluster_token`（用于 HMAC-SHA256 快照验签，无法哈希存储）。容器启动时强制将数据库文件权限收敛为 `0600`、数据目录 `0700`（见 `internal/db/permissions.go`）。请勿以非 root 用户共享或挂载该目录。
- **CA 凭证存储**：ZeroSSL EAB 凭证（`eab_kid` + `eab_hmac_key`）和 DNS 提供商凭证（`dns_credentials`）以**明文 JSON** 存储在 `data/lazy-balancer.db` 的 `ca_providers.credentials` 和 `global_config.dns_credentials` 字段中。API 直接返回实际凭证（不做掩码），数据库文件本身不加密。请妥善保护数据库文件权限。
- **传输安全**：所有集群通信强制 HTTPS，首次连接采用 TOFU（Trust On First Use）记录主节点 TLS 指纹，后续比对防止 MITM。
- **令牌生命周期**：集群令牌从注册密钥确定性地派生，无内置轮换机制。若怀疑令牌泄露，请删除该从节点记录后重新注册。

## 配置备份与迁移

- **导出**：系统设置 → 系统信息 → 配置备份 → 导出（JSON，含规则/用户/密钥/证书任务/全局配置）
- **导入**：同一入口选择备份文件，先校验再导入（覆盖式，Caddy 验证不通过则零写入）
- **v1 迁移**：直接选择 v1（nginx 版）备份文件，自动转换负载均衡规则（含内联证书），仅导入规则部分

## 技术栈

Go 1.26 · Gin · SQLite · Caddy v2.11.4 + caddy-l4 v0.1.2 + caddy-ratelimit v0.1.0 · Coraza v3（coraza-caddy v2.5.0）· OWASP CRS v4 · IP2Region v3 · Vue 3 · Element Plus · Vite

## 镜像

```
v55448330/lazy-balancer-v2:v2.1.1
```

## License

本项目采用 [Apache License 2.0](LICENSE) 授权。

第三方组件致谢：Caddy（Apache 2.0）、caddy-l4（Apache 2.0）、caddy-ratelimit（Apache 2.0）、Coraza（Apache 2.0）、OWASP CRS（Apache 2.0）、IP2Region（Apache 2.0）、Gin（MIT）、Vue 3（MIT）、Element Plus（MIT）、glebarez/sqlite（MIT）、golang-jwt（MIT）、x/crypto（BSD-3）。
