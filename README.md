# Lazy Balancer V2

[English](README.en.md) | 简体中文

基于 **Caddy v2.11 + caddy-l4** 的可视化负载均衡管理平台（Go + Vue 3 单容器交付），内置完整 WAF 安全防护。

## 功能特性

- **负载均衡**：HTTP/HTTPS 反向代理 + TCP 四层代理；加权轮询（百分比联动）、最少连接、IP 哈希、Cookie 会话粘性；主动/被动健康检查与故障转移；路径级自定义路由；代理超时（全局默认 + 按规则覆盖，含 SSE/LLM 流式）；TCP PROXY v2 透传真实客户端 IP
- **安全防护**：Coraza v3 WAF + OWASP CRS v4（检测/拦截双模式）；IP2Region 地域控制；IP 白名单/黑名单/信任名单；可复用命名 IP 地址列表（IP/CIDR + 备注、分类、按策略引用；事件处理一键保存）；限流；自定义规则；自定义拦截页与状态码；安全事件采集与总览仪表盘
- **免费证书**：Let's Encrypt / ZeroSSL ACME 自动签发（DNS-01，DNSPod/腾讯云，直查权威 NS 加速），自动续签，退避重试，手动上传
- **主从集群**：注册审批，增量同步（规则/证书/用户/密钥/设置/安全策略），状态上报，一键提升；快照 HMAC-SHA256 签名防篡改防重放；从节点全只读
- **监控**：流量/速率/延迟分位数（P50/95/99），三态上游健康，按规则指标与历史趋势，按规则访问日志（JSON，实时查看）与 TOP 统计
- **管理面板 HTTPS**：一键强制 HTTPS（自签或上传证书），HTTP 自动 301 重定向，从节点同步后自动重启
- **MCP 服务**：AI 代理通过 Streamable HTTP + API Key 操作全部功能（只读 Key 自动收敛为只读工具集，支持 IP 白名单），操作手册内置为 MCP 资源
- **多用户与 API**：管理员/只读用户，API 密钥（SHA-256），改密即时吊销旧 JWT，RESTful v1 API + OpenAPI 文档
- **运维**：操作日志全中文记录每一动作；配置备份导出/导入（校验失败零写入，兼容 v1 nginx 备份）；品牌定制（应用名/页脚/版本号）

## 快速开始

```bash
# 1. 发布构建（正式方式：前端先行——Dockerfile COPY web/dist 进镜像）
cd web && npm install && npm run build && cd ..

# 2. 多架构镜像：一次 buildx 构建双架构，双标签推送 Docker Hub
docker buildx build --builder lazy-builder --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v2.2.7 \
  -t v55448330/lazy-balancer-v2:v2.2.7 -t v55448330/lazy-balancer-v2:latest --push .

# 3. 本地部署：拉取已推送镜像，保证本地与远端 digest 一致
docker pull v55448330/lazy-balancer-v2:v2.2.7 && docker compose up -d

# 本地开发迭代（仅调试：单平台、仅本地，不用于发布）
docker compose up -d --build

# docker run（生产推荐参数——完整调优指南：docs/production-tuning.zh-CN.md）
docker run -d --name lazy-balancer --network host \
  --restart unless-stopped \
  --ulimit nofile=1048576:1048576 \
  -v $(pwd)/data:/app/data -v $(pwd)/logs:/app/logs \
  -v $(pwd)/certs:/app/certs -v $(pwd)/waf:/app/waf \
  -e LOG_FILE=/app/logs/lazy-balancer.log \
  v55448330/lazy-balancer-v2:v2.2.7
```

> 镜像需直接绑定宿主 80/443 端口及自定义监听端口；Linux 推荐 `--network host`。macOS/Windows 用 `-p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp`（UDP 映射是 HTTP/3 必需的）。首次访问 `http://<host>:8000` 进入初始化向导创建管理员账户，无默认凭据。

## 生产调优（摘要）

完整五层指南——内核/容器、负载均衡、WAF、HTTP/3/TLS、可观测性，每条建议映射到实际面板/API 字段——见 **[docs/production-tuning.zh-CN.md](docs/production-tuning.zh-CN.md)**。摘要：

- **内核（Ubuntu 宿主，可选——默认值已生产就绪，仅按症状调优）**：`--network host` 下容器级 sysctl 不生效，需在宿主 `/etc/sysctl.d/` 设置：`net.core.rmem_max/wmem_max=7500000`（HTTP/3 UDP 缓冲区，清除启动接收缓冲警告）、`somaxconn=4096`、`ip_local_port_range=10000 65535`、`fs.file-max=2097152`；防火墙开放 `443/udp`
- **文件描述符**：`--ulimit nofile=1048576:1048576`（每连接一个 fd，默认 1024 在生产环境必炸；已内置在随附 compose 文件中）
- **负载均衡**：启用上游 keepalive 复用（`upstream_keepalive_timeout` 60-120s——收益最大的单项调优）；`proxy_dial_timeout` 3-5s + 主动健康检查 + `least_conn` 实现快速故障转移；`max_connections` 限制上游
- **WAF**：先运行 `detection` 模式 3-7 天再切 `blocking`；按攻击组裁剪 CRS；误报通过 CRS 排除/自定义放行规则处理而非降阈值；按规则限流（登录端点小桶）
- **可观测性**：`caddy_log_level=warn`，审计保留按合规（1-12 月），高 QPS 规则禁用按规则访问日志、依赖指标

### 即用 sysctl 配置（可选，按症状）

保存为宿主 `/etc/sysctl.d/99-lazy-balancer.conf`，执行 `sudo sysctl --system`：

```conf
# HTTP/3 (QUIC/UDP) 套接字缓冲区——清除启动接收缓冲警告
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000

# TCP accept 积压——防止突发新建连接丢连（默认 128）
net.core.somaxconn = 4096

# 出站到上游的临时端口范围——单上游并发接近 ~28k 时扩宽
net.ipv4.ip_local_port_range = 10000 65535

# 端口发布(bridge/NAT)模式的连接跟踪表；--network host 下不在数据路径可省略
net.netfilter.nf_conntrack_max = 262144
```

> 再次强调：以上均为可选——Ubuntu 默认值已生产就绪。唯一必需项是进程 fd 上限（`--ulimit nofile=1048576:1048576`，已内置在 compose 中）。用 `sysctl net.core.rmem_max` 验证（应读 7500000），重启后确认容器启动日志中不再出现接收缓冲警告。

每次配置写入经过四道合法性关卡（前端 → 后端字段校验 → caddy CLI 校验 → 事务内应用）：非法值 400 拒绝、零落库；运行中的规则与策略永不被干扰。

## 挂载目录

| 容器路径 | 内容 | 必需 |
|---|---|---|
| `/app/data` | 业务/审计/指标数据库、branding.json、ACME 账户密钥、IP2Region 省份缓存 | **是** |
| `/app/certs` | 证书与私钥（手动上传和 ACME 签发） | **是** |
| `/app/logs` | 应用日志、Caddy 日志、按规则访问日志、规则集更新日志 | 推荐 |
| `/app/waf` | CRS 规则文件、IP2Region xdb、Coraza 审计日志；容器重建后保留 | 推荐 |
| `/app/config` | Caddyfile（仅高级定制） | 可选 |

> 不挂载 `/app/waf` 时，容器重建会将 CRS 回退到镜像捆绑版本；系统会自动将更新后的规则树快照持久化到数据卷并在启动时对账恢复（记录在操作日志中）。挂载该目录可完全避免回退。数据库是配置的唯一真实来源，Caddy 配置从其实时渲染。

## 环境变量与配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `JWT_SECRET` | 自动生成，持久化到 `data/jwt_secret` | JWT 签名密钥；生产建议显式设置 |
| `LOG_FILE` | 空 | 应用日志同时写入此文件，可在 UI 查看 |
| `NODE_NAME` | `node-1` | 集群注册的默认节点名 |
| `APP_VERSION` | 构建时注入 | 显示版本号 |
| `TZ` | 数据库 `timezone` | 进程时区；修改后建议重启 |

集群角色在「系统设置 → 集群管理」页面配置（非环境变量）。日志级别、时区、日志保留、审计日志大小均在「基础设置」页面配置。

`data/branding.json` 自定义品牌（修改即时生效；`version` 留空显示构建版本）：

```json
{ "app_name": "Lazy Balancer", "footer_text": "Copyright © 2026 XiaoBao.", "version": "" }
```

| 端口 | 用途 |
|---|---|
| `8000` | 管理面板与 REST API（文档在 `/api/v1/docs`） |
| `80 / 443` | HTTP/HTTPS 代理流量 |
| `2019` | Caddy Admin API（仅回环） |
| 自定义 | TCP 规则监听端口 |

## 安全子系统

请求处理链（任一阶段拦截即刻返回配置的状态码与拦截页）：

```
入站 → IP 预检(多策略 IP ACL 合并,最高优先级) → GeoIP 标签(Coraza 链内地域拦截) → 限流(按 IP 速率+突发) → WAF(Coraza + CRS + 自定义规则)
     → 请求体大小限制 → 反向代理
```

| 组件 | 版本 |
|---|---|
| WAF 引擎 | Coraza v3 (coraza-caddy v2.6.0) |
| 规则集 | OWASP CRS v4.29.0（捆绑，支持在线更新） |
| GeoIP 库 | IP2Region v3.17.0（离线 xdb，中国省级）。地域规则仅对 IPv4 生效：IPv6/不可解析客户端按「海外」处理（fail-closed）；IP 库未安装时地域规则不可启用 |
| 限流 | caddy-ratelimit v0.1.0 |

**安全策略**以独立实体管理并绑定到 HTTP 规则（一个策略可绑多规则；一个规则最多绑 5 个策略，按 policy_id 顺序评估，首个绑定策略的拦截页生效）。多策略绑定时，全部策略的 deny 侧 IP 控制合并为链首预检——被拒 IP 在任何 CRS/自定义规则评估前即被中断，不产生前置策略的检测事件：

| 设置 | 选项 |
|---|---|
| WAF 模式 | 关闭 / 检测（仅记录）/ 拦截（异常分达阈值即 403） |
| 异常阈值 | 1/3/5/10/15/20；越低越严格 |
| CRS 规则组与排除 | 按攻击类型组加载 / 按文件名排除 |
| 自定义规则 | 多条件链式匹配 URI/args/headers/body/User-Agent（包含/正则/精确/前缀），可分配分值 |
| IP 访问控制 | 白名单（仅允许）/ 黑名单（拒绝）/ 信任名单（跳过检查），支持 CIDR；可引用可复用 IP 地址列表 |
| 地域控制 | 拦截所选区域 / 仅允许所选区域，基于 IP2Region（被拦请求经 Coraza 产生安全事件） |
| 限流 | 按 IP 速率上限 + 突发容量 |
| 拦截响应 | 自定义 HTML 拦截页 + 状态码（400/401/403/404/429/503，WAF/IP ACL/GeoIP/限流统一） |

**安全事件**：WAF 拦截（从 Coraza 审计日志解析，覆盖 CRS、自定义规则、GeoIP 地域拦截）、IP ACL 拒绝、GeoIP 地域拦截自动采集，含趋势图与 TOP 攻击类型 / 来源 IP（带地理位置展示 + 一键加入策略名单）/ 区域；保留期与操作日志共享。审计日志按大小自动轮转（默认 10 MB × 5 份）。事件日志与安全总览中的客户端 IP 展示 IP2Region 地理位置；点击弹出添加到任意关联策略的黑名单/白名单/信任名单（经 IP ACL 统一，带模式切换守卫与确认弹框）。

**规则集更新**：CRS 和 IP2Region 支持一键手动更新与每日自动更新（进度实时记录，失败自动回滚，结果留痕）。每次成功更新将规则树（含用户定制迁移文件）持久化为数据卷快照；容器重建导致磁盘态回退时，启动对账自动恢复。

## 主从集群

1. 主节点：集群管理 → 生成注册令牌（一次性，30 分钟有效）
2. 从节点：选择「从节点」，输入主节点地址 + 令牌注册
3. 主节点：在节点列表点击「确认」；从节点开始同步并周期上报
4. 从节点全只读（集群管理除外），可「提升为主节点」脱离集群

主节点配置变更自动递增集群版本；从节点按节哈希增量同步。安全策略、CRS/IP2Region 版本、设置均在同步范围内。

**MFA（v2.1.8）**：TOTP 两步登录（Google/Microsoft 身份验证器）。设置 → 基础设置 → MFA 卡片自助绑定（二维码 + 10 个一次性恢复码，SHA-256 存储）。禁用/重新绑定仅需有效 TOTP 验证码；恢复码重新生成仅需已登录会话（登录后零密码输入，2026-09 政策）。全局开关（默认关闭）：写操作验证（60 秒窗口，428 + 全局重试）与验证失败锁定（5 次失败 → 10 分钟锁定）。从节点登录票据要求管理员已启用 MFA；用户 MFA 状态经集群快照与完整配置备份同步。管理员可重置任意用户 MFA（留痕审计）。账户锁定：登录阶段密码与 MFA 验证码错误同计一个计数器——5 次失败锁定 10 分钟（受「登录失败锁定」开关控制）。

**安全模型**：集群令牌与 CA/DNS 凭证以明文存储在 `data/lazy-balancer.db`（令牌用于 HMAC 签名验证，无法哈希；启动时强制数据库 `0600` 与数据目录 `0700`），请勿将此目录共享挂载。集群通信默认 HTTPS + TOFU 指纹钉扎防中间人；可信网络允许明文 HTTP 主节点地址（带审计警告——明文 HTTP 不适用 TOFU 钉扎，注册令牌与同步的证书密钥以明文传输）。令牌无内置自动轮换，但重新生成注册令牌即刻作废全部未使用令牌；怀疑泄漏时删除节点记录并重新注册。

**Pin 不匹配恢复**：每个从节点首次连接时钉扎主节点管理面板 TLS 证书指纹（TOFU）。主节点更换证书（如切换为上传证书）后，从节点持续拒绝同步并报指纹不匹配（`PinMismatch`），直到新指纹被信任。在受影响的从节点上，管理员调用 `POST /api/v1/cluster/forget-pins`（管理员 JWT；留痕审计）清除全部已记指纹——下次同步自动重新钉扎主节点当前证书。执行前确认主节点地址仍归你所有：忘记指纹即对它重新启用首次接触信任。

## 配置备份与迁移

- **导出/导入**：系统信息 → 配置备份（完整 JSON，导入前校验；Caddy 校验失败零写入）；导入 v2 备份需 ≥ v2.1.2 导出的文件
- **导出是完整备份**：导出文件包含全部配置（含 DNS/ACME 凭证、证书与私钥、密码哈希），可完整恢复一个可用部署；请妥善保管备份文件，防止泄漏
- **v1 迁移**：选择 v1（nginx 版）备份文件即可，负载均衡规则自动转换（含内联证书）

## 升级须知

**滚动升级窗口**：CRS/IP2Region 安全数据同步的打包口径随版本演进——旧主节点+新从节点的组合在窗口期内安全数据哈希可能持续不匹配（每轮被拒并记录 last_sync_error，主节点升级后自愈）。集群升级建议主从同窗口完成。跨 schema 升级窗口（快照 v2→v3，canonical_payload 形态）中先升级主节点时，旧从节点报快照版本不兼容（"snapshot requires a newer reader / please upgrade this node"）——这是预期的安全拒绝（非攻击），从节点升级后自动恢复。

## 技术栈与镜像

Go 1.26 · Gin · SQLite · Caddy v2.11.4 + caddy-l4 v0.1.2 + caddy-ratelimit v0.1.0 · Coraza v3 · OWASP CRS v4 · IP2Region v3 · Vue 3 · Element Plus · Vite

```
v55448330/lazy-balancer-v2:v2.2.7
```

## 交流群

<div align="center">

**LazyBalancer 交流群**

群号：**303410331**

<img src="docs/qq-group-qr.webp" alt="LazyBalancer QQ 交流群" width="280">

扫一扫二维码，加入群聊

</div>

## License

[Apache License 2.0](LICENSE)。第三方组件：Caddy/caddy-l4/caddy-ratelimit/Coraza/CRS/IP2Region（Apache 2.0）、Gin/Vue/Element Plus（MIT）、glebarez/sqlite（MIT）、golang-jwt（MIT）、x/crypto（BSD-3）。
