# Lazy Balancer V2

[English](README.md) | 简体中文

基于 **Caddy v2.11 + caddy-l4** 的可视化负载均衡管理平台（Go + Vue 3 单容器交付），内置完整 WAF 安全防护。

## 功能概览

- **负载均衡**：HTTP/HTTPS 反向代理与 TCP 四层代理；加权轮询（百分比互锁）、最少连接、IP 哈希、Cookie 粘滞；主动/被动健康检查与失败转移；路径级自定义路由；代理超时全局默认 + 规则级覆盖（含 SSE/LLM 流式）；TCP PROXY v2 透传真实客户端 IP
- **安全防护**：Coraza v3 WAF + OWASP CRS v4（拦截/检测双模式）；IP2Region 区域控制；IP 白名单/黑名单/信任名单；支持可复用 IP 地址列表（IP/CIDR+备注、分类、被策略引用、事件处置一键存入）；限流；自定义规则；拦截页与状态码定制；安全事件采集与总览仪表盘（详见下文专节）
- **免费证书**：Let's Encrypt / ZeroSSL ACME 自动签发（DNS-01，DNSPod/腾讯云，权威 NS 直查加速），自动续签、退避重试、手动上传
- **主从集群**：注册审批、增量同步（规则/证书/用户/密钥/设置/安全策略）、状态上报、一键提升；快照 HMAC-SHA256 签名防篡改/重放；从节点全站只读
- **监控**：流量/速率/延迟分位数（P50/95/99）、上游健康三态、规则级指标与历史趋势、按规则访问日志（JSON，实时查看）与 TOP 统计
- **管理面板 HTTPS**：一键强制 HTTPS（自签名/上传证书），HTTP 301 自动跳转，从节点同步后自动重启
- **MCP 服务**：AI Agent 经 Streamable HTTP + API Key 操作全部功能（只读 Key 自动收敛只读工具集，支持 IP 白名单），操作手册以 MCP 资源内置
- **多用户与 API**：管理员/只读用户、API Key（SHA-256）、密码修改即时吊销旧 JWT、RESTful v1 API + OpenAPI 文档
- **运维**：操作日志全量中文留痕；配置备份导出/导入（校验失败零写入，兼容 v1 nginx 版备份）；品牌定制（应用名/页脚/版本号）

## 快速开始

```bash
# 1. 发布构建（正式方式）：先构建前端——Dockerfile 只 COPY web/dist 进镜像，前端不参与镜像内构建
cd web && npm install && npm run build && cd ..

# 2. 多架构镜像：buildx 一次构建双架构，双 tag，推送 Docker Hub
docker buildx build --builder lazy-builder --platform linux/amd64,linux/arm64 \
  -t v55448330/lazy-balancer-v2:<tag> -t v55448330/lazy-balancer-v2:latest --push .

# 3. 本地部署：拉取已推送镜像，保证本地与远端 digest 一致
docker pull v55448330/lazy-balancer-v2:<tag> && docker compose up -d

# 本地开发迭代（仅调试：单平台、仅本地，不用于发布）
docker compose up -d --build

# docker run（生产推荐参数——完整调优见 docs/production-tuning.zh-CN.md）
docker run -d --name lazy-balancer --network host \
  --restart unless-stopped \
  --ulimit nofile=1048576:1048576 \
  -v $(pwd)/data:/app/data -v $(pwd)/logs:/app/logs \
  -v $(pwd)/certs:/app/certs -v $(pwd)/waf:/app/waf \
  -e LOG_FILE=/app/logs/lazy-balancer.log \
  v55448330/lazy-balancer-v2:v2.2.5
```

> 镜像需直接绑定宿主机 80/443 及自定义监听端口，Linux 建议 `--network host`；macOS/Windows 用 `-p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp`（UDP 映射是 HTTP/3 必需）。首次访问 `http://<host>:8000` 进入初始化向导创建管理员，无默认账号密码。

## 生产优化建议（摘要）

内核/容器、负载均衡、WAF、HTTP/3 与观测五层的完整调优（每条建议均映射到面板/API 实际配置项）见 **[docs/production-tuning.zh-CN.md](docs/production-tuning.zh-CN.md)**。速览：

- **内核（Ubuntu 宿主，可选——默认内核可直接跑生产，症状驱动才调）**：`--network host` 下容器级 sysctl 不可用，需在宿主 `/etc/sysctl.d/` 配置 `net.core.rmem_max/wmem_max=7500000`（HTTP/3 UDP 缓冲，消除启动期 receive buffer 警告）、`somaxconn=4096`、`ip_local_port_range=10000 65535`、`fs.file-max=2097152`；防火墙放行 `443/udp`（host 模式天然绑定）
- **fd 上限**：`--ulimit nofile=1048576:1048576`（每连接一个 fd，默认 1024 在 LB 场景必炸；compose 已内置）
- **负载均衡**：开启上游 KeepAlive 复用（`upstream_keepalive_timeout` 60–120s，单项收益最大）；`proxy_dial_timeout` 3–5s + 主动健康检查 + `least_conn` 快速故障转移；上游按容量设 `max_connections`
- **WAF**：`detection` 观察 3–7 天再切 `blocking`；CRS 按攻击组裁剪；误报优先用 CRS 排除/自定义放行而非降阈值；限流按规则粒度（登录端点小桶）
- **观测**：`caddy_log_level=warn`、审计保留按合规（1–12 月）、高 QPS 规则关闭访问日志靠指标观测


### 可直接使用的 sysctl 配置（可选，症状驱动）

保存为宿主机 `/etc/sysctl.d/99-lazy-balancer.conf` 并执行 `sudo sysctl --system`：

```conf
# HTTP/3（QUIC/UDP）收发缓冲——消除启动期 receive buffer 警告，高带宽 h3 防丢包
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000

# TCP accept 积压队列——突发大量新建连接时防丢连（默认 128）
net.core.somaxconn = 4096

# 负载均衡到上游的出站临时端口范围——单上游并发逼近 ~2.8 万时扩大
net.ipv4.ip_local_port_range = 10000 65535

# 发布端口（bridge/NAT）模式下的连接跟踪表；host 模式不走 NAT 可省略
net.netfilter.nf_conntrack_max = 262144
```

> 再次强调：以上全部可选，默认 Ubuntu 内核可直接跑生产；唯一必选项是进程 fd 上限
> （`--ulimit nofile=1048576:1048576`，compose 已内置）。验证：
> `sysctl net.core.rmem_max` 应为 7500000，重启容器后启动日志不再出现 receive buffer 警告。

## 挂载目录

| 容器路径 | 内容 | 必须 |
|---|---|---|
| `/app/data` | 业务库/审计库/指标库、branding.json、ACME 账户密钥、IP2Region 省份缓存 | **是** |
| `/app/certs` | 证书与私钥文件（手动上传与 ACME 签发） | **是** |
| `/app/logs` | 应用日志、Caddy 日志、规则访问日志、规则库更新日志 | 建议 |
| `/app/waf` | CRS 规则文件、IP2Region xdb、Coraza 审计日志；跨重建保留 | 建议 |
| `/app/config` | Caddyfile（仅高级自定义场景） | 可选 |

> 未挂载 `/app/waf` 时容器重建会使 CRS 回退到镜像内置版本；系统会在数据卷持久化已更新的规则树快照并在启动时自动对账恢复（操作日志留痕）。挂载该目录可完全避免回退。数据库是配置的唯一事实来源，Caddy 配置由数据库实时渲染。

## 环境变量与配置

| 变量 | 默认 | 说明 |
|---|---|---|
| `JWT_SECRET` | 自动生成持久化到 `data/jwt_secret` | JWT 签名密钥，生产建议显式设置 |
| `LOG_FILE` | 空 | 应用日志同时写入该文件，页面可查看 |
| `NODE_NAME` | `node-1` | 集群注册默认节点名 |
| `APP_VERSION` | 构建注入 | 显示版本号 |
| `TZ` | 数据库 `timezone` | 进程时区，改时区后建议重启 |

集群角色在“系统设置 → 集群管理”页面配置（不走环境变量）。日志级别、时区、日志保留期、审计日志大小均在“基础设置”页面配置。

`data/branding.json` 定制品牌（改后即时生效，`version` 留空显示构建版本号）：

```json
{ "app_name": "Lazy Balancer", "footer_text": "Copyright © 2026 XiaoBao.", "version": "" }
```

| 端口 | 用途 |
|---|---|
| `8000` | 管理界面与 REST API（文档 `/api/v1/docs`） |
| `80 / 443` | HTTP/HTTPS 代理流量 |
| `2019` | Caddy Admin API（仅 loopback） |
| 自定义 | TCP 规则监听端口 |

## 安全防护子系统

 请求处理链（任一阶段拦截即直接返回配置的状态码与拦截页）：

```
入站 → IP 预检（多策略 IP ACL 合并，最高优先级） → GeoIP 标记（Coraza 内区域拦截） → 限流（per-IP 速率+突发） → WAF（Coraza+CRS+自定义规则）
     → 请求体大小限制 → 反向代理
```

| 组件 | 版本 |
|---|---|
| WAF 引擎 | Coraza v3（coraza-caddy v2.5.0） |
| 规则集 | OWASP CRS v4.28.0（内置，支持在线更新） |
| GeoIP 库 | IP2Region v3.17.0（离线 xdb，中国省份级） |
| 限流 | caddy-ratelimit v0.1.0 |

**安全策略**以独立实体管理并绑定到 HTTP 规则（一策略可绑多规则，一规则最多绑 5 条策略，按 policy_id 顺序评估，首绑策略的拦截页面生效）。多策略绑定时合并全部绑定策略的 deny 侧 IP 控制为链首预检（被拒 IP 在任何 CRS/自定义规则评估前即中断，不产生前置策略检测事件）：

| 配置 | 选项 |
|---|---|
| WAF 模式 | 关闭 / 检测（仅记录） / 拦截（异常分值达阈值后 403） |
| 异常阈值 | 1/3/5/10/20，越低越严格 |
| CRS 规则组与排除 | 按攻击类型组加载 / 按文件名排除 |
| 自定义规则 | URI/参数/请求头/请求体/User-Agent 多条件链式匹配（包含/正则/精确/前缀），可设分值 |
| IP 访问控制 | 白名单（仅允许）/ 黑名单（拒绝）/ 信任名单（跳过检测），CIDR；可引用 IP 地址列表（白名单侧/黑名单侧） |
| 区域控制 | 基于 IP2Region 在 Coraza 内拦截所选 / 仅允许所选（被拦请求产生安全事件） |
| 限流 | per-IP 速率上限 + 突发余量 |
| 拦截响应 | 自定义 HTML 拦截页 + 状态码（400/401/403/404/429/503，WAF/IP ACL/GeoIP/限流统一） |

**安全事件**：自动采集 WAF 拦截（Coraza 审计日志解析，含 CRS 与自定义规则）、IP ACL 拒绝及 GeoIP 区域拦截，含趋势图、TOP 攻击类型 / 源 IP（含归属地显示+一键加入策略名单）/区域统计；与操作日志共用保留期。审计日志按大小自动轮转（默认 10 MB × 5 份）。事件日志与总览中的客户端 IP 显示 IP2Region 归属地，点击可弹窗加入任意关联策略的黑/白/信任名单（统一走 IP ACL，含模式切换守卫与确认弹框）。

**规则库更新**：CRS 与 IP2Region 支持手动一键 / 每日自动更新（进度日志实时显示，失败自动回滚，结果留痕）。每次成功更新将规则树（含用户自定义配置迁移文件）持久化到数据卷快照，容器重建导致磁盘回退时启动对账自动恢复。

## 主从集群

1. 主节点：集群管理 → 生成注册令牌（一次性，30 分钟有效）
2. 从节点：选择“从节点”，填主节点地址 + 令牌注册
3. 主节点：节点列表“确认”后从节点开始同步并周期上报
4. 从节点全站只读（集群管理除外），可“提升为主节点”脱离集群

主节点配置变更自动递增集群版本，从节点按节哈希增量同步；安全策略、CRS/IP2Region 版本与设置均在同步范围内。

**安全模型**：集群令牌与 CA/DNS 凭证以明文存于 `data/lazy-balancer.db`（令牌需用于 HMAC 验签无法哈希化；启动时强制数据库 `0600`/数据目录 `0700`），请勿共享挂载该目录；集群通信强制 HTTPS + TOFU 指纹防 MITM；令牌无内置自动轮换，但重新生成注册令牌会作废所有未使用令牌（旧令牌立即失效），疑似泄露请删除节点记录重新注册。

## 配置备份与迁移

- **导出/导入**：系统信息 → 配置备份（JSON 全量，先校验后导入，Caddy 验证不过则零写入）；v2 备份导入需 ≥ v2.1.2 导出的文件
- **导出即完整备份**：导出文件包含全部配置（含 DNS/ACME 凭证、证书与私钥、密码哈希），可完整恢复到可用状态；请将备份文件妥善保管，谨防外泄
- **v1 迁移**：直接选择 v1（nginx 版）备份，自动转换负载均衡规则（含内联证书）

## 升级须知

滚动升级（主从不同版本共存）窗口内，旧版本从节点不识别「IP 地址列表」——策略中引用列表的 IP 访问控制在其上静默失效，直至该节点升级完成。建议主从节点同步升级。另注：跨 schema 大版本（快照 v2→v3，canonical_payload 形态）升级窗口内，若主节点先行升级，旧版本从节点会显示快照版本不兼容类错误（「快照需要更新的读取端/请升级本节点」）——这是预期的安全拒绝（非真实攻击），从节点完成升级后自动恢复。

## 技术栈与镜像

Go 1.26 · Gin · SQLite · Caddy v2.11.4 + caddy-l4 v0.1.2 + caddy-ratelimit v0.1.0 · Coraza v3 · OWASP CRS v4 · IP2Region v3 · Vue 3 · Element Plus · Vite

```
v55448330/lazy-balancer-v2:v2.2.5
```

## License

[Apache License 2.0](LICENSE)。第三方：Caddy/caddy-l4/caddy-ratelimit/Coraza/CRS/IP2Region（Apache 2.0）、Gin/Vue/Element Plus（MIT）、glebarez/sqlite（MIT）、golang-jwt（MIT）、x/crypto（BSD-3）。
