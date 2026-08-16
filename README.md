# Lazy Balancer V2

基于 **Caddy v2.11 + caddy-l4** 的可视化负载均衡管理平台（Go + Vue 3 单容器交付），内置完整 WAF 安全防护。

## 功能概览

- **负载均衡**：HTTP/HTTPS 反向代理与 TCP 四层代理；加权轮询（百分比互锁）、最少连接、IP 哈希、Cookie 粘滞；主动/被动健康检查与失败转移；路径级自定义路由；代理超时全局默认 + 规则级覆盖（含 SSE/LLM 流式）；TCP PROXY v2 透传真实客户端 IP
- **安全防护**：Coraza v3 WAF + OWASP CRS v4（拦截/检测双模式）；IP2Region 区域控制；IP 白名单/黑名单/信任名单；限流；自定义规则；拦截页与状态码定制；安全事件采集与总览仪表盘（详见下文专节）
- **免费证书**：Let's Encrypt / ZeroSSL ACME 自动签发（DNS-01，DNSPod/腾讯云，权威 NS 直查加速），自动续签、退避重试、手动上传
- **主从集群**：注册审批、增量同步（规则/证书/用户/密钥/设置/安全策略）、状态上报、一键提升；快照 HMAC-SHA256 签名防篡改/重放；从节点全站只读
- **监控**：流量/速率/延迟分位数（P50/95/99）、上游健康三态、规则级指标与历史趋势、按规则访问日志（JSON，实时查看）与 TOP 统计
- **管理面板 HTTPS**：一键强制 HTTPS（自签名/上传证书），HTTP 301 自动跳转，从节点同步后自动重启
- **MCP 服务**：AI Agent 经 Streamable HTTP + API Key 操作全部功能（只读 Key 自动收敛只读工具集，支持 IP 白名单），操作手册以 MCP 资源内置
- **多用户与 API**：管理员/只读用户、API Key（SHA-256）、密码修改即时吊销旧 JWT、RESTful v1 API + OpenAPI 文档
- **运维**：操作日志全量中文留痕；配置备份导出/导入（校验失败零写入，兼容 v1 nginx 版备份）；品牌定制（应用名/页脚/版本号）

## 快速开始

```bash
# Docker Compose（推荐）
cd web && npm install && npm run build && cd ..
docker compose up -d --build

# 多架构镜像
docker buildx build --platform linux/amd64,linux/arm64 -t <image>:<tag> --push .

# docker run
docker run -d --name lazy-balancer --network host \
  -v $(pwd)/data:/app/data -v $(pwd)/logs:/app/logs \
  -v $(pwd)/certs:/app/certs -v $(pwd)/waf:/app/waf \
  -e LOG_FILE=/app/logs/lazy-balancer.log \
  v55448330/lazy-balancer-v2:v2.1.5
```

> 镜像需直接绑定宿主机 80/443 及自定义监听端口，Linux 建议 `--network host`；macOS/Windows 用 `-p 8000:8000 -p 80:80 -p 443:443`。首次访问 `http://<host>:8000` 进入初始化向导创建管理员，无默认账号密码。

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

集群角色在"系统设置 → 集群管理"页面配置（不走环境变量）。日志级别、时区、日志保留期、审计日志大小均在"基础设置"页面配置。

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
入站 → GeoIP 标记 → 限流（per-IP 速率+突发） → WAF（Coraza+CRS+自定义规则）
     → IP ACL → 请求体大小限制 → 反向代理
```

| 组件 | 版本 |
|---|---|
| WAF 引擎 | Coraza v3（coraza-caddy v2.5.0） |
| 规则集 | OWASP CRS v4.28.0（内置，支持在线更新） |
| GeoIP 库 | IP2Region v3.17.0（离线 xdb，中国省份级） |
| 限流 | caddy-ratelimit v0.1.0 |

**安全策略**以独立实体管理并绑定到 HTTP 规则（一策略可绑多规则，一规则只绑一策略）：

| 配置 | 选项 |
|---|---|
| WAF 模式 | 关闭 / 检测（仅记录） / 拦截（异常分值达阈值后 403） |
| 异常阈值 | 1/3/5/10/20，越低越严格 |
| CRS 规则组与排除 | 按攻击类型组加载 / 按文件名排除 |
| 自定义规则 | URI/参数/请求头/请求体/User-Agent 多条件链式匹配（包含/正则/精确/前缀），可设分值 |
| IP 访问控制 | 白名单（仅允许）/ 黑名单（拒绝）/ 信任名单（跳过检测），CIDR |
| 区域控制 | 基于 IP2Region 拦截所选 / 仅允许所选 |
| 限流 | per-IP 速率上限 + 突发余量 |
| 拦截响应 | 自定义 HTML 拦截页 + 状态码（400/401/403/404/429/503，WAF/IP ACL/限流统一） |

**安全事件**：自动采集 WAF 拦截（Coraza 审计日志解析，含 CRS 与自定义规则）与 IP ACL 拒绝，含趋势图、TOP 攻击类型/源 IP/区域统计；与操作日志共用保留期。审计日志按大小自动轮转（默认 10 MB × 5 份）。

**规则库更新**：CRS 与 IP2Region 支持手动一键 / 每日自动更新（进度日志实时显示，失败自动回滚，结果留痕）。每次成功更新将规则树（含用户自定义配置迁移文件）持久化到数据卷快照，容器重建导致磁盘回退时启动对账自动恢复。

## 主从集群

1. 主节点：集群管理 → 生成注册令牌（一次性，30 分钟有效）
2. 从节点：选择"从节点"，填主节点地址 + 令牌注册
3. 主节点：节点列表"确认"后从节点开始同步并周期上报
4. 从节点全站只读（集群管理除外），可"提升为主节点"脱离集群

主节点配置变更自动递增集群版本，从节点按节哈希增量同步；安全策略、CRS/IP2Region 版本与设置均在同步范围内。

**安全模型**：集群令牌与 CA/DNS 凭证以明文存于 `data/lazy-balancer.db`（令牌需用于 HMAC 验签无法哈希化；启动时强制数据库 `0600`/数据目录 `0700`），请勿共享挂载该目录；集群通信强制 HTTPS + TOFU 指纹防 MITM；令牌无内置轮换，疑似泄露请删除节点记录重新注册。

## 配置备份与迁移

- **导出/导入**：系统信息 → 配置备份（JSON 全量，先校验后导入，Caddy 验证不过则零写入）；v2 备份导入需 ≥ v2.1.2 导出的文件
- **v1 迁移**：直接选择 v1（nginx 版）备份，自动转换负载均衡规则（含内联证书）

## 技术栈与镜像

Go 1.26 · Gin · SQLite · Caddy v2.11.4 + caddy-l4 v0.1.2 + caddy-ratelimit v0.1.0 · Coraza v3 · OWASP CRS v4 · IP2Region v3 · Vue 3 · Element Plus · Vite

```
v55448330/lazy-balancer-v2:v2.1.5
```

## License

[Apache License 2.0](LICENSE)。第三方：Caddy/caddy-l4/caddy-ratelimit/Coraza/CRS/IP2Region（Apache 2.0）、Gin/Vue/Element Plus（MIT）、glebarez/sqlite（MIT）、golang-jwt（MIT）、x/crypto（BSD-3）。
