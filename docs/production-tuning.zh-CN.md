# 生产环境优化指南（WAF + 负载均衡 + Caddy 机制）

> 适用版本：v2.2.5+。本文所有建议均映射到本产品的实际配置项（面板/API 字段），
> 不要求手工修改 Caddy 配置。变更入口：管理面板对应页面或 REST API（MCP 同）。
> 任何配置写入均受四道合法性关卡保护（前端校验 → 后端字段校验 → caddy CLI 校验
> → 事务内应用门控），非法值不会落库、不会扰动运行中的服务。

---

## 1. 内核与容器层（Ubuntu）

主节点采用 `network_mode: host`（Caddy 直接绑定宿主端口），因此命名空间化的
`--sysctl` 不适用，内核参数必须在**宿主机**配置。

> **必要性分级**：以下 sysctl 全部为「症状驱动的进阶调优」，默认 Ubuntu 内核
> 可直接跑生产，不调不影响功能与稳定性。真正必须的只有进程 fd 上限
> （`ulimits`，仓库 compose 已内置）。各项的触发条件见表格备注。

### 宿主机 sysctl（`/etc/sysctl.d/99-lazy-balancer.conf`，`sysctl --system` 生效）

```conf
# HTTP/3（QUIC/UDP）收发缓冲——消除启动期
# "failed to sufficiently increase receive buffer size" 警告，高吞吐 h3 防丢包
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000

# TCP accept 积压队列（突发新建连接场景）
net.core.somaxconn = 4096

# 负载均衡到上游的出站连接临时端口范围（默认 ~28k 个，高并发易耗尽）
net.ipv4.ip_local_port_range = 10000 65535

# docker 发布端口的连接跟踪表（仅 bridge/从节点模式相关；host 模式不走 NAT）
net.netfilter.nf_conntrack_max = 262144

# 系统级 fd 上限
fs.file-max = 2097152
```

> 不建议默认开启 `tcp_tw_reuse=1`：现代内核默认语义已足够，全局开启在某些内核
> 版本存在 TIME_WAIT 回收副作用；确遇出站端口耗尽时再按需处理。

### 文件描述符

每个连接消耗一个 fd（含 TLS/日志/证书文件）。容器内进程上限由 compose
`ulimits` 控制（仓库已配置），宿主机 systemd 单元如需放宽：
`/etc/systemd/docker.service.d/override.conf` 设 `LimitNOFILE=1048576`。

### HTTP/3 端口

- **host 模式（主节点）**：UDP 443 由 Caddy 直接绑定，天然可用，无需额外映射；
  防火墙需放行 `443/udp`。
- **bridge 模式（从节点/独立部署）**：必须显式 `-p 443:443/udp`，否则 HTTP/3 不通。

### 验证

```bash
sysctl net.core.rmem_max          # 应为 7500000
docker exec lazy-balancer sh -c 'ulimit -n'   # 应为 1048576
docker logs lazy-balancer 2>&1 | grep -c "receive buffer"  # 重启后应为 0
```

---

## 2. 负载均衡（反向代理）层

### 2.1 上游连接复用（收益最大的单项优化）

到上游默认每请求新建 TCP 连接；开启 keepalive 后空闲连接复用，省去每请求的
TCP 握手 + 慢启动。高 QPS 场景延迟与上游负载双降。

- **全局默认**：设置 → Caddy 设置 → 上游 KeepAlive 空闲超时（`upstream_keepalive_timeout`）
- **规则级覆盖**：规则编辑 → 传输设置（规则值 >0 时覆盖全局）
- **建议值**：60–120 秒（小于上游服务器自身的空闲超时，避免复用已被上游关闭的连接）
- 上游为 HTTPS 时复用同时省 TLS 握手，收益更大

### 2.2 超时阶梯（避免慢上游拖垮整体）

规则 → 代理超时（秒，0 = 继承全局/Caddy 默认）：

| 字段 | 建议值 | 说明 |
|---|---|---|
| 连接超时 `proxy_dial_timeout` | 3–5s | 上游不可达快速失败转移 |
| 响应头超时 `proxy_response_header_timeout` | 10–15s | 覆盖上游处理 + 首字节 |
| 读/写超时 `proxy_read/write_timeout` | 按业务 30–120s | 长响应（导出/大文件）单独调 |
| TCP 规则流超时 `proxy_stream_timeout` | 按业务 | L4 长连接（数据库/ WebSocket over TCP）需足够大 |

### 2.3 负载策略

| 策略 | 适用 |
|---|---|
| `least_conn` | 上游处理时长不均时的默认推荐 |
| `weighted_round_robin` | 异构机器按权重分流 |
| `ip_hash` | 需会话粘性但上游无共享存储 |
| `cookie` | 显式会话保持（Set-Cookie，注意仅 HTTP 规则支持） |

### 2.4 健康检查（主动）

规则 → 健康检查：建议开启主动检查，路径用轻量端点（`/health`），默认参数
（间隔 10s / 超时 2s / 2 次成功恢复 / 3 次失败摘除）适合多数场景；失败摘除
配合 `least_conn` 实现快速故障转移。被动健康检查（Caddy 内建）始终生效。

### 2.5 压缩与限流保护

- **响应压缩**：`enable_compress` + `compress_types`；CPU 充足时用 `zstd`
  （压缩比/速度优于 gzip），文本类站点建议开启，已压缩内容（图片/视频）勿开。
- **请求体上限** `request_body_max_size_mb`：按业务最小化（如 2–16MB）——
  同时是 WAF 请求体检测的内存上界（见 3.5）。
- **上游并发保护**：上游的「最大连接数」（`max_connections`，渲染为
  reverse_proxy `max_requests`）防止单一上游被打穿。
- **版本隐藏**：`server_tokens_hidden = 2`（完全隐藏 Server 头，渲染为
  deferred headers 处理器）。

---

## 3. WAF 层（coraza + CRS + GeoIP）

### 3.1 模式灰度（标准上线路径）

```
off → detection（观察 3–7 天，事件日志零误报确认） → blocking
```

detection 模式仅记录不拦截；切换 blocking 前用安全事件页确认误报率，
误报处理优先用「CRS 排除规则」或自定义放行规则，而非调低阈值。

### 3.2 CRS 规则组裁剪

只启用业务相关的规则组（策略编辑 → CRS 规则组），降低每请求的规则评估开销
与误报面。常用组速查：

| 组 | 内容 | 建议 |
|---|---|---|
| 920–921 | 协议异常/编解码 | 建议启用 |
| 930–940 | LFI/RFI/PHP/Session | Web 站点建议 |
| 41x/42x/43x | XSS/SQLi | **必开** |
| 44x/95x | Spring/Java | 按技术栈 |
| 49x | 聚合报告 | blocking 模式配合阈值 |
| 92x | 协议攻击（slowloris 等） | 有前置代理时按需 |

### 3.3 阈值与限流

- `anomaly_threshold`：blocking 模式保持 CRS 默认 **5**；detection 观察期可用 5
  直接评估真实拦截面。
- 限流（`rate_limit_rps` + `rate_limit_burst`，令牌桶）：登录/验证码/API 端点
  建议小桶（如 10 rps/burst 20），静态资源不限。按规则粒度配置——绑定到对应
  路径的规则上，避免全站限流误伤。

### 3.4 IP 名单管理

- **IP 列表引用**（策略的 ACL/信任名单引用列表 ID）优于内联名单：可复用、
  可在事件详情页一键追加处置 IP、集群同步自动携带。
- 内联名单仅用于一次性小规模场景。
- GeoIP 地域策略：海外源站无业务时开启「deny 海外」收益明显（拦截发生在
  coraza 之前/旁路 pass 路由，开销低）。

### 3.5 检测开关的成本意识

| 开关 | 成本 | 建议 |
|---|---|---|
| `log_request_body`（请求体记录） | 内存 + 磁盘 + 隐私 | 默认关；排查期临时开 |
| `waf_check_response`（响应体检测） | 高（需缓冲完整响应体） | 仅高危数据出口站点开 |
| 自定义规则 conditions | 每请求正则评估 | 用精确 target（uri/host）而非全字段 |

---

## 4. HTTP/3 与 TLS（Caddy 机制）

- **HTTP/3**：满足 §1 的 UDP 443 + 缓冲区配置即自动生效（Caddy 对 HTTPS 站点
  默认通告 h3）。弱网/移动端收益明显；不启用也可用 h2，仅失去该增益。
- **TLS 会话恢复/票据、OCSP Stapling**：Caddy 全自动，无需配置。
- **证书**：ACME（DNS-01）自动签发续期，重载由证书部署管线自动完成并留痕。
- **手动重载**（`POST /config/reload` / MCP `reload_caddy`）：语义是「强制从
  数据库收敛」，可击穿相同配置短路，用于数据类更新（IP 库/CRS）后的兜底。

---

## 5. 观测与日志

| 项 | 入口 | 建议 |
|---|---|---|
| Caddy 运行日志级别 `caddy_log_level` | 设置 | 生产 `warn` |
| 应用日志级别 `log_level` | 设置 | 生产 `info` |
| 日志轮转 | 日志页（按类配置大小/轮转） | 访问日志按流量调，避免磁盘占满 |
| 审计保留 `audit_retention_months` | 设置（1–12） | 按合规要求，默认 3 |
| 指标采集间隔 `metrics_interval` | 环境变量/配置文件（默认 30s，最小 5s） | 常规 30s，排障期临时调小 |
| 规则访问日志 | 规则级 `log_enabled` | 高 QPS 规则可关，靠指标聚合观测 |

---

## 6. 速查：建议 → 配置项映射

| 建议 | 字段/位置 |
|---|---|
| 上游连接复用 | 全局/规则 `upstream_keepalive_timeout`（60–120s） |
| 快速故障转移 | `proxy_dial_timeout` 3–5s + 主动健康检查 + `least_conn` |
| WAF 灰度上线 | 策略 `mode`：detection → blocking |
| CRS 裁剪 | 策略 `crs_rule_groups` + `crs_excluded_rules` |
| 限流 | 策略 `rate_limit_rps`/`rate_limit_burst`（按规则粒度） |
| 请求体上界 | 全局/规则 `request_body_max_size_mb` |
| 上游保护 | 上游 `max_connections` |
| 响应压缩 | 规则 `enable_compress` + `compress_types=zstd` |
| 隐藏版本 | `server_tokens_hidden=2` |
| H3 | 宿主 `rmem/wmem_max` + 放行 443/udp（host 模式天然可用） |
| 出站端口充足 | 宿主 `ip_local_port_range` |
| fd 上限 | compose `ulimits.nofile`（已配置）/ 宿主 `fs.file-max` |

> 所有面板/API 写入均即时生效（事务内应用 + 自动重载留痕）；失败会有明确
> 400 提示与操作日志，运行中的规则与策略不受影响。
