# XDP 前置防护 · 可选模块设计方案（归档备用，2026-09-25 用户裁定：暂不实施）

> 状态：**设计归档，未实施**。触发条件：用户明确立项。
> 调研结论（2026-09-25）：技术可行、生态成熟（Katran/Cilium/Cloudflare 生产先例），
> 常规流量下收益≈零（现有 @ipListFast 内存二分已达 82ns），真实价值区间是
> L4 泛洪（>10 万 pps）抗打 + 被丢流量绘图（攻击态势唯一数据源）。

## 1. 定位与开关语义（用户裁定 2026-09-25）

- **策略级开关**：`security_policies` 新增 `xdp_offload` 列（0/1），默认关。
- **仅 stage1（IP 访问控制 deny 模式）与 stage2（限流）策略可开**；
  stage0（信任名单）、stage3（WAF）、mixed、off/detection 模式一律不可开
  （向导置灰 + tooltip 原因 + 后端 validateRuleFeatures 同款校验 400）。
- **XDP 与非 XDP 策略共存**：XDP 是叠加前置层而非替代——Caddy 链对全部策略
  照常渲染（语义兜底 + 回退零成本），被 XDP 丢弃的包根本到不了 Caddy；
  XDP 失效/不支持时 Caddy 链照常执行，防护语义无缺口。
- 卸载后该策略的 ACL/限流流量**不再产生** 403/429 拦截页与安全事件
  （内核丢包无应用层语义）——面板文案必须明示此语义折损。

## 2. 端口聚合模型（核心设计约束）

XDP 逐包处理，只见 L3/L4（源/目的 IP、端口、协议、包长、标志位），
**没有域名**（TLS 加密；SNI 虽明文但 ClientHello 跨包时 XDP 无重组，不可靠）。
因此策略→XDP 的映射只能解析为「监听端口 × 源地址」维度：

- 同一监听端口上多条规则的 XDP 策略按端口聚合投影。
- **deny 集** = 该端口全部 XDP 开启 stage1 deny 策略名单（内联∪引用，含
  GeoIP 国家前缀聚合——复用 `wafiplist.AggregatePrefixes`）的并集。
- **allow 模式不支持 XDP 卸载**（v1 裁定）：同端口聚合下 allow 语义
  （「只放行名单内」）会误伤同端口未开 XDP 的规则——向导对 allow 模式
  策略置灰并说明。
- **限流** = 按（目的端口，源 IP）令牌桶；同端口多个 XDP 限流策略取
  最严格者（min rps, min burst）。
- TCP 规则天然兼容（端口维度模型）——本模块若实施，同时覆盖 2026-09-14
  归档的「TCP 规则 IP ACL spike」需求（L4 matcher 插件路径即被本方案取代）。

### 与受信代理（CDN 真实 IP）互斥（硬性）

XDP 看到的是**对端 TCP 地址**——CDN 回源场景下那是 CDN 节点 IP，真实访客
IP 在 HTTP 头里 XDP 拿不到。**启用受信代理的端口上的规则，其绑定策略禁止
XDP 卸载**（否则限流会把整个 CDN 节点掐死、ACL 形同虚设）。写路径校验：
规则启用 trusted_proxy 且策略开 XDP → 400 互斥提示。

## 3. 内核态数据面（BPF 程序，~200 行 C）

| Map | 类型 | 用途 |
|---|---|---|
| `acl_v4` / `acl_v6` | LPM_TRIE | key=(port\|prefix)，value=策略位图（归因计数用） |
| `ratelimit_cfg` | HASH | port → {rps_ns, burst} |
| `ratelimit_state` | LRU_HASH | (port, src_ip) → 令牌桶 {last_ns, tokens} |
| `drop_stats` | PERCPU_HASH | (port, reason, policy_id) → {packets, bytes} |
| `pass_stats` | PERCPU_HASH | port → {packets, bytes}（分布绘图基线） |

程序逻辑（XDP 钩子，eth/IP/TCP|UDP 解析后）：
1. allowlist 兜底端口（面板自身 8000/8001、SSH 22）硬编码跳过——**防自锁**
   （设计红线：任何形态不得拦截面板管理端口）。
2. 查 LPM deny：命中 → 计数 + XDP_DROP。
3. 查限流：令牌不足 → 计数 + XDP_DROP。
4. 其余 XDP_PASS 进协议栈（Caddy 链照常）。

## 4. 控制面（用户态，cilium/ebpf，~600-800 行 Go）

- `internal/xdp/` 新包：probe（能力探测）/ loader（bpf2go 装载+pin）/
  projector（策略→端口聚合→map diff 更新）/ poller（计数器轮询）。
- **投影触发点**：安全策略/绑定/IP 列表/威胁库内容变更的事务提交后
  （`finishTxApply` 同钩位），重算受影响端口的 map 投影并 diff 更新。
  XDP 面秒级生效且不触发 Caddy 重载；Caddy 面仍走原渲染链（不变）。
- **生命周期**：程序与 map pin 到 bpffs（`/sys/fs/bpf/lazy-balancer`），进程
  重启不丢防护；启动时 reattach + 版本戳校验（不符即卸载重建）。
- **探测与回退**：启动探测（netlink attach 试探 + LPM trie 创建试探）；
  不支持的内核/环境（Docker Desktop、OpenVZ、老内核）→ 全局 XDP 不可用，
  开关置灰；运行时 attach 失败 → 受影响策略自动回落 Caddy 执行（本来就在），
  面板横幅告警。回退方向恒安全（Caddy 链是全量渲染的）。

## 5. 事件与绘图（攻击态势）

- 用户态 poller（1s 间隔）读 percpu 计数器 → 聚合落 `metrics` 库新表
  `xdp_drop_stats`（ts, port, reason, policy_id, packets, bytes）。
- 面板新增「攻击态势」卡（安全总览内）：被前置拦截的 pps/bps 时间序列、
  来源 /24 前缀 TOP N、按策略归因分布——**含 Caddy 永远看不到的被丢流量**，
  这是本模块对绘图需求的独有价值。
- **不进 security_events 表**（无 URI/UA/方法，归因语义会污染现有事件口径）；
  独立图表 + 独立口径文案（「前置拦截（内核态）」）。
- HTTP 请求级分布（URL/方法）物理不可得（TLS）——绘图需求中的这部分
  由现有 Caddy metrics/security_events 承担，方案不承诺。

## 6. 部署与构建变更

- Dockerfile：新增 clang/llvm + bpftool 构建阶段（bpf2go 编译 BPF C 为
  内嵌字节码，运行时零外部依赖）；amd64/arm64 双架构 CO-RE 一次编译。
- docker-compose.yml：XDP 开关需要的 `cap_add: NET_ADMIN + BPF` 写成注释
  块（默认注释掉，开启 XDP 时取消注释）——不开 XDP 的部署零特权变化。
- README/部署文档：内核要求段（Linux ≥5.4 建议、SKB 通用模式兜底说明、
  不支持环境清单）。

## 7. 集群语义

各节点本地独立 XDP agent：策略数据经既有集群同步到各节点库后，各节点
独立探测、独立投影自己网卡的 maps。从节点默认可用（探测通过即可）。
主节点面板的「攻击态势」图 v1 仅本节点口径（同安全事件节点本地语义，
已裁定豁免族同哲学）。

## 8. 里程碑（若立项）

1. **M1 最小闭环**：探测 + deny 卸载 + drop 计数器 + 面板开关与互斥校验
   （无绘图）——验证内核兼容面。
2. **M2 限流卸载** + 受信代理互斥门。
3. **M3 攻击态势面板**（poller + 表 + 图）。
4. **M4 集群各节点** + bpffs pin 生命周期加固。

## 9. 风险登记

| 风险 | 等级 | 缓解 |
|---|---|---|
| 内核兼容参差（老 VPS/OpenVZ/桌面 Docker） | 高 | 探测+自动回退 Caddy，Caddy 链恒全量渲染 |
| 特权面扩大（NET_ADMIN+BPF） | 中 | 可选模块，不开零变化；文档明示 |
| CDN 回源场景误伤（限流掐 CDN 节点） | 高 | 受信代理端口互斥硬门（§2） |
| 排障复杂度（内核丢包无日志） | 中 | 随模块附 bpftool 诊断 playbook + 面板「XDP 在丢包」横幅 |
| allow 模式聚合误伤同端口规则 | 高 | v1 不支持 allow 卸载（§2） |
| SNI 不可用导致按域名策略无法卸载 | 已知 | 端口聚合模型明示（§2），同端口语义文档化 |
| CI 不可测（需特权内核） | 中 | 投影/diff 逻辑纯 Go 单测；XDP 集成测试=手工 VM 脚本 |

## 10. 与既有架构的关系

- Caddy 渲染链、四道配置合法性门控、审计/事件体系**全部不变**——XDP 是
  独立旁路，失败域不交叉（回退方向恒安全）。
- 与 @ipListFast 关系：互补不替代——Caddy 侧继续用 @ipListFast（82ns 已
  足够），XDP 侧用内核 LPM trie；同一名单数据两个投影面，由同一聚合算法
  （AggregatePrefixes）供给。
- 若实施，2026-09-14 归档的「TCP 规则 IP ACL spike」（caddy-l4 matcher 插件
  路线）被本方案取代，不再单独实施。
