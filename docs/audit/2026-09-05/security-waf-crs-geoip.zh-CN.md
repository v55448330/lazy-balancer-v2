# 安全模块（WAF/CRS/GeoIP）审计报告（2026-09-05）

## 一、概览

### 1.1 审计范围与文件清单

本报告覆盖「安全模块 — WAF/CRS/GeoIP 链」，全部发现均在本会话中实际读码核实（file:line + 原文摘录）。主从双实例运行数据目录（`data*`、`logs*`、`waf*`、`certs*`）仅查看目录结构，未触碰内容。

后端（Go）：

| 文件 | 说明 |
|---|---|
| `internal/services/crsinstall.go`（604 行，全文精读） | CRS 下载安装、备份/回滚、overrides 迁移合并、快照持久化 |
| `internal/services/crsupdate.go`（350 行，全文精读） | CRS 更新管理器、状态机、版本行读写 |
| `internal/services/crsscheduler.go`（256 行，全文精读） | 24h/小时级自动更新调度、失败退避、rearm |
| `internal/services/crsrelease.go`（216 行，全文精读） | 发布包校验、tar 解压防炸弹、版本比较、SecRule 计数 |
| `internal/services/crshttp.go`（357 行，全文精读） | 下载/限界/进度日志、GitHub 代理白名单、最新 tag 双路查询 |
| `internal/services/crsseed.go`（320 行，全文精读） | 空树播种、启动对账（ReconcileCRSState）、退化快照自愈 |
| `internal/services/crsstatus.go`、`crslog.go`（全文精读） | 状态快照回退、规则计数缓存、更新日志轮转 |
| `internal/services/crs_rule_index.go`（全文精读） | 结构化规则索引、缓存键、文件分类 |
| `internal/services/downloadintegrity.go`（全文精读） | 下载 TOFU 完整性基线 |
| `internal/services/waffiles_sync.go`（522 行，全文精读） | WAF 文件打包/指纹/主从同步/解包校验 |
| `internal/services/ip2regionupdate.go`（关键段精读 run/install/rollback） | IP 库更新、回滚升级链、fail-open 语义 |
| `internal/services/ip2region.go`、`ip2regionhttp.go`（表与下载链精读） | xdb 装载、地域树、别名/拼音/自治州映射表、下载 |
| `internal/services/security.go`（WAF/GeoIP 发射段精读 :99-665、:1319-1517） | BuildCorazaDirectives、GeoIP SecRule、自定义规则发射、校验 |
| `internal/services/caddy.go`（WAF/GeoIP 生成段精读） | coraza handler 编排、GeoIP pass 路由、强制重载变体 |
| `internal/services/cluster_apply.go`（:71-231 精读） | 从节点快照应用 + waf-files 拉取 + 强制重载 |
| `caddygeoip/handler.go`（348 行，全文精读） | IP2Region 打标插件：X-GeoIP-* 头、省/市规范化、fail-closed 哨兵 |
| `internal/handlers/security.go`（WAF/CRS/IP2Region handler 段精读） | CRS 文件/规则/配置读端点、更新触发/开关/状态/日志端点、自定义规则 CRUD |

前端（Vue/TS）：

| 文件 | 说明 |
|---|---|
| `web/src/views/security/SecurityRules.vue`（1125 行，全文精读） | 规则集页：CRS 信息卡、规则文件表、自定义规则表、更新弹框与轮询 |
| `web/src/views/security/SecurityPolicies.vue`（GeoIP/CRS 表单段精读） | 区域控制级联、CRS 规则组级联、文案 |
| `web/src/views/security/SecurityEvents.vue`、`SecurityOverview.vue`（相关段） | 事件族标签、总览 CRS 版本展示 |
| `web/src/composables/useCrsRuleIndex.ts`、`web/src/utils/date.ts` | 索引消费、时间解析口径 |

目录布局核验（只读 `ls`）：`waf/`、`waf-slave/` 均为 `VERSION / crs-setup.conf / crs-setup.stock.conf / rules/` + `audit/audit.log` + 空 `custom/`；`logs/rules/lb_*.log` 为逐规则访问日志（路由域）。`waf/crs.transient` 当前不存在（无在途更新）。

### 1.2 方法

1. 全文精读上述文件，重点追踪五条链：①CRS 安装/升级链（下载→TOFU→落盘→版本行→reload 顺序）；②自定义规则生命周期（校验→存储→发射→事件归因）；③GeoIP 打标（xdb→caddygeoip 变量/头→coraza SecRule→前端选项树）；④WAF 文件主从同步（指纹→按需拉取→解包校验→收敛）；⑤定时任务语义（调度 tick→rearm 退避→UI「下次更新」）。
2. 两侧镜像表（caddygeoip vs internal/services）逐条人工比对。
3. UI 语义 → 存储 → 消费 → 真实渲染 四段对照（见三、开头的对照核验表）。
4. 编译验证（`go build ./internal/services/... ./internal/handlers/...`、`cd caddygeoip && go build ./...`）与单测抽样（`go test ./internal/services -run 'TestBuildCorazaDirectives|TestApplyWafFileBundle|TestUntarGzTo|TestMergeOverridesLines|TestStripTarRoot|TestExtractCRSTarball' -count=1` → `ok`）。

### 1.3 结论摘要

该域经过约 40 轮内部审计迭代（代码内 R33–R72、M2–M24 等标记密度极高），主链路（安装事务性、回滚、TOFU、解包防炸弹、主从收敛、从节点只读三门控）质量显著高于常规项目，本次未发现高严重度问题。发现集中在两类：①一个中严重度的「池指纹覆盖面」缺口（运维手改 `crs-setup.conf`/规则文件后 coraza 池复用旧 WAF，静默不生效）；②一个中严重度的前端展示语义漂移（`pass` 动作显示为「记录」）。其余为低严重度的注释与实现漂移、死脚手架、冗余写法与待裁定的边界语义。两侧 GeoIP 镜像表当前逐条一致，但无一致性测试守门（历史上已漂移过一次）。

## 二、发现清单总表

| 编号 | 位置 | 分类 | 严重度 | 判定 |
|---|---|---|---|---|
| W1 | internal/services/security.go:136-148 | 逻辑 bug（功能失效） | 中 | 缺陷（部分待裁定） |
| W2 | web/src/views/security/SecurityRules.vue:113 | 逻辑 bug（UI 语义） | 中 | 缺陷 |
| W3 | internal/services/crshttp.go:212-215, 330-349 | 不合理逻辑（注释与实现矛盾） | 低 | 设计漂移 |
| W4 | Dockerfile:47 + internal/services/crsseed.go:53-60 | 已弃用代码（死目录） | 低 | 设计漂移 |
| W5 | Dockerfile:49-56 + 4 处注释 | 已弃用代码（ghfast 残留） | 低 | 设计漂移 |
| W6 | internal/services/crsinstall.go:111-131 | 冗余代码 | 低 | 设计漂移 |
| W7 | internal/services/waffiles_sync.go:348-355 | 冗余代码 | 低 | 设计漂移 |
| W8 | internal/handlers/security.go:2838 | 冗余代码（遮蔽+硬编码） | 低 | 设计漂移 |
| W9 | internal/services/crsupdate.go:270-299 + crsinstall.go:176-178, 384-399 | 不合理逻辑（过度恢复） | 低 | 待裁定 |
| W10 | internal/services/crsupdate.go:226 vs handlers/security.go:2303 | 不合理逻辑（NULL 口径） | 低 | 有意设计（文案瑕疵） |
| W11 | internal/services/crsinstall.go:23-60 | 不合理逻辑（overrides 只增不减，语义未披露） | 低 | 有意设计（R60） |
| W12 | caddygeoip/handler.go:244-348 vs internal/services/ip2region.go:341-408, 659-680 | 不合理逻辑（镜像表无守门） | 低 | 有意设计 + 待裁定 |
| W13 | caddygeoip/handler.go:215-225 vs SecurityPolicies.vue:443-451 | 不合理逻辑（文案与哨兵粒度） | 低 | 有意设计 + 待裁定 |
| W14 | internal/services/crsupdate.go:104 | 冗余代码 | 低 | 设计漂移 |
| W15 | internal/services/crsupdate.go:239-248 vs waffiles_sync.go:503-522 | 不合理逻辑（tag 形状校验不对称） | 低 | 待裁定 |

统计：**15 条**。按严重度：高 0 / 中 2 / 低 13。按分类：逻辑 bug 2（W1、W2）；不合理逻辑 6（W3、W9、W10、W11、W12、W13、W15 中的 6 条——W15 计入）；冗余代码 4（W6、W7、W8、W14）；已弃用代码 2（W4、W5）。（W11/W12/W13 兼具「有意设计」属性，分类按主要风险面归入不合理逻辑。）

## 三、逐条详述

### 三-0 四段链路对照核验（先立基线，再列问题）

以下对照均经本会话读码逐段核实，结论为「一致」者是本次未发现问题的正面核验，作为 W 系列发现的参照系：

| 链路 | UI 语义 | 存储 | 消费 | 真实渲染 | 结论 |
|---|---|---|---|---|---|
| GeoIP 区域选择 | 级联多选：省=整省、`省/市` 联值、`海外` 一级（SecurityPolicies.vue:761-775，城市节点 value=`${prov}/${city}`） | `geoip_countries` JSON 数组文本（:2213） | `geoipLocOperator`（services/security.go:417-432）：省条目 `^(?:省(?:/.*)?)$`、`省/市` 精确锚定、allow 取反，QuoteMeta 转义 | caddygeoip setGeoIPPlaceholders（handler.go:215-225）发 `海外`/`省`/`省/市`，与树侧同款规范化表 | 一致 |
| GeoIP fail-closed | alert 披露「IPv6 与不可解析客户端按海外处理」（SecurityPolicies.vue:443-451） | — | coraza `id:8` 读 `X-GeoIP-Loc`；xdb 缺失时 ServeHTTP 恒设 `海外` 哨兵（handler.go:127-133） | IPv6/查询失败→海外；但国内省列缺失→空串（见 W13） | 基本一致，粒度见 W13 |
| CRS 更新状态 | 状态 tag/轮询 2s/成功后刷新版本与文件表（SecurityRules.vue:863-902） | `security_crs_version` 行 + 内存 taskState | StatusSnapshot 内存优先、stored 兜底（crsupdate.go:340-350） | stage 枚举与前端 `crsStageLabels` 一一对应 | 一致 |
| 自动更新排程 | 开关即写 `next_update=+24h`（R69）、「下次更新」列 | `next_update` UTC naive 文本 | schedulerTick 到期触发 + rearm 失败退避 1h→24h（crsscheduler.go:118-215） | 前端 date.ts:80 将 naive 串按 UTC 解析→配置时区渲染 | 一致 |
| 自定义规则动作 | 编辑器三态 拦截/仅记录/放行计分（:259-266） | `security_custom_rules.action`（block/log/pass，handlers/security.go:76-78） | emitCustomRules：block→deny+skipAfter；log→不累分；pass→`setvar:tx.inbound_anomaly_score_pl1=+N`（services/security.go:544-551） | **列表标签二值化，pass 显示为「记录」** | 不一致 → W2 |
| 从节点只读 | 开关/按钮 `isReadOnly` 禁用 | — | 三层门：handler 直查 403（security.go:2300-2328）、run() 起点复查（crsupdate.go:222-229）、调度器 tick is_master 守卫（crsscheduler.go:118-122） | 从节点 UI 只读 + 后端 403 | 一致 |
| WAF 文件主从同步 | 集群设置「规则库数据库」（ClusterSettings.vue:427） | 快照嵌 `WafFiles` 哈希引用（无内容） | 双门 `wafFilesRefDiffers || wafFilesDrifted`（cluster_apply.go:162）→按需拉取→`untarGzTo` 解包+整树哈希复核→落盘 | VERSION 原始字节随 tar 落盘（R46-E1）、`.version` sidecar 双写（R57 A-#4） | 一致 |

### W1 coraza 池指纹未覆盖 crs-setup.conf / rules/*.conf 的带外手改（中）

**位置**：internal/services/security.go:136-148（`crsPoolFingerprint`）、:152-164（嵌入 directives）；参照 handlers/security.go:2859-2862、internal/services/security_waf_test.go:421-465。

**代码证据**（security.go:136-148）：

```go
func crsPoolFingerprint() string {
	var version string
	if db.DB == nil {
		version = "unknown"
	} else if err := db.DB.QueryRow("SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1").Scan(&version); err != nil {
		version = "unknown"
	}
	var mtime, size int64
	if st, err := os.Stat(filepath.Join(crsDirectivesDir, "zz-user-overrides.conf")); err == nil {
		mtime, size = st.ModTime().UnixNano(), st.Size()
	}
	return fmt.Sprintf("%s-%d-%d", version, mtime, size)
}
```

设计自述（security.go:124-130）：「coraza-caddy v2.5.0 的 computePoolKey() = hash(directives + include + crs flag)……在 directives 里嵌内容指纹（**CRS 版本 + overrides mtime+size**……），指纹变 → 池键变 → 新 WAF 真正编译新规则。」——即团队已知 coraza WAF 按池键复用，指纹是唯一的内容失效信号。

而 `crs-setup.conf` 被明确视为运维可手改文件（handlers/security.go:2859-2862 注释：「crs-setup.conf 是运维可手改文件」；`GET /security/crs/setup` 即为其只读查看端点；CRS 更新的整套 overrides 迁移机制也以「用户手改 setup」为前提，见 crsinstall.go:214-257）。

**问题推导**：手改 `/app/waf/crs/crs-setup.conf` 或 `rules/*.conf` 后——
1. `security_crs_version` 行不变、`zz-user-overrides.conf` 不存在或不变 → 指纹不变 → directives 不变 → Caddy 配置 JSON 不变（普通 apply 被 errSameConfig 短路，见 caddy.go:88-93 注释）；
2. 即便走 `GenerateAndApplyConfigForce`（caddy.go:94-97，UI「重载配置」、CRS/IP 库/CA 队列入口），provision 重新执行但 coraza 池键相同 → `LoadOrNew` 复用旧 WAF（该行为由 security.go:124-127 注释与 security_waf_test.go:421-465 测试锚定；本报告未读 coraza-caddy 源码，此环节依据仓库自述模型，标注为基于代码注释的推导）；
3. 结果：手改内容静默不生效，直到 Caddy 进程重启或下一次 CRS 版本变更（版本行变化改变指纹）。

**主从两侧同病**：从节点 `ApplyWafFileBundle` 落盘新文件后由 cluster_apply.go:181 `ApplyConfigForce` 强制重载，但若内容变化不伴随版本行/overrides 变化（典型：主节点手改 setup 后被同步），从节点同样池键不变——磁盘新、coraza 内存旧，且 `wafFilesDrifted` 收敛后无任何纠偏通道。

**分类**：逻辑 bug（功能失效——支持的运维操作不生效）。**判定**：缺陷。依据：指纹作者枚举的变化向量只有「CRS 文件替换（经版本行）」与「手动改 overrides」两个（security.go:126-128 原文），遗漏了同一文件族中明确支持手改的 `crs-setup.conf` 与 `rules/*.conf`；若是刻意取舍，成本论证（「2 个 stat + 1 个 db 查询」）表明再加 1 个 `crs-setup.conf` stat 并不昂贵，故更接近疏漏而非权衡。**影响**：运维按官方注释手改 CRS 配置后无告警地不生效（安全策略可能长期停留在旧阈值/旧开关）。**建议**：将 `crs-setup.conf` 的 mtime+size 纳入指纹（成本 +1 stat）；`rules/` 树可用（文件数,最大 mtime,总 size）聚合键（crs_rule_index.go:299-323 已有同款实现可复用）。**是否待裁定**：是——若团队裁定「手改 setup/rules 不属于支持面」，则降级为文档问题（应同步修正 handlers/security.go:2861 的「运维可手改文件」表述与 overrides 迁移机制的前提）。

### W2 自定义规则列表把 action=pass 显示为「记录」（中）

**位置**：web/src/views/security/SecurityRules.vue:111-115（列表渲染）、:259-266（编辑器三态）；后端依据 handlers/security.go:76-78、services/security.go:544-551；对照 SecurityPolicies.vue:1749-1750。

**代码证据**：

SecurityRules.vue:112-114（列表「动作」列）：

```vue
<template #default="{ row }">
  <el-tag :type="row.action === 'block' ? 'danger' : 'warning'" size="small" effect="light">{{ row.action === 'block' ? '拦截' : '记录' }}</el-tag>
</template>
```

SecurityRules.vue:260-265（编辑器提供三态并阐明语义差异）：

```vue
<el-radio-group v-model="ruleForm.action">
  <el-radio value="block">拦截</el-radio>
  <el-radio value="log">仅记录</el-radio>
  <el-radio value="pass">放行计分</el-radio>
</el-radio-group>
<div class="form-tip-line">拦截=命中即阻断；仅记录=只记录事件；放行计分=记录并向异常分累加（由 WAF 评分拦截统一裁决）</div>
```

后端确证 pass 是合法且语义独立的动作：handlers/security.go:76-78（`rule.Action != "block" && ... != "pass"` 才拒绝）；发射端 services/security.go:544-551 中 `pass` 累加 `tx.inbound_anomaly_score_pl1`、`log` 不累分——两者对 949 评分拦截的贡献完全不同。前端策略冲突检测也区分二者（SecurityPolicies.vue:1749-1750：`p.customRefs.some((r) => r.action === 'pass')`）。

**分类**：逻辑 bug（UI 语义）。**判定**：缺陷。依据：pass 动作引入时（编辑器、冲突检测均已跟进）列表渲染未同步，二值化丢失第三态；非有意设计——同文件内其他消费点均三态。**影响**：用户在列表页无法区分「放行计分」与「仅记录」，可能误判某规则不会影响拦截决策（实际会推高异常分触发 949 拦截），安全语义误读。**建议**：列表 tag 按三态映射（block=拦截/danger、pass=放行计分/warning 或 info、log=仅记录/info）。**是否待裁定**：否。

### W3 GitHub 最新 tag 查询的 403 重试与函数头注释矛盾（低）

**位置**：internal/services/crshttp.go:212-215（`defaultFetchCRSLatestTag` 文档）、:330-349（`fetchGitHubLatestTagFromAPI` 文档与实现）；同款文档另见 ip2regionhttp.go:26-29。

**代码证据**：

crshttp.go:330-333（函数头注释）：

```go
// fetchGitHubLatestTagFromAPI 直连 GitHub releases/latest API 解析 tag_name。
// transport 报告失败是否为网络/传输类（Do() 错误、5xx、响应体读取中断）——
// 只有这类失败值得经 GitHub 代理重试；4xx（含限流 403）不重试（R57：代理对
// api.github.com 同样 403，重试只会放大延迟）。
```

crshttp.go:345-350（实现与行内注释）：

```go
	if resp.StatusCode != http.StatusOK {
		// 403 = GitHub API 未认证限流（60 次/小时/IP），可经代理 releases/latest
		// 页面绕过；5xx = 传输类故障，同样走代理回退。其余 4xx 不重试。
		return "", fmt.Errorf("GitHub 返回 %d", resp.StatusCode),
			resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusForbidden
	}
```

实现把 403 计为 transport=true → `defaultFetchCRSLatestTag`（:216-230）会经代理的 `github.com/<repo>/releases/latest` 页面重试（该 URL 与 api.github.com 不同源，代理可用）。行为本身合理（限流绕行），且行内注释正确；但两处函数头注释（crshttp.go:214「4xx 与 tag 解析失败不重试」、:331-333「4xx（含限流 403）不重试」）与实现相反，ip2regionhttp.go:27-28 同样照抄了旧口径。

**分类**：不合理逻辑（文档与实现矛盾）。**判定**：设计漂移——403 重试为后期有意加入（行内注释与 R57 上下文可证），函数头注释未同步。**影响**：误导后续维护（按注释删除 403 分支会回归限流场景）。**建议**：修正两处（含 ip2regionhttp.go）函数头注释为「403 限流与 5xx/传输类失败经代理 releases/latest 页面重试；其余 4xx 与解析失败不重试」。**是否待裁定**：否。

### W4 `/app/waf/custom` 死目录脚手架（低）

**位置**：Dockerfile:47（创建）、internal/services/crsseed.go:53-60（播种时重建骨架）；全仓库 grep 无读写方。

**代码证据**：

Dockerfile:47：

```dockerfile
RUN mkdir -p /app/data /app/config /app/logs /app/certs /app/waf/crs /app/waf/custom /app/waf/audit
```

crsseed.go:53-59：

```go
	// The bind mount also hides the aux dirs referenced by the generated WAF
	// config (SecAuditLog lives under waf/audit), so recreate the skeleton.
	wafDir := filepath.Dir(liveDir)
	for _, sub := range []string{"custom", "audit"} {
		if err := os.MkdirAll(filepath.Join(wafDir, sub), 0755); err != nil {
```

注释只解释了 `audit` 的用途（SecAuditLog 所在）；`custom` 无任何消费者——自定义规则的真实现是 DB 表 `security_custom_rules` 经 `BuildCorazaDirectives` 内联发射（services/security.go:517-602），全仓库（含 caddygeoip 模块、前端）没有任何路径读写 `waf/custom`。实测 `waf/custom` 与 `waf-slave/custom` 均为空目录。

**分类**：已弃用代码（目录约定残留）。**判定**：设计漂移——早期「自定义规则以文件形态存放」设计的脚手架残留，规则改为 DB 形态后未清理。**影响**：无功能影响；误导运维与后续开发（任务书本身也把「audit/crs/custom」并列为目录约定，说明残留已造成认知成本）。**建议**：从 Dockerfile 与 crsseed.go 骨架列表移除 `custom`（保留 `audit`），并在发布说明中注明该目录废弃。**是否待裁定**：否。

### W5 ghfast.top 代理残留：构建期单源依赖 + 运行期注释陈旧（低）

**位置**：Dockerfile:49-56（CRS 构建下载）、:64-68（xdb 双源）；运行期注释 internal/services/downloadintegrity.go:3-4、crsupdate.go:326-327、ip2regionupdate.go:401-403、ip2regionhttp.go:27-28；对照 crshttp.go:142。

**代码证据**：

Dockerfile:53-56（CRS 发布包仅经 ghfast.top 单源下载，无直连回退）：

```dockerfile
ARG CRS_VERSION=v4.28.0
RUN apk add --no-cache curl && \
    mkdir -p /tmp/crs-src && \
    curl -sL "https://ghfast.top/https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" | tar xz --strip-components=1 -C /tmp/crs-src && \
```

Dockerfile:66-68（xdb 却有双源回退，二者不对称）：

```dockerfile
    (curl -sfL -o /app/waf.dist/ip2region.xdb "https://ghfast.top/https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb" || \
     curl -sfL -o /app/waf.dist/ip2region.xdb "https://raw.githubusercontent.com/lionsoul2014/ip2region/v3.17.0/data/ip2region_v4.xdb") && \
```

而运行时代码已声明废弃该代理（crshttp.go:142）：「仅允许 gitHubProxyOptions 内置选项；历史硬编码 ghfast.top 已废弃」，白名单为 gh-proxy.org 家族（:147-151）。同时 4 处运行期注释仍以 ghfast 指代现役代理（如 downloadintegrity.go:3「ghfast.top 代理下载无上游官方校验和可钉」、crsupdate.go:326「携带完整来源 URL（含 ghfast 代理前缀）」）。

**分类**：已弃用代码（构建依赖与注释残留）。**判定**：设计漂移——运行时代理已收敛到白名单，构建链与文档未跟上。**影响**：①构建可复现性/可用性风险：ghfast.top 失效且构建网络无法直连 GitHub 时镜像无法构建（CRS 无回退）；②注释误导排障（按注释去找 ghfast 前缀的日志行会落空，实际前缀是 gh-proxy.org）。**建议**：Dockerfile 的 CRS 下载补直连回退（对齐 xdb 双源模式）；4 处注释统一改为「GitHub 加速代理（github_proxy_url 白名单）」。**是否待裁定**：否。

### W6 cleanupLegacyCRSTransient 恒真条件与倒置循环（低）

**位置**：internal/services/crsinstall.go:111-131。

**代码证据**：

```go
func (m *CRSUpdateManager) cleanupLegacyCRSTransient() {
	removed := 0
	for _, name := range []string{".staging", "rules.bak", "rules.bak.tmp", "rules.old"} {
		if entries, err := os.ReadDir(m.crsDir); err == nil {
			for _, e := range entries {
				match := e.Name() == name
				if !match && (strings.HasSuffix(e.Name(), ".bak") || strings.HasSuffix(e.Name(), ".old")) {
					match = e.IsDir() || true
				}
				if match {
					if err := os.RemoveAll(filepath.Join(m.crsDir, e.Name())); err == nil {
						removed++
					}
				}
			}
		}
	}
```

两个问题：①`match = e.IsDir() || true` 恒为 true，`e.IsDir()` 判断是死代码；②循环结构倒置——外层遍历 4 个目标名、每个名字重读一次目录，而自然写法是读一次目录、对每个条目判断（是否属于目标名集合或 .bak/.old 后缀）。行为正确（每次迭代重新 ReadDir，已删条目不会重复计数），但可读性差、目录被读 4 次。

**分类**：冗余代码。**判定**：设计漂移（一次性清理补丁的痕迹，未做整理）。**影响**：无功能影响；维护成本与误读风险。**建议**：重写为单次 ReadDir + `transientNames` 集合 + 后缀判断；删除恒真表达式。**是否待裁定**：否。

### W7 untarGzTo 的两段式文件写法与 extractCRSTarball 不一致（低）

**位置**：internal/services/waffiles_sync.go:345-355；对照 internal/services/crsrelease.go:180-186。

**代码证据**：

waffiles_sync.go:348-355（先写空文件再以无 O_CREATE 标志打开）：

```go
			if err := os.WriteFile(target, []byte{}, 0644); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			written, err := io.Copy(f, tr)
```

crsrelease.go:180-186（同仓库另一解包器的一段式写法）：

```go
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return fmt.Errorf("创建目录 %s: %w", filepath.Dir(rel), err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("写入 %s: %w", rel, err)
		}
```

功能等价（WriteFile 充当「确保存在」，随后 OpenFile 截断写），但多一次 open/close 系统调用，且两处解包器风格分叉。无注释解释差异。

**分类**：冗余代码。**判定**：设计漂移。**影响**：无功能影响；同步解包逻辑时的不一致样板。**建议**：统一为 crsrelease.go 的一段式。**是否待裁定**：否。

### W8 GetCRSRuleContent：filepath 变量遮蔽包名 + 硬编码路径形成第三份目录真源（低）

**位置**：internal/handlers/security.go:2838；对照 :26-27（`crsRulesDir` 测试缝）与 internal/services/crs_rule_index.go:29-31（`CRSRuleIndexDir`）。

**代码证据**：

handlers/security.go:26-27：

```go
// crsRulesDir 是 CRS 规则文件目录；定义为变量以便测试注入临时目录。
var crsRulesDir = "/app/waf/crs/rules"
```

handlers/security.go:2833-2839：

```go
func (h *Handlers) GetCRSRuleContent(c *gin.Context) {
	filename := c.Param("filename")
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的文件名"})
		return
	}
	filepath := filepath.Join("/app/waf/crs/rules", filename)
```

两个问题：①局部变量 `filepath` 遮蔽同名包（本函数恰好只此一处用包，能编译；后续维护者在同函数再写 `filepath.Xxx` 即编译错误，且极易看漏）；②硬编码字面量 `"/app/waf/crs/rules"` 绕过了 `crsRulesDir` 测试缝（ListCRSRules 用缝、Content 端点不用，security_r33_test.go:63 的注入只影响列表），与 services 侧 `CRSRuleIndexDir` 构成三份同值真源。

**分类**：冗余代码（重复真源）+ 不合理逻辑（遮蔽）。**判定**：设计漂移。**影响**：测试盲区（Content 端点无法在临时目录下测试）与目录调整时的三处同步成本。**建议**：改写为 `path := filepath.Join(crsRulesDir, filename)`。**是否待裁定**：否。

### W9 CRS 更新对「未动盘」的失败也执行 restoreBackup + 强制重载；stale bak 可被消费（低，待裁定）

**位置**：internal/services/crsupdate.go:270-273、:293-299（fail）；crsinstall.go:137-178（失败点早于备份点）、:384-399（restoreBackup 对 rules/setup 段不校验运行归属）。

**代码证据**：

crsupdate.go:270-273（downloadAndInstall 的任何错误都按 restore=true 处理）：

```go
	if err := m.downloadAndInstall(tag); err != nil {
		m.fail(err, true)
		return
	}
```

crsupdate.go:293-299（restore=true 时无条件重载 Caddy）：

```go
func (m *CRSUpdateManager) fail(cause error, restore bool) {
	if restore {
		m.restoreBackup()
		if err := m.reloader(); err != nil {
			log.Printf("crs update: reload after restore failed: %v", err)
		}
	}
```

而 downloadAndInstall 中下载（:153）、解压（:156）、校验（:161）、TOFU（:169）均发生在任何备份/落盘之前；`rulesBak` 的清理点在 :176-178（备份段之前）：

```go
	rulesPath := filepath.Join(m.crsDir, "rules")
	rulesBak := crsTransientPath(m.crsDir, "rules.bak")
	os.RemoveAll(rulesBak)
```

restoreBackup 中 rules/setup/stock 段按「.bak 存在即恢复」执行（crsinstall.go:385-408），仅 overrides 段有 `m.overridesBakCreated` 运行归属门（:411-415）。

由此形成两个次生现象：
1. **纯下载失败也强制重载**：`m.reloader()` 即 `GenerateAndApplyConfigForce`（main.go:104-108）——must-revalidate 全量 provision。自动更新 + 代理持续故障 + 退避重试（1h→…→24h）期间，每次失败都附带一次无意义的全量重载。无正确性问题，属冗余动作。
2. **stale bak 消费窗口**：若上次更新在「已创建备份、未消费」处崩溃（代码自认的崩溃窗口，crsinstall.go:259-263、:333-335），残留的 `rules.bak`/`setup.bak` 会在下一次更新的**下载失败**路径被 restoreBackup 直接搬回 live——本次运行并未改动过 live 树，live 却被替换为上一次中断更新前的旧树，且该路径不回滚版本行（版本行回滚仅存在于 reload 失败分支，:314-322），磁盘树与 `security_crs_version` 可能分叉直至重启对账。触发链长（崩溃残留 + 后续下载失败），概率低。

**分类**：不合理逻辑（过度恢复）。**判定**：待裁定——统一失败路径简化了状态机（有意成分），但「pre-mutation 失败不做恢复/不重载」的区分缺失使恢复动作越过了本次运行的变更边界（缺陷成分）。**影响**：现象 1 为冗余重载；现象 2 为低概率的版本行/磁盘分叉。**建议**：downloadAndInstall 内部区分阶段（如返回 sentinel 包装的 pre-mutation 错误），fail() 对 pre-mutation 失败仅落库失败状态；或 restoreBackup 对 rules/setup 段同样引入运行归属标记。**是否待裁定**：是。

### W10 is_master 为 NULL 时 handler 门与 run() 复查口径相反（低）

**位置**：internal/services/crsupdate.go:224-229 vs internal/handlers/security.go:2300-2306、:2319-2328（IP2Region 同构：ip2regionupdate.go:181-187 vs handlers/security.go:2419-2424）。

**代码证据**：

run() 复查（crsupdate.go:226，NULL→0，从严）：

```go
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,0) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		m.setStage(CRSStatusFailed, "当前节点为从节点，终止 CRS 更新")
		return
	}
```

handler 门（security.go:2303，NULL→1，从宽）：

```go
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
		return
	}
```

`is_master` 为 NULL 时：handler 放行（视为 master）→ run() 拒绝（视为 slave），用户得到「当前节点为从节点」的误导性失败文案；实际语义是「角色未知」。查询失败（ErrNoRows 等）时两层都拒绝，无分歧。

**分类**：不合理逻辑（NULL 语义不对称 + 文案失真）。**判定**：有意设计——入口从宽、执行从严的纵深防御方向本身合理（宁可失败也不在未知角色上写盘），但两处 COALESCE 默认值相反未在注释中说明，失败文案把「NULL/未知」误报为「从节点」。**影响**：仅限 `is_master` NULL 的异常数据形态；影响为排障误导。**建议**：统一两处 COALESCE 默认值（建议均 0，从严），或将 run() 文案改为「节点角色未知或为从节点，终止 CRS 更新」。**是否待裁定**：否（倾向文案修正即可）。

### W11 zz-user-overrides.conf 只增不减的合并语义无任何 UI/文档披露（低）

**位置**：internal/services/crsinstall.go:19-60（mergeOverridesLines）、:227-257（迁移点）。

**代码证据**（crsinstall.go:19-22 注释自述）：

```go
// mergeOverridesLines 生成合并后的 overrides 内容：既有 overrides 的有效行
// 在前（保留历史自定义），本次迁移 diff 追加在后，按行文本去重（同一行只写
// 一次，消除 R53 新-2 的重复 SecRule id 顾虑），header 仅保留新的一份。
```

合并取并集（既有 ∪ 新 diff），无任何减法通道：用户若在 `crs-setup.conf` 中**删除**一条曾被迁移进 overrides 的自定义行，该行仍留在 `zz-user-overrides.conf` 中继续生效；overrides 文件本身没有任何 UI 编辑入口（仅 `GET /security/crs/setup` 查看 setup，规则文件端点只读 rules/ 目录），只能手工编辑文件——而手改 overrides 恰好被 W1 的指纹覆盖（mtime+size）。

**分类**：不合理逻辑（生命周期不完整：有增无删）。**判定**：有意设计——R60 明确选择「合并保全」以修复此前整体覆写丢行的问题（注释 :247-254 引测试为证），方向正确；缺口在于「删除自定义配置」这一用户意图没有对应的操作面与披露。**影响**：用户通过回改 setup 撤销自定义时静默失效（规则继续生效），安全语义上可能是「该关的没关」。**建议**：短期在 `GET /security/crs/setup` 端点/页面补充说明（自定义行应编辑 zz-user-overrides.conf）；长期考虑提供 overrides 查看/编辑 UI 或在迁移时 diff 双向比对提示。**是否待裁定**：是（是否补 UI 属产品决策）。

### W12 caddygeoip 与 services 的四张镜像表当前一致，但无一致性测试守门（低，待裁定）

**位置**：caddygeoip/handler.go:244-259（provinceAliases）、:261-265（taiwanCities）、:273-289（cityPinyinFixes）、:327-348（autonomousPrefectures）↔ internal/services/ip2region.go:341-355、:358-362、:392-408、:659-680。

**核验过程**：本会话对四张表逐条人工比对——省别名 17 条、台湾城市 13 条、拼音城市修正 45 条、自治州/地区 29 条，两侧键值完全一致（含注释中自认曾缺失 11 条的港澳台恒等映射，现已在位）。

**代码证据**（handler.go:245-247 自认历史漂移）：

```go
	// R72 二十六次 W3-4：与 internal/services/ip2region.go 的 ip2ProvinceAliases
	// 逐条镜像（此前缺 11 条恒等映射与港澳台——无行为分歧但同步不变量破坏；
	// 修改需两侧同步）。
```

两侧同步仅靠注释纪律（多处「修改需两侧同步」），全仓库无任何跨模块一致性测试（grep 无同时引用两表的测试；caddygeoip 是独立 Go module，internal 无法 import，但可用源码文本比对或 go:embed 方式守门）。表一旦漂移：选项树（策略可配置的省/市）与发射变量（X-GeoIP-Loc）不一致 → 城市级地域规则对受影响段**恒不命中且无报错**，属该域最典型的静默失效形态。

**分类**：不合理逻辑（不变量无守门）。**判定**：有意设计（叶子 Caddy 模块不可 import internal 的结构性权衡）+ 待裁定（守门机制缺失是否补齐）。**影响**：未来再次漂移时城市级规则静默失效（历史上已发生一次）。**建议**：在 internal/services 增加一个读取 `caddygeoip/handler.go` 源文件文本并解析四张 map 字面量、与 services 侧表比对的守门测试（模块路径不依赖 import，仅文件读取）。**是否待裁定**：是。

### W13 国内省份不可解析时 X-GeoIP-Loc 为空串而非「海外」，与 UI 披露文案存在粒度出入（低，待裁定）

**位置**：caddygeoip/handler.go:215-225；对照 web/src/views/security/SecurityPolicies.vue:443-451。

**代码证据**：

handler.go:215-225（末段覆盖哨兵）：

```go
	if fields[0] != "中国" {
		r.Header.Set("X-GeoIP-Loc", "海外")
	} else if city != "" {
		r.Header.Set("X-GeoIP-Loc", province+"/"+city)
	} else {
		r.Header.Set("X-GeoIP-Loc", province)
	}
```

当国家列为「中国」而省列缺失/为 "0" 时，province=city=""，最终 `X-GeoIP-Loc` 被 Set 为**空串**（覆盖了 :168 预设的「海外」哨兵）。消费端（services/security.go:417-432 geoipLocOperator + :271-274 的 id:8 SecRule）：deny 模式勾选「海外」时空串不命中（放行）；allow 模式取反后空串命中（拦截）。

SecurityPolicies.vue:449 的披露文案：「IPv6 与不可解析客户端按『海外』处理（拦截模式勾选海外时将被拦截；仅允许模式只勾选省份时将被拦截）」——「不可解析客户端」若被理解为包含「国内段省份不可解析」，则 deny+海外 的实际行为（放行）与文案（拦截）不符；空串形态的实际语义是「deny 模式 fail-open、allow 模式 fail-closed」（handler.go:151-157 注释对空串的表述为「省/市项对空串恒不匹配（不误伤）」，即有意如此）。

**分类**：不合理逻辑（文案粒度 vs 哨兵分支）。**判定**：有意设计（R72 D1 哨兵体系，注释明示空串对省/市项恒不匹配的动机是「不误伤」）+ 待裁定（该子形态是否属于应披露的「不可解析」范畴，取决于真实 xdb 中「中国+空省列」段的存在比例，本次未对运行中 xdb 做全量扫描验证）。**影响**：若存在此类段，deny+海外 策略对其放行，与用户对文案的预期相反。**建议**：二选一——①文案精确化（「查询失败/IPv6/海外客户端按海外处理；国内省份缺失段不参与地域匹配」）；②发射侧把国内空省段也归一为「海外」哨兵（语义变更，需产品裁定）。**是否待裁定**：是。

### W14 CRSUpdateManager.ruleCount 的 -1 哨兵从未被消费（低）

**位置**：internal/services/crsupdate.go:104（构造）；消费方 crsstatus.go:56-75。

**代码证据**：

crsupdate.go:98-107：

```go
func newCRSUpdateManager(reloader func() error) *CRSUpdateManager {
	return &CRSUpdateManager{
		...
		crsDir:            crsLiveDir,
		ruleCount:         -1,
```

crsstatus.go:58-75 中实际门是 `m.hasRuleCount`（`if m.hasRuleCount { return m.ruleCount }`；扫描失败返回 0 且不置缓存），`ruleCount` 的初值 -1 无任何读取方区分语义（RuleCount 在 hasRuleCount=false 时不会读 ruleCount）。`-1` 是残留的「未扫描」哨兵，被 hasRuleCount 布尔取代后未清理。

**分类**：冗余代码。**判定**：设计漂移（重构残留）。**影响**：无。**建议**：初值改 0 并删注释性哨兵，或删除字段初始化。**是否待裁定**：否。

### W15 上游 tag 无形状校验直接入库/入 URL，与从节点侧 sanitizeBundleVersion 不对称（低，待裁定）

**位置**：internal/services/crsupdate.go:239-248（tag 来源与使用）；crshttp.go:201-203（URL 拼接）；对照 waffiles_sync.go:499-522（从节点侧存在形状校验）。

**代码证据**：

crsupdate.go:240-248（fetchLatestTag 结果直接参与比较、下载与落库）：

```go
	m.setStage(CRSStatusChecking, "查询最新 CRS 版本")
	tag, err := m.fetchLatestTag(context.Background())
	...
	writeCRSUpdateLog("INFO", string(CRSStatusChecking), fmt.Sprintf("最新版本 %s，当前版本 %s", tag, currentCRSVersion()))

	if tag == currentCRSVersion() {
```

tag 的两条来源：直连 api.github.com（可信 HTTPS）或白名单代理的 `releases/latest` 302 Location / 页面正则（crshttp.go:271-328，正则 `[^"'/]+` 已排除斜杠与引号）。tag 随后被：①拼入下载 URL（crshttp.go:201-203）；②与 DB 版本做字符串等值比较；③成功后原样写入 `security_crs_version.version` 与 live `VERSION` 标记（crsinstall.go:304-306、:340）。主节点侧无任何 `^v?\d+(\.\d+)*$` 形状校验；而从节点收到的版本串却有 `sanitizeBundleVersion`（≤64 可打印 ASCII，waffiles_sync.go:506-522）防线。恶代/劫持的白名单代理可注入怪异 tag：多数情况下 `parseVersionParts`（crsrelease.go:97-112）会在 IsLatest 比较处报错、或下载/解压失败进入退避，实际危害有限；残余面是「可解析但非预期」的 tag 形态直接入库并展示。

**分类**：不合理逻辑（防线不对称）。**判定**：待裁定——从节点侧防线针对「流氓主节点」威胁模型，主节点侧对上游/代理的信任边界更高，不对称有其逻辑；但 tag 同时是 URL 组件与落盘内容，加一道形状校验成本极低。**影响**：低（TOFU 基线以完整 URL 为键，内容投毒有二次下载拦截；形状怪异的 tag 主要造成日志/DB/UI 展示噪声）。**建议**：在 defaultFetchCRSLatestTag / defaultFetchIP2RegionLatestTag 返回前复用 sanitizeBundleVersion 同款校验（不合法即按查询失败处理）。**是否待裁定**：是。

## 四、待裁定项汇总

| 编号 | 议题 | 需要裁定的点 |
|---|---|---|
| W1 | coraza 池指纹未覆盖 crs-setup.conf / rules/*.conf | 「运维手改 crs-setup.conf/规则文件」是否属于受支持的运维面？若是 → 补指纹输入；若否 → 修正 handlers/security.go:2861 等处「运维可手改文件」表述，并明确 overrides 迁移机制的前提边界 |
| W9 | pre-mutation 失败也走 restoreBackup + 强制重载 | 是否接受统一失败路径的冗余重载与 stale-bak 消费窗口（低概率版本行/磁盘分叉），或按变更边界区分恢复动作 |
| W11 | overrides 只增不减 | 是否为「删除已迁移自定义行」提供操作面（overrides 编辑 UI / 迁移时双向 diff 提示），或仅补文档披露 |
| W12 | caddygeoip/services 四张镜像表无一致性测试 | 是否接受以源码文本比对测试守门（模块不可 import 的结构性约束下的折中） |
| W13 | 国内省份缺失段发空串而非「海外」 | 该子形态归入「不可解析按海外」还是维持「不误伤」语义；对应 UI 文案或发射行为二选一调整 |
| W15 | 主节点侧上游 tag 无形状校验 | 是否对齐从节点侧 sanitizeBundleVersion 口径 |

（其余 9 条——W2、W3、W4、W5、W6、W7、W8、W10、W14——事实与建议均明确，无需裁定。）
