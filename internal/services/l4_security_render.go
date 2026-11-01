package services

// L4（TCP 规则）阶段 0/1 安全路由渲染（契约 C2，.omp/local/l4-stage01-contract.md）：
//
//	① 信任直通（零事件零开销）→ ①b 信任检测（trust_detection=1：logged 事件
//	后直通，HTTP id:12 DetectionOnly 的路由序等价物）→ ② deny 拒绝 →
//	③ 独立黑名单 → ④ allow 交集外 → ⑤ 逐策略 GeoIP → ⑥ 兜底采样+proxy。
//
// 模块 ID 固定 layer4.handlers.lb_l4_sec / layer4.matchers.lb_geoip（与
// caddyl4sec 模块注册对账，见 l4sec_module_contract_test.go）。投影复用
// writeIPListFile 稳定命名，scope=l4-<kind>-<caddyID>（规则身份编入 scope——
// 粒度铁律：逐规则渲染的并集内容是调用方规则的函数，禁止复用 HTTP u-* 的
// 规则身份或更粗的全局名）。配置字节只含文件路径 → 名单变化零 /load。
// 缺库降级门与 HTTP 链 securityLibsOK 同款（crs/ip2region 缺失 → 安全段整体
// 不渲染 + 告警日志，负载均衡不被拖死）。
// G2（限流）/G3（WAF）特征在渲染层零贡献：绑定写侧 400 拒绝 + 残留自愈
// （db.TCPRuleUnsupportedBindingPruneSQL 族）收敛，渲染侧对带外存量静默忽略
// （fail-visible 会整份配置拒绝，波及全部规则，方向更差）。

import (
	"encoding/json"
	"sync"
	"time"

	"lazy-balancer-v2/internal/models"
)

// l4SecHandlerID / l4SecGeoipMatcherID / l4SecIPFileMatcherID 是 caddyl4sec
// 模块注册 ID 的渲染侧字面量（契约 C2 固定；模块侧同名注册由契约对账测试
// 钉住。lb_ipfile 为仓内模块，绕开 caddy-l4 v0.1.2 上游 remote_ip_list 的
// Cleanup 死锁——主审裁定，A2 交付前不得发版渲染引用）。
const (
	l4SecHandlerID       = "lb_l4_sec"
	l4SecGeoipMatcherID  = "lb_geoip"
	l4SecIPFileMatcherID = "lb_ipfile"
	l4SecSampleModeValue = "allow_sample"
	// l4SecTrustDetectReason 是信任检测（trust_detection=1）路由的事件 reason
	// （caddyl4sec reasonTrustDetect 同值，契约 C2；段位=HTTP 保留检测 id:12）。
	l4SecTrustDetectReason = "trust_detect"
)

// tcpSecurityRenderInput 是 L4 安全渲染输入：绑定启用策略集 + 批量生成上下文
// （批量路径经 loadSecurityPolicyContext 预载；单规则路径 ctx 为 nil，策略经
// GetSecurityPoliciesForRule 读已提交视图、库探测就地执行）。
type tcpSecurityRenderInput struct {
	policies []*models.SecurityPolicy
	ctx      *securityPolicyContext
}

// l4ProjectionScope 是 L4 投影 scope 命名单源：kind ∈ trust/trust12/deny/bl/allow
// （trust12=保留检测信任并集，与 HTTP u-trust12 同族命名），规则 caddyID 编入
// 身份（validIPListScope 字符集内的稳定命名）。
func l4ProjectionScope(kind, ruleCaddyID string) string {
	return "l4-" + kind + "-" + ruleCaddyID
}

// buildTCPSecurityRoutes 按契约 C2 生成安全段 routes（不含兜底路由）。
// 无绑定/缺库降级返回 nil（调用方只落兜底路由）。渲染错误（投影写失败等）
// 向上传播——与 HTTP 链同 fail-closed 口径（保存侧事务回滚）。
func buildTCPSecurityRoutes(rule SingleRuleConfig, proxyHandler map[string]interface{}, input *tcpSecurityRenderInput) ([]interface{}, error) {
	cid := rule.CaddyID
	policies := input.policies
	routes := make([]interface{}, 0, len(policies)+4)

	// ① 信任直通：stage0 直通并集（trust_detection=0）命中即 [（proxy_protocol
	// →）proxy] 透传，零事件零开销。内容门控与 HTTP 直通包裹同口径（并集为空
	// 不渲染；名单从空到非空的发射面变化经既有全量链自愈收敛）。
	// 规则开 TCPProxyProtocol 时与 deny/兜底路由对称前置 proxy_protocol——客户端
	// 伪造的 PROXY 头不再原样透传上游，且不开 PROXY 协议时零发射（配置字节不变）。
	detectionTrust, passthroughUnion := stage0TrustSets(policies)
	if len(passthroughUnion) > 0 {
		path, err := writeIPListFile(l4ProjectionScope("trust", cid), passthroughUnion)
		if err != nil {
			return nil, err
		}
		handle := make([]interface{}, 0, 2)
		if pp := l4ProxyProtocolHandler(rule); pp != nil {
			handle = append(handle, pp)
		}
		handle = append(handle, l4PassthroughProxyHandler(proxyHandler))
		routes = append(routes, map[string]interface{}{
			"match":  l4IPFileMatchers(path),
			"handle": handle,
		})
	}

	// ①b 信任检测（trust_detection=1，与 HTTP 行为一致性裁定）：保留检测信任
	// 命中 → [（proxy_protocol →）lb_l4_sec(reason=trust_detect) → proxy]——
	// 产 logged 事件（is_interrupted=false，action=logged；段位沿用 HTTP 保留
	// 检测 id:12，评分/归因走摄取侧既有预检分支零新增）后直通上游。caddy-l4
	// 路由首 match 即执行，其后 deny/黑名单/allow/GeoIP 全部不再评估——即 HTTP
	// DetectionOnly「记录不拦」的路由序等价物。内容门控与直通同口径（空并集
	// 不渲染）。投影 scope=l4-trust12-<caddyID>（与 HTTP u-trust12 同族命名，
	// GC 白名单收编）。
	if len(detectionTrust) > 0 {
		path, err := writeIPListFile(l4ProjectionScope("trust12", cid), detectionTrust)
		if err != nil {
			return nil, err
		}
		handle := make([]interface{}, 0, 3)
		if pp := l4ProxyProtocolHandler(rule); pp != nil {
			handle = append(handle, pp)
		}
		handle = append(handle, l4SecEventHandler(cid, l4SecTrustDetectReason, 0), l4PassthroughProxyHandler(proxyHandler))
		routes = append(routes, map[string]interface{}{
			"match":  l4IPFileMatchers(path),
			"handle": handle,
		})
	}

	// ② deny 拒绝：deny 模式 ACL 并集。flag 门控（始终发射收敛同 HTTP 预检）：
	// ACL 开启即计入发射面，并集可空=空文件永不命中，空↔非空纯内容变化走
	// 热路径。合并段 policy_id=0（多策略合并无单策略归因，与 HTTP 预检 id:2
	// 同口径；事件归因走 X-LB-Rule-ID → 名单成员判定）。
	denyUnion, hasDenyACL := mergedDenyACLPolicies(policies)
	if hasDenyACL {
		path, err := writeIPListFile(l4ProjectionScope("deny", cid), aggregateIPEntries(denyUnion))
		if err != nil {
			return nil, err
		}
		routes = append(routes, l4SecCloseRoute(rule, l4IPFileMatchers(path), cid, "deny", 0))
	}

	// ③ 独立黑名单拒绝：内联字段内容门控（与 HTTP id:4 同口径），policy_id=0
	// 合并段，reason=blacklist。
	blacklistUnion := mergedBlacklistPolicies(policies)
	if len(blacklistUnion) > 0 {
		path, err := writeIPListFile(l4ProjectionScope("bl", cid), aggregateIPEntries(blacklistUnion))
		if err != nil {
			return nil, err
		}
		routes = append(routes, l4SecCloseRoute(rule, l4IPFileMatchers(path), cid, "blacklist", 0))
	}

	// ④ allow 交集外拒绝：allow 模式 ACL 交集（复用 HTTP 的交集缓存单源，
	// 按「绑定 allow 策略集合签名」在同轮内复用）。否定算子（not 包裹）：
	// 名单外连接即拒绝；交集为空（互不相交）投影空文件=恒命中=全拒，与
	// HTTP id:7 恒拒形态等价。策略名单为空照常入列（与 mergedAllowACLPolicies
	// 同语义：空名单参与交集 → 空交集恒拒，不因内容门剔除而静默放行）。
	allowLists := mergedAllowACLPolicies(policies)
	if len(allowLists) > 0 {
		signature := allowPolicySetSignature(policies)
		intersection := aggregateIPEntries(input.ctx.allowIntersectionCached(signature, func() []string {
			return intersectIPLists(allowLists)
		}))
		path, err := writeIPListFile(l4ProjectionScope("allow", cid), intersection)
		if err != nil {
			return nil, err
		}
		routes = append(routes, l4SecCloseRoute(rule, []interface{}{notMatcherSet(l4IPFileMatchers(path))}, cid, "allow", 0))
	}

	// ⑤ 逐策略 GeoIP（policy_id 精确归因）：matcher 直接编码阻断方向——
	// deny 模式命中名单地区断连；allow 模式名单外地区断连（mode:allow，
	// 无 not 包裹）。查库失败/私网/IPv6 由模块 fail-open 放行（用户裁定；
	// 私网豁免在模块层承担，与 HTTP 链首私网豁免同语义）。
	for _, policy := range policies {
		// 发射门与 HTTP 链 PolicyHasGeoIP 同一口径（mode≠off 且名单非空）。
		// mode≠off 但名单空 = 带外脏行形态（写侧启用校验与名单校验双 400 在
		// 前，正常写路径不可达）：限流留痕后跳过——allow 模式该形态跳过=静默
		// 放行，与 HTTP 空名单恒拒口径的缺口至少可见。off 为正常停用态（名单
		// 保留不清空）不告警；畸形 JSON 已由 geoipCountries 内部节流 WARN。
		if policy == nil || !PolicyHasGeoIP(policy) {
			if policy != nil && policy.GeoIPMode != "off" && len(geoipCountries(policy)) == 0 {
				warnL4GeoipEmptyListThrottled(policy.ID, cid, time.Now())
			}
			continue
		}
		// policy_id 段界软跳过（与 HTTP 预检链同界同口径，段界由
		// encodeGeoIPPrecheckRuleID 单一裁决）：越出 [1,9999] 时 lb_l4_sec
		// Provision 显性拒绝会把整份 L4 配置打死——单策略越界只跳过本策略
		// GeoIP 路由并告警，不波及负载均衡（危害面=该策略 GeoIP 不生效，
		// 与 HTTP 缺链同向）。
		if _, ok := encodeGeoIPPrecheckRuleID(policy.ID); !ok {
			Logf("warn", "策略 %d 的 GeoIP 预检链 id 越出普通 GeoIP 段 [%d,%d)，已跳过发射（TCP 规则 %s 的 L4 安全路由）", policy.ID, geoipPrecheckRuleBase+1, geoipCrawlerRuleBase, cid)
			continue
		}
		// 名单由发射门同一纯函数派生，过门即非空（空名单脏行已在门口留痕跳过）。
		entries := geoipCountries(policy)
		routes = append(routes, l4SecCloseRoute(rule, []interface{}{geoipMatcherSet(entries, policy.GeoIPMode == "allow")}, cid, "geoip", policy.ID))
	}
	return routes, nil
}

// l4GeoipEmptyListWarn 是 GeoIP 开启（mode≠off）但名单为空的带外脏行告警的
// 限频状态：脏行存续期逐规则批量渲染会反复命中同一策略——按策略 ID 限流，
// 同键窗口内只告警一次，插入时顺带回收过期键（与 nodeHealthWarn 同族单源）。
var (
	l4GeoipEmptyListWarnMu     sync.Mutex
	l4GeoipEmptyListWarnSeen   = map[int]time.Time{}
	l4GeoipEmptyListWarnWindow = 60 * time.Second
)

// warnL4GeoipEmptyListThrottled 按 policyID 限频输出空名单脏行跳过告警。
func warnL4GeoipEmptyListThrottled(policyID int, cid string, now time.Time) {
	l4GeoipEmptyListWarnMu.Lock()
	allowed := throttleWarnAllowed(l4GeoipEmptyListWarnSeen, policyID, now, l4GeoipEmptyListWarnWindow, l4GeoipEmptyListWarnWindow)
	l4GeoipEmptyListWarnMu.Unlock()
	if !allowed {
		return
	}
	Logf("warn", "策略 %d 开启地域拦截但 geoip_countries 为空（带外脏行形态，写侧启用与名单校验双 400 在前，正常写路径不可达），该策略 GeoIP 路由跳过发射（allow 模式跳过=放行，与 HTTP 空名单恒拒口径不一致——留痕不改变行为；TCP 规则 %s 的 L4 安全路由）", policyID, cid)
}

// buildTCPSecurityRoutesWithDegradation 是 buildTCPSecurityRoutes 的降级门
// 包装：缺库时安全段整体缺席并按批量/单规则两种口径告警（与 HTTP 链
// securityLibsOK 同一次探测结论透传，不逐规则重探）。
func buildTCPSecurityRoutesWithDegradation(rule SingleRuleConfig, proxyHandler map[string]interface{}, input *tcpSecurityRenderInput) ([]interface{}, error) {
	if input == nil || rule.CaddyID == "" || len(input.policies) == 0 {
		return nil, nil
	}
	var libsOK bool
	if input.ctx != nil {
		libsOK = input.ctx.securityLibsOK
	} else {
		crsOK, ip2regionOK := SecurityLibraryStatus()
		libsOK = crsOK && ip2regionOK
	}
	if !libsOK {
		if input.ctx != nil {
			// 批量路径每次生成一条（描述来自上下文的一次探测），不逐规则刷屏。
			input.ctx.securityLibsWarnOnce.Do(func() {
				Logf("warn", "安全规则库缺失（%s），本次生成的全部规则安全链不渲染（含 TCP 规则 L4 安全路由）", input.ctx.securityLibsMissingDesc())
			})
		} else {
			Logf("warn", "安全规则库缺失，规则 %s 的 L4 安全路由本次渲染不生效", rule.CaddyID)
		}
		return nil, nil
	}
	return buildTCPSecurityRoutes(rule, proxyHandler, input)
}

// l4IPFileMatchers 是文件族匹配器集（layer4.matchers.lb_ipfile，仓内模块，
// 绕开 caddy-l4 v0.1.2 上游 remote_ip_list 的 Cleanup 死锁——主审裁定）：
// 每实例单文件键 file；match 数组跨 matcher set 为 OR——多文件=多 set，
// 任一文件命中即该集命中。本渲染器每条安全路由恰好投影一个名单文件。
func l4IPFileMatchers(paths ...string) []interface{} {
	sets := make([]interface{}, 0, len(paths))
	for _, path := range paths {
		sets = append(sets, map[string]interface{}{
			l4SecIPFileMatcherID: map[string]interface{}{
				"file": path,
			},
		})
	}
	return sets
}

// geoipMatcherSet 是 lb_geoip 匹配集：matcher 直接编码阻断方向（mode:allow
// =名单外断连；deny 缺省=命中断连）——不可判定（查库失败/私网/IPv6）由
// matcher fail-open 放行，不再经 not 包裹（not 会把不可判定反转为断连，
// allow 模式下全部 IPv6 客户端被误断）。countries=策略 geoip_countries
// 原值（国名/省/省-市/「海外」，与 ValidateGeoIPCountries 同源——非 ISO 码，
// A2 matcher 的匹配语义与 geoipLocOperator 同构）。xdb_path 仅在派生值≠
// 插件默认时发射（与 buildGeoipHandler 的 XdbPath 约定同口径：默认形态
// 渲染字节不变；deny 模式不发射 mode，字节不变）。
func geoipMatcherSet(countries []string, allowMode bool) map[string]interface{} {
	conf := map[string]interface{}{
		"countries": countries,
	}
	if allowMode {
		conf["mode"] = "allow"
	}
	if ip2regionLivePath != defaultIP2RegionLivePath {
		conf["xdb_path"] = ip2regionLivePath
	}
	// IPv6 库：与 buildGeoipHandler 同口径——开启即显式发射（插件无 v6 路径
	// 兜底），关闭不发射（字节稳定）。
	if IsIP2RegionV6Enabled() {
		conf["xdb_v6_path"] = ip2regionV6LivePath
	}
	return map[string]interface{}{
		l4SecGeoipMatcherID: conf,
	}
}

// l4PassthroughProxyHandler 是信任路由的 proxy 副本（浅拷贝去 health_checks）：
// Caddy 按出现次数实例化 proxy——主动/被动健康检查只由兜底 proxy 实例承担，
// 透传/检测实例各挂一份会把上游探测频次按实例数放大（健康/失联日志同倍
// 放大）。透传语义不受影响（转发目标 upstreams 不变）。
func l4PassthroughProxyHandler(proxyHandler map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(proxyHandler))
	for k, v := range proxyHandler {
		cp[k] = v
	}
	delete(cp, "health_checks")
	return cp
}

// notMatcherSet 是否定匹配集包装（allow 名单交集外断连——IP 文件族仍用
// not：lb_ipfile 的 Match 无不可判定形态，not 语义安全）。
func notMatcherSet(sets []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"not": sets,
	}
}

// l4ProxyProtocolHandler 是 layer4.handlers.proxy_protocol 路由前置单源：
// rule.TCPProxyProtocol 开启时返回该 handler（lb_l4_sec 的 client_ip 归因与
// 发往上游的 PROXY 头都按改写后对端），关闭时返回 nil（零发射，配置字节不变）。
// 信任直通/信任检测（与 deny 族/兜底采样路由共用本单源。
func l4ProxyProtocolHandler(rule SingleRuleConfig) map[string]interface{} {
	if rule.TCPProxyProtocol {
		return map[string]interface{}{"handler": "proxy_protocol"}
	}
	return nil
}

// l4SecCloseRoute 拼装「[proxy_protocol →] lb_l4_sec 事件上报 → close 断连」
// 路由。上报 handler 上报事件后继续执行（断连由 close 负责）；policyID=0
// 表示合并段。否定语义由调用方经 notMatcherSet 编入 matcherSet。
// rule.TCPProxyProtocol 开启时在 lb_l4_sec 之前发射 layer4.handlers.proxy_protocol
// （A2 契约：lb_l4_sec 的 client_ip 取 cx.RemoteAddr()，proxy_protocol handler
// 把它改写为 PROXY 源地址；不发射=回退 socket 对端）。
func l4SecCloseRoute(rule SingleRuleConfig, matchSets []interface{}, cid, reason string, policyID int) map[string]interface{} {
	handle := make([]interface{}, 0, 3)
	if pp := l4ProxyProtocolHandler(rule); pp != nil {
		handle = append(handle, pp)
	}
	handle = append(handle,
		l4SecEventHandler(cid, reason, policyID),
		map[string]interface{}{"handler": "close"},
	)
	return map[string]interface{}{
		"match":  matchSets,
		"handle": handle,
	}
}

// l4SecEventHandler 是事件上报 handler 载荷单源：reason ∈
// deny/blacklist/allow/geoip/trust_detect；mode 键仅采样态（allow_sample）存在。
func l4SecEventHandler(cid, reason string, policyID int) map[string]interface{} {
	return map[string]interface{}{
		"handler":       l4SecHandlerID,
		"rule_caddy_id": cid,
		"reason":        reason,
		"policy_id":     policyID,
	}
}

// l4SecSampleHandler 是兜底路由的采样计数 handler（计数后透传，不阻断）。
// xdb_path 与 geoipMatcherSet 同口径：仅在派生值≠插件默认时发射（默认形态
// 渲染字节不变）——allow_sample 的归属采样读模块侧 sampleXdbPath 的同一默认
// 兜底，自定义 data_dir 部署不发射会让采样读 /app 默认库、与面板 GeoIP 分叉。
func l4SecSampleHandler(cid string) map[string]interface{} {
	h := map[string]interface{}{
		"handler":       l4SecHandlerID,
		"rule_caddy_id": cid,
		"mode":          l4SecSampleModeValue,
	}
	if ip2regionLivePath != defaultIP2RegionLivePath {
		h["xdb_path"] = ip2regionLivePath
	}
	// IPv6 库：归属采样与面板 GeoIP 同语义（开启即发射，关闭字节稳定）。
	if IsIP2RegionV6Enabled() {
		h["xdb_v6_path"] = ip2regionV6LivePath
	}
	return h
}

// mergedDenyACLPolicies 汇总 deny 模式 ACL 的并集与发射面 flag（与 HTTP
// 预检 hasDenyACL 同口径：IPACLEnabled && mode=deny 即计入，并集可空）。
func mergedDenyACLPolicies(policies []*models.SecurityPolicy) (union []string, hasDenyACL bool) {
	for _, p := range policies {
		if p == nil || !p.IPACLEnabled || p.IPACLMode != "deny" {
			continue
		}
		hasDenyACL = true
		union = append(union, mergedACLList(p)...)
	}
	return union, hasDenyACL
}

// mergedBlacklistPolicies 汇总独立黑名单并集（内联字段，畸形 JSON WARN 留痕
// 后按空集——与 HTTP 预检同口径）。
func mergedBlacklistPolicies(policies []*models.SecurityPolicy) []string {
	var union []string
	for _, p := range policies {
		if p == nil {
			continue
		}
		var blacklist []string
		if err := json.Unmarshal(p.IPBlacklist, &blacklist); err != nil {
			logMalformedInlineIPList(p.ID, "ip_blacklist", err)
		}
		union = append(union, blacklist...)
	}
	return union
}

// mergedAllowACLPolicies 收集 allow 模式的 ACL 名单（参与交集）。空名单
// 照常入列：交集为空 → 投影空文件 → not(lb_ipfile) 恒命中 = 全拒，与
// HTTP 预检「空集不因内容门剔除而静默 fail-open」同语义（allow 名单运行期
// 被清空时 TCP 与 HTTP 行为必须一致：全拒，不是放行）。
func mergedAllowACLPolicies(policies []*models.SecurityPolicy) [][]string {
	var lists [][]string
	for _, p := range policies {
		if p == nil || !p.IPACLEnabled || p.IPACLMode != "allow" {
			continue
		}
		lists = append(lists, mergedACLList(p))
	}
	return lists
}

// tcpSecurityRouteList 组装 L4 server 的完整 routes：安全段（可缺）+ 兜底
// 采样路由。无绑定/缺库时 routes 与既有单 proxy 形状逐字节一致（@id 同位）。
func tcpSecurityRouteList(rule SingleRuleConfig, proxyHandler map[string]interface{}, securityCtxs ...*tcpSecurityRenderInput) ([]interface{}, error) {
	// 兜底：lb_l4_sec 采样计数后透传给 proxy；@id 保持在兜底路由（与现状同位，
	// Caddy @id 全配置唯一，安全路由不得重复挂载）。
	fallbackHandle := make([]interface{}, 0, 2)
	var input *tcpSecurityRenderInput
	if len(securityCtxs) > 0 {
		input = securityCtxs[0]
	}
	secured := false
	if input != nil && rule.CaddyID != "" && len(input.policies) > 0 {
		secured = true
	}
	if secured {
		if pp := l4ProxyProtocolHandler(rule); pp != nil {
			// 兜底采样同样先改写 client_ip（A2 契约：采样归因按改写后对端）。
			fallbackHandle = append(fallbackHandle, pp)
		}
		fallbackHandle = append(fallbackHandle, l4SecSampleHandler(rule.CaddyID))
	}
	fallbackHandle = append(fallbackHandle, proxyHandler)
	fallback := map[string]interface{}{"handle": fallbackHandle}
	if rule.CaddyID != "" {
		fallback["@id"] = rule.CaddyID
	}
	if !secured {
		return []interface{}{fallback}, nil
	}
	securedRoutes, err := buildTCPSecurityRoutesWithDegradation(rule, proxyHandler, input)
	if err != nil {
		return nil, err
	}
	routes := make([]interface{}, 0, len(securedRoutes)+1)
	routes = append(routes, securedRoutes...)
	routes = append(routes, fallback)
	return routes, nil
}
