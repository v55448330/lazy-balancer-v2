package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

type ruleFeatureInput struct {
	Protocol                   string
	Strategy                   string
	ListenPort                 int
	EnableTLS                  bool
	TLSHTTPRedirect            bool
	DynamicDNS                 bool
	EnableDnsServer            bool
	DnsServer                  string
	EnabledUpstreamCount       int
	EnabledUpstreamHosts       []string
	DnsFamily                  string
	HealthCheckInterval        int
	HealthCheckTimeout         int
	EnableCompress             bool
	CompressTypes              string
	CustomRoutesEnabled        bool
	PathRules                  []models.PathRule
	ProxyDialTimeout           int
	ProxyResponseHeaderTimeout int
	ProxyReadTimeout           int
	ProxyWriteTimeout          int
	ProxyStreamTimeout         int
	ProxyFlushInterval         int
	ProxyStreamCloseDelay      int
	TCPHealthCheckPort         int
	TCPTryDuration             int
	TCPTryInterval             int
	NTLMCompatible             int
	UpstreamForceHTTP1         int
	UpstreamKeepaliveTimeout   int
}

func createRuleFeatures(req models.CreateRuleRequest) ruleFeatureInput {
	enabledUpstreams := 0
	enabledHosts := make([]string, 0, len(req.Upstreams))
	for _, u := range req.Upstreams {
		if u.Enabled {
			enabledUpstreams++
			enabledHosts = append(enabledHosts, u.Host)
		}
	}
	return ruleFeatureInput{
		Protocol:                   req.Protocol,
		Strategy:                   req.Strategy,
		NTLMCompatible:             req.NTLMCompatible,
		UpstreamForceHTTP1:         req.UpstreamForceHTTP1,
		UpstreamKeepaliveTimeout:   req.UpstreamKeepaliveTimeout,
		ListenPort:                 req.ListenPort,
		EnableTLS:                  req.EnableTLS,
		TLSHTTPRedirect:            req.TLSHTTPRedirect,
		DynamicDNS:                 req.DynamicDNS,
		EnableDnsServer:            req.EnableDnsServer,
		DnsServer:                  req.DnsServer,
		EnabledUpstreamCount:       enabledUpstreams,
		EnabledUpstreamHosts:       enabledHosts,
		DnsFamily:                  req.DnsFamily,
		HealthCheckInterval:        req.HealthCheckInterval,
		HealthCheckTimeout:         req.HealthCheckTimeout,
		EnableCompress:             req.EnableCompress,
		CompressTypes:              req.CompressTypes,
		CustomRoutesEnabled:        req.CustomRoutesEnabled,
		PathRules:                  normalizePathRules(req.PathRules),
		ProxyDialTimeout:           req.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: req.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           req.ProxyReadTimeout,
		ProxyWriteTimeout:          req.ProxyWriteTimeout,
		ProxyStreamTimeout:         req.ProxyStreamTimeout,
		ProxyFlushInterval:         req.ProxyFlushInterval,
		ProxyStreamCloseDelay:      req.ProxyStreamCloseDelay,
		TCPHealthCheckPort:         req.TCPHealthCheckPort,
		TCPTryDuration:             req.TCPTryDuration,
		TCPTryInterval:             req.TCPTryInterval,
	}
}

func updateRuleFeatures(req models.UpdateRuleRequest, existing models.LbRule) ruleFeatureInput {
	enabledUpstreams := 0
	var enabledHosts []string
	// 调用契约——唯一调用点 UpdateRule 在调用前已把
	// req.Upstreams 合并为非 nil（nil=保留存量，赋值为 oldUpstreams），此处
	// 不再有 existing.Upstreams 回退（LbRule.Upstreams 本就不随 scanLbRules
	// 填充，回退拿到的恒为空集，属误导性死分支）。
	upstreams := req.Upstreams
	for _, u := range upstreams {
		if u.Enabled {
			enabledUpstreams++
			enabledHosts = append(enabledHosts, u.Host)
		}
	}
	// 对非指针字段（handler 已在调用前完成 merge），直接使用 req 值。
	// 对指针字段，nil 时用 existing 值，非 nil 时解引用。
	input := ruleFeatureInput{
		Protocol:                 existing.Protocol,
		Strategy:                 req.Strategy,
		NTLMCompatible:           existing.NTLMCompatible,
		UpstreamForceHTTP1:       existing.UpstreamForceHTTP1,
		UpstreamKeepaliveTimeout: existing.UpstreamKeepaliveTimeout,
		ListenPort:               req.ListenPort,
		EnableTLS:                existing.EnableTLS,
		TLSHTTPRedirect:          existing.TLSHTTPRedirect,
		DynamicDNS:               existing.DynamicDNS,
		EnableDnsServer:          existing.EnableDnsServer,
		DnsServer:                existing.DnsServer,
		EnabledUpstreamCount:     enabledUpstreams,
		EnabledUpstreamHosts:     enabledHosts,
		DnsFamily:                existing.DnsFamily,
		HealthCheckInterval:      req.HealthCheckInterval,
		HealthCheckTimeout:       req.HealthCheckTimeout,
		EnableCompress:           existing.EnableCompress,
		CompressTypes:            req.CompressTypes,
		CustomRoutesEnabled:      existing.CustomRoutesEnabled,
		// 库原始行必须先归一（match_type 空→prefix、路径/上游地址 TrimSpace）：
		// 导入/带外写入的 match_type='' 形态若原样进 validateRuleFeatures，任何
		// 不带 path_rules 的部分更新都会恒 400，整条规则改不动。与创建侧
		// （normalizePathRules(req.PathRules)）同一单源——归一结果随后经
		// replacePathRulesTx 落库，形态收敛为 prefix。
		PathRules:                  normalizePathRules(existing.PathRules),
		ProxyDialTimeout:           existing.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: existing.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           existing.ProxyReadTimeout,
		ProxyWriteTimeout:          existing.ProxyWriteTimeout,
		ProxyStreamTimeout:         existing.ProxyStreamTimeout,
		ProxyFlushInterval:         existing.ProxyFlushInterval,
		ProxyStreamCloseDelay:      existing.ProxyStreamCloseDelay,
	}
	if req.DynamicDNS != nil {
		input.DynamicDNS = *req.DynamicDNS
	}
	if req.EnableDnsServer != nil {
		input.EnableDnsServer = *req.EnableDnsServer
	}
	if req.DnsServer != nil {
		input.DnsServer = *req.DnsServer
	}
	// DnsFamily 为非指针（handler 预合并），空串=未变更沿用 existing。
	if req.DnsFamily != "" {
		input.DnsFamily = req.DnsFamily
	}
	if req.EnableTLS != nil {
		input.EnableTLS = *req.EnableTLS
	}
	if req.TLSHTTPRedirect != nil {
		input.TLSHTTPRedirect = *req.TLSHTTPRedirect
	}
	if req.EnableCompress != nil {
		input.EnableCompress = *req.EnableCompress
	}
	if req.CustomRoutesEnabled != nil {
		input.CustomRoutesEnabled = *req.CustomRoutesEnabled
		if !input.CustomRoutesEnabled && req.PathRules == nil {
			input.PathRules = []models.PathRule{}
		}
	}
	if req.PathRules != nil {
		input.PathRules = normalizePathRules(*req.PathRules)
	}
	if req.ProxyDialTimeout != nil {
		input.ProxyDialTimeout = *req.ProxyDialTimeout
	}
	if req.ProxyResponseHeaderTimeout != nil {
		input.ProxyResponseHeaderTimeout = *req.ProxyResponseHeaderTimeout
	}
	if req.ProxyReadTimeout != nil {
		input.ProxyReadTimeout = *req.ProxyReadTimeout
	}
	if req.ProxyWriteTimeout != nil {
		input.ProxyWriteTimeout = *req.ProxyWriteTimeout
	}
	if req.ProxyStreamTimeout != nil {
		input.ProxyStreamTimeout = *req.ProxyStreamTimeout
	}
	if req.ProxyFlushInterval != nil {
		input.ProxyFlushInterval = *req.ProxyFlushInterval
	}
	if req.ProxyStreamCloseDelay != nil {
		input.ProxyStreamCloseDelay = *req.ProxyStreamCloseDelay
	}
	// TCP 三字段指针字段同口径合并——nil 沿用 existing,非 nil 解引用,
	// 使 validateRuleFeatures 的负值门在更新路径看到真实值。
	if req.TCPHealthCheckPort != nil {
		input.TCPHealthCheckPort = *req.TCPHealthCheckPort
	}
	if req.TCPTryDuration != nil {
		input.TCPTryDuration = *req.TCPTryDuration
	}
	if req.TCPTryInterval != nil {
		input.TCPTryInterval = *req.TCPTryInterval
	}
	// NTLM 兼容开关：nil=沿用存量（handler 已预合并），显式 0/1 落库。
	if req.NTLMCompatible != nil {
		input.NTLMCompatible = *req.NTLMCompatible
	}
	if req.UpstreamForceHTTP1 != nil {
		input.UpstreamForceHTTP1 = *req.UpstreamForceHTTP1
	}
	if req.UpstreamKeepaliveTimeout != nil {
		input.UpstreamKeepaliveTimeout = *req.UpstreamKeepaliveTimeout
	}
	return input
}

func normalizePathRules(pathRules []models.PathRule) []models.PathRule {
	normalized := append([]models.PathRule(nil), pathRules...)
	for index := range normalized {
		if normalized[index].MatchType == "" {
			normalized[index].MatchType = "prefix"
		}
		// 存储前 TrimSpace，与校验侧（validateRuleFeatures 277 行先 TrimSpace
		// 再归一）及渲染侧 pathMatcherSpecs 对齐，避免空格路径校验误报冲突。
		normalized[index].Path = strings.TrimSpace(normalized[index].Path)
		// 路径上游地址与主上游同口径归一——校验/查重侧一直用
		// TrimSpace 后的值判定，但落库/渲染原样消费 Address；" up.test" 能过
		// host 门并渲染成 dial:" up.test:9001"（该路径恒 502）。深拷贝上游
		// 切片后回写 TrimSpace，避免改动调用方共享的底层数组。
		if normalized[index].Upstreams != nil {
			// 保留「非 nil 空切片」形态（nil 与 [] 在保存门语义不同：
			// nil=回退主上游，[]=显式空上游 400）——append(nil, empty...)
			// 会把它压成 nil。
			upstreams := make([]models.PathRuleUpstream, len(normalized[index].Upstreams))
			copy(upstreams, normalized[index].Upstreams)
			for upstreamIndex := range upstreams {
				upstreams[upstreamIndex].Address = strings.TrimSpace(upstreams[upstreamIndex].Address)
			}
			normalized[index].Upstreams = upstreams
		}
	}
	return normalized
}

func toPathRuleConfigs(pathRules []models.PathRule) []services.PathRuleConfig {
	configs := make([]services.PathRuleConfig, 0, len(pathRules))
	for _, pathRule := range pathRules {
		config := services.PathRuleConfig{
			SortOrder:    pathRule.SortOrder,
			MatchType:    pathRule.MatchType,
			Path:         pathRule.Path,
			UpstreamPath: pathRule.UpstreamPath,
			// 预检渲染回填直返/301 五列——丢失会让预检
			// 把 static/redirect 路径规则当转发链渲染，与真实渲染分叉。
			ResponseMode:        pathRule.ResponseMode,
			ResponseStatus:      pathRule.ResponseStatus,
			ResponseBody:        pathRule.ResponseBody,
			ResponseContentType: pathRule.ResponseContentType,
			RedirectTo:          pathRule.RedirectTo,
		}
		if pathRule.Upstreams != nil {
			config.Upstreams = make([]services.UpstreamConfig, 0, len(pathRule.Upstreams))
			for _, upstream := range pathRule.Upstreams {
				protocol := upstream.Protocol
				if protocol == "" {
					protocol = "http"
				}
				config.Upstreams = append(config.Upstreams, services.UpstreamConfig{
					Host: upstream.Address, Port: upstream.Port, Weight: upstream.Weight, Protocol: protocol, Enabled: true,
				})
			}
		}
		configs = append(configs, config)
	}
	return configs
}

// validateStrategyForProtocol:strategy 白名单
// 协议感知校验——cookie 仅 HTTP 支持,TCP 规则拒绝;保存门(validateRuleFeatures)
// 与存量启用门(validateStoredRuleConfig)同口径。空 strategy 走默认不校验。
func validateStrategyForProtocol(protocol, strategy string) error {
	if strategy == "" {
		return nil
	}
	httpStrategies := map[string]bool{
		"weighted_round_robin": true, "least_conn": true,
		"ip_hash": true, "cookie": true,
		"random": true, "first": true,
	}
	tcpStrategies := map[string]bool{
		"weighted_round_robin": true, "least_conn": true,
		"ip_hash": true,
		"random":  true, "first": true,
	}
	switch protocol {
	case "http":
		if !httpStrategies[strategy] {
			return fmt.Errorf("无效的负载策略：HTTP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first / cookie")
		}
	case "tcp":
		if !tcpStrategies[strategy] {
			return fmt.Errorf("无效的负载策略：TCP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first")
		}
	}
	return nil
}

// ntlmTakeoverShapeError 是 NTLM 接管四列一致性门：
// ntlm_compatible 仅为展示/声明列（渲染零感知），真实接管行为由
// tcp_try_duration=-1（禁用跨上游重试）/upstream_force_http1=1/
// proxy_flush_interval=-1（立即透传）/upstream_keepalive_timeout=300 决定
// （UI 修改器 Rules.vue applyNtlmTakeover 落下的唯一合法形态）。保存族
// （validateRuleFeatures，Create/Update/Duplicate/导入共用）与存量启用/启动
// 聚合族（validateStoredRuleProtocolFields）同源调用。调用方保证已在
// ntlm_compatible=1 分支内。
func ntlmTakeoverShapeError(tryDuration, forceHTTP1, flushInterval, keepaliveTimeout int) error {
	if tryDuration == -1 && forceHTTP1 == 1 && flushInterval == -1 && keepaliveTimeout == 300 {
		return nil
	}
	return fmt.Errorf("NTLM 接管需要同时设置：重试窗口 -1（禁用重试）、强制 HTTP/1.1、响应刷新间隔 -1（立即透传）、上游 keepalive 超时 300 秒（当前 tcp_try_duration=%d、upstream_force_http1=%d、proxy_flush_interval=%d、upstream_keepalive_timeout=%d）——请通过规则向导的 NTLM 兼容开关整体开启",
		tryDuration, forceHTTP1, flushInterval, keepaliveTimeout)
}

func validateRuleFeatures(input ruleFeatureInput) error {
	// 协议白名单。此前 Create/Update 仅拒绝空协议（rules.go:564），
	// "https" 等未知值可经 API/MCP 落库，全量渲染按「非 http 即 TCP」处理
	// （caddy.go:1276）——域名匹配静默丢失、TLS 字段被忽略。统一在特性校验入口
	// 拒绝未知协议，Create/Update/复制/导入全链路复用；保存校验 validateRuleConfigGeneration
	// 亦仅放行 http/tcp，存量 https 行由 db 迁移归一为 http+TLS。
	if input.Protocol != "http" && input.Protocol != "tcp" {
		return fmt.Errorf("协议仅支持 http 或 tcp")
	}
	// strategy 白名单校验，非法值不再透传到 Caddy。
	if err := validateStrategyForProtocol(input.Protocol, input.Strategy); err != nil {
		return err
	}
	// NTLM 兼容开关（2026-10-12 用户定稿）：①值域 0/1；②仅 HTTP 语义；③开启
	// 时强制 Cookie 会话保持——挑战-应答必须固定同一上游，任何无会话策略都会
	// 打断握手。保存（Create/Update/复制）/启用（validateStoredRuleConfig）/
	// 导入（validateV2BackupRules）三链同门。
	if input.NTLMCompatible != 0 && input.NTLMCompatible != 1 {
		return fmt.Errorf("ntlm_compatible 必须为 0 或 1")
	}
	// upstream_force_http1 与 ntlm_compatible 同为 0/1 开关列，
	// MCP schema 已枚举 0/1 但 REST 无对应门——2/-1 可落库，UI/渲染按
	// `==1` 静默当关闭，用户意图与运行行为不一致。保存门单源拒绝越界值。
	if input.UpstreamForceHTTP1 != 0 && input.UpstreamForceHTTP1 != 1 {
		return fmt.Errorf("upstream_force_http1 必须为 0 或 1")
	}
	// 重试窗口值域（单源 validateTCPTryWindowBounds，见下）——保存族与存量门
	// 共用同一张值域表，避免「保存拒绝、启用/启动放行」分叉。
	if err := validateTCPTryWindowBounds(input.Protocol, input.TCPTryDuration, input.TCPTryInterval); err != nil {
		return err
	}
	if input.NTLMCompatible == 1 {
		if input.Protocol == "tcp" {
			return fmt.Errorf("TCP 规则不支持 NTLM 兼容模式（仅 HTTP 规则可用）")
		}
		if input.Strategy != "cookie" {
			return fmt.Errorf("NTLM 兼容模式要求负载策略为 Cookie 会话保持")
		}
		// ntlm_compatible 列与渲染脱钩（渲染零感知，真实
		// NTLM 行为由四列接管形态决定）——API/导入/快照可绕过 UI 修改器产
		// 「宣称 NTLM 实际非 NTLM」规则。ntlm=1 必须接管四列全齐，缺一 400；
		// ntlm=0 不约束（UI restoreNtlmDefaults 已复位）。
		if err := ntlmTakeoverShapeError(input.TCPTryDuration, input.UpstreamForceHTTP1, input.ProxyFlushInterval, input.UpstreamKeepaliveTimeout); err != nil {
			return err
		}
	}
	// 健康检查超时必须小于检查间隔（两者都 > 0 时）。
	if input.HealthCheckInterval > 0 && input.HealthCheckTimeout > 0 && input.HealthCheckTimeout >= input.HealthCheckInterval {
		return fmt.Errorf("健康检查超时时间（%d 秒）必须小于检查间隔（%d 秒）", input.HealthCheckTimeout, input.HealthCheckInterval)
	}
	// compress_types 白名单校验，不支持编码不再静默丢弃。值域门不随
	// enable_compress 关闭而失效：关闭态落库的非法编码渲染零消费，却会随
	// 导出/备份/集群快照放大；空值放行（写侧归 gzip）。
	if input.CompressTypes != "" {
		for _, ct := range strings.Split(input.CompressTypes, ",") {
			ct = strings.TrimSpace(ct)
			if ct == "" {
				continue
			}
			if ct != "gzip" && ct != "zstd" {
				return fmt.Errorf("压缩类型 %q 不支持，当前仅支持 gzip 和 zstd", ct)
			}
		}
	}
	// dynamic_dns + 多 upstream 前置校验（原仅在 Caddy 渲染阶段检查，规则已入库）。
	if input.DynamicDNS && input.EnabledUpstreamCount > 1 {
		return fmt.Errorf("动态上游模式仅允许一个启用的上游服务器，当前有 %d 个", input.EnabledUpstreamCount)
	}
	// DynamicDNS + IP 字面量上游的地址族一致性门——Go resolver 对
	// IP 字面量走快速路径（不查 DNS），Caddy 动态上游的 LookupIP 族过滤会把
	// 与 dns_family 矛盾的字面量剔除为空集 → 每请求立即 502（加载校验不解析，
	// 全链路静默）。域名形态上游不检查（其解析结果由 DNS 决定，本门无从判定）；
	// dns_family=both 免疫。
	if input.DynamicDNS && input.DnsFamily != "" && input.DnsFamily != "both" {
		for _, host := range input.EnabledUpstreamHosts {
			ip := net.ParseIP(strings.TrimSpace(host))
			if ip == nil {
				continue
			}
			mismatch := (input.DnsFamily == "ipv6" && ip.To4() != nil) ||
				(input.DnsFamily == "ipv4" && ip.To4() == nil)
			if mismatch {
				return fmt.Errorf("动态上游模式的上游地址 %s 是 IP 字面量且地址族与 dns_family=%s 不一致（该组合运行时恒 502），请改为域名或调整地址族", host, input.DnsFamily)
			}
		}
	}
	// 80 端口 + TLS 跳转自环：跳转目标 https://host:80 与来源同为 80 端口，
	// 请求会被跳回自身监听器形成循环，必须在保存前拒绝。
	if input.Protocol == "http" && input.ListenPort == 80 && input.EnableTLS && input.TLSHTTPRedirect {
		return fmt.Errorf("80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转")
	}
	if input.Protocol == "tcp" {
		// L4 代理无 HTTP Host 头可驱动动态 DNS 解析（Caddy layer4 直拨
		// IP:port），TCP+dynamic_dns 规则渲染侧被整体跳过、
		// 看门狗亦不标记——保存前不拒绝即静默死规则。与 （TCP+cookie）同口径。
		if input.DynamicDNS {
			return fmt.Errorf("TCP 规则不支持动态上游（dynamic_dns），请关闭动态 DNS 或改用 HTTP 协议")
		}
		// enable_dns_server/dns_server 同为 HTTP 语义
		// （L4 直拨 IP:port，无 resolver 消费点）——此前拒绝清单漏列，用户可
		// 在 TCP 规则携带 DNS 配置落库但永不生效且无告警（对照 dynamic_dns
		// 有本门+渲染告警双保险）。协议切换的零值化（rules.go 块）
		// 与存量迁移（db.migrateTCPRuleStaleDNSServer）已清空，显式携带即拒。
		if input.EnableDnsServer || strings.TrimSpace(input.DnsServer) != "" {
			return fmt.Errorf("TCP 规则不支持 DNS 服务发现配置（enable_dns_server/dns_server），请关闭或改用 HTTP 协议")
		}
		if input.CustomRoutesEnabled || len(input.PathRules) > 0 {
			return fmt.Errorf("TCP 规则不支持自定义路径规则")
		}
		if input.ProxyDialTimeout > 0 || input.ProxyResponseHeaderTimeout > 0 || input.ProxyReadTimeout > 0 || input.ProxyWriteTimeout > 0 || input.ProxyStreamTimeout > 0 || input.ProxyFlushInterval != 0 || input.ProxyStreamCloseDelay > 0 {
			return fmt.Errorf("TCP 规则不支持 HTTP 代理超时配置")
		}
		// TCP 三字段无哨兵语义——负值仅被渲染侧静默钳制，保存前拒绝显式负值。
		// 重试时长/间隔的负值已由上方 validateTCPTryWindowBounds 统一拒绝
		// （与存量门同源），此处只余健康检查端口。
		if input.TCPHealthCheckPort < 0 {
			return fmt.Errorf("TCP 健康检查端口与重试时长/间隔不能为负数")
		}
	}
	// 「重试窗口 >0 时重试间隔必填」与渲染门同文案，已由
	// validateTCPTryWindowBounds 前置（与存量门同源）；此处不再重复。
	if !input.CustomRoutesEnabled && len(input.PathRules) > 0 {
		return fmt.Errorf("自定义路径规则未启用，不能提交路径规则")
	}
	seenPaths := make(map[string]int, len(input.PathRules))
	// prefix 会渲染为 [路径, 路径/*] 双 matcher，同一路径再配 exact 必被遮蔽
	// （路由按 SortOrder 排序、首条终结匹配），在保存前整组拒绝。
	// 查重/查遮蔽必须与渲染侧 pathMatcherSpecs 同源归一（TrimRight 尾 / 与 *），
	// 否则 "/api" 与 "/api/"（或 "/api//"）原始串不同、渲染 matcher 完全相同，
	// SortOrder 靠后的一条会成为整条死规则。
	seenPrefixRoots := make(map[string]int, len(input.PathRules))
	seenExactNorms := make(map[string]int, len(input.PathRules))
	for index, pathRule := range input.PathRules {
		if !strings.HasPrefix(pathRule.Path, "/") {
			return fmt.Errorf("第 %d 条路径规则的路径必须以 / 开头", index+1)
		}
		if strings.ContainsAny(pathRule.Path, "*?{}") {
			return fmt.Errorf("第 %d 条路径规则的路径不能包含 * ? { } 通配字符", index+1)
		}
		switch pathRule.MatchType {
		case "prefix", "exact":
		default:
			return fmt.Errorf("第 %d 条路径规则的匹配类型只能是 prefix 或 exact", index+1)
		}
		// 上游 path 改写：非空须以 / 开头且不含空格与 ? #（query/fragment 不允许，
		// 空白字符会破坏 Caddy rewrite URI 形状）；空串=原样转发放行。
		if pathRule.UpstreamPath != "" {
			if !strings.HasPrefix(pathRule.UpstreamPath, "/") {
				return fmt.Errorf("第 %d 条路径规则的上游 path 必须以 / 开头", index+1)
			}
			if strings.ContainsFunc(pathRule.UpstreamPath, unicode.IsSpace) || strings.ContainsAny(pathRule.UpstreamPath, "?#") {
				return fmt.Errorf("第 %d 条路径规则的上游 path 不能包含空格 ? # 字符", index+1)
			}
		}
		trimmedPath := strings.TrimSpace(pathRule.Path)
		canonicalPath := trimmedPath
		if pathRule.MatchType == "prefix" {
			canonicalPath = strings.TrimRight(trimmedPath, "/*")
			if canonicalPath == "" {
				canonicalPath = "/"
			}
		}
		duplicateKey := pathRule.MatchType + ":" + canonicalPath
		if seenAt, exists := seenPaths[duplicateKey]; exists {
			return fmt.Errorf("第 %d 条路径规则与第 %d 条重复（%s）", index+1, seenAt, pathRule.Path)
		}
		seenPaths[duplicateKey] = index + 1
		if pathRule.MatchType == "prefix" {
			if seenAt, exists := seenExactNorms[canonicalPath]; exists {
				return fmt.Errorf("第 %d 条路径规则与第 %d 条：同一路径同时存在前缀与精确匹配规则会造成遮蔽，请调整", index+1, seenAt)
			}
			seenPrefixRoots[canonicalPath] = index + 1
		} else {
			normalizedExact := strings.TrimRight(trimmedPath, "/")
			if normalizedExact == "" {
				normalizedExact = "/"
			}
			if seenAt, exists := seenPrefixRoots[normalizedExact]; exists {
				return fmt.Errorf("第 %d 条路径规则与第 %d 条：同一路径同时存在前缀与精确匹配规则会造成遮蔽，请调整", index+1, seenAt)
			}
			seenExactNorms[normalizedExact] = index + 1
		}
		// 直接返回/301 跳转（2026-10-10 用户裁定）：模式枚举 + 按模式字段门 +
		// 与转发配置互斥。static=常用状态码白名单 + 响应体 ≤64 字符 + 格式
		// {text/plain,application/json,text/html}；redirect=目标必填且形状合法。
		switch pathRule.ResponseMode {
		case "":
			// 转发现状：响应字段为死配置，写侧归一为默认值（replacePathRulesTx），
			// 此处不拒（旧客户端/备份缺省形态直达）。
		case "static":
			// 缺省 0=默认 200（写侧归一同口径）；白名单只拦截显式的非常用值。
			status := pathRule.ResponseStatus
			if status == 0 {
				status = 200
			}
			if !validStaticResponseStatuses[status] {
				return fmt.Errorf("第 %d 条路径规则：直接返回的状态码 %d 不在常用集合（200/201/204/400/401/403/404/410/500/502/503）", index+1, pathRule.ResponseStatus)
			}
			if len([]rune(pathRule.ResponseBody)) > 64 {
				return fmt.Errorf("第 %d 条路径规则：响应内容不能超过 64 个字符", index+1)
			}
			if pathRule.ResponseContentType != "" && pathRule.ResponseContentType != "text/plain" &&
				pathRule.ResponseContentType != "application/json" && pathRule.ResponseContentType != "text/html" {
				return fmt.Errorf("第 %d 条路径规则：响应格式仅支持 text/plain、application/json、text/html", index+1)
			}
			if pathRule.RedirectTo != "" {
				return fmt.Errorf("第 %d 条路径规则：直接返回与跳转目标互斥（请清空跳转地址）", index+1)
			}
			if pathRule.Upstreams != nil || pathRule.UpstreamPath != "" {
				return fmt.Errorf("第 %d 条路径规则：直接返回模式与上游配置互斥（不访问上游）", index+1)
			}
		case "redirect":
			if strings.TrimSpace(pathRule.RedirectTo) == "" {
				return fmt.Errorf("第 %d 条路径规则：301 跳转需要填写跳转地址", index+1)
			}
			for _, r := range pathRule.RedirectTo {
				if r < 0x20 || r == 0x7f {
					return fmt.Errorf("第 %d 条路径规则：跳转地址含非法字符", index+1)
				}
			}
			if !strings.HasPrefix(pathRule.RedirectTo, "/") &&
				!strings.HasPrefix(pathRule.RedirectTo, "http://") && !strings.HasPrefix(pathRule.RedirectTo, "https://") {
				return fmt.Errorf("第 %d 条路径规则：跳转地址须为 http(s):// 绝对地址或 / 开头路径", index+1)
			}
			if pathRule.ResponseBody != "" || pathRule.ResponseContentType != "" {
				return fmt.Errorf("第 %d 条路径规则：301 跳转与响应内容互斥（请清空内容/格式）", index+1)
			}
			if pathRule.Upstreams != nil || pathRule.UpstreamPath != "" {
				return fmt.Errorf("第 %d 条路径规则：301 跳转模式与上游配置互斥（不访问上游）", index+1)
			}
		default:
			return fmt.Errorf("第 %d 条路径规则：response_mode %q 无效（仅支持空=转发/static=直接返回/redirect=301 跳转）", index+1, pathRule.ResponseMode)
		}
		// 空数组虽在生成阶段已回退主上游，
		// 仍禁止写入上游表占位的空 upstreams_json——保存前拒绝保持数据整洁。
		if pathRule.Upstreams != nil && len(pathRule.Upstreams) == 0 {
			return fmt.Errorf("第 %d 条路径规则至少需要配置一个上游", index+1)
		}
		// 路径规则上游 host:port 去重(主上游 handlers.go hostPortSeen
		// 同口径;JoinHostPort 兼容 IPv6 裸地址形态)——同 host:port 双条目
		// 权重翻倍,均衡语义静默漂移。
		pathHostPortSeen := make(map[string]bool)
		// 同族：路径规则自定义上游池同样拒绝 http/https
		// 混布——同一 reverse_proxy 池级 TLS 传输下 http 上游静默全灭。
		pathPoolProtos := make(map[string]bool, 2)
		for _, upstream := range pathRule.Upstreams {
			proto := upstream.Protocol
			if proto == "" {
				proto = "http"
			}
			pathPoolProtos[proto] = true
		}
		if pathPoolProtos["http"] && pathPoolProtos["https"] {
			return fmt.Errorf("第 %d 条路径规则的自定义上游 http/https 混布（同一上游池协议须一致）", index+1)
		}
		for upstreamIndex, upstream := range pathRule.Upstreams {
			if strings.TrimSpace(upstream.Address) == "" {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游地址不能为空", index+1, upstreamIndex+1)
			}
			if !isValidHost(strings.TrimSpace(upstream.Address)) {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游：主机 '%s' 无效", index+1, upstreamIndex+1, upstream.Address)
			}
			if upstream.Port < 1 || upstream.Port > 65535 {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游端口必须在 1-65535 之间", index+1, upstreamIndex+1)
			}
			// 与主池（handlers.go weight<1 响亮拒绝，0→1 静默归一已裁定废除）
			// 同口径：0 虽被渲染层归一为 1，保存侧不得让 0 落库。
			if upstream.Weight < 1 {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游权重必须为不小于 1 的整数", index+1, upstreamIndex+1)
			}
			if upstream.Protocol != "" && upstream.Protocol != "http" && upstream.Protocol != "https" {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游协议只能是 http 或 https", index+1, upstreamIndex+1)
			}
			key := net.JoinHostPort(upstreamDedupeHost(upstream.Address), strconv.Itoa(upstream.Port))
			if pathHostPortSeen[key] {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游 %s:%d 重复", index+1, upstreamIndex+1, upstream.Address, upstream.Port)
			}
			pathHostPortSeen[key] = true
		}
	}
	if input.ProxyDialTimeout < 0 || input.ProxyResponseHeaderTimeout < 0 || input.ProxyReadTimeout < 0 || input.ProxyWriteTimeout < 0 || input.ProxyStreamTimeout < 0 {
		return fmt.Errorf("代理超时时间不能为负数")
	}
	// proxy_flush_interval: 0 = 自动（仅 text/event-stream 触发立即刷新），-1 = 立即刷新所有响应，>0 = 每 N 秒刷新一次
	if input.ProxyFlushInterval < -1 {
		return fmt.Errorf("代理刷新间隔不能小于 -1")
	}
	if input.ProxyStreamCloseDelay < 0 {
		return fmt.Errorf("代理流关闭延迟不能为负数")
	}
	return nil
}

// storedPathRule 是 path_rules 的现有行投影（仅收敛判定所需列）。
type storedPathRule struct {
	id           int
	sortOrder    int
	matchType    string
	path         string
	upstreamPath string
	upstreams    string // COALESCE(upstreams_json,'')：NULL 与 '' 判定等价，写回时仍按 nil 保持 NULL
	// 直接返回/301 跳转（2026-10-10）：五列全内容列——变更触发原地 UPDATE。
	responseMode        string
	responseStatus      int
	responseBody        string
	responseContentType string
	redirectTo          string
}

// validStaticResponseStatuses 直接返回的常用状态码白名单（2026-10-10 用户裁定）。
var validStaticResponseStatuses = map[int]bool{
	200: true, 201: true, 204: true,
	400: true, 401: true, 403: true, 404: true, 410: true,
	500: true, 502: true, 503: true,
}

// replacePathRulesTx 以「保留不变行」的方式收敛给定规则的路径规则集合（历史
// 修复前恒 DELETE 全删 + INSERT：任何规则编辑（含纯改名）都会重建全部
// 行（id/created_at/updated_at 重置），且恒触发行级触发器（path_rules 在同步版本
// 矩阵内）→ 每次 UpdateRule 多一轮从端同步。现语义：
//   - 内容完全一致（含 sort_order 与上游集合）的存量行 → 零写入，id/时间戳原样保留；
//   - 内容变更但身份一致（match_type+path+upstream_path）或显式回传真实 id 的行 →
//     原地 UPDATE，保留 id/created_at、刷新 updated_at；
//   - 消失的行 DELETE（按 id）、新增的行 INSERT。
//
// 身份判定的两个入口：前端编辑既有行回传真实 id（新增行为负的临时 id）；无 id 的
// 调用方（MCP/导出导入/集群 apply）退化为按身份键配对。
func replacePathRulesTx(ctx context.Context, tx *sql.Tx, ruleID string, pathRules []models.PathRule) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, sort_order, match_type, path, upstream_path, COALESCE(upstreams_json,''),
		response_mode, response_status, response_body, response_content_type, redirect_to
		FROM path_rules WHERE rule_id = ? ORDER BY sort_order, id`, ruleID)
	if err != nil {
		return fmt.Errorf("读取规则 %s 的路径规则: %w", ruleID, err)
	}
	var existing []storedPathRule
	for rows.Next() {
		var row storedPathRule
		if err := rows.Scan(&row.id, &row.sortOrder, &row.matchType, &row.path, &row.upstreamPath, &row.upstreams,
			&row.responseMode, &row.responseStatus, &row.responseBody, &row.responseContentType, &row.redirectTo); err != nil {
			rows.Close()
			return fmt.Errorf("解析规则 %s 的路径规则: %w", ruleID, err)
		}
		existing = append(existing, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历规则 %s 的路径规则: %w", ruleID, err)
	}

	indexByID := make(map[int]int, len(existing))
	for index, row := range existing {
		indexByID[row.id] = index
	}
	consumed := make([]bool, len(existing))
	inserts := make([]storedPathRule, 0, len(pathRules))
	for _, pathRule := range pathRules {
		var upstreamsValue any
		upstreamsJSON := ""
		if pathRule.Upstreams != nil {
			encoded, err := json.Marshal(pathRule.Upstreams)
			if err != nil {
				return fmt.Errorf("序列化路径规则 %s 的上游: %w", pathRule.Path, err)
			}
			upstreamsJSON = string(encoded)
			upstreamsValue = upstreamsJSON
		}
		incoming := storedPathRule{
			sortOrder:    pathRule.SortOrder,
			matchType:    pathRule.MatchType,
			path:         pathRule.Path,
			upstreamPath: pathRule.UpstreamPath,
			upstreams:    upstreamsJSON,
			// 缺省归一（nil/0 载荷与默认值的同义形态）：模式空=转发；static 缺省
			// 状态码 200、格式空=text/plain（渲染侧同口径兜底）。
			responseMode:        pathRule.ResponseMode,
			responseStatus:      pathRule.ResponseStatus,
			responseBody:        pathRule.ResponseBody,
			responseContentType: pathRule.ResponseContentType,
			redirectTo:          pathRule.RedirectTo,
		}
		// 按模式归一死字段（2026-10-10）：转发=五字段全默认；static=清跳转目标，
		// 缺省状态码 0→200；redirect=清内容/格式（状态码渲染侧恒 301）。保持
		// 存储值规范形，no-op 编辑不触发原地 UPDATE（零写入语义不破）。
		switch incoming.responseMode {
		case "":
			incoming.responseStatus = 200
			incoming.responseBody = ""
			incoming.responseContentType = ""
			incoming.redirectTo = ""
		case "static":
			if incoming.responseStatus == 0 {
				incoming.responseStatus = 200
			}
			incoming.redirectTo = ""
		case "redirect":
			incoming.responseStatus = 200
			incoming.responseBody = ""
			incoming.responseContentType = ""
		}
		// ① 显式 id 命中（前端编辑既有行回传真实 id）
		if index, ok := indexByID[pathRule.ID]; ok && !consumed[index] {
			consumed[index] = true
			if err := updatePathRuleTx(ctx, tx, existing[index], incoming, upstreamsValue); err != nil {
				return fmt.Errorf("更新规则 %s 的路径规则 %s: %w", ruleID, pathRule.Path, err)
			}
			continue
		}
		// ② 内容完全一致 → 原样保留（零写入 ⇒ 不触发同步触发器）
		if index := matchStoredPathRule(existing, consumed, incoming, true); index >= 0 {
			consumed[index] = true
			continue
		}
		// ③ 身份一致（match_type+path+upstream_path）→ 原地 UPDATE 保留 id/created_at
		if index := matchStoredPathRule(existing, consumed, incoming, false); index >= 0 {
			consumed[index] = true
			if err := updatePathRuleTx(ctx, tx, existing[index], incoming, upstreamsValue); err != nil {
				return fmt.Errorf("更新规则 %s 的路径规则 %s: %w", ruleID, pathRule.Path, err)
			}
			continue
		}
		inserts = append(inserts, incoming)
	}
	for index, row := range existing {
		if consumed[index] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM path_rules WHERE id = ?", row.id); err != nil {
			return fmt.Errorf("删除规则 %s 的路径规则 %d: %w", ruleID, row.id, err)
		}
	}
	for _, insert := range inserts {
		var upstreamsValue any
		if insert.upstreams != "" {
			upstreamsValue = insert.upstreams
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`, ruleID, insert.sortOrder, insert.matchType, insert.path, insert.upstreamPath, upstreamsValue, insert.responseMode, insert.responseStatus, insert.responseBody, insert.responseContentType, insert.redirectTo); err != nil {
			return fmt.Errorf("写入规则 %s 的路径规则 %s: %w", ruleID, insert.path, err)
		}
	}
	return nil
}

// matchStoredPathRule 在未消费的存量行中定位与 incoming 配对的行：exactContent 为
// true 时要求含 sort_order 与上游集合完全一致（零写入），否则仅按身份键
// （match_type+path+upstream_path）配对（原地 UPDATE，保留 created_at）。
func matchStoredPathRule(existing []storedPathRule, consumed []bool, incoming storedPathRule, exactContent bool) int {
	if !exactContent {
		for index, row := range existing {
			if consumed[index] {
				continue
			}
			if row.matchType == incoming.matchType && row.path == incoming.path && row.upstreamPath == incoming.upstreamPath {
				return index
			}
		}
		return -1
	}
	for index, row := range existing {
		if consumed[index] {
			continue
		}
		if row.sortOrder == incoming.sortOrder && row.matchType == incoming.matchType && row.path == incoming.path &&
			row.upstreamPath == incoming.upstreamPath && row.upstreams == incoming.upstreams &&
			row.responseMode == incoming.responseMode && row.responseStatus == incoming.responseStatus &&
			row.responseBody == incoming.responseBody && row.responseContentType == incoming.responseContentType &&
			row.redirectTo == incoming.redirectTo {
			return index
		}
	}
	return -1
}

// updatePathRuleTx 内容真有变化时才 UPDATE（保留 id/created_at，刷新 updated_at）。
func updatePathRuleTx(ctx context.Context, tx *sql.Tx, row, incoming storedPathRule, upstreamsValue any) error {
	if row.sortOrder == incoming.sortOrder && row.matchType == incoming.matchType && row.path == incoming.path &&
		row.upstreamPath == incoming.upstreamPath && row.upstreams == incoming.upstreams &&
		row.responseMode == incoming.responseMode && row.responseStatus == incoming.responseStatus &&
		row.responseBody == incoming.responseBody && row.responseContentType == incoming.responseContentType &&
		row.redirectTo == incoming.redirectTo {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE path_rules SET sort_order=?, match_type=?, path=?, upstream_path=?, upstreams_json=?, response_mode=?, response_status=?, response_body=?, response_content_type=?, redirect_to=?, updated_at=datetime('now') WHERE id=?`,
		incoming.sortOrder, incoming.matchType, incoming.path, incoming.upstreamPath, upstreamsValue,
		incoming.responseMode, incoming.responseStatus, incoming.responseBody, incoming.responseContentType, incoming.redirectTo, row.id); err != nil {
		return err
	}
	return nil
}

func dumpRowsByKey(ctx context.Context, table, keyColumn string, keyValue any) ([]map[string]any, error) {
	return queryRowsAsMaps(ctx, db.DB, rowQuery{
		label: table + " 快照",
		query: fmt.Sprintf("SELECT * FROM %s WHERE %s = ?", table, keyColumn),
		args:  []any{keyValue},
	})
}

func dumpRowByKey(ctx context.Context, table, keyColumn string, keyValue any) (map[string]any, error) {
	rows, err := dumpRowsByKey(ctx, table, keyColumn, keyValue)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s 中不存在 %s=%v", table, keyColumn, keyValue)
	}
	return rows[0], nil
}

func insertRowFromMapTx(ctx context.Context, tx *sql.Tx, table string, row map[string]any) error {
	columns := make([]string, 0, len(row))
	placeholders := make([]string, 0, len(row))
	args := make([]any, 0, len(row))
	for column, value := range row {
		columns = append(columns, column)
		placeholders = append(placeholders, "?")
		args = append(args, value)
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ","), strings.Join(placeholders, ","))
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func restoreRuleSnapshot(ctx context.Context, caddyID string, ruleRow map[string]any, upstreamRows []map[string]any, pathRules []models.PathRule) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "restoreRuleSnapshot rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	if _, err := tx.ExecContext(ctx, "DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		return fmt.Errorf("恢复规则快照: %w", err)
	}
	if err := insertRowFromMapTx(ctx, tx, "lb_rules", ruleRow); err != nil {
		return fmt.Errorf("恢复规则快照: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		return fmt.Errorf("恢复上游快照: %w", err)
	}
	for _, upstreamRow := range upstreamRows {
		if err := insertRowFromMapTx(ctx, tx, "upstreams", upstreamRow); err != nil {
			return fmt.Errorf("恢复上游快照: %w", err)
		}
	}
	if err := replacePathRulesTx(ctx, tx, caddyID, pathRules); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func derefBool(p *bool) bool {
	return p != nil && *p
}

// userIDFromContext 类型化读取上下文 user_id（单源：contextUserID 与
// step-up 判定共用）。生产 jwtAuth 链路恒存 float64，apiKeyAuth 存 int；
// int64/string 分支为测试与 MCP 调用路径的防御性兼容（单测直连 handler 常
// 注入 int，MCP 内部转发可能注入 string 数字），生产 JWT 链路不依赖；
// 删除会让这些路径静默退回「无 user_id 直通」。gin GetString 对数字恒返回
// 空串，不得用。返回 (0,false) 表示缺失/类型未知/不可解析。
func userIDFromContext(c *gin.Context) (int, bool) {
	v, ok := c.Get("user_id")
	if !ok || v == nil {
		return 0, false
	}
	switch id := v.(type) {
	case float64:
		return int(id), true
	case int:
		return id, true
	case int64:
		return int(id), true
	case string:
		parsed, err := strconv.Atoi(id)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

// JWT 中间件存 float64，API Key 中间件存 int，统一在此收敛
func contextUserID(c *gin.Context) int64 {
	id, _ := userIDFromContext(c)
	return int64(id)
}

// ContextUserID 是 contextUserID 的跨包出口（middleware 的只读门自助判定与
// 管理员/本人参数门共用同一解析），使 user_id 的类型归一在包内仍只有一份
// 实现。缺失/未知类型返回 0——调用方一律按「非本人/无身份」处理。
func ContextUserID(c *gin.Context) int64 { return contextUserID(c) }

// 列表查询不加载 tls_cert/tls_key 正文，减少大字段 I/O。
// 由完整投影派生两个空占位，列顺序与 lbRuleColumns 恒一致，scanLbRules 无需修改。
// 列表投影派生断言：派生依赖「证书列字样必须命中」——字样改名/重排时 strings.Replace
// 会静默返回原文（列表回读私钥正文且大字段 I/O 回归），故派生函数在命中
// 失败时于包初始化 panic（fail-visible：全部入口拒绝以错误投影启动），另
// 有钉测断言列表列不含 tls_cert/tls_key 字样。
var lbRuleListColumns = deriveLbRuleListColumns()

// deriveLbRuleListColumns 从完整投影派生列表投影并断言替换命中（列表投影派生断言）。
func deriveLbRuleListColumns() string {
	const certColumns = "COALESCE(tls_cert,''), COALESCE(tls_key,'')"
	if !strings.Contains(lbRuleColumns, certColumns) {
		panic("lbRuleColumns 证书列字样缺失：lbRuleListColumns 派生失效（列表投影会回读 tls_cert/tls_key 正文）")
	}
	return strings.Replace(lbRuleColumns, certColumns, "'', ''", 1)
}

// lbRuleColumns 是规则完整投影（ListRules/GetRule/DuplicateRule 共用）。
// 治理默认值单源：治理默认值列（健康检查间隔/超时/阈值、tcp_try_interval）的 SQL
// 兜底字面量是默认值的第三次复制（DDL DEFAULT + 启动回填 + 本读路径）——
// 改为 db.Default* 常量单源（与 GetConfig 的 COALESCE(col,?) 绑定同模式）。
// 非治理列字面量维持原状。
var lbRuleColumns = fmt.Sprintf(`COALESCE(id,0), COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, COALESCE(strategy,''),
	COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
	COALESCE(health_check_path,''), COALESCE(health_check_interval,%d), COALESCE(health_check_timeout,%d), COALESCE(health_check_unhealthy_threshold,%d), COALESCE(health_check_healthy_threshold,%d),
	COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,%d),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(ntlm_compatible,0), COALESCE(upstream_force_http1,0),
	COALESCE(custom_routes_enabled,0),
	COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
	COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
	COALESCE(tls_http_redirect,0), COALESCE(enable_compress,0), COALESCE(compress_types,'gzip'), IIF(enabled IN ('1',1),1,0), COALESCE(log_enabled,0),
	created_by, created_at, updated_at, updated_by, COALESCE(host_header,''), COALESCE(health_check_host,''),
	COALESCE(block_page_stage1_id,0), COALESCE(block_page_stage1_status,0), COALESCE(block_page_stage3_id,0), COALESCE(block_page_stage3_status,0)`,
	db.DefaultHealthCheckInterval, db.DefaultHealthCheckTimeout,
	db.DefaultHealthCheckUnhealthyThreshold, db.DefaultHealthCheckHealthyThreshold,
	db.DefaultTCPTryInterval)

// 规范化规则行扫描：ListRules/GetRule/DuplicateRule 共用，避免列清单多处漂移
func scanLbRules(rows *sql.Rows) ([]models.LbRule, error) {
	rules := make([]models.LbRule, 0)
	for rows.Next() {
		var r models.LbRule
		var description, domain, strategy, dnsFamily, tlsSource, tlsCert, tlsKey, compressTypes, hostHeader, healthCheckHost string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect, enableCompress bool
		var acmeConfigID, caProviderID int
		var createdBy, updatedBy sql.NullInt64
		var createdAt, updatedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&enableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPProxyProtocol, &r.TCPTryDuration, &r.TCPTryInterval,
			&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden, &r.NTLMCompatible, &r.UpstreamForceHTTP1,
			&r.CustomRoutesEnabled,
			&r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout, &r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout, &r.ProxyFlushInterval, &r.ProxyStreamCloseDelay,
			&enableTLS, &tlsSource, &acmeConfigID, &caProviderID, &tlsCert, &tlsKey, &tlsHTTPRedirect,
			&enableCompress, &compressTypes, &r.Enabled, &r.LogEnabled,
			&createdBy, &createdAt, &updatedAt, &updatedBy, &hostHeader, &healthCheckHost,
			&r.BlockPageStage1ID, &r.BlockPageStage1Status, &r.BlockPageStage3ID, &r.BlockPageStage3Status); err != nil {
			return nil, err
		}
		r.Description = description
		r.Domain = domain
		r.Strategy = strategy
		if r.Strategy == "" {
			r.Strategy = "weighted_round_robin"
		}
		r.DynamicDNS = dynamicDNS
		r.EnableDnsServer = enableDnsServer
		r.DnsFamily = dnsFamily
		r.EnableActiveHealthCheck = enableActiveHealthCheck
		r.EnableTLS = enableTLS
		r.TLSSource = tlsSource
		r.ACMEConfigID = acmeConfigID
		r.CAProviderID = caProviderID
		r.TLSCert = tlsCert
		r.TLSKey = tlsKey
		r.TLSHTTPRedirect = tlsHTTPRedirect
		r.EnableCompress = enableCompress
		r.CompressTypes = compressTypes
		r.HostHeader = hostHeader
		r.HealthCheckHost = healthCheckHost
		if createdBy.Valid {
			r.CreatedBy = int(createdBy.Int64)
		}
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time
		}
		if updatedAt.Valid {
			r.UpdatedAt = models.JSONNullTime{NullTime: updatedAt}
		}
		if updatedBy.Valid {
			r.UpdatedBy = int(updatedBy.Int64)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ruleRelationBatchSize 关系批量查询的分块大小：单条
// IN (...) 的占位符数量随规则数线性增长，超过驱动绑定变量上限（旧 SQLite
// 999）时 ListRules/GetRule/DuplicateRule 直接 500。按 500 分块（与
// BatchRuleBlockPages 的显式上限同量级），超大规模只增加往返次数。
const ruleRelationBatchSize = 500

// ruleIDChunks 按 ruleRelationBatchSize 切分规则 ID 列表。
func ruleIDChunks(ruleIDs []string) [][]string {
	chunks := make([][]string, 0, (len(ruleIDs)+ruleRelationBatchSize-1)/ruleRelationBatchSize)
	for start := 0; start < len(ruleIDs); start += ruleRelationBatchSize {
		end := start + ruleRelationBatchSize
		if end > len(ruleIDs) {
			end = len(ruleIDs)
		}
		chunks = append(chunks, ruleIDs[start:end])
	}
	return chunks
}

func loadUpstreamsBatch(ctx context.Context, ruleIDs []string) (map[string][]models.Upstream, error) {
	result := make(map[string][]models.Upstream, len(ruleIDs))
	loadChunk := func(batch []string) error {
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, id := range batch {
			placeholders[i] = "?"
			args[i] = id
		}
		// 与渲染侧同口径（services.UpstreamEnabledSQLValue 单源，NULL 视禁用）——
		// 此前 COALESCE(enabled,1) 将遗留 NULL 行视为启用，UI 显示与生成配置分裂。
		rows, err := db.DB.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), `+services.UpstreamEnabledSQLValue+`, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,'')
			FROM upstreams u WHERE rule_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY id`, args...)
		if err != nil {
			return fmt.Errorf("批量读取上游: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var u models.Upstream
			if err := rows.Scan(&u.ID, &u.RuleID, &u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.OriginDomain); err != nil {
				return err
			}
			result[u.RuleID] = append(result[u.RuleID], u)
		}
		return rows.Err()
	}
	for _, batch := range ruleIDChunks(ruleIDs) {
		if err := loadChunk(batch); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// enabledUpstreamRuleIDs 返回 ids 中「至少一个启用上游」的规则集合。与渲染层
// 和域名冲突门同源（services.UpstreamEnabledSQLValue 单源，NULL 视禁用）：
// 全部上游被禁用的规则不产生 host 路由，不作为域名占用方。批量复用
// loadUpstreamsBatch 的分块读取，避免逐规则 N 次往返。
func enabledUpstreamRuleIDs(ctx context.Context, ruleIDs []string) (map[string]bool, error) {
	owned := make(map[string]bool, len(ruleIDs))
	if len(ruleIDs) == 0 {
		return owned, nil
	}
	upstreams, err := loadUpstreamsBatch(ctx, ruleIDs)
	if err != nil {
		return nil, err
	}
	for ruleID, list := range upstreams {
		for _, u := range list {
			if u.Enabled {
				owned[ruleID] = true
				break
			}
		}
	}
	return owned, nil
}

func loadPathRulesBatch(ctx context.Context, ruleIDs []string) (map[string][]models.PathRule, error) {
	result := make(map[string][]models.PathRule, len(ruleIDs))
	loadChunk := func(batch []string) error {
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, id := range batch {
			placeholders[i] = "?"
			args[i] = id
		}
		rows, err := db.DB.QueryContext(ctx, `SELECT id,rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to
			FROM path_rules WHERE rule_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY rule_id, sort_order, id`, args...)
		if err != nil {
			return fmt.Errorf("批量读取路径规则: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var pathRule models.PathRule
			var upstreamsJSON sql.NullString
			if err := rows.Scan(&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &pathRule.UpstreamPath, &upstreamsJSON,
				&pathRule.ResponseMode, &pathRule.ResponseStatus, &pathRule.ResponseBody, &pathRule.ResponseContentType, &pathRule.RedirectTo); err != nil {
				return err
			}
			if upstreamsJSON.Valid {
				if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
					return fmt.Errorf("解析路径规则 %d 的上游: %w", pathRule.ID, err)
				}
			}
			result[pathRule.RuleID] = append(result[pathRule.RuleID], pathRule)
		}
		return rows.Err()
	}
	for _, batch := range ruleIDChunks(ruleIDs) {
		if err := loadChunk(batch); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func hydrateRuleRelations(ctx context.Context, rules []models.LbRule) error {
	ruleIDs := make([]string, len(rules))
	for i, r := range rules {
		ruleIDs[i] = r.CaddyID
	}
	upstreamsMap, err := loadUpstreamsBatch(ctx, ruleIDs)
	if err != nil {
		return err
	}
	pathRulesMap, err := loadPathRulesBatch(ctx, ruleIDs)
	if err != nil {
		return err
	}
	for i := range rules {
		rules[i].Upstreams = upstreamsMap[rules[i].CaddyID]
		rules[i].PathRules = pathRulesMap[rules[i].CaddyID]
	}
	return nil
}

type configValidationError struct {
	message string
}

func (e *configValidationError) Error() string {
	return e.message
}

// acmeReferenceInput 汇总共享 ACME 引用校验（validateRuleACMEReferences）所需字段。
type acmeReferenceInput struct {
	EnableTLS    bool
	TLSSource    string
	ACMEConfigID int
	CAProviderID int
}

// validateRuleACMEReferences 校验 enable_tls+acme_dns 规则的 ACME 引用可解析：
// acme_config_id 非 0 且引用存在且启用（COALESCE(enabled,1)=1）的
// certificate_configs 行（发现4：与 ca_provider 检查及签发侧 certissuer.go
// 的同口径对齐，引用禁用配置会在签发期查空单任务失败 + TLS 端口明文服务）；
// ca_provider_id 为 0（系统默认）或引用存在且启用的 ca_providers 行。校验失败
// 返回 *configValidationError（调用侧映射 400），查询失败返回普通错误（500）。
// enabled 的 NULL 按启用处理——与列表展示（COALESCE(enabled,1)）及编辑基线
// 同一口径：展示「启用」的行必须能绑定，否则 UI 无法一键纠正（开关原值即启用
// 时保存不写列，NULL 永久保留）。
// 全部「把规则投入运行/复制引用」入口（Create/Update 写侧、EnableRule、启动与
// UpdateConfig 聚合校验、DuplicateRule、v2 备份导入）共用本门或其备份行同口径
// 变体（config_backup.go acmeImportRefIndex.validate），保证悬挂/禁用引用
// 无从进入运行态。
func validateRuleACMEReferences(input acmeReferenceInput) error {
	if !input.EnableTLS || input.TLSSource != "acme_dns" {
		return nil
	}
	if input.ACMEConfigID == 0 {
		return &configValidationError{message: "使用 ACME 签发时必须选择 DNS 提供商配置"}
	}
	var configOK bool
	if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM certificate_configs WHERE id = ? AND COALESCE(enabled,1) = 1)", input.ACMEConfigID).Scan(&configOK); err != nil {
		return fmt.Errorf("校验 DNS 提供商配置失败: %v", err)
	}
	if !configOK {
		return &configValidationError{message: "选择的 DNS 提供商配置不存在或已禁用"}
	}
	if input.CAProviderID != 0 {
		var providerOK bool
		if err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM ca_providers WHERE id = ? AND enabled = 1)", input.CAProviderID).Scan(&providerOK); err != nil {
			return fmt.Errorf("校验 CA 提供商失败: %v", err)
		}
		if !providerOK {
			return &configValidationError{message: "指定的 CA 提供商不存在或已禁用"}
		}
	}
	return nil
}

// validateStageBlockPageRef 阶段拦截页（规则级覆盖层）引用校验：status ∈
// {0,400,401,403,404,503}（0=渲染侧归一 403）；pageID>0 须存在于
// security_block_pages（悬空引用会使阶段路由回落 403 兜底且 UI 显示「已失效」）。
// 规则保存（validateRulePayloadBeforeSave）与批量设置（batch-block-pages）共用。
func validateStageBlockPageRef(pageID, status int, label string) error {
	return validateStageBlockPageRefWith(pageID, status, label, func(id int) (bool, error) {
		var pageOK bool
		err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM security_block_pages WHERE id = ?)", id).Scan(&pageOK)
		return pageOK, err
	})
}

// validateStageBlockPageRefWith 同 validateStageBlockPageRef，页存在性由调用方
// 提供：v2 导入的页集合必须按「备份携带 security_block_pages
// 则备份行、缺席则 live」解析（与口径一致），不能直连 db.DB。
func validateStageBlockPageRefWith(pageID, status int, label string, pageExists func(id int) (bool, error)) error {
	switch status {
	case 0, 400, 401, 403, 404, 503:
	default:
		return &configValidationError{message: fmt.Sprintf("%s拦截页状态码 %d 无效（可选 400/401/403/404/503）", label, status)}
	}
	if pageID < 0 {
		return &configValidationError{message: fmt.Sprintf("%s拦截页 id 不能为负数", label)}
	}
	// 跨字段门——渲染只在 pageID>0 时发射阶段路由，单独携带
	// status（page=0）会保存成永不消费的死配置（UI 显示未配置、导出/复制
	// 放大）。与策略侧零化门同口径：无页即无码。
	if pageID == 0 && status != 0 {
		return &configValidationError{message: fmt.Sprintf("%s拦截页状态码 %d 需要先选择拦截页（未选择拦截页时状态码必须为 0）", label, status)}
	}
	if pageID > 0 {
		pageOK, err := pageExists(pageID)
		if err != nil {
			return fmt.Errorf("校验%s拦截页引用失败: %v", label, err)
		}
		if !pageOK {
			return &configValidationError{message: fmt.Sprintf("%s拦截页不存在（id=%d）", label, pageID)}
		}
	}
	return nil
}

// mixedUpstreamPoolError：HTTP 规则启用上游池混布
// （保存门 handlers.go:615 同款文案/口径）——主池按启用上游统计（IIF 归一，
// 空协议视同 http），路径池全量统计（PathRuleUpstream 无 enabled 位，与
// 保存门 rule_features.go 路径池同口径）。启用链（EnableRule 经
// validateStoredRuleConfig）、启动/UpdateConfig 聚合校验、复制链
// （DuplicateRule）共用本 helper。
func mixedUpstreamPoolError(rule models.LbRule) error {
	if rule.Protocol != "http" {
		return nil
	}
	protos := map[string]bool{}
	for _, u := range rule.Upstreams {
		if !u.Enabled {
			continue
		}
		proto := u.Protocol
		if proto == "" {
			proto = "http"
		}
		protos[proto] = true
	}
	if protos["http"] && protos["https"] {
		return fmt.Errorf("同一 HTTP 规则的启用上游协议须一致（http/https 混布时 http 上游会被 TLS 化静默全灭；如需共存请拆分为两条规则）")
	}
	for _, pr := range rule.PathRules {
		pathProtos := map[string]bool{}
		for _, u := range pr.Upstreams {
			proto := u.Protocol
			if proto == "" {
				proto = "http"
			}
			pathProtos[proto] = true
		}
		if pathProtos["http"] && pathProtos["https"] {
			return fmt.Errorf("路径规则 %s 的自定义上游 http/https 混布（同一上游池协议须一致）", pr.Path)
		}
	}
	return nil
}

// validateTCPTryWindowBounds 是重试窗口的单源值域门：保存族
// （Create/Update/复制）与存量门（单规则启用、启动/UpdateConfig 聚合）共用。
// 回填默认与渲染单位同源：tcp_try_interval 的 0 值由启动回填与传输归一回填为
// db.DefaultTCPTryInterval（250 毫秒，渲染输出 "250ms"，见 models 字段注释）。
// http 侧 tcp_try_duration ∈ [-1,60000]（-1=显式禁用重试，NTLM 接管态），
// tcp 规则 ∈ [0,60000]（L4 无哨兵语义）；两协议同值上界 60000——越界值落库
// 后 L4 proxy try_duration 溢出、http 侧亦为死值。duration>0 时 interval 必须
// ≥1，与渲染侧两处 <=0 显性报错同文案前置，避免用户在事务渲染阶段拿到泛化失败。
func validateTCPTryWindowBounds(protocol string, duration, interval int) error {
	if protocol == "http" {
		if duration < -1 || duration > 60000 {
			return fmt.Errorf("重试窗口必须在 -1 到 60000 毫秒之间（-1=禁用重试，0=默认 5 秒窗口）")
		}
		if interval < 0 || interval > 60000 {
			return fmt.Errorf("重试间隔必须在 0 到 60000 毫秒之间")
		}
	} else {
		if duration < 0 || interval < 0 {
			return fmt.Errorf("TCP 重试时长/间隔不能为负数")
		}
		if duration > 60000 || interval > 60000 {
			return fmt.Errorf("TCP 重试时长/间隔必须在 0 到 60000 毫秒之间")
		}
	}
	if duration > 0 && interval < 1 {
		return fmt.Errorf("重试间隔必须大于 0（重试窗口 >0 时必填）")
	}
	return nil
}

// validateStoredRuleProtocolFields 是单规则启用门与启动/UpdateConfig 聚合门
// 共用的字段检查：先按保存族归一 TCP 死字段，再校验策略/协议白名单、NTLM
// 形态与上游池混布。两入口必须同源，否则同一坏规则会「启用时报错、重启时静默降级」。
func validateStoredRuleProtocolFields(rule models.LbRule, includeMixedPool bool) error {
	if rule.Protocol == "tcp" {
		tcpDeadFieldReset(rule.Protocol, storedRuleTCPDeadFields(&rule))
		rule.PathRules = []models.PathRule{}
	}
	if err := validateStrategyForProtocol(rule.Protocol, rule.Strategy); err != nil {
		return &configValidationError{message: err.Error()}
	}
	// 重试窗口与保存族同源：存量/导入/集群快照的越界值不得「启用时报错、
	// 重启时静默降级」——两入口共用同一张值域表。
	if err := validateTCPTryWindowBounds(rule.Protocol, rule.TCPTryDuration, rule.TCPTryInterval); err != nil {
		return &configValidationError{message: err.Error()}
	}
	if rule.NTLMCompatible != 0 {
		if rule.NTLMCompatible != 1 {
			return &configValidationError{message: "ntlm_compatible 必须为 0 或 1"}
		}
		if rule.Strategy != "cookie" {
			return &configValidationError{message: "NTLM 兼容模式要求负载策略为 Cookie 会话保持"}
		}
		// 与保存族同源的接管四列一致性门——兜住存量/直改
		// DB/集群快照落库的不一致行（启动迁移归一前的窗口与运行期旁路）。
		if err := ntlmTakeoverShapeError(rule.TCPTryDuration, rule.UpstreamForceHTTP1, rule.ProxyFlushInterval, rule.UpstreamKeepaliveTimeout); err != nil {
			return &configValidationError{message: err.Error()}
		}
	}
	if includeMixedPool {
		if err := mixedUpstreamPoolError(rule); err != nil {
			return &configValidationError{message: err.Error()}
		}
	}
	return nil
}

// errStoredRuleMissing 标记启用预校验按 caddy_id 重读时规则已不存在——
// 首读与校验读之间的并发删除属冲突（409），不是服务端故障（500）。
var errStoredRuleMissing = errors.New("规则不存在（可能已被并发删除）")

func validateStoredRuleConfig(ctx context.Context, caddyID string) error {
	rules, err := loadRulesForConfigValidation(ctx, " WHERE caddy_id = ?", caddyID)
	if err != nil {
		return err
	}
	if len(rules) != 1 {
		return errStoredRuleMissing
	}
	rule := rules[0]
	// 与 validateRuleFeatures 同口径，兜住历史存量/导入的 80 端口 + TLS 跳转自环规则。
	if rule.Protocol == "http" && rule.ListenPort == 80 && rule.EnableTLS && rule.TLSHTTPRedirect {
		return &configValidationError{message: "80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转"}
	}
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource != "manual" && rule.TLSSource != "acme_dns" {
		return &configValidationError{message: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"}
	}
	// 发现1：共享 ACME 引用校验（0 值门 + 存在性/enabled=1），与
	// Create/Update 写侧 400 口径对齐——导入残留的 acme_dns+0 坏规则与悬挂/禁用
	// 引用均不得经 EnableRule 投入运行（签发必败且明文服务）。
	if err := validateRuleACMEReferences(acmeReferenceInput{
		EnableTLS: rule.EnableTLS, TLSSource: rule.TLSSource,
		ACMEConfigID: rule.ACMEConfigID, CAProviderID: rule.CAProviderID,
	}); err != nil {
		return err
	}
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource == "manual" &&
		(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
		return &configValidationError{message: "手动证书模式下必须提供 TLS 证书和私钥"}
	}
	// 策略白名单、NTLM、TCP dynamic_dns、上游池混布
	// 与启动/UpdateConfig 聚合门共用同一 helper。
	if err := validateStoredRuleProtocolFields(rule, true); err != nil {
		return err
	}
	return validateRuleConfigGeneration(rule)
}

// 收集全部坏规则错误聚合返回（每条含规则名+caddy_id），
// 避免首错即 return 导致多条坏规则需重启多次逐一暴露；errors.Join 保持
// 与 configValidationError 的 errors.As 兼容（UpdateConfig/EnableRule 类型断言路径）。
func validateEnabledStoredRuleConfigs(ctx context.Context) error {
	rules, err := loadRulesForConfigValidation(ctx, " WHERE enabled = 1")
	if err != nil {
		return err
	}
	// 全局请求体上限只读一次（此前 precheckRuleConfig 逐
	// 规则点查同值配置 → 启动/UpdateConfig 聚合校验 N 条规则 N 次往返）。
	globalBody := 0
	if len(rules) > 0 {
		globalBody = globalRequestBodyMaxSizeMBForPrecheck()
	}
	problems := make([]error, 0)
	for _, rule := range rules {
		// 存量规则可能建于校验上线前：80 端口 + TLS 跳转生成自环 Location，
		// 启动再生配置前按保存路径同口径拦截并指出具体规则。
		if rule.Protocol == "http" && rule.ListenPort == 80 && rule.EnableTLS && rule.TLSHTTPRedirect {
			problems = append(problems, &configValidationError{message: fmt.Sprintf("规则 %s（%s）80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转", rule.Name, rule.CaddyID)})
			continue
		}
		// 与 validateStoredRuleConfig 同口径的 tls_source 白名单——
		// 存量（白名单上线前落库）/直改 DB 的垃圾 tls_source 启用行必须在启动与
		// UpdateConfig 聚合校验点名（渲染侧 availableCerts 仅认 manual/acme_dns →
		// 无 tls_connection_policies → TLS 端口明文服务，disable_certificates 阻自愈）。
		if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource != "manual" && rule.TLSSource != "acme_dns" {
			problems = append(problems, &configValidationError{message: fmt.Sprintf("规则 %s（%s）启用 TLS 时必须选择证书来源（manual 或 acme_dns）", rule.Name, rule.CaddyID)})
			continue
		}
		// 发现1：启动/UpdateConfig 聚合校验与 EnableRule 同门——ACME 引用
		// 不可解析（0 值/悬挂/已禁用）的启用规则必须点名，不得静默通过。
		if err := validateRuleACMEReferences(acmeReferenceInput{
			EnableTLS: rule.EnableTLS, TLSSource: rule.TLSSource,
			ACMEConfigID: rule.ACMEConfigID, CAProviderID: rule.CAProviderID,
		}); err != nil {
			var validationErr *configValidationError
			if errors.As(err, &validationErr) {
				problems = append(problems, &configValidationError{message: fmt.Sprintf("规则 %s（%s）%s", rule.Name, rule.CaddyID, validationErr.Error())})
			} else {
				problems = append(problems, fmt.Errorf("规则 %s（%s）ACME 引用校验失败：%w", rule.Name, rule.CaddyID, err))
			}
		}
		// 与 validateStoredRuleConfig 单规则门对称的 manual 材料检查——
		// enable_tls=1 + manual + 空证书的启用行会让 TLS 端口明文服务
		//（availableCerts 要求 cert/key 非空）。保存/导入链均拦截该形态，此门
		// 兜住存量/直改 DB（与同定位）。
		if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource == "manual" &&
			(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
			problems = append(problems, &configValidationError{message: fmt.Sprintf("规则 %s（%s）手动证书模式缺少证书或私钥，请补齐材料或切换证书来源", rule.Name, rule.CaddyID)})
		}
		// 与单规则 EnableRule 同源的字段门，避免
		// 「启用时报错、启动/UpdateConfig 静默降级」的不对称。
		if err := validateStoredRuleProtocolFields(rule, false); err != nil {
			if validationErr, ok := err.(*configValidationError); ok {
				problems = append(problems, &configValidationError{message: fmt.Sprintf("规则 %s（%s）%s", rule.Name, rule.CaddyID, validationErr.Error())})
			} else {
				problems = append(problems, fmt.Errorf("规则 %s（%s）字段校验失败：%w", rule.Name, rule.CaddyID, err))
			}
			continue
		}
		if err := validateRuleConfigGenerationWithGlobalBody(rule, globalBody); err != nil {
			problems = append(problems, fmt.Errorf("规则 %s（%s）配置无效：%w", rule.Name, rule.CaddyID, err))
		}
	}
	// 同端口多启用 TCP 规则点名(兜存量双启用——启用方向第二条由
	// validatePortFromDB 拦截,此门兜直改 DB/历史存量;L4 监听同端口只能由
	// 一条规则占用,后注册者顶替先注册者)。与不同:该形态渲染即
	// 相互顶替,必须报错而非仅告警。
	tcpByPort := make(map[int][]string)
	for _, rule := range rules {
		if rule.Protocol != "tcp" {
			continue
		}
		tcpByPort[rule.ListenPort] = append(tcpByPort[rule.ListenPort], fmt.Sprintf("%s（%s）", rule.Name, rule.CaddyID))
	}
	for port, names := range tcpByPort {
		if len(names) > 1 {
			problems = append(problems, &configValidationError{message: fmt.Sprintf("端口 %d 存在多条启用的 TCP 规则（%s）——L4 监听同端口只能由一条规则占用，请保留一条或调整端口", port, strings.Join(names, "、"))})
		}
	}
	// 同端口同归一化域名的多条启用 HTTP 规则点名（与 TCP 同端口同格=硬错）：
	// 保存/启用路径由 enabledRuleDomainConflict 拦截，但直改 DB/历史脏库可绕过
	//（导入链另由 disableV2RuleConflicts 冲突矩阵置禁用）。渲染层同 server 内
	// 两条 host matcher + terminal 路由时，按 rowid 先出现者吃掉全部流量，后者
	// 成为永不命中的死规则且面板仍显示「已启用」——必须点名而非静默。
	// 占用方口径与冲突门/渲染层同源：零启用上游的规则不产生 host 路由，
	// 不参与归组（否则把运行时无冲突的组合判为硬错，管理员无法保存配置）。
	type httpDomainSlot struct {
		port   int
		domain string
	}
	httpRuleIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Protocol == "http" && rule.Enabled {
			httpRuleIDs = append(httpRuleIDs, rule.CaddyID)
		}
	}
	httpDomainOwners, ownerErr := enabledUpstreamRuleIDs(ctx, httpRuleIDs)
	if ownerErr != nil {
		return fmt.Errorf("读取域名占用规则的启用上游失败: %w", ownerErr)
	}
	domainOwners := make(map[httpDomainSlot][]string)
	for _, rule := range rules {
		if rule.Protocol != "http" || !rule.Enabled || !httpDomainOwners[rule.CaddyID] {
			continue
		}
		for _, domain := range normalizedRuleDomains(rule.Domain) {
			slot := httpDomainSlot{port: rule.ListenPort, domain: domain}
			domainOwners[slot] = append(domainOwners[slot], fmt.Sprintf("%s（%s）", rule.Name, rule.CaddyID))
		}
	}
	conflicted := make([]httpDomainSlot, 0)
	for slot, owners := range domainOwners {
		if len(owners) > 1 {
			conflicted = append(conflicted, slot)
		}
	}
	// map 遍历序不确定会让错误文本/启动日志在两次运行间漂移。
	sort.Slice(conflicted, func(i, j int) bool {
		if conflicted[i].port != conflicted[j].port {
			return conflicted[i].port < conflicted[j].port
		}
		return conflicted[i].domain < conflicted[j].domain
	})
	for _, slot := range conflicted {
		problems = append(problems, &configValidationError{message: fmt.Sprintf("端口 %d 的域名 %s 被多条启用的 HTTP 规则占用（%s）——同一监听端口内只有首条规则会收到流量，其余为永不命中的死规则，请保留一条或调整端口/域名", slot.port, slot.domain, strings.Join(domainOwners[slot], "、"))})
	}
	// 存量同端口 TLS/明文混布点名告警(不阻断启动——存量形态可能是
	// 混布前已落库的历史数据,阻断会让节点起不来;点名提示管理员修正)。
	portTLSMix := make(map[int][2][]string)
	for _, rule := range rules {
		if rule.Protocol != "http" || !rule.Enabled {
			continue
		}
		idx := 0
		if rule.EnableTLS {
			idx = 1
		}
		mix := portTLSMix[rule.ListenPort]
		mix[idx] = append(mix[idx], rule.CaddyID)
		portTLSMix[rule.ListenPort] = mix
	}
	for port, mix := range portTLSMix {
		if len(mix[0]) > 0 && len(mix[1]) > 0 {
			services.Logf("warn", "端口 %d 存在 TLS 与明文规则混布（明文：%v；TLS：%v）——该端口监听器将整体切换为 TLS，明文规则流量将握手失败，请调整规则端口", port, mix[0], mix[1])
		}
	}
	// 存量启用行启用上游池混布点名告警（镜像 portTLSMix 形态，不阻断启动——
	// 阻断会让节点起不来；新写入方向已被 validateStoredRuleConfig 400 拦截，
	// 此门兜「直改 DB 或更早版本落库」的存量，提示管理员修正）。
	for _, rule := range rules {
		if !rule.Enabled || rule.Protocol != "http" {
			continue
		}
		if err := mixedUpstreamPoolError(rule); err != nil {
			services.Logf("warn", "规则 %s（%s）%s——混布池已进入运行态，http 上游正被池级 TLS 化静默 502，请统一上游协议或拆分规则", rule.Name, rule.CaddyID, err.Error())
		}
	}
	return errors.Join(problems...)
}

func loadRulesForConfigValidation(ctx context.Context, suffix string, args ...any) ([]models.LbRule, error) {
	rows, err := db.DB.QueryContext(ctx, "SELECT "+lbRuleColumns+" FROM lb_rules"+suffix, args...)
	if err != nil {
		return nil, fmt.Errorf("读取待验证规则: %w", err)
	}
	rules, scanErr := scanLbRules(rows)
	closeErr := rows.Close()
	if err := errors.Join(scanErr, closeErr); err != nil {
		return nil, fmt.Errorf("读取待验证规则: %w", err)
	}
	if err := hydrateRuleRelations(ctx, rules); err != nil {
		return nil, fmt.Errorf("读取待验证规则关联配置: %w", err)
	}
	return rules, nil
}

// precheckRuleConfig 构造预校验渲染输入（EnableRule/启动聚合校验共用）。
// 回填本日新特性列：upstreams 携带 OriginDomain、
// path_rules 携带 response_* 五列、规则级携带 HostHeader/HealthCheckHost/
// EnableCompress/CompressTypes——此前预检渲染把直返/301 路径规则当转发链
// 渲染、不发射回源域名 map 处理器，与真实渲染分叉（错误拦截时机后移）。
// 库值唯一真相（批 1+2）：健康检查族/tcp_try_interval 随 DB 行携带——渲染层
// 对这些值型列已零兜底（0 值渲染报错），预检不再复制会把「带外脏行」的拦截
// 时机后移到 applyFromTxNote（原「有意保留的空口子集（勿回填）」清单中
// 「健康检查间隔族」一项就此移除；代理超时族维持 0=省略合法语义，保留空口）。
// TLS 开关与证书材料仍为有意空口（GenerateSingleRuleCaddyConfig 单规则形态
// 约定——TLS 跳转分支自述无预检调用方）。
// globalRequestBodyMaxSizeMBForPrecheck 读取全局 request_body_max_size_mb 供
// 单规则预检携带（生产渲染由 generateCaddyConfigWithCertSource 从
// global_config 灌入；预检此前缺位、靠渲染层「兜底 128」幸存——兜底废除后
// 必须显式携带）。查询失败置 0：渲染层 resolveRuleOverrides 显性报错，预检
// 随真实渲染同 fail-visible。聚合校验把本函数的结果一次
// 传入（N 条规则不再 N 次点查同值配置）。
func globalRequestBodyMaxSizeMBForPrecheck() int {
	globalBody := 0
	if db.DB != nil {
		if err := db.DB.QueryRow(`SELECT request_body_max_size_mb FROM global_config WHERE id=1`).Scan(&globalBody); err != nil {
			services.Logf("warn", "precheckRuleConfig: 读取全局 request_body_max_size_mb 失败: %v", err)
			globalBody = 0
		}
	}
	return globalBody
}

// precheckRuleConfig 把库行投影为单规则渲染输入；globalBody 为全局
// request_body_max_size_mb（调用方按批量/单条语义取一次）。
func precheckRuleConfig(rule models.LbRule, globalBody int) services.SingleRuleConfig {
	upstreams := make([]services.UpstreamConfig, 0, len(rule.Upstreams))
	for _, upstream := range rule.Upstreams {
		upstreams = append(upstreams, services.UpstreamConfig{
			Host: upstream.Host, Port: upstream.Port, Weight: upstream.Weight,
			Protocol: upstream.Protocol, Enabled: upstream.Enabled, MaxConnections: upstream.MaxConnections,
			OriginDomain: upstream.OriginDomain,
		})
	}
	return services.SingleRuleConfig{
		CaddyID: rule.CaddyID, Protocol: rule.Protocol, Domain: rule.Domain, ListenPort: rule.ListenPort,
		Strategy: rule.Strategy, DynamicDNS: rule.DynamicDNS, EnableDnsServer: rule.EnableDnsServer,
		DnsServer: rule.DnsServer, DnsFamily: rule.DnsFamily, CustomRoutesEnabled: rule.CustomRoutesEnabled,
		HostHeader: rule.HostHeader, HealthCheckHost: rule.HealthCheckHost,
		HealthCheckInterval:           rule.HealthCheckInterval,
		HealthCheckTimeout:            rule.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: rule.HealthCheckUnhealthyThreshold,
		HealthCheckHealthyThreshold:   rule.HealthCheckHealthyThreshold,
		EnableActiveHealthCheck:       rule.EnableActiveHealthCheck,
		TCPHealthCheckPort:            rule.TCPHealthCheckPort,
		TCPProxyProtocol:              rule.TCPProxyProtocol,
		NTLMCompatible:                rule.NTLMCompatible,
		UpstreamForceHTTP1:            rule.UpstreamForceHTTP1,
		TCPTryDuration:                rule.TCPTryDuration, TCPTryInterval: rule.TCPTryInterval,
		EnableCompress: rule.EnableCompress, CompressTypes: rule.CompressTypes,
		GlobalRequestBodyMaxSizeMB: globalBody,
		BlockPageStage1ID:          rule.BlockPageStage1ID, BlockPageStage1Status: rule.BlockPageStage1Status,
		BlockPageStage3ID: rule.BlockPageStage3ID, BlockPageStage3Status: rule.BlockPageStage3Status,
		PathRules: toPathRuleConfigs(rule.PathRules), Upstreams: upstreams,
	}
}

// validateRuleConfigGeneration 单规则渲染预校验（EnableRule 单条语义：
// 全局请求体上限就地读取一次）。
func validateRuleConfigGeneration(rule models.LbRule) error {
	return validateRuleConfigGenerationWithGlobalBody(rule, globalRequestBodyMaxSizeMBForPrecheck())
}

// validateRuleConfigGenerationWithGlobalBody 同上一形态，全局请求体上限由
// 调用方传入。
func validateRuleConfigGenerationWithGlobalBody(rule models.LbRule, globalBody int) error {
	config := services.GenerateSingleRuleCaddyConfig(precheckRuleConfig(rule, globalBody))
	genErr, hasErr := config["error"].(error)
	if !hasErr {
		return nil
	}
	// 仅特判零上游——全量渲染路径对零上游规则是跳过而非失败
	// （caddy.go 按启用上游数 continue），该特判是有意的，保持与渲染侧一致；
	// 其余生成错误（含 generateHTTPRouteObjects 的硬错误）一律返回，
	// 避免聚合与 EnableRule 预校验漏报（此前全被吞掉）。
	// 精确串比较改哨兵 errors.Is——生成侧两处产出点
	// （GenerateSingleRuleCaddyConfig 直返 / buildHTTPHandleChain %w 包装）
	// 统一引用 services.ErrNoEnabledUpstreams，未来加规则上下文包装仍能命中。
	if errors.Is(genErr, services.ErrNoEnabledUpstreams) {
		return nil
	}
	// 动态 DNS 多上游同样哨兵化（ErrDynamicDNSUpstreamCount），
	// 不再依赖文案 Contains——文案调整即静默漏报。
	if errors.Is(genErr, services.ErrDynamicDNSUpstreamCount) {
		return &configValidationError{message: "动态 DNS 模式仅支持一个启用的上游"}
	}
	// 其余生成失败同样源于规则数据/库值（预检输入全部来自
	// 库行 + 一次全局配置值，生成路径无 DB I/O），按 configValidationError 分类
	// ——EnableRule 映射 400「可自行修正」而非 500 内部故障，UpdateConfig 的
	// isPureConfigValidationError 判定同受益；错误文本是渲染层确定性文案，
	// 不含底层 DB 错误（DB 故障在更早的读行阶段已 500）。
	return &configValidationError{message: "生成规则配置失败: " + genErr.Error()}
}
