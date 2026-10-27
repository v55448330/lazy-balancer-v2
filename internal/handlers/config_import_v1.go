package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type v1Backup struct {
	ProxyConfig    *v1Section `json:"proxy_config"`
	UpstreamConfig *v1Section `json:"upstream_config"`
}

type v1Section struct {
	Config json.RawMessage `json:"config"`
}

type v1Upstream struct {
	PK     int `json:"pk"`
	Fields struct {
		Status  bool   `json:"status"`
		Address string `json:"address"`
		Port    int    `json:"port"`
		Weight  int    `json:"weight"`
	} `json:"fields"`
}

type v1Proxy struct {
	PK     int `json:"pk"`
	Fields struct {
		ProxyName           string `json:"proxy_name"`
		Protocol            bool   `json:"protocol"`
		Listen              int    `json:"listen"`
		ServerName          string `json:"server_name"`
		BalancerType        string `json:"balancer_type"`
		HTTPCheck           bool   `json:"http_check"`
		Gzip                bool   `json:"gzip"`
		Description         string `json:"description"`
		SSL                 bool   `json:"ssl"`
		SSLRedirectHTTPS    bool   `json:"ssl_redirect_https"`
		SSLCert             string `json:"ssl_cert"`
		SSLKey              string `json:"ssl_key"`
		BackendProtocol     string `json:"backend_protocol"`
		BackendDomainToggle bool   `json:"backend_domain_toggle"`
		BackendDomain       string `json:"backend_domain"`
		Status              bool   `json:"status"`
		MaxFails            int    `json:"max_fails"`
		FailTimeout         int    `json:"fail_timeout"`
		UpstreamList        []int  `json:"upstream_list"`
	} `json:"fields"`
}

type convertedRule struct {
	Name        string
	Domain      string
	ListenPort  int
	Protocol    string
	Strategy    string
	EnableTLS   bool
	TLSCert     string
	TLSKey      string
	Redirect    bool
	Compress    bool
	HealthFails int
	HealthInt   int
	ActiveHC    bool
	Enabled     bool
	HostHeader  string
	Description string
	Upstreams   []convertedUpstream
}

type convertedUpstream struct {
	Host     string
	Port     int
	Weight   int
	Enabled  bool
	Protocol string
}

type ruleConflictCandidate struct {
	name, caddyID, protocol, domain string
	listenPort                      int
	enabled                         bool
	enableTLS                       bool
	tlsHTTPRedirect                 bool
}

// v1（disableConvertedRuleConflicts）与 v2（disableV2RuleConflicts）
// 各自组装 ruleConflictCandidate 的字段清单此前重复两份，新增字段需同步两处；
// 收敛为单一构造函数，双路径共用。
func newRuleConflictCandidate(name, caddyID, protocol, domain string, listenPort int, enabled, enableTLS, tlsHTTPRedirect bool) ruleConflictCandidate {
	return ruleConflictCandidate{
		name: name, caddyID: caddyID, protocol: protocol, domain: domain,
		listenPort: listenPort, enabled: enabled, enableTLS: enableTLS, tlsHTTPRedirect: tlsHTTPRedirect,
	}
}

type disabledRuleConflict struct {
	index         int
	Name          string                 `json:"name,omitempty"`
	CaddyID       string                 `json:"caddy_id,omitempty"`
	Reason        string                 `json:"reason"`
	ConflictsWith []ruleConflictOpponent `json:"conflicts_with"`
}

type ruleConflictOpponent struct {
	Name    string `json:"name,omitempty"`
	CaddyID string `json:"caddy_id,omitempty"`
	Reason  string `json:"reason"`
}

func validateRuleConflictMatrix(candidates []ruleConflictCandidate) []disabledRuleConflict {
	reasons := make(map[int][]string)
	opponents := make(map[int][]ruleConflictOpponent)
	// 一次性预计算 canonical 域名（normalizedRuleDomains 含 IDNA
	// 转换，逐对调用是 O(N²) 次）与按 listenPort 分桶——矩阵内只做集合
	// 交集；同端口对只在本桶内枚举，跨端口对仅 80↔非 80 可能相关（其余在
	// 原 switch 的「端口不同 → continue」分支零产出）。
	domainLists := make([][]string, len(candidates))
	domainSets := make([]map[string]struct{}, len(candidates))
	byPort := make(map[int][]int, 8)
	for index := range candidates {
		list := normalizedRuleDomains(candidates[index].domain)
		domainLists[index] = list
		set := make(map[string]struct{}, len(list))
		for _, domain := range list {
			set[domain] = struct{}{}
		}
		domainSets[index] = set
		byPort[candidates[index].listenPort] = append(byPort[candidates[index].listenPort], index)
	}
	// 同端口 TLS/明文混布（保存/启用链 checkPortTLSMix 的导入侧
	// 同口径落地）。Caddy 按端口生成单一 server，只要任一启用 HTTP 规则带证书
	// 即生成 tls_connection_policies——同端口明文规则在该监听器上握手必败，
	// 整条规则静默不可达。导入无法像保存链一样即时 400（备份可能来自旧版本/
	// 手造/nginx 转换），按矩阵既有「冲突置禁用」语义只禁用不可达的明文一侧，
	// TLS 一侧继续服务（该侧行为健康）。禁用行为不参与（不渲染、不占端口）。
	for port, indexes := range byPort {
		var tlsIndexes, plainIndexes []int
		for _, index := range indexes {
			candidate := candidates[index]
			if !candidate.enabled || candidate.protocol != "http" {
				continue
			}
			if candidate.enableTLS {
				tlsIndexes = append(tlsIndexes, index)
			} else {
				plainIndexes = append(plainIndexes, index)
			}
		}
		if len(tlsIndexes) == 0 || len(plainIndexes) == 0 {
			continue
		}
		reason := fmt.Sprintf("端口 %d 的 TLS 与明文规则不能混布（该端口监听器将整体切换为 TLS，明文规则不可达）", port)
		for _, plainIndex := range plainIndexes {
			reasons[plainIndex] = append(reasons[plainIndex], reason)
			for _, tlsIndex := range tlsIndexes {
				opponents[plainIndex] = append(opponents[plainIndex], ruleConflictOpponent{
					Name: candidates[tlsIndex].name, CaddyID: candidates[tlsIndex].caddyID, Reason: reason,
				})
			}
		}
	}
	intersectFirst := func(primaryIndex, otherIndex int) (string, bool) {
		for _, domain := range domainLists[primaryIndex] {
			if _, exists := domainSets[otherIndex][domain]; exists {
				return domain, true
			}
		}
		return "", false
	}
	evaluate := func(leftIndex, rightIndex int) {
		left, right := candidates[leftIndex], candidates[rightIndex]
		reason := ""
		switch {
		case left.protocol == "http" && right.protocol == "http" && left.listenPort == right.listenPort:
			// 禁用规则无运行时占用——与禁用行的「同端口同域名」不构成
			// 真实冲突，不得把启用中的一方静默置禁用（与跨端口分支同口径门控）。
			// 放行禁用自环行后该组合首次可达此分支。
			if left.enabled && right.enabled {
				if domain, hit := intersectFirst(rightIndex, leftIndex); hit {
					reason = fmt.Sprintf("HTTP 域名 %s 重复", domain)
				}
			}
		case left.protocol == "http" && right.protocol == "http" && left.listenPort != right.listenPort:
			// 跨端口跳转遮蔽方向——TLS+跳转规则在 80 端口服务器头部
			// 生成 terminal 301（caddy.go redirectRoutes），同域名直接监听 80 的规则
			// 会被静默遮蔽为死规则。仅双方均启用时判定，按矩阵惯例冲突双方置禁用。
			if left.enabled && right.enabled {
				if left.listenPort == 80 && right.enableTLS && right.tlsHTTPRedirect {
					if domain, hit := intersectFirst(rightIndex, leftIndex); hit {
						reason = fmt.Sprintf("HTTP 域名 %s 被 HTTPS 跳转遮蔽", domain)
					}
				} else if right.listenPort == 80 && left.enableTLS && left.tlsHTTPRedirect {
					if domain, hit := intersectFirst(leftIndex, rightIndex); hit {
						reason = fmt.Sprintf("HTTP 域名 %s 被 HTTPS 跳转遮蔽", domain)
					}
				}
			}
		case left.listenPort != right.listenPort:
			return
		case left.protocol == "tcp" && right.protocol == "tcp":
			// 与 HTTP 同端口分支同口径门控——
			// 禁用 TCP 规则不渲染（caddy.go WHERE enabled=1）、无运行时端口占用，
			// 不得把启用中的一方静默置禁用。
			if left.enabled && right.enabled {
				reason = fmt.Sprintf("TCP 监听端口 %d 重复", left.listenPort)
			}
		case left.protocol == "tcp" || right.protocol == "tcp":
			if left.enabled && right.enabled {
				reason = fmt.Sprintf("TCP 与 HTTP 监听端口 %d 冲突", left.listenPort)
			}
		}
		if reason == "" {
			return
		}
		reasons[leftIndex] = append(reasons[leftIndex], reason)
		reasons[rightIndex] = append(reasons[rightIndex], reason)
		opponents[leftIndex] = append(opponents[leftIndex], ruleConflictOpponent{Name: right.name, CaddyID: right.caddyID, Reason: reason})
		opponents[rightIndex] = append(opponents[rightIndex], ruleConflictOpponent{Name: left.name, CaddyID: left.caddyID, Reason: reason})
	}
	for leftIndex := range candidates {
		port := candidates[leftIndex].listenPort
		rights := make([]int, 0, len(byPort[port]))
		for _, rightIndex := range byPort[port] {
			if rightIndex > leftIndex {
				rights = append(rights, rightIndex)
			}
		}
		if port == 80 {
			for otherPort, indexes := range byPort {
				if otherPort == 80 {
					continue
				}
				for _, rightIndex := range indexes {
					if rightIndex > leftIndex {
						rights = append(rights, rightIndex)
					}
				}
			}
		} else {
			for _, rightIndex := range byPort[80] {
				if rightIndex > leftIndex {
					rights = append(rights, rightIndex)
				}
			}
		}
		// 保持原始 (i<j) 枚举顺序，冲突/对手列表文案与旧实现逐字一致。
		sort.Ints(rights)
		for _, rightIndex := range rights {
			evaluate(leftIndex, rightIndex)
		}
	}
	conflicts := make([]disabledRuleConflict, 0, len(reasons))
	for index, candidate := range candidates {
		if candidateReasons := reasons[index]; len(candidateReasons) > 0 {
			conflicts = append(conflicts, disabledRuleConflict{
				index: index, Name: candidate.name, CaddyID: candidate.caddyID,
				Reason: strings.Join(candidateReasons, "；"), ConflictsWith: opponents[index],
			})
		}
	}
	return conflicts
}

func disableConvertedRuleConflicts(rules []convertedRule) []disabledRuleConflict {
	candidates := make([]ruleConflictCandidate, 0, len(rules))
	for _, rule := range rules {
		candidates = append(candidates, newRuleConflictCandidate(rule.Name, "", rule.Protocol, rule.Domain, rule.ListenPort, rule.Enabled, rule.EnableTLS, rule.Redirect))
	}
	conflicts := validateRuleConflictMatrix(candidates)
	for _, conflict := range conflicts {
		rules[conflict.index].Enabled = false
	}
	return conflicts
}

func formatDisabledRuleConflicts(conflicts []disabledRuleConflict) string {
	parts := make([]string, 0, len(conflicts))
	for _, conflict := range conflicts {
		identifier := conflict.Name
		if identifier == "" {
			identifier = conflict.CaddyID
		}
		opponentParts := make([]string, 0, len(conflict.ConflictsWith))
		for _, opponent := range conflict.ConflictsWith {
			opponentIdentifier := opponent.Name
			if opponentIdentifier == "" {
				opponentIdentifier = opponent.CaddyID
			}
			opponentParts = append(opponentParts, fmt.Sprintf("%s：%s", opponentIdentifier, opponent.Reason))
		}
		parts = append(parts, fmt.Sprintf("%s（冲突对象：%s）", identifier, strings.Join(opponentParts, "、")))
	}
	return strings.Join(parts, "；")
}

func (b *v1Backup) parse() ([]v1Proxy, map[int]v1Upstream, error) {
	if b.ProxyConfig == nil || b.UpstreamConfig == nil {
		return nil, nil, fmt.Errorf("不是有效的 V1 备份文件（缺少 proxy_config/upstream_config）")
	}
	proxiesRaw, err := unwrapJSONString(b.ProxyConfig.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 proxy_config 失败: %w", err)
	}
	var proxies []v1Proxy
	if err := json.Unmarshal(proxiesRaw, &proxies); err != nil {
		return nil, nil, fmt.Errorf("解析 proxy_config 失败: %w", err)
	}
	upstreamsRaw, err := unwrapJSONString(b.UpstreamConfig.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 upstream_config 失败: %w", err)
	}
	var upstreams []v1Upstream
	if err := json.Unmarshal(upstreamsRaw, &upstreams); err != nil {
		return nil, nil, fmt.Errorf("解析 upstream_config 失败: %w", err)
	}
	byPK := make(map[int]v1Upstream, len(upstreams))
	for _, u := range upstreams {
		if _, dup := byPK[u.PK]; dup {
			return nil, nil, fmt.Errorf("upstream_config 中存在重复的主键: %d", u.PK)
		}
		byPK[u.PK] = u
	}
	return proxies, byPK, nil
}

func unwrapJSONString(raw json.RawMessage) (json.RawMessage, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		return json.RawMessage(encoded), nil
	}
	return raw, nil
}

func convertV1Rules(proxies []v1Proxy, upstreams map[int]v1Upstream) ([]convertedRule, []string) {
	rules := make([]convertedRule, 0, len(proxies))
	warnings := make([]string, 0)
	for _, p := range proxies {
		f := p.Fields
		strategy, mapped := mapV1BalancerStrategy(f.BalancerType)
		if !mapped && f.BalancerType != "" {
			warnings = append(warnings, fmt.Sprintf("规则 %s 的负载策略 %q 无法映射，已使用 weighted_round_robin", f.ProxyName, f.BalancerType))
		}
		rule := convertedRule{
			Name:        f.ProxyName,
			Domain:      strings.Join(strings.Fields(f.ServerName), ", "),
			ListenPort:  f.Listen,
			Protocol:    "http",
			Strategy:    strategy,
			EnableTLS:   f.SSL,
			Redirect:    f.SSLRedirectHTTPS,
			Compress:    f.Gzip,
			HealthFails: f.MaxFails,
			HealthInt:   f.FailTimeout,
			ActiveHC:    f.HTTPCheck,
			Enabled:     f.Status,
			Description: f.Description,
		}
		if !f.Protocol {
			rule.Protocol = "tcp"
		}
		if rule.Protocol == "http" && strings.TrimSpace(rule.Domain) == "" {
			warnings = append(warnings, fmt.Sprintf("规则 %s 的域名为空，已跳过导入", f.ProxyName))
			continue
		}
		if rule.HealthFails <= 0 {
			rule.HealthFails = db.DefaultHealthCheckUnhealthyThreshold
		}
		if rule.HealthInt <= 0 {
			rule.HealthInt = db.DefaultHealthCheckInterval
		}
		if f.SSL {
			rule.TLSCert = f.SSLCert
			rule.TLSKey = f.SSLKey
		}
		if f.BackendDomainToggle && f.BackendDomain != "" {
			rule.HostHeader = f.BackendDomain
		}
		for _, pk := range f.UpstreamList {
			u, ok := upstreams[pk]
			if !ok {
				continue
			}
			protocol := f.BackendProtocol
			if protocol == "" {
				protocol = "http"
			}
			weight := u.Fields.Weight
			if weight <= 0 {
				weight = 100
			}
			rule.Upstreams = append(rule.Upstreams, convertedUpstream{
				Host: u.Fields.Address, Port: u.Fields.Port, Weight: weight, Enabled: u.Fields.Status, Protocol: protocol,
			})
		}
		rules = append(rules, rule)
	}
	return rules, warnings
}

func mapV1BalancerStrategy(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "least_conn":
		return "least_conn", true
	case "ip_hash":
		return "ip_hash", true
	case "round_robin", "weighted":
		return "weighted_round_robin", true
	default:
		return "weighted_round_robin", false
	}
}

// validateConvertedV1Rules 的 portGate 与 validateV2BackupRules 同口径
// 生产预览/导入传入进程实际管理端口门；省略退回包级默认。
func validateConvertedV1Rules(rules []convertedRule, portGates ...func(string, int) error) ([]convertedRule, []string, []string) {
	validatePort := validateRuleListenPort
	if len(portGates) > 0 && portGates[0] != nil {
		validatePort = portGates[0]
	}
	var valid []convertedRule
	var skips []string
	var normalizations []string
	for index, rule := range rules {
		if err := validatePort(rule.Protocol, rule.ListenPort); err != nil {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：%v", index+1, rule.Name, err))
			continue
		}
		if rule.Protocol != "http" && rule.Protocol != "tcp" {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：协议无效", index+1, rule.Name))
			continue
		}
		if rule.Protocol == "http" {
			domainBad := false
			for _, domain := range strings.Split(rule.Domain, ",") {
				domain = strings.TrimSpace(domain)
				if domain != "" && !isValidDomain(domain) {
					skips = append(skips, fmt.Sprintf("规则 #%d（%s）：域名 %q 无效", index+1, rule.Name, domain))
					domainBad = true
					break
				}
			}
			if domainBad {
				continue
			}
		}
		// 先把 v1 协议名归一到 v2 值域，再复用保存侧上游单源校验。
		upstreamBad := false
		for upstreamIndex := range rule.Upstreams {
			upstream := &rule.Upstreams[upstreamIndex]
			switch upstream.Protocol {
			case "http", "https", "tcp", "tls":
				if rule.Protocol == "http" && (upstream.Protocol == "tcp" || upstream.Protocol == "tls") {
					normalized := "http"
					if upstream.Protocol == "tls" {
						normalized = "https"
					}
					normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）上游 #%d：HTTP 规则上游协议 %s 已按 %s 导入", index+1, rule.Name, upstreamIndex+1, upstream.Protocol, normalized))
					upstream.Protocol = normalized
				} else if rule.Protocol == "tcp" && (upstream.Protocol == "http" || upstream.Protocol == "https") {
					normalized := "tcp"
					if upstream.Protocol == "https" {
						normalized = "tls"
					}
					normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）上游 #%d：TCP 规则上游协议 %s 已按 %s 导入", index+1, rule.Name, upstreamIndex+1, upstream.Protocol, normalized))
					upstream.Protocol = normalized
				}
			default:
				skips = append(skips, fmt.Sprintf("规则 #%d（%s）上游 #%d：上游协议 %q 无效（支持 http/https/tcp/tls）", index+1, rule.Name, upstreamIndex+1, upstream.Protocol))
				upstreamBad = true
			}
			if upstreamBad {
				break
			}
		}
		if upstreamBad {
			continue
		}
		upstreams := make([]models.Upstream, 0, len(rule.Upstreams))
		for _, upstream := range rule.Upstreams {
			upstreams = append(upstreams, models.Upstream{Host: upstream.Host, Port: upstream.Port, Weight: upstream.Weight, Enabled: upstream.Enabled, Protocol: upstream.Protocol})
		}
		enabledUpstreams, err := validateRuleUpstreams(rule.Protocol, false, upstreams, true)
		if err != nil {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：%v", index+1, rule.Name, err))
			continue
		}
		if err := validateRuleHostHeader(rule.HostHeader); err != nil {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：%v", index+1, rule.Name, err))
			continue
		}
		// 导入 INSERT 的 health_check_timeout 恒取 db.DefaultHealthCheckTimeout，
		// 而保存/启用侧的不变式要求超时小于间隔。v1 的 fail_timeout 直接映射为
		// 间隔，过短时该行落库后会在下一次保存/启用被拒（规则变成不可维护的
		// 陷阱行），故按落库超时归一间隔。阈值与文案同源派生自默认超时，
		// 不区分主动/被动（被动熔断窗口同样由间隔派生）。
		if minInterval := db.DefaultHealthCheckTimeout + 1; rule.HealthInt < minInterval {
			rule.HealthInt = minInterval
			normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）：v1 健康检查间隔过短，已提为 %d 秒（须大于健康检查超时 %d 秒）", index+1, rule.Name, minInterval, db.DefaultHealthCheckTimeout))
		}
		// TCP 规则在 v2 渲染侧不终结入站 TLS（buildTCPServer 不触碰 TLS
		// 字段），v1 的 SSL 开关对 TCP 无意义；保留 enable_tls=1 + 空 manual 证书会因
		// UpdateRule 非协议门控的手动证书检查使该规则任何编辑恒 400，且 UI 向导对
		// TCP 隐藏 TLS 开关、无域名 TCP 规则无界面自救路径——导入即归一（与
		// UpdateRule 切换到 TCP 的归一分支同语义，证书材料一并清空）。
		if rule.Protocol == "tcp" && rule.EnableTLS {
			rule.EnableTLS = false
			rule.TLSCert, rule.TLSKey = "", ""
			normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）：TCP 规则不支持入站 TLS，已按关闭 TLS 导入", index+1, rule.Name))
		}
		// v1 SSL 规则导入后 tls_source 恒为 manual（tlsSource()）；启用但
		// 证书/私钥为空的规则会在 TLS 端口明文服务（镜像 rule_features.go 保存/启用侧
		// 口径），按 v1 风格软跳过并警告而非整包拒绝。
		if rule.Enabled && rule.Protocol == "http" && rule.EnableTLS &&
			(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：启用 TLS 但证书或私钥为空，已跳过导入", index+1, rule.Name))
			continue
		}
		// 禁用的空证书 SSL 行此前原样落库（enable_tls=1 + tls_source=
		// 'manual' + 空证书），并随 v2 导出回流；导入时归一为 enable_tls=0（证书
		// 可后续补齐再启用），逐条告警但不计入跳过数。
		if !rule.Enabled && rule.Protocol == "http" && rule.EnableTLS &&
			(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
			rule.EnableTLS = false
			normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）：启用 TLS 但证书或私钥为空，已按关闭 TLS 导入（规则为禁用状态）", index+1, rule.Name))
		}
		// /：strategy 白名单与 80 端口
		// +TLS 跳转自环门自导入循环前移至此——预览/导入共用同门，summary 计数
		// 与实际导入数保持一致；strategy 空值按导入循环同款默认补齐。
		mappedStrategy := rule.Strategy
		if mappedStrategy == "" {
			mappedStrategy = "weighted_round_robin"
		}
		if validateErr := validateRuleFeatures(ruleFeatureInput{
			Protocol: rule.Protocol, Strategy: mappedStrategy,
			ListenPort: rule.ListenPort, EnableTLS: rule.EnableTLS, TLSHTTPRedirect: rule.Redirect,
			HealthCheckInterval: rule.HealthInt, HealthCheckTimeout: db.DefaultHealthCheckTimeout,
			EnabledUpstreamCount: enabledUpstreams, EnableCompress: rule.Compress, CompressTypes: "gzip",
		}); validateErr != nil {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：%v", index+1, rule.Name, validateErr))
			continue
		}
		valid = append(valid, rule)
	}
	return valid, skips, normalizations
}

type importValidateResponse struct {
	Valid             bool                   `json:"valid"`
	Type              string                 `json:"type"`
	Error             string                 `json:"error,omitempty"`
	Summary           map[string]int         `json:"summary,omitempty"`
	Warnings          []string               `json:"warnings,omitempty"`
	DisabledConflicts []disabledRuleConflict `json:"disabled_conflicts"`
	// v2.3.0:备份是否携带规则库数据文件(仅 lbbak 且含 waf 条目)——前端据此
	// 控制「规则库数据库」分类可选性(纯 JSON 备份无文件,选了会造成记录与
	// 文件分叉,用户裁定不可选)。
	HasWafFiles bool `json:"has_waf_files"`
}

// lbbak 解压总字节上限 256MB；压缩上传上限取 128MB（远高于已知 ~15MB 完整包），
// 导出侧同样拒绝超限产物，兼顾大备份往返与导入瞬态内存峰值。
var maxConfigImportBytes int64 = 128 << 20

// configImportLimitMessage 413 文案从 maxConfigImportBytes 派生（单源）：测试
// 收窄限额后文案必须同步，否则「断言照过、文案失真」。
func configImportLimitMessage() string {
	return fmt.Sprintf("备份文件不能超过 %dMB", maxConfigImportBytes>>20)
}

// lbbakPayloadFromCtx 取 validate 流程中解包的 lbbak 载荷(可能为 nil)。
func lbbakPayloadFromCtx(c *gin.Context) *lbbakPayload {
	v, _ := c.Get("lbbak_payload")
	p, _ := v.(*lbbakPayload)
	return p
}

func limitConfigImportBody(c *gin.Context) bool {
	if c.Request.ContentLength > maxConfigImportBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: configImportLimitMessage()})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxConfigImportBytes)
	return true
}

func isRequestBodyTooLarge(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

func (h *Handlers) ValidateConfigImport(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	body, err := c.GetRawData()
	if isRequestBodyTooLarge(err) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: configImportLimitMessage()})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件读取失败: " + err.Error()})
		return
	}
	// BOM 剥离必须先于 lbbak 魔数检测（与导入核心同序）——带 BOM 的
	// lbbak 否则被当作纯 JSON 解析失败；BOM 与 gzip 魔数不冲突。
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	// v2.3.0 lbbak:tar.gz 先解包校验(含逐条目 sha256),内部 config.json
	// 以其原始字节走下方 V2 解析——validate 端点对两种格式统一返回。
	if isLbbakBytes(body) {
		payload, perr := parseLbbak(body)
		if perr != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "lbbak", Error: perr.Error()}})
			return
		}
		body = payload.ConfigJSON
		c.Set("lbbak_payload", payload)
	}
	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件内容为空"})
		return
	}
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	var v2Probe struct {
		Meta struct {
			App string `json:"app"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &v2Probe); err == nil && v2Probe.Meta.App == "lazy-balancer-v2" {
		var backup configBackup
		if err := json.Unmarshal(body, &backup); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: "备份文件格式不正确: " + err.Error()}})
			return
		}
		// 与 ImportConfigBackup 共用 importValidationSteps 单一门序：完整性 →
		// 分类选择/过滤 → 软跳过 → 行级门 → 规则库元数据剔除 → 零导入判据 →
		// 形态/引用/任务/全局配置门。预览不再自行编排子集门，新增校验自然
		// 双路径同序（此前两条路径各写一遍，增删门时静默分叉）。
		chain, chainErr := validateImportBackupChain(c.Request.Context(), importValidationDeps{
			DB:                     db.DB,
			ValidateRuleListenPort: h.validateRuleListenPortForSave,
		}, &backup, importValidationOptions{LbbakPayload: lbbakPayloadFromCtx(c), RequestedSections: c.Query("sections")})
		if chainErr != nil {
			// 受信代理校验内含 DB 读取：服务端故障不回「备份校验失败」（会把
			// 「硬盘 I/O 错误」说成备份内容问题，并透出 SQL 文本）。
			var readErr *trustedProxyReadError
			if errors.As(chainErr, &readErr) {
				writeInternalError(c, http.StatusInternalServerError, errTrustedProxyRead.Error(), readErr.Unwrap())
				return
			}
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: chainErr.Error()}})
			return
		}
		sectionTables := chain.SectionTables
		skipWarnings := chain.SkipWarnings
		disabledConflicts := chain.DisabledConflicts
		crsTreeReplaced := chain.CRSTreeReplaced
		acmeDanglingImported := chain.ACMEDanglingImported
		certJobProviderWarnings := chain.CertJobProviderWarnings
		// 2026-09-18 用户裁定:操作者缺席不再阻断——降级为预览 warning(分类
		// 未选系统数据时操作者不受影响;选了也尊重用户选择)。
		// 同序后 sections 已知——未选系统数据/备份 users 缺席不再误告
		// (与导入侧口径一致)。
		validateWarnings := skipWarnings[:0:0]
		validateWarnings = append(validateWarnings, skipWarnings...)
		if warning := backupProductVersionWarning(backup.Meta, h.cfg.Version); warning != "" {
			validateWarnings = append(validateWarnings, warning)
		}
		// 完全不含校验和的史前 v1 备份：导入照常（结构门全执行），预览必须
		// 明确告知内容未经摘要校验——与导入侧审计警告同文案。
		if chain.NoIntegrityChecksum {
			validateWarnings = append(validateWarnings, warningNoIntegrityChecksum)
		}
		if crsTreeReplaced {
			validateWarnings = append(validateWarnings, warningCRSTreeReplaced)
		}
		if importUsername := c.GetString("username"); importUsername != "" && sectionTables["users"] && len(backup.Tables["users"]) > 0 && !backupContainsUsername(backup.Tables["users"], importUsername) {
			validateWarnings = append(validateWarnings, "备份不包含当前操作账户——若导入时勾选“系统数据”，导入后请使用备份内的管理员账户登录")
		}
		// 反向悬挂降级警告进预览(与导入 responseWarnings 同文案)。
		if acmeDanglingImported > 0 {
			validateWarnings = append(validateWarnings, fmt.Sprintf("导入后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐", acmeDanglingImported))
		}
		// 证书任务级 CA 提供商悬挂/禁用引用的归一警告（与导入同通道）。
		validateWarnings = append(validateWarnings, certJobProviderWarnings...)
		// 链内自动封禁钳制事实（阈值/窗口越界被归一）与上述并列，预览必须
		// 可见——否则预览显示 valid 且无提示，导入后实际生效值已变。
		validateWarnings = append(validateWarnings, chain.AutobanClampNotes...)
		// 全局配置数值归一（整型钳制表 + request_body_max_size_mb）同源可见：
		// 预览与导入共用链内归一点，同一份备份两侧给出同一组文案。
		validateWarnings = append(validateWarnings, chain.ConfigClampNotes...)
		// live 证书任务引用 live CA 提供商的悬挂预检：链内单源产出（按
		// 「已禁用=真失败 / 不存在=回落自愈」分档，规则源按备份是否携带
		// lb_rules 二选一），预览与导入对同一备份给出同一组文案。
		validateWarnings = append(validateWarnings, chain.CertJobDanglingWarnings...)
		hasWaf := false
		if payload := lbbakPayloadFromCtx(c); payload != nil {
			// 威胁库名单条目也是规则库数据文件
			// ——RDB 文件化后存在「仅威胁 .iplist、无 CRS/xdb」的合法 lbbak
			// （只启用威胁库更新的节点）。此前 hasWaf 只认 CRS/xdb，预览据此
			// 提示「不含规则库文件」而实际会落盘名单文件（文案与真实能力不符）。
			hasWaf = payload.CRSTarGz != nil || payload.Xdb != nil || len(payload.ThreatIplists) > 0
			if hasWaf {
				if payload.CRSTarGz != nil || payload.Xdb != nil {
					validateWarnings = append(validateWarnings, "lbbak 完整备份（含规则库数据文件，完整性已校验）——规则库数据库分类将随导入落盘")
				} else {
					validateWarnings = append(validateWarnings, "lbbak 含威胁库名单文件（完整性已校验）——导入「安全防护」将落盘名单文件；本包不含 CRS/IP2Region 数据文件")
				}
			}
			// manifest 未登记的威胁库条目——预览/导入
			// 同文案告警（不拒绝，老备份兼容）。
			if len(payload.UnregisteredThreatEntries) > 0 {
				warning := fmt.Sprintf("lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验，已按原样落盘；建议核实来源后重新导出备份", strings.Join(payload.UnregisteredThreatEntries, "、"))
				if !sectionTables["security_crs_version"] {
					warning = fmt.Sprintf("lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验；本次分类未选择安全防护数据，条目未导入、未落盘", strings.Join(payload.UnregisteredThreatEntries, "、"))
				}
				validateWarnings = append(validateWarnings, warning)
			}
		}
		// 版本表随文件缺失的剔除及其零导入判据已在链内按导入同序完成
		// （行级校验 → 版本表剔除 → 剔除后判据），此处只把同一事实呈现为
		// 响应 warning，文案与导入侧共用常量。
		if chain.WAFMetadataSkipped {
			validateWarnings = append(validateWarnings, warningWafMetadataSkipped)
		}
		if chain.WAFCRSMetadataSkipped {
			validateWarnings = append(validateWarnings, warningWafCRSMetadataSkipped)
		}
		if chain.WAFXdbMetadataSkipped {
			validateWarnings = append(validateWarnings, warningWafXdbMetadataSkipped)
		}
		summary := map[string]int{}
		for table, rows := range backup.Tables {
			summary[table] = len(rows)
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: true, Type: "v2", Summary: summary, Warnings: validateWarnings, DisabledConflicts: disabledConflicts, HasWafFiles: hasWaf}})
		return
	}
	var v1 v1Backup
	if err := json.Unmarshal(body, &v1); err == nil && v1.ProxyConfig != nil && v1.UpstreamConfig != nil {
		proxies, upstreams, err := v1.parse()
		if err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v1", Error: err.Error()}})
			return
		}
		rules, conversionWarnings := convertV1Rules(proxies, upstreams)
		validRules, validationSkips, normalizations := validateConvertedV1Rules(rules, h.validateRuleListenPortForSave)
		allWarnings := append(conversionWarnings, validationSkips...)
		allWarnings = append(allWarnings, normalizations...)
		// 证书质量警告与导入路径同源（预览阶段无 caddy_id，前缀只带规则名）。
		for _, r := range validRules {
			allWarnings = append(allWarnings, v1CertificateWarnings(r, "")...)
		}
		if len(validRules) == 0 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v1", Error: "所有规则均校验失败", Warnings: allWarnings}})
			return
		}
		disabledConflicts := disableConvertedRuleConflicts(validRules)
		tlsCount := 0
		upstreamCount := 0
		for _, r := range validRules {
			if r.EnableTLS {
				tlsCount++
			}
			upstreamCount += len(r.Upstreams)
		}
		warnings := []string{
			"仅导入负载规则（用户、全局配置不导入；旧规则的证书任务、证书材料与日志将随规则替换一并清理）",
			"v1 不支持 ACME，HTTPS 规则的证书与私钥将以手动方式随规则导入",
			"nginx 特有配置（custom_config、日志路径等）已忽略",
		}
		warnings = append(warnings, allWarnings...)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{
			Valid: true,
			Type:  "v1",
			Summary: map[string]int{
				"rules":     len(validRules),
				"tls_rules": tlsCount,
				"upstreams": upstreamCount,
			},
			Warnings:          warnings,
			DisabledConflicts: disabledConflicts,
		}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Error: "无法识别的备份文件格式（既不是 V2 备份，也不是 V1 备份）"}})
}

func (h *Handlers) ImportV1Config(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	body, err := c.GetRawData()
	if isRequestBodyTooLarge(err) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: configImportLimitMessage()})
		return
	}
	if err != nil {
		failImportValidation(c, "导入", "备份文件读取失败: "+err.Error())
		return
	}
	// BOM 剥离先于魔数检测——与 validate/v2 两路径同序。
	// 此前 BOM+lbbak 请求绕过 lbbak 指引、落入「不是有效的 JSON」，提示失真
	// （安全面本就拒绝，仅语义质量）。BOM 与 gzip 魔数不冲突。
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	// lbbak(tar.gz)是 V2 形态:提前给出正确端点指引,避免落入 JSON 解析
	// 「不是有效的 JSON」困惑(安全面本就必拒,仅提示质量)。
	if isLbbakBytes(body) {
		failImportValidation(c, "导入", "V1 导入仅支持旧版 JSON 备份；lbbak 备份请使用 /api/v1/config/import")
		return
	}
	if len(body) == 0 {
		failImportValidation(c, "导入", "备份文件内容为空")
		return
	}
	var v1 v1Backup
	if err := json.Unmarshal(body, &v1); err != nil {
		failImportValidation(c, "导入", "备份文件不是有效的 JSON")
		return
	}
	proxies, upstreams, err := v1.parse()
	if err != nil {
		failImportValidation(c, "导入", err.Error())
		return
	}
	rules, conversionWarnings := convertV1Rules(proxies, upstreams)
	validRules, validationSkips, normalizations := validateConvertedV1Rules(rules, h.validateRuleListenPortForSave)
	var allWarnings []string
	allWarnings = append(allWarnings, conversionWarnings...)
	allWarnings = append(allWarnings, validationSkips...)
	allWarnings = append(allWarnings, normalizations...)
	if len(validRules) == 0 {
		failImportValidation(c, "导入", "备份中没有可导入的有效规则")
		return
	}
	disabledConflicts := disableConvertedRuleConflicts(validRules)
	ctx := c.Request.Context()
	session, err := h.beginConfigImport(ctx, "导入")
	if err != nil {
		respondImportBeginError(c, err)
		return
	}
	defer session.close()
	// v1 全量导入替换规则面：允许导入后清理消失规则产物。
	session.replaceRuleArtifacts = true
	tx := session.tx
	restoreImportNodeRole, err := suppressImportClusterVersionBumps(ctx, tx)
	if err != nil {
		err = failImportTx(c, session, "导入", "准备导入事务", err, http.StatusInternalServerError, "准备导入事务失败")
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM path_rules"); err != nil {
		err = failImportTx(c, session, "导入", "清理旧路径规则", err, http.StatusInternalServerError, "清理旧路径规则失败")
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM upstreams"); err != nil {
		err = failImportTx(c, session, "导入", "清理旧上游", err, http.StatusInternalServerError, "清理旧上游失败")
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM lb_rules"); err != nil {
		err = failImportTx(c, session, "导入", "清理旧规则", err, http.StatusInternalServerError, "清理旧规则失败")
		return
	}
	// v1 导入覆盖 lb_rules 后须同步清空 security_policy_bindings——
	// 绑定表对 rule_caddy_id 无外键级联，残留行会指向已删除规则成为悬挂绑定。
	// v1 无策略概念：此处清空全表且不回写、不告警——normalizeRuleRowsForTransport
	// 的 droppedTCPBindings 在 v1 恒为 0（表已空），因此 v1 路径不复用 v2 的
	// 「已解除 N 条 TCP 绑定」文案。
	if _, err := tx.ExecContext(ctx, "DELETE FROM security_policy_bindings"); err != nil {
		err = failImportTx(c, session, "导入", "清理旧策略绑定", err, http.StatusInternalServerError, "清理旧策略绑定失败")
		return
	}
	userID := int(contextUserID(c))
	imported := 0
	tlsCount := 0
	upstreamCount := 0
	affectedRuleIDs := append([]string(nil), session.existingRuleIDs...)
	var pendingCerts []importCertificate
	for _, r := range validRules {
		caddyID, err := services.GenerateCaddyID()
		if err != nil {
			err = failImportAbort(c, session, "导入", "生成规则编号", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则编号失败: " + err.Error()})
			return
		}
		affectedRuleIDs = append(affectedRuleIDs, caddyID)
		_, err = tx.ExecContext(ctx, `INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			host_header, enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_by, updated_at, caddy_id, log_enabled)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, '', '', ?, ?, ?, ?, ?, 0, 0, ?, 0, 0, 0, ?, ?, ?, 0, 0, ?, ?, ?, ?, 'gzip', ?, ?, ?, datetime('now'), ?, 0)`,
			r.Name, r.Description, r.Protocol, r.Domain, r.ListenPort, r.Strategy,
			r.HealthInt, db.DefaultHealthCheckTimeout, r.HealthFails, db.DefaultHealthCheckHealthyThreshold, r.ActiveHC, db.DefaultTCPTryInterval,
			r.HostHeader, r.EnableTLS, tlsSource(r), r.TLSCert, r.TLSKey, r.Redirect,
			r.Compress, r.Enabled, userID, userID, caddyID)
		if err != nil {
			err = failImportTx(c, session, "导入", "规则 "+r.Name, err, http.StatusInternalServerError, "导入规则失败")
			return
		}
		for _, u := range r.Upstreams {
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
				VALUES (?, ?, ?, ?, 0, ?, ?, 0)`, caddyID, u.Host, u.Port, u.Weight, u.Enabled, u.Protocol); err != nil {
				err = failImportTx(c, session, "导入", "规则 "+r.Name+" 上游", err, http.StatusInternalServerError, "导入上游失败")
				return
			}
			upstreamCount++
		}
		if r.EnableTLS && r.TLSCert != "" && r.TLSKey != "" {
			pendingCerts = append(pendingCerts, importCertificate{ruleID: caddyID, certPEM: r.TLSCert, keyPEM: r.TLSKey})
		}
		// 证书质量警告与规则保存/v2 导入同源（导入响应与「导入」审计都带出）。
		allWarnings = append(allWarnings, v1CertificateWarnings(r, caddyID)...)
		if r.EnableTLS {
			tlsCount++
		}
		imported++
	}
	// v1 导入此前是规则归一四面（导出/从端落库/v2 备份
	// 导入/此处）中唯一事务内零归一的写路径——转换器对 BackendDomain/Gzip 无
	// 协议门，TCP 行可携带 host_header/enable_compress/compress_types 死值落库。
	// INSERT 后统一调与 v2 备份导入共享的 normalizeRuleRowsForTransport（单一
	// 事实源）。其 droppedTCPBindings 在 v1 恒为 0（绑定表已在上方清空），
	// 故 v1 不消费返回值、也不复用 v2 的告警文案。
	if _, err := normalizeRuleRowsForTransport(ctx, tx); err != nil {
		err = failImportTx(c, session, "导入", "", err, http.StatusInternalServerError, "导入规则归一失败")
		return
	}
	if err := restoreImportNodeRole(); err != nil {
		err = failImportTx(c, session, "导入", "", err, http.StatusInternalServerError, "恢复导入前节点角色失败")
		return
	}
	if err := session.commit(affectedRuleIDs, pendingCerts); err != nil {
		// 队列阶段=DB 已提交，与 v2 同语义返回 200+partial（500 会让前端
		// 按“已回滚”处理并诱发重复导入）。
		if importFailurePhase(err) == importPhaseQueue {
			// 与 v2 尾部（config_backup.go queue
			// 分支后继续提交后收敛）对齐——此前提前返回丢失全部转换/跳过/
			// 归一化警告、不写「重载」审计、不清陈旧 caddy_apply_error 横幅。
			// detail 走单源：审计 action 已带「部分失败」，detail 不再重复动作词。
			auditDetail := importFailureAuditDetail(err)
			if len(disabledConflicts) > 0 {
				auditDetail = services.FormatAuditDetail(auditDetail, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
			}
			recordAudit(c, "部分失败", "配置备份", auditDetail)
			recordAudit(c, "重载", "Caddy服务", "导入配置后自动重载")
			h.recordCaddyApplyResult(nil)
			// 提交已落地：imported 是真实已提交条数（回滚路径相反，不报条数）。
			// message/warnings 只带阶段说明与真实原因（不重复动作词）。
			partialWarnings := append(append([]string{}, allWarnings...), "数据库已提交，但证书任务恢复失败: "+importFailureCause(err))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置已导入，但证书任务恢复失败: " + importFailureCause(err), Data: gin.H{
				"imported": imported, "disabled_conflicts": disabledConflicts,
				"partial": true, "warnings": partialWarnings,
			}})
			return
		}
		// message 正文与审计 detail 同源（阶段描述+真实错误）：err.Error() 自带
		// 「导入失败」动作前缀，再拼「配置导入失败:」会双前缀。
		status := http.StatusInternalServerError
		message := "配置导入失败: " + importFailureAuditDetail(err)
		if importFailureCaddyRejected(err) {
			status = http.StatusBadRequest
			message = "备份生成的配置未通过 Caddy 验证，未执行导入: " + importFailureAuditDetail(err)
		}
		recordAudit(c, "导入失败", "配置备份", importFailureAuditDetail(err))
		// 事务已回滚：循环里的插入计数全部作废，不得报 imported（否则前端/
		// 运维会误判部分规则已落地）。warnings 透出会话收尾披露（提交不确定态
		// 下的产物清理去向），否则「删除失败」被读成「磁盘也已收敛」。
		failureWarnings := append([]string{}, session.failureWarnings...)
		c.JSON(status, models.APIResponse{Code: status, Message: message, Data: gin.H{
			"disabled_conflicts": disabledConflicts, "warnings": failureWarnings,
		}})
		return
	}
	auditParts := []string{"来源：v1 备份（覆盖导入规则）", fmt.Sprintf("规则 %d 条", imported), fmt.Sprintf("TLS 规则 %d 条", tlsCount), fmt.Sprintf("上游 %d 个", upstreamCount)}
	if len(disabledConflicts) > 0 {
		auditParts = append(auditParts, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
	}
	if len(allWarnings) > 0 {
		auditParts = append(auditParts, "转换/跳过警告："+strings.Join(allWarnings, "；"))
	}
	auditParts = append(auditParts, services.AuditResultPart("success"))
	recordAudit(c, "导入", "配置备份", services.FormatAuditDetail(auditParts...))
	recordAudit(c, "重载", "Caddy服务", "导入配置后自动重载")
	// 2026-09-07：导入成功后清除陈旧 caddy_apply_error（对齐口径）。
	h.recordCaddyApplyResult(nil)
	tlsSuffix := ""
	if tlsCount > 0 {
		tlsSuffix = fmt.Sprintf("、TLS 规则 %d 条", tlsCount)
	}
	skipSuffix := ""
	if len(validationSkips) > 0 {
		skipSuffix = fmt.Sprintf("、跳过 %d 条", len(validationSkips))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: fmt.Sprintf("配置导入成功：规则 %d 条、上游 %d 个%s%s", imported, upstreamCount, tlsSuffix, skipSuffix), Data: gin.H{"imported": imported, "disabled_conflicts": disabledConflicts, "warnings": allWarnings}})
}

func tlsSource(r convertedRule) string {
	if r.EnableTLS {
		return "manual"
	}
	return ""
}

// v1CertificateWarnings 返回一条 v1 转化规则的手动证书质量警告（前缀与 v2
// 备份导入同源）：规则保存与 v2 导入都会对手动证书做「域名不匹配/过期/未生效/
// 链不完整」提示，v1 导入此前零判定——错域名或过期证书静默导入，上线后只在
// 浏览器层面暴露。caddyID 为空（预览阶段尚未生成编号）时前缀只带规则名。
func v1CertificateWarnings(r convertedRule, caddyID string) []string {
	if !r.EnableTLS || r.TLSCert == "" || r.TLSKey == "" {
		return nil
	}
	prefix := "规则 " + r.Name
	if caddyID != "" {
		prefix += "（" + caddyID + "）"
	}
	var out []string
	for _, warning := range tlsCertificateWarnings(r.TLSCert, r.TLSKey, r.Domain) {
		out = append(out, prefix+"："+warning)
	}
	return out
}
