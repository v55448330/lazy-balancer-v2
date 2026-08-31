package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type v1Backup struct {
	UserList       *v1Section `json:"user_list"`
	MainConfig     *v1Section `json:"main_config"`
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

// Round 30 F-9: v1（disableConvertedRuleConflicts）与 v2（disableV2RuleConflicts）
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
	for leftIndex, left := range candidates {
		for rightIndex := leftIndex + 1; rightIndex < len(candidates); rightIndex++ {
			right := candidates[rightIndex]
			reason := ""
			switch {
			case left.protocol == "http" && right.protocol == "http" && left.listenPort == right.listenPort:
				// Round 31 C-1: 禁用规则无运行时占用——与禁用行的「同端口同域名」不构成
				// 真实冲突，不得把启用中的一方静默置禁用（与跨端口分支同口径门控）。
				// R30 F1 放行禁用自环行后该组合首次可达此分支。
				if left.enabled && right.enabled {
					leftDomains := make(map[string]struct{})
					for _, domain := range normalizedRuleDomains(left.domain) {
						leftDomains[domain] = struct{}{}
					}
					for _, domain := range normalizedRuleDomains(right.domain) {
						if _, exists := leftDomains[domain]; exists {
							reason = fmt.Sprintf("HTTP 域名 %s 重复", domain)
							break
						}
					}
				}
			case left.protocol == "http" && right.protocol == "http" && left.listenPort != right.listenPort:
				// Round 29 G-1: 跨端口跳转遮蔽方向——TLS+跳转规则在 80 端口服务器头部
				// 生成 terminal 301（caddy.go redirectRoutes），同域名直接监听 80 的规则
				// 会被静默遮蔽为死规则。仅双方均启用时判定，按矩阵惯例冲突双方置禁用。
				if left.enabled && right.enabled {
					if left.listenPort == 80 && right.enableTLS && right.tlsHTTPRedirect {
						reason = httpRedirectShadowReason(left.domain, right.domain)
					} else if right.listenPort == 80 && left.enableTLS && left.tlsHTTPRedirect {
						reason = httpRedirectShadowReason(right.domain, left.domain)
					}
				}
			case left.listenPort != right.listenPort:
				continue
			case left.protocol == "tcp" && right.protocol == "tcp":
				// Round 32 F-2: 与 HTTP 同端口分支（Round 31 C-1）同口径门控——
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
			if reason != "" {
				reasons[leftIndex] = append(reasons[leftIndex], reason)
				reasons[rightIndex] = append(reasons[rightIndex], reason)
				opponents[leftIndex] = append(opponents[leftIndex], ruleConflictOpponent{Name: right.name, CaddyID: right.caddyID, Reason: reason})
				opponents[rightIndex] = append(opponents[rightIndex], ruleConflictOpponent{Name: left.name, CaddyID: left.caddyID, Reason: reason})
			}
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

// httpRedirectShadowReason 判定 80 端口规则域名是否被 TLS+跳转规则域名遮蔽，
// 命中返回遮蔽原因，未命中返回空串。
func httpRedirectShadowReason(port80Domain, redirectDomain string) string {
	leftDomains := make(map[string]struct{})
	for _, domain := range normalizedRuleDomains(port80Domain) {
		leftDomains[domain] = struct{}{}
	}
	for _, domain := range normalizedRuleDomains(redirectDomain) {
		if _, exists := leftDomains[domain]; exists {
			return fmt.Sprintf("HTTP 域名 %s 被 HTTPS 跳转遮蔽", domain)
		}
	}
	return ""
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
			rule.HealthFails = 3
		}
		if rule.HealthInt <= 0 {
			rule.HealthInt = 10
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

func validateConvertedV1Rules(rules []convertedRule) ([]convertedRule, []string, []string) {
	var valid []convertedRule
	var skips []string
	var normalizations []string
	for index, rule := range rules {
		if err := validateRuleListenPort(rule.Protocol, rule.ListenPort); err != nil {
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
		enabledUpstreams := 0
		upstreamBad := false
		for upstreamIndex, upstream := range rule.Upstreams {
			if !isValidHost(upstream.Host) {
				skips = append(skips, fmt.Sprintf("规则 #%d（%s）上游 #%d：主机无效", index+1, rule.Name, upstreamIndex+1))
				upstreamBad = true
				break
			}
			if upstream.Port < 1 || upstream.Port > 65535 {
				skips = append(skips, fmt.Sprintf("规则 #%d（%s）上游 #%d：端口必须在 1-65535 之间", index+1, rule.Name, upstreamIndex+1))
				upstreamBad = true
				break
			}
			// R70 C-2/R71 S-1：上游协议白名单 + http 规则归一化——值域与保存侧/渲染侧
			// 一致；口径经 R71 S-1 统一：HTTP 规则下 tcp/tls 上游归一（tcp 渲染等同
			// http 明文转发；tls 归一 https 即 TLS transport，封堵「明文 HTTP 打 TLS
			// 端口静默 502」形态——v2 导入/保存侧均拒绝、v1 此前是唯一入口）。TCP
			// 规则下 http 为 v1 原生（nginx stream 明文）语义、https 渲染按 TLS 处理
			//（=tls），均保留。归一记入 normalizations 供导入报告呈现。
			switch upstream.Protocol {
			case "http", "https", "tcp", "tls":
				if rule.Protocol == "http" && (upstream.Protocol == "tcp" || upstream.Protocol == "tls") {
					normalized := "http"
					if upstream.Protocol == "tls" {
						normalized = "https"
					}
					normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）上游 #%d：HTTP 规则上游协议 %s 已按 %s 导入", index+1, rule.Name, upstreamIndex+1, upstream.Protocol, normalized))
					upstream.Protocol = normalized
					rule.Upstreams[upstreamIndex].Protocol = normalized
				}
			default:
				skips = append(skips, fmt.Sprintf("规则 #%d（%s）上游 #%d：上游协议 %q 无效（支持 http/https/tcp/tls）", index+1, rule.Name, upstreamIndex+1, upstream.Protocol))
				upstreamBad = true
			}
			if upstreamBad {
				break
			}
			if upstream.Enabled {
				enabledUpstreams++
			}
		}
		if upstreamBad {
			continue
		}
		if enabledUpstreams == 0 {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：至少需要一个已启用的上游服务器", index+1, rule.Name))
			continue
		}
		// R62 C3-F3: 导入 INSERT 的探测超时硬编码 5s，Round 37 I-6 的
		// timeout<interval 不变量（保存侧门控）在导入链未生效——fail_timeout ≤ 5 的
		// v1 规则会让活动检查单次耗时与间隔重叠。钳位 interval ≥ 6（语义近似保留，
		// 仅活动检查启用时生效；被动检查的 fail_duration=interval*3 不受超时约束）。
		if rule.ActiveHC && rule.HealthInt <= 5 {
			rule.HealthInt = 6
			normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）：v1 健康检查间隔过短，已提为 6 秒（探测超时 5 秒须小于间隔）", index+1, rule.Name))
		}
		// R62 C2-N1: TCP 规则在 v2 渲染侧不终结入站 TLS（buildTCPServer 不触碰 TLS
		// 字段），v1 的 SSL 开关对 TCP 无意义；保留 enable_tls=1 + 空 manual 证书会因
		// UpdateRule 非协议门控的手动证书检查使该规则任何编辑恒 400，且 UI 向导对
		// TCP 隐藏 TLS 开关、无域名 TCP 规则无界面自救路径——导入即归一（与
		// UpdateRule 切换到 TCP 的归一分支同语义，证书材料一并清空）。
		if rule.Protocol == "tcp" && rule.EnableTLS {
			rule.EnableTLS = false
			rule.TLSCert, rule.TLSKey = "", ""
			normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）：TCP 规则不支持入站 TLS，已按关闭 TLS 导入", index+1, rule.Name))
		}
		// R43 F-C: v1 SSL 规则导入后 tls_source 恒为 manual（tlsSource()）；启用但
		// 证书/私钥为空的规则会在 TLS 端口明文服务（镜像 rule_features.go 保存/启用侧
		// 口径），按 v1 风格软跳过并警告而非整包拒绝。
		if rule.Enabled && rule.Protocol == "http" && rule.EnableTLS &&
			(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
			skips = append(skips, fmt.Sprintf("规则 #%d（%s）：启用 TLS 但证书或私钥为空，已跳过导入", index+1, rule.Name))
			continue
		}
		// R46 C-B-1: 禁用的空证书 SSL 行此前原样落库（enable_tls=1 + tls_source=
		// 'manual' + 空证书），并随 v2 导出回流；导入时归一为 enable_tls=0（证书
		// 可后续补齐再启用），逐条告警但不计入跳过数。
		if !rule.Enabled && rule.Protocol == "http" && rule.EnableTLS &&
			(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
			rule.EnableTLS = false
			normalizations = append(normalizations, fmt.Sprintf("规则 #%d（%s）：启用 TLS 但证书或私钥为空，已按关闭 TLS 导入（规则为禁用状态）", index+1, rule.Name))
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
}

const maxConfigImportBytes int64 = 16 << 20

func limitConfigImportBody(c *gin.Context) bool {
	if c.Request.ContentLength > maxConfigImportBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
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
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	body, err := c.GetRawData()
	if isRequestBodyTooLarge(err) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
		return
	}
	if err != nil || len(body) == 0 {
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
		if _, err := validateV2Backup(backup); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		skipWarnings := skipEmptyDomainHTTPRules(backup.Tables)
		// N+13 H2-F3：与 ImportConfigBackup 同序——空内容拦截页软跳过也须
		// 进预览，否则预览静默、导入才跳（summary/warnings 口径一致）。
		skipWarnings = append(skipWarnings, skipEmptyBlockPages(backup.Tables)...)
		// R39 C-3: 与 ImportConfigBackup 同序——skip 之后、逐行校验之前校验
		// upstreams/path_rules 引用存在性，预览结果与实际导入一致（否则悬挂引用
		// 备份在预览显示可导入、实际导入才 400）。
		if err := validateBackupRuleReferences(backup.Tables); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		if err := validateV2BackupRules(backup.Tables); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		// 与 ImportConfigBackup 同序：安全策略 CRS 字段校验也须进预览，否则坏
		// 组号备份在预览显示可导入、实际导入才 400（R47 B-5）。
		if err := validateV2BackupSecurityPolicies(backup.Tables); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		disabledConflicts := disableV2RuleConflicts(backup.Tables["lb_rules"])
		// R55 C-1：与 ImportConfigBackup 同序——TLS 形态校验在冲突置禁用之后
		// 执行，预览结果与实际导入一致（冲突可自愈备份不得在预览误报不可导入）。
		if err := validateV2BackupTLSShape(backup.Tables); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		// R54 新发现2：与 ImportConfigBackup 同序——任务不变量在冲突置禁用之后
		// 执行，预览结果与实际导入一致（冲突可自愈备份不得在预览误报不可导入）。
		if err := validateV2BackupCertJobs(backup.Tables); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		// R55 C-4：与 ImportConfigBackup 同序——坏 admin_tls_* 形态预览即报
		// 不可导入，不得预览通过、导入才 400。
		if err := validateV2BackupAdminTLS(backup.Config); err != nil {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: false, Type: "v2", Error: err.Error()}})
			return
		}
		summary := map[string]int{}
		for table, rows := range backup.Tables {
			summary[table] = len(rows)
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: importValidateResponse{Valid: true, Type: "v2", Summary: summary, Warnings: skipWarnings, DisabledConflicts: disabledConflicts}})
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
		validRules, validationSkips, normalizations := validateConvertedV1Rules(rules)
		allWarnings := append(conversionWarnings, validationSkips...)
		allWarnings = append(allWarnings, normalizations...)
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
			"仅导入负载规则（用户、全局配置不导入，证书任务保持不变）",
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
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持导入配置"})
		return
	}
	if !limitConfigImportBody(c) {
		return
	}
	body, err := c.GetRawData()
	if isRequestBodyTooLarge(err) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "备份文件不能超过 16MB"})
		return
	}
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件内容为空"})
		return
	}
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	var v1 v1Backup
	if err := json.Unmarshal(body, &v1); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件不是有效的 JSON"})
		return
	}
	proxies, upstreams, err := v1.parse()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	rules, conversionWarnings := convertV1Rules(proxies, upstreams)
	validRules, validationSkips, normalizations := validateConvertedV1Rules(rules)
	var allWarnings []string
	allWarnings = append(allWarnings, conversionWarnings...)
	allWarnings = append(allWarnings, validationSkips...)
	allWarnings = append(allWarnings, normalizations...)
	if len(validRules) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份中没有可导入的有效规则"})
		return
	}
	disabledConflicts := disableConvertedRuleConflicts(validRules)
	ctx := c.Request.Context()
	session, err := h.beginConfigImport(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer session.close()
	tx := session.tx
	if _, err := tx.ExecContext(ctx, "DELETE FROM path_rules"); err != nil {
		err = session.abort(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧路径规则失败，已回滚: " + err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM upstreams"); err != nil {
		err = session.abort(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧上游失败，已回滚: " + err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM lb_rules"); err != nil {
		err = session.abort(err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧规则失败，已回滚: " + err.Error()})
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
			err = session.abort(err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则编号失败: " + err.Error()})
			return
		}
		affectedRuleIDs = append(affectedRuleIDs, caddyID)
		// Round 38 B4: v1 导入规则也需通过 strategy 白名单校验。
		mappedStrategy := r.Strategy
		if mappedStrategy == "" {
			mappedStrategy = "weighted_round_robin"
		}
		// Round 29 G-1: 补传端口/TLS/跳转字段，v1 转换后同样拦截 80 端口 + TLS 跳转自环规则。
		if validateErr := validateRuleFeatures(ruleFeatureInput{
			Protocol: r.Protocol, Strategy: mappedStrategy,
			ListenPort: r.ListenPort, EnableTLS: r.EnableTLS, TLSHTTPRedirect: r.Redirect,
			CompressTypes: "gzip",
		}); validateErr != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("规则 %s 跳过：%s", r.Name, validateErr.Error()))
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			host_header, enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_by, updated_at, caddy_id, log_enabled)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, '', '', ?, 5, ?, 2, ?, 0, 0, 250, 0, 0, 0, ?, ?, ?, 0, 0, ?, ?, ?, ?, 'gzip', ?, ?, ?, datetime('now'), ?, 0)`,
			r.Name, r.Description, r.Protocol, r.Domain, r.ListenPort, r.Strategy,
			r.HealthInt, r.HealthFails, r.ActiveHC,
			r.HostHeader, r.EnableTLS, tlsSource(r), r.TLSCert, r.TLSKey, r.Redirect,
			r.Compress, r.Enabled, userID, userID, caddyID)
		if err != nil {
			err = session.abort(err)
			recordAudit(c, "导入失败", "配置备份", fmt.Sprintf("规则 %s: %v", r.Name, err))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入规则失败，已回滚: " + err.Error()})
			return
		}
		for _, u := range r.Upstreams {
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections)
				VALUES (?, ?, ?, ?, 0, ?, ?, 0)`, caddyID, u.Host, u.Port, u.Weight, u.Enabled, u.Protocol); err != nil {
				err = session.abort(err)
				recordAudit(c, "导入失败", "配置备份", fmt.Sprintf("规则 %s 上游: %v", r.Name, err))
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "导入上游失败，已回滚: " + err.Error()})
				return
			}
			upstreamCount++
		}
		if r.EnableTLS && r.TLSCert != "" && r.TLSKey != "" {
			pendingCerts = append(pendingCerts, importCertificate{ruleID: caddyID, certPEM: r.TLSCert, keyPEM: r.TLSKey})
		}
		if r.EnableTLS {
			tlsCount++
		}
		imported++
	}
	if err := session.commit(affectedRuleIDs, pendingCerts); err != nil {
		status := http.StatusInternalServerError
		message := "配置导入失败: " + err.Error()
		if importFailurePhase(err) == importPhaseCaddy {
			status = http.StatusBadRequest
			message = "备份生成的配置未通过 Caddy 验证，未执行导入: " + err.Error()
		}
		if importFailurePhase(err) == importPhaseQueue {
			message = "配置已导入但证书任务恢复失败: " + err.Error()
		}
		auditAction := "导入失败"
		if importFailurePhase(err) == importPhaseQueue {
			auditAction = "部分失败"
		}
		auditDetail := err.Error()
		if importFailurePhase(err) == importPhaseQueue && len(disabledConflicts) > 0 {
			auditDetail = services.FormatAuditDetail(auditDetail, "冲突置为禁用："+formatDisabledRuleConflicts(disabledConflicts))
		}
		recordAudit(c, auditAction, "配置备份", auditDetail)
		c.JSON(status, models.APIResponse{Code: status, Message: message, Data: gin.H{"imported": imported, "disabled_conflicts": disabledConflicts}})
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
