package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

const compensationTimeout = 10 * time.Second
const minimumPasswordLength = 6

type Handlers struct {
	cfg               *config.Config
	caddyService      *services.CaddyService
	metricsService    *services.MetricsService
	syncService       *services.SyncService
	clusterService    *services.ClusterService
	caProviderService *services.CAProviderService
	removeCertFiles   func(string) error
	caddyOpMu         sync.Mutex
}

type Dependencies struct {
	Config            *config.Config
	CaddyService      *services.CaddyService
	MetricsService    *services.MetricsService
	SyncService       *services.SyncService
	ClusterService    *services.ClusterService
	CAProviderService *services.CAProviderService
}

func (h *Handlers) removeRuleCertFiles(ruleID string) error {
	if h.removeCertFiles != nil {
		return h.removeCertFiles(ruleID)
	}
	return services.RemoveCertFiles(ruleID)
}

func NewHandlers(deps Dependencies) *Handlers {
	return &Handlers{
		cfg:               deps.Config,
		caddyService:      deps.CaddyService,
		metricsService:    deps.MetricsService,
		syncService:       deps.SyncService,
		clusterService:    deps.ClusterService,
		caProviderService: deps.CAProviderService,
	}
}

func compensationContext(requestCtx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(requestCtx), compensationTimeout)
}

func passwordTooShort(password string) bool {
	return password != "" && utf8.RuneCountInString(password) < minimumPasswordLength
}

type EnableCertJobAction int

const (
	EnableCertJobCreate EnableCertJobAction = iota
	EnableCertJobKeep
	EnableCertJobResume
	EnableCertJobRetry
	EnableCertJobRenew
	EnableCertJobInProgress
)

func ShouldRenewIssuedCert(now, expiresAt time.Time, renewalDays int) bool {
	renewalTime := expiresAt.AddDate(0, 0, -renewalDays)
	return !now.Before(renewalTime)
}

func ResolveEnableCertJobAction(hasJob bool, status string, expiresAt *time.Time, now time.Time, renewalDays int) EnableCertJobAction {
	if !hasJob {
		return EnableCertJobCreate
	}
	if (status == "issued" || status == "disabled" || status == "failed") && expiresAt != nil {
		if !ShouldRenewIssuedCert(now, *expiresAt, renewalDays) {
			if status == "issued" {
				return EnableCertJobKeep
			}
			return EnableCertJobResume
		}
		if status == "issued" {
			return EnableCertJobRenew
		}
		return EnableCertJobRetry
	}
	if status == "failed" || status == "disabled" {
		return EnableCertJobRetry
	}
	return EnableCertJobInProgress
}

func boolText(value bool) string {
	if value {
		return "启用"
	}
	return "禁用"
}

// recordCaddyApplyResult persists the last apply outcome and leaves an audit
// trail. Failures keep the previous Caddy config running, so the error must
// survive restarts and async paths to stay visible to operators.
func (h *Handlers) recordCaddyApplyResult(err error) {
	if err == nil {
		if db.DB != nil {
			db.DB.Exec(`UPDATE global_config SET caddy_apply_error='' WHERE id=1 AND caddy_apply_error<>''`)
		}
		return
	}
	wrapped := fmt.Sprintf("Caddy 配置应用失败（旧配置已保留）：%v", err)
	services.Logf("error", "%s", wrapped)
	services.RecordAuditLog("system", "应用失败", "Caddy配置", wrapped, "")
	if db.DB != nil {
		db.DB.Exec(`UPDATE global_config SET caddy_apply_error=? WHERE id=1`, wrapped)
	}
}

// caddyApplyNote returns a response-message suffix describing an apply
// failure; empty string means the config applied cleanly. Callers inside an
// import session (which already holds caddyOpMu) must use
// caddyApplyNoteLocked instead — applyCaddyConfigE is not reentrant.
// caddyApplyNote 重载 Caddy 配置并统一记录重载审计。所有触发重载的
// handler 必须使用此方法（或 caddyApplyNoteLocked），重载审计自动留痕
// ——调用方不可能遗漏。
func (h *Handlers) caddyApplyNote(c *gin.Context) string {
	if err := h.applyCaddyConfigE(); err != nil {
		recordAudit(c, "重载失败", "Caddy服务", err.Error())
		return "；但 Caddy 配置应用失败：" + err.Error()
	}
	recordAudit(c, "重载", "Caddy服务", "配置变更后自动重载")
	return ""
}

func (h *Handlers) caddyApplyNoteLocked() string {
	err := h.caddyService.GenerateAndApplyConfig()
	h.recordCaddyApplyResult(err)
	if err != nil {
		return "；但 Caddy 配置应用失败：" + err.Error()
	}
	return ""
}

// applyCaddyConfigE serializes against rule/config writes (caddyOpMu) and
// persists the apply outcome; all manual re-apply entry points must use it.
// R72 二十六次 W1-2：改用强制变体——手动重载（HTTP /caddy/reload 与 MCP
// reload_caddy）的语义就是「强制收敛」，必须能击穿 errSameConfig 短路
// （磁盘数据变化而 JSON 相同的场景），否则文档承诺的收敛能力不存在。
func (h *Handlers) applyCaddyConfigE() error {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	err := h.caddyService.GenerateAndApplyConfigForce()
	h.recordCaddyApplyResult(err)
	return err
}

func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, features ruleFeatureInput, uniqueID string, serverName string) error {
	type requestUpstream struct {
		Host           string
		Port           int
		Weight         int
		Enabled        bool
		Protocol       string
		MaxConnections int
	}

	type requestData struct {
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		DnsServer                     string
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSSource                     string
		ACMEConfigID                  int
		CAProviderID                  int
		TLSCert                       string
		TLSKey                        string
		TLSHTTPRedirect               bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
		RequestBodyMaxSizeMB          int
		UpstreamKeepaliveTimeout      int
		ServerTokensHidden            int
		Upstreams                     []requestUpstream
	}

	var data requestData
	// 审计 B2-S1：TCP/DNS 字段从原始请求（Create/Update 两形态）提取。
	var tcpFields struct {
		enableDnsServer    bool
		tcpHealthCheckPort int
		tcpProxyProtocol   bool
		tcpTryDuration     int
		tcpTryInterval     int
	}
	switch v := req.(type) {
	case models.CreateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol
		tcpFields.tcpTryDuration = v.TCPTryDuration
		tcpFields.tcpTryInterval = v.TCPTryInterval
	case *models.CreateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol
		tcpFields.tcpTryDuration = v.TCPTryDuration
		tcpFields.tcpTryInterval = v.TCPTryInterval
	case models.UpdateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer != nil && *v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol != nil && *v.TCPProxyProtocol
		tcpFields.tcpTryDuration = v.TCPTryDuration
		tcpFields.tcpTryInterval = v.TCPTryInterval
	case *models.UpdateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer != nil && *v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol != nil && *v.TCPProxyProtocol
		tcpFields.tcpTryDuration = v.TCPTryDuration
		tcpFields.tcpTryInterval = v.TCPTryInterval
	}
	var upstreams []requestUpstream

	switch r := req.(type) {
	case models.CreateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		data.CAProviderID = r.CAProviderID
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		data.RequestBodyMaxSizeMB = r.RequestBodyMaxSizeMB
		data.UpstreamKeepaliveTimeout = r.UpstreamKeepaliveTimeout
		data.ServerTokensHidden = r.ServerTokensHidden
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight,
				Enabled: u.Enabled, Protocol: u.Protocol,
				MaxConnections: u.MaxConnections,
			})
		}
		data.Upstreams = upstreams
	case models.UpdateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		if r.DynamicDNS != nil {
			data.DynamicDNS = *r.DynamicDNS
		}
		data.DnsServer = derefStr(r.DnsServer)
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = derefStr(r.HealthCheckPath)
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		if r.EnableTLS != nil {
			data.EnableTLS = *r.EnableTLS
		}
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		if r.CAProviderID != nil {
			data.CAProviderID = *r.CAProviderID
		}
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		if r.TLSHTTPRedirect != nil {
			data.TLSHTTPRedirect = *r.TLSHTTPRedirect
		}
		if r.EnableCompress != nil {
			data.EnableCompress = *r.EnableCompress
		}
		data.CompressTypes = r.CompressTypes
		if r.EnableActiveHealthCheck != nil {
			data.EnableActiveHealthCheck = *r.EnableActiveHealthCheck
		}
		data.HostHeader = derefStr(r.HostHeader)
		if r.RequestBodyMaxSizeMB != nil {
			data.RequestBodyMaxSizeMB = *r.RequestBodyMaxSizeMB
		}
		if r.UpstreamKeepaliveTimeout != nil {
			data.UpstreamKeepaliveTimeout = *r.UpstreamKeepaliveTimeout
		}
		if r.ServerTokensHidden != nil {
			data.ServerTokensHidden = *r.ServerTokensHidden
		}
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight,
				Enabled: u.Enabled, Protocol: u.Protocol,
				MaxConnections: u.MaxConnections,
			})
		}
		data.Upstreams = upstreams
	default:
		return nil
	}

	if data.Strategy == "" {
		data.Strategy = "weighted_round_robin"
	}
	if data.HealthCheckInterval == 0 {
		data.HealthCheckInterval = 10
	}
	if data.HealthCheckTimeout == 0 {
		data.HealthCheckTimeout = 2
	}
	if data.HealthCheckUnhealthyThreshold == 0 {
		data.HealthCheckUnhealthyThreshold = 3
	}
	if data.HealthCheckHealthyThreshold == 0 {
		data.HealthCheckHealthyThreshold = 2
	}
	if data.CompressTypes == "" {
		data.CompressTypes = "gzip"
	}

	if data.Protocol != "http" && data.Protocol != "tcp" {
		return fmt.Errorf("无效的协议：仅支持 http 或 tcp")
	}

	if data.ListenPort < 1 || data.ListenPort > 65535 {
		return fmt.Errorf("无效的监听端口：必须在 1-65535 之间")
	}

	httpStrategies := map[string]bool{
		"ip_hash": true, "least_conn": true,
		"random": true, "first": true, "weighted_round_robin": true,
		"cookie": true,
	}
	tcpStrategies := map[string]bool{
		"ip_hash": true, "least_conn": true,
		"random": true, "first": true, "weighted_round_robin": true,
	}
	if data.Protocol == "http" && !httpStrategies[data.Strategy] {
		return fmt.Errorf("无效的负载策略：HTTP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first / cookie")
	}
	if data.Protocol == "tcp" && !tcpStrategies[data.Strategy] {
		return fmt.Errorf("无效的负载策略：TCP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first")
	}

	if data.Domain != "" && data.Protocol == "http" {
		domains := strings.Split(data.Domain, ",")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if !isValidDomain(d) {
				return fmt.Errorf("无效的域名格式：'%s'", d)
			}
		}
	}

	if len(data.Upstreams) == 0 {
		return fmt.Errorf("至少需要一个上游服务器")
	}

	enabledUpstreamCount := 0
	hostPortSeen := make(map[string]bool)
	for i, u := range data.Upstreams {
		if u.Host == "" {
			return fmt.Errorf("上游 #%d：主机地址不能为空", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("上游 #%d：端口 %d 无效（必须在 1-65535 之间）", i+1, u.Port)
		}
		if u.Weight < 0 {
			return fmt.Errorf("上游 #%d：权重不能为负数", i+1)
		}
		if data.Protocol == "http" {
			if u.Protocol != "" && u.Protocol != "http" && u.Protocol != "https" {
				return fmt.Errorf("上游 #%d：协议 '%s' 无效（HTTP 规则仅支持 http/https）", i+1, u.Protocol)
			}
		} else {
			if u.Protocol != "" && u.Protocol != "tcp" && u.Protocol != "tls" {
				return fmt.Errorf("上游 #%d：协议 '%s' 无效（TCP 规则仅支持 tcp/tls）", i+1, u.Protocol)
			}
		}
		if u.MaxConnections < 0 {
			return fmt.Errorf("上游 #%d：最大连接数不能为负数", i+1)
		}

		key := fmt.Sprintf("%s:%d", u.Host, u.Port)
		if hostPortSeen[key] {
			return fmt.Errorf("上游 %s:%d 重复", u.Host, u.Port)
		}
		hostPortSeen[key] = true

		if !isValidHost(u.Host) {
			return fmt.Errorf("上游 #%d：主机 '%s' 无效", i+1, u.Host)
		}

		if u.Enabled {
			enabledUpstreamCount++
		}
	}

	if enabledUpstreamCount == 0 {
		return fmt.Errorf("至少需要一个启用的上游服务器")
	}

	if data.DynamicDNS && enabledUpstreamCount > 1 {
		return fmt.Errorf("动态 DNS 模式仅支持一个启用的上游（DNS 会解析出多个 IP）")
	}
	if data.DynamicDNS && data.DnsFamily != "ipv4" && data.DnsFamily != "ipv6" && data.DnsFamily != "both" {
		return fmt.Errorf("无效的 DNS 协议栈 '%s'（仅支持 ipv4、ipv6 或 both）", data.DnsFamily)
	}

	if data.HealthCheckPath != "" && !strings.HasPrefix(data.HealthCheckPath, "/") {
		return fmt.Errorf("健康检查路径必须以 / 开头")
	}

	if data.EnableTLS && data.TLSSource == "acme_dns" {
		// R52 F-1/F-3（写侧）→ R53 发现4 共享门：0 值、悬挂 id 与引用已禁用
		// （enabled=0）配置/提供商一律 400——与签发侧 certissuer.go 的
		// AND enabled=1 口径对齐，悬挂/禁用引用会静默落库并在签发期单任务失败。
		if err := validateRuleACMEReferences(acmeReferenceInput{
			EnableTLS: data.EnableTLS, TLSSource: data.TLSSource,
			ACMEConfigID: data.ACMEConfigID, CAProviderID: data.CAProviderID,
		}); err != nil {
			return err
		}
		if data.Domain == "" {
			return fmt.Errorf("ACME DNS 证书需要填写域名")
		}
		if err := services.ValidateACMEDomains(data.Domain); err != nil {
			return err
		}
	}

	if data.HealthCheckInterval < 1 {
		return fmt.Errorf("健康检查间隔必须 ≥ 1 秒")
	}

	if data.HealthCheckTimeout < 1 {
		return fmt.Errorf("健康检查超时必须 ≥ 1 秒")
	}

	tempCaddyID := "validate_" + uniqueID

	var global struct {
		requestBodyMaxSizeMB, upstreamKeepaliveTimeout                                                        int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout int
		proxyFlushInterval, proxyStreamCloseDelay                                                             int
		serverTokensHidden                                                                                    bool
	}
	if err := db.DB.QueryRow(`
		SELECT COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
			COALESCE(server_tokens_hidden,FALSE)
		FROM global_config WHERE id = 1
	`).Scan(&global.requestBodyMaxSizeMB, &global.upstreamKeepaliveTimeout,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout, &global.proxyStreamTimeout, &global.proxyFlushInterval, &global.proxyStreamCloseDelay,
		&global.serverTokensHidden); err != nil {
		return fmt.Errorf("加载全局配置失败: %v", err)
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                      data.Protocol,
		Domain:                        data.Domain,
		ListenPort:                    data.ListenPort,
		Strategy:                      data.Strategy,
		DynamicDNS:                    data.DynamicDNS,
		DnsServer:                     data.DnsServer,
		DnsFamily:                     data.DnsFamily,
		HealthCheckPath:               data.HealthCheckPath,
		HealthCheckInterval:           data.HealthCheckInterval,
		HealthCheckTimeout:            data.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: data.HealthCheckUnhealthyThreshold,
		HealthCheckHealthyThreshold:   data.HealthCheckHealthyThreshold,
		TLSSource:                     data.TLSSource,
		ACMEConfigID:                  data.ACMEConfigID,
		// 审计 B2-S1：补齐校验副本缺失的字段（含全部 TCP 字段）——否则 TCP
		// 规则预检在「校验另一份零值配置」，用户真实值触发的错误被推迟到
		// apply 阶段才暴露（多付一次 snapshot/restore 周期）。TCP/DNS 字段
		// 不在 requestData 内，从原始请求提取。
		EnableDnsServer:                  tcpFields.enableDnsServer,
		TCPHealthCheckPort:               tcpFields.tcpHealthCheckPort,
		TCPProxyProtocol:                 tcpFields.tcpProxyProtocol,
		TCPTryDuration:                   tcpFields.tcpTryDuration,
		TCPTryInterval:                   tcpFields.tcpTryInterval,
		EnableTLS:                        data.EnableTLS,
		TLSCert:                          data.TLSCert,
		TLSKey:                           data.TLSKey,
		TLSHTTPRedirect:                  data.TLSHTTPRedirect,
		EnableCompress:                   data.EnableCompress,
		CompressTypes:                    data.CompressTypes,
		EnableActiveHealthCheck:          data.EnableActiveHealthCheck,
		HostHeader:                       data.HostHeader,
		RequestBodyMaxSizeMB:             data.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:         data.UpstreamKeepaliveTimeout,
		ServerTokensHidden:               data.ServerTokensHidden,
		GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
		GlobalUpstreamKeepaliveTimeout:   global.upstreamKeepaliveTimeout,
		GlobalServerTokensHidden:         global.serverTokensHidden,
		CustomRoutesEnabled:              features.CustomRoutesEnabled,
		PathRules:                        toPathRuleConfigs(features.PathRules),
		ProxyDialTimeout:                 features.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:       features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:                 features.ProxyReadTimeout,
		ProxyWriteTimeout:                features.ProxyWriteTimeout,
		ProxyStreamTimeout:               features.ProxyStreamTimeout,
		ProxyFlushInterval:               features.ProxyFlushInterval,
		ProxyStreamCloseDelay:            features.ProxyStreamCloseDelay,
		GlobalProxyDialTimeout:           global.proxyDialTimeout,
		GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
		GlobalProxyReadTimeout:           global.proxyReadTimeout,
		GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
		GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
		GlobalProxyFlushInterval:         global.proxyFlushInterval,
		GlobalProxyStreamCloseDelay:      global.proxyStreamCloseDelay,
		CaddyID:                          tempCaddyID,
	}

	for _, u := range data.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			if data.Protocol == "tcp" {
				protocol = "tcp"
			} else {
				protocol = "http"
			}
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
			MaxConnections: u.MaxConnections,
		})
	}

	if data.Protocol == "tcp" {
		// R69 C-N3：TCP 校验改合并口径——此前 ValidateConfig(GenerateSingleRuleCaddyConfig)
		// 因 Caddy /load 无 validate-only 语义而整体替换运行配置（validate 窗口内全部
		// 其他规则下线；真 apply 失败时补偿快照已污染）。改为把候选 server 并入
		// 运行配置副本校验（与 HTTP 侧 ValidateRouteMergedConfig 同口径）。
		single := services.GenerateSingleRuleCaddyConfig(ruleConfig)
		apps, _ := single["apps"].(map[string]interface{})
		layer4, _ := apps["layer4"].(map[string]interface{})
		servers, _ := layer4["servers"].(map[string]interface{})
		for serverName, serverConfig := range servers {
			if serverMap, valid := serverConfig.(map[string]interface{}); valid {
				return h.caddyService.ValidateTCPServerMergedConfig(serverName, serverMap)
			}
		}
		return nil
	}

	routeConfig, routeErr := services.GenerateRouteObject(ruleConfig)
	if routeErr != nil {
		return fmt.Errorf("路由配置生成失败: %v", routeErr)
	}
	if mergeErr := h.caddyService.ValidateRouteMergedConfig(serverName, routeConfig); mergeErr != nil {
		return fmt.Errorf("Caddy 配置验证失败: %v", mergeErr)
	}

	if delErr := h.caddyService.DeleteRouteByID(serverName, tempCaddyID); delErr != nil {
		log.Printf("Warning: failed to delete validation temp route %s: %v (continuing anyway)", tempCaddyID, delErr)
	}

	return nil
}

// clampAuditRetentionMonthsOnStartup 将存量越界 audit_retention_months 钳位到
// [1,12] 最近边界并记日志（R55 F3）：写侧已加范围校验，历史越界值（超大值使
// 年龄裁剪 datetime 越界静默失效，仅剩条数兜底）在启动时收敛。
// 注：不得移入 caddy.go——TestCaddySectionKeys_matchUpdateSQL 按文本定位
// caddy.go 内首个 "UPDATE global_config SET" 提取 UpdateConfig 的列集合。
func clampAuditRetentionMonthsOnStartup() {
	var months int
	if err := db.DB.QueryRow(`SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1`).Scan(&months); err != nil {
		log.Printf("读取日志保留月数失败，跳过启动钳位: %v", err)
		return
	}
	clamped := months
	if clamped < 1 {
		clamped = 1
	}
	if clamped > 12 {
		clamped = 12
	}
	if clamped == months {
		return
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=? WHERE id=1`, clamped); err != nil {
		log.Printf("钳位日志保留月数失败: %v", err)
		return
	}
	log.Printf("日志保留月数 %d 超出 1-12 范围，已钳位为 %d", months, clamped)
}

func (h *Handlers) ApplyConfigOnStartup() error {
	// R55 F3：存量越界 audit_retention_months 启动钳位（写侧已加 1-12 校验）。
	clampAuditRetentionMonthsOnStartup()
	// Round 29 G-3: 启动路径补存量规则校验（保存/导入/启用路径已有自环与遮蔽拦截），
	// 命中即响亮报错并记审计，但不阻断启动：单条坏规则不应拖垮整个服务，与
	// 「启动应用失败仅记日志保旧配置」的既有取舍一致（main.go 调用侧同样不退出）。
	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		services.Logf("error", "启动校验发现无效规则配置，继续启动（保留旧配置）：%v", err)
		services.RecordAuditLog("system", "启动警告", "系统配置", "启动校验发现无效规则配置："+err.Error(), "")
	}

	// Wait for Caddy to be ready (up to 10 seconds)
	maxRetries := 20
	retryDelay := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		client := &http.Client{Timeout: 2 * time.Second}
		// Round 35 I-21: 即使 err != nil，resp 也可能非 nil（如重定向），需统一关闭。
		resp, err := client.Get(strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/config/") // D5-S3：就绪探针与 GetCaddyStatus 同源取配置地址，不再硬编码 localhost:2019
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil && resp.StatusCode < 500 {
			break
		}
		time.Sleep(retryDelay)
	}

	rows, err := db.DB.Query(`SELECT caddy_id FROM lb_rules WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var caddyID string
		if err := rows.Scan(&caddyID); err != nil {
			return err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	log.Printf("Applying Caddy config on startup (enabled rules: %d)", count)
	if err := h.applyCaddyConfigE(); err != nil {
		return fmt.Errorf("apply Caddy config on startup: %w", err)
	}
	services.RecordAuditLog("system", "载入", "系统配置", fmt.Sprintf("启动时从数据库载入配置并应用 Caddy；启用规则 %d 条", count), "")

	return nil
}

func (h *Handlers) validatePortFromDB(protocol string, port int, excludeCaddyID string) error {
	// Check conflict with existing rules:
	// - HTTP rules may share a port (Caddy routes by host), but cannot share with TCP.
	// - TCP rules are L4 and cannot share a port with any other rule (HTTP or TCP).
	// 仅统计启用中的规则：禁用规则不占用端口，创建/更新时不应被其阻塞；启用时
	// 本函数同样按 enabled=1 过滤，第二条禁用规则启用时会看到第一条已启用而冲突。
	var count int
	var err error
	if excludeCaddyID != "" {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND enabled = 1", port, excludeCaddyID).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND protocol = 'tcp' AND enabled = 1", port, excludeCaddyID).Scan(&count)
		}
	} else {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND enabled = 1", port).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND protocol = 'tcp' AND enabled = 1", port).Scan(&count)
		}
	}
	if err != nil {
		return fmt.Errorf("验证端口时数据库错误: %v", err)
	}

	if count > 0 {
		return fmt.Errorf("端口 %d 已被其他规则占用", port)
	}

	return nil
}
