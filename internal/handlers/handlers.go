package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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

func (h *Handlers) applyCaddyConfig() {
	// Generate Caddy config from DB
	config := services.GenerateCaddyConfig(h.cfg)

	// Push to Caddy
	if err := h.caddyService.ApplyConfig(config); err != nil {
		log.Printf("Failed to apply Caddy config: %v", err)
	}
}

func (h *Handlers) applyCaddyConfigE() error {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	config := services.GenerateCaddyConfig(h.cfg)
	return h.caddyService.ApplyConfig(config)
}

func (h *Handlers) applyCaddyConfigWithRollback() error {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	return h.applyCaddyConfigWithRollbackLocked()
}

// applyCaddyConfigWithRollbackLocked 供已持有 caddyOpMu 的调用方使用，避免重入死锁
func (h *Handlers) applyCaddyConfigWithRollbackLocked() error {
	// Backup current Caddy config before applying; without a restore point
	// the rollback contract cannot be honored, so abort instead of applying.
	if err := h.caddyService.BackupConfig(); err != nil {
		return fmt.Errorf("备份 Caddy 配置失败: %w", err)
	}

	// Generate Caddy config from DB
	config := services.GenerateCaddyConfig(h.cfg)

	configJSON, _ := json.Marshal(config)
	log.Printf("Generated Caddy config: %s", string(configJSON))

	// Push to Caddy
	if err := h.caddyService.ApplyConfig(config); err != nil {
		log.Printf("Failed to apply Caddy config: %v", err)

		// Attempt rollback
		if rollbackErr := h.caddyService.Rollback(); rollbackErr != nil {
			log.Printf("CRITICAL: Failed to rollback Caddy config: %v", rollbackErr)
			return fmt.Errorf("配置应用失败且回滚也失败: %v（回滚错误: %v）", err, rollbackErr)
		}

		return fmt.Errorf("配置应用失败，已回滚到之前的配置: %v", err)
	}

	// Clear backup after successful apply
	h.caddyService.ClearBackup()
	return nil
}

func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, features ruleFeatureInput, uniqueID string, serverName string) error {
	type requestUpstream struct {
		Host           string
		Port           int
		Weight         int
		Domain         string
		DynamicDNS     bool
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
				Host: u.Host, Port: u.Port, Weight: u.Weight, Domain: u.Domain,
				DynamicDNS: u.DynamicDNS, Enabled: u.Enabled, Protocol: u.Protocol,
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
		data.DnsServer = r.DnsServer
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		if r.EnableTLS != nil {
			data.EnableTLS = *r.EnableTLS
		}
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
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
		data.HostHeader = r.HostHeader
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
				Host: u.Host, Port: u.Port, Weight: u.Weight, Domain: u.Domain,
				DynamicDNS: u.DynamicDNS, Enabled: u.Enabled, Protocol: u.Protocol,
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
		data.HealthCheckTimeout = 5
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

	if data.Domain != "" && (data.Protocol == "http" || data.Protocol == "https") {
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
		if data.ACMEConfigID == 0 {
			return fmt.Errorf("使用 ACME 签发时必须选择 DNS 提供商配置")
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
		serverTokensHidden                                                                                    bool
	}
	if err := db.DB.QueryRow(`
		SELECT COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
			COALESCE(server_tokens_hidden,FALSE)
		FROM global_config WHERE id = 1
	`).Scan(&global.requestBodyMaxSizeMB, &global.upstreamKeepaliveTimeout,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout, &global.proxyStreamTimeout,
		&global.serverTokensHidden); err != nil {
		return fmt.Errorf("加载全局配置失败: %v", err)
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                         data.Protocol,
		Domain:                           data.Domain,
		ListenPort:                       data.ListenPort,
		Strategy:                         data.Strategy,
		DynamicDNS:                       data.DynamicDNS,
		DnsServer:                        data.DnsServer,
		DnsFamily:                        data.DnsFamily,
		HealthCheckPath:                  data.HealthCheckPath,
		HealthCheckInterval:              data.HealthCheckInterval,
		HealthCheckTimeout:               data.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold:    data.HealthCheckUnhealthyThreshold,
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
		IPACLMode:                        features.IPACLMode,
		IPACLList:                        features.IPACLList,
		CustomRoutesEnabled:              features.CustomRoutesEnabled,
		PathRules:                        toPathRuleConfigs(features.PathRules),
		ProxyDialTimeout:                 features.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:       features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:                 features.ProxyReadTimeout,
		ProxyWriteTimeout:                features.ProxyWriteTimeout,
		ProxyStreamTimeout:               features.ProxyStreamTimeout,
		GlobalProxyDialTimeout:           global.proxyDialTimeout,
		GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
		GlobalProxyReadTimeout:           global.proxyReadTimeout,
		GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
		GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
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
		})
	}

	if data.Protocol == "tcp" {
		return h.caddyService.ValidateConfig(services.GenerateSingleRuleCaddyConfig(ruleConfig), uniqueID+"_l4")
	}

	routeConfig, routeErr := services.GenerateRouteObject(ruleConfig)
	if routeErr != nil {
		return fmt.Errorf("路由配置生成失败: %v", routeErr)
	}
	if mergeErr := h.caddyService.ValidateRouteMergedConfig(serverName, routeConfig, uniqueID+"_merge"); mergeErr != nil {
		return fmt.Errorf("Caddy 配置验证失败: %v", mergeErr)
	}

	if delErr := h.caddyService.DeleteRouteByID(serverName, tempCaddyID); delErr != nil {
		log.Printf("Warning: failed to delete validation temp route %s: %v (continuing anyway)", tempCaddyID, delErr)
	}

	return nil
}

func (h *Handlers) ApplyConfigOnStartup() error {
	// Wait for Caddy to be ready (up to 10 seconds)
	maxRetries := 20
	retryDelay := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://localhost:2019/config/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				break
			}
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
			continue
		}
		count++
	}

	log.Printf("Applying Caddy config on startup (enabled rules: %d)", count)
	h.applyCaddyConfig()
	services.RecordAuditLog("system", "载入", "系统配置", fmt.Sprintf("启动时从数据库载入配置并应用 Caddy；启用规则 %d 条", count), "")

	return nil
}

func (h *Handlers) validatePort(protocol string, port int, excludeCaddyID string) error {
	adminPorts := []int{8000, 2019}
	httpReservedPorts := []int{80, 443}

	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1-65535 之间")
	}

	for _, p := range adminPorts {
		if port == p {
			return fmt.Errorf("端口 %d 为管理端口，不可使用", port)
		}
	}

	if protocol == "tcp" {
		for _, p := range httpReservedPorts {
			if port == p {
				return fmt.Errorf("端口 %d 为 HTTP/HTTPS 保留端口", p)
			}
		}
	}

	return h.validatePortFromDB(protocol, port, excludeCaddyID)
}

func (h *Handlers) validatePortFromDB(protocol string, port int, excludeCaddyID string) error {
	// Check conflict with existing rules:
	// - HTTP rules may share a port (Caddy routes by host), but cannot share with TCP.
	// - TCP rules are L4 and cannot share a port with any other rule (HTTP or TCP).
	var count int
	var err error
	if excludeCaddyID != "" {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ?", port, excludeCaddyID).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND protocol = 'tcp'", port, excludeCaddyID).Scan(&count)
		}
	} else {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ?", port).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND protocol = 'tcp'", port).Scan(&count)
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
