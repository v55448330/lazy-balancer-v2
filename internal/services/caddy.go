package services

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

const (
	caddyConfigGenerationErrorKey = "__lazy_balancer_generation_error"
	caddyCertFilesSnapshotKey     = "__lazy_balancer_cert_files_snapshot"
	caddyConfigStoreKey           = "__lazy_balancer_config_store"
)

// CaddyService handles Caddy configuration management
type CaddyService struct {
	adminURL string
	client   *http.Client
	mu       sync.Mutex
}

func NewCaddyService(adminURL string) *CaddyService {
	return &CaddyService{
		adminURL: adminURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func GenerateCaddyID() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	id := make([]byte, 13)
	id[0] = 'l'
	id[1] = 'b'
	id[2] = '_'
	for i := 3; i < 13; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		id[i] = charset[idx.Int64()]
	}
	return string(id), nil
}

// ApplyConfig pushes configuration to Caddy
func (s *CaddyService) ApplyConfig(config map[string]interface{}) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if store, ok := config[caddyConfigStoreKey].(caddyConfigStore); ok {
		config = generateCaddyConfigFromStore(store)
	}
	return s.applyConfigLocked(config)
}

func (s *CaddyService) GenerateAndApplyConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLocked(generateCaddyConfigFromStore(db.DB))
}

func (s *CaddyService) applyConfigLocked(config map[string]interface{}) (err error) {
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return errors.New(message)
	}
	snapshot, hasSnapshot := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot)
	if hasSnapshot {
		defer func() {
			if err != nil {
				err = errors.Join(err, RestoreCertFiles(snapshot))
			}
		}()
	}

	data, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/load", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("config apply failed: %s", string(body))
	}

	log.Println("Caddy config applied successfully")
	return nil
}

// ValidateConfig validates Caddy configuration using the /load API with validate=true
func (s *CaddyService) ValidateConfig(config map[string]interface{}) (err error) {
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return errors.New(message)
	}
	snapshot, hasSnapshot := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot)
	if hasSnapshot {
		defer func() {
			err = errors.Join(err, RestoreCertFiles(snapshot))
		}()
	}
	data, err := json.Marshal(caddyPayload(config))
	if err != nil {
		return err
	}

	validateURL := s.adminURL + "/load?validate=true"
	resp, err := s.client.Post(validateURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("validation failed: %s", string(body))
	}

	return nil
}

func caddyPayload(config map[string]interface{}) map[string]interface{} {
	payload := make(map[string]interface{}, len(config))
	for key, value := range config {
		if key != caddyCertFilesSnapshotKey && key != caddyConfigStoreKey {
			payload[key] = value
		}
	}
	return payload
}

// ValidateRouteMergedConfig validates the full config after inserting a route before the catch-all.
func (s *CaddyService) ValidateRouteMergedConfig(serverName string, routeConfig map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullConfig, err := s.GetConfig()
	if err != nil {
		// Round 24 C-N4: GetConfig 失败是传输/解码错误（管理接口不可达），不能静默按
		// “校验通过”放行；“尚无任何已加载配置”的空配置走下方空结构早退。
		return fmt.Errorf("无法连接 Caddy 管理接口，未能校验配置: %w", err)
	}

	apps, ok := fullConfig["apps"].(map[string]interface{})
	if !ok {
		return nil
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return nil
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return nil
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		// Server doesn't exist, so prepend won't cause merge issues
		return nil
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		routes = []interface{}{}
	}

	// Find default route (keep it at the end)
	var defaultRoute interface{}
	newRoutes := make([]interface{}, 0, len(routes)+1)

	for _, r := range routes {
		if routeMap, ok := r.(map[string]interface{}); ok {
			if isRunningDefaultRoute(routeMap) {
				defaultRoute = r
				continue
			}
		}
		newRoutes = append(newRoutes, r)
	}

	newRoutes = append(newRoutes, routeConfig)

	if defaultRoute != nil {
		newRoutes = append(newRoutes, defaultRoute)
	}

	server["routes"] = newRoutes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	fullConfig["apps"] = apps

	// Validate the merged full config
	return s.validateConfigInternal(fullConfig)
}

// validateConfigInternal validates config using Caddy /load API with validate=true
func (s *CaddyService) validateConfigInternal(config map[string]interface{}) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	validateURL := s.adminURL + "/load?validate=true"
	resp, err := s.client.Post(validateURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("validation failed: %s", string(body))
	}

	return nil
}

func (s *CaddyService) GetConfigByID(id string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", s.adminURL+"/id/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get config failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

func (s *CaddyService) DeleteRouteByID(serverName string, caddyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return nil
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return nil
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return nil
	}

	server, ok := servers[serverName].(map[string]interface{})
	if !ok {
		return nil
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		return nil
	}

	filteredRoutes := make([]interface{}, 0, len(routes))
	removed := false
	for _, r := range routes {
		routeMap, ok := r.(map[string]interface{})
		if !ok {
			filteredRoutes = append(filteredRoutes, r)
			continue
		}

		if existingID, hasID := routeMap["@id"].(string); hasID && routeIDBelongsToRule(existingID, caddyID) {
			removed = true
			continue
		}

		filteredRoutes = append(filteredRoutes, r)
	}

	// 未匹配到该规则的路由时配置未变化，跳过全量下发避免无谓的 Caddy 重载。
	if !removed {
		return nil
	}

	server["routes"] = filteredRoutes
	servers[serverName] = server
	httpApp["servers"] = servers
	apps["http"] = httpApp
	config["apps"] = apps

	return s.applyConfigRaw(config)
}

func isRunningDefaultRoute(route map[string]interface{}) bool {
	handlers, ok := route["handle"].([]interface{})
	if !ok || len(handlers) == 0 {
		return false
	}
	handler, ok := handlers[0].(map[string]interface{})
	return ok && handler["handler"] == "static_response" && handler["body"] == "Lazy Balancer V2 is running!"
}

func routeIDBelongsToRule(routeID, ruleID string) bool {
	return ruleID != "" && (routeID == ruleID || strings.HasPrefix(routeID, ruleID+"_"))
}

func (s *CaddyService) applyConfigRaw(config map[string]interface{}) error {
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	resp, err := s.client.Post(s.adminURL+"/config/", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("config apply failed: %s", string(body))
	}

	return nil
}

// GetConfig gets current Caddy configuration
func (s *CaddyService) GetConfig() (map[string]interface{}, error) {
	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

// UpstreamHealthDetail contains detailed health information for an upstream
type UpstreamHealthDetail struct {
	Healthy     bool `json:"healthy"`
	Unknown     bool `json:"unknown"`
	Degraded    bool `json:"degraded"`
	NumRequests int  `json:"num_requests"`
	Fails       int  `json:"fails"`
}

// GetUpstreamHealthDetailed returns detailed health status of all upstreams from Caddy
func (s *CaddyService) GetUpstreamHealthDetailed() (map[string]map[string]*UpstreamHealthDetail, error) {
	healthStatus := make(map[string]map[string]*UpstreamHealthDetail)

	upstreamHealth := s.getUpstreamHealthFromMetrics()
	upstreamMetrics := s.getUpstreamMetrics()

	resp, err := s.client.Get(s.adminURL + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return healthStatus, nil
	}

	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
			for serverName, serverVal := range servers {
				server, ok := serverVal.(map[string]interface{})
				if !ok {
					continue
				}

				routes, ok := server["routes"].([]interface{})
				if !ok {
					continue
				}

				for _, route := range routes {
					routeMap, ok := route.(map[string]interface{})
					if !ok {
						continue
					}

					handleGroups, ok := routeMap["handle"].([]interface{})
					if !ok {
						continue
					}

					for _, handleGroup := range handleGroups {
						handle, ok := handleGroup.(map[string]interface{})
						if !ok || handle["handler"] != "reverse_proxy" {
							continue
						}
						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)
						}

						// Handle static upstreams (dial addresses)
						if upstreams, ok := handle["upstreams"].([]interface{}); ok {
							for _, upstream := range upstreams {
								up, ok := upstream.(map[string]interface{})
								if !ok {
									continue
								}

								dial, ok := up["dial"].(string)
								if !ok {
									continue
								}

								detail := &UpstreamHealthDetail{}

								if metrics, ok := upstreamMetrics[dial]; ok {
									detail.NumRequests = metrics.NumRequests
									detail.Fails = metrics.Fails
								}

								if observedHealthy, ok := upstreamHealth[dial]; ok {
									// Caddy reports a definitive health status for this upstream.
									detail.Healthy = observedHealthy
									// Passive circuit breakers forget failures after the fail
									// window, so the gauge flaps back to healthy while the
									// upstream is still erroring; surface that as degraded.
									if observedHealthy && detail.Fails > 0 {
										detail.Degraded = true
									}
								} else if detail.Fails > 0 {
									// Passive health observed failures.
									detail.Healthy = false
								} else {
									// No observation from Caddy at all.
									detail.Unknown = true
								}

								healthStatus[serverName][dial] = detail
							}
						}

						// Handle dynamic upstreams (SRV/A record resolution)
						if dynamicUpstreams, ok := handle["dynamic_upstreams"].(map[string]interface{}); ok {
							name, _ := dynamicUpstreams["name"].(string)
							port, _ := dynamicUpstreams["port"].(string)
							if name != "" {
								dial := net.JoinHostPort(name, port)

								detail := &UpstreamHealthDetail{}

								if metrics, ok := upstreamMetrics[dial]; ok {
									detail.NumRequests = metrics.NumRequests
									detail.Fails = metrics.Fails
								}

								if observedHealthy, ok := upstreamHealth[dial]; ok {
									detail.Healthy = observedHealthy
									if observedHealthy && detail.Fails > 0 {
										detail.Degraded = true
									}
								} else if detail.Fails > 0 {
									detail.Healthy = false
								} else {
									detail.Unknown = true
								}

								healthStatus[serverName][dial] = detail
							}
						}
					}
				}
			}
		}
	}

	if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
		if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
			for serverName, serverVal := range servers {
				server, ok := serverVal.(map[string]interface{})
				if !ok {
					continue
				}
				routes, ok := server["routes"].([]interface{})
				if !ok {
					continue
				}
				for _, route := range routes {
					routeMap, ok := route.(map[string]interface{})
					if !ok {
						continue
					}
					handleGroups, ok := routeMap["handle"].([]interface{})
					if !ok {
						continue
					}
					for _, handleGroup := range handleGroups {
						handle, ok := handleGroup.(map[string]interface{})
						if !ok || handle["handler"] != "proxy" {
							continue
						}
						upstreams, ok := handle["upstreams"].([]interface{})
						if !ok {
							continue
						}
						if _, exists := healthStatus[serverName]; !exists {
							healthStatus[serverName] = make(map[string]*UpstreamHealthDetail)
						}
						for _, upstream := range upstreams {
							up, ok := upstream.(map[string]interface{})
							if !ok {
								continue
							}
							dialList, ok := up["dial"].([]interface{})
							if !ok || len(dialList) == 0 {
								continue
							}
							dial, _ := dialList[0].(string)
							if dial == "" {
								continue
							}
							detail := &UpstreamHealthDetail{}
							if metrics, ok := upstreamMetrics[dial]; ok {
								detail.NumRequests = metrics.NumRequests
								detail.Fails = metrics.Fails
							}
							if observedHealthy, ok := upstreamHealth[dial]; ok {
								detail.Healthy = observedHealthy
								if observedHealthy && detail.Fails > 0 {
									detail.Degraded = true
								}
							} else if detail.Fails > 0 {
								detail.Healthy = false
							} else {
								detail.Unknown = true
							}
							healthStatus[serverName][dial] = detail
						}
					}
				}
			}
		}
	}

	return healthStatus, nil
}

// upstreamMetric stores num_requests and fails for an upstream
type upstreamMetric struct {
	NumRequests int
	Fails       int
}

// getUpstreamMetrics fetches num_requests and fails from /reverse_proxy/upstreams
func (s *CaddyService) getUpstreamMetrics() map[string]*upstreamMetric {
	result := make(map[string]*upstreamMetric)

	resp, err := s.client.Get(s.adminURL + "/reverse_proxy/upstreams")
	if err != nil {
		log.Printf("Failed to get reverse_proxy/upstreams: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("reverse_proxy/upstreams returned status %d", resp.StatusCode)
		return result
	}

	var upstreams []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&upstreams); err != nil {
		log.Printf("Failed to decode reverse_proxy/upstreams: %v", err)
		return result
	}

	for _, up := range upstreams {
		// Caddy uses "address" for the upstream key in this endpoint.
		key, ok := up["address"].(string)
		if !ok {
			key, ok = up["dial"].(string)
		}
		if !ok {
			continue
		}

		metric := &upstreamMetric{}

		if numReq, ok := up["num_requests"].(float64); ok {
			metric.NumRequests = int(numReq)
		}

		if fails, ok := up["fails"].(float64); ok {
			metric.Fails = int(fails)
		}

		result[key] = metric
	}

	return result
}

func (s *CaddyService) getUpstreamHealthFromMetrics() map[string]bool {
	result := make(map[string]bool)

	resp, err := s.client.Get(s.adminURL + "/metrics")
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "caddy_reverse_proxy_upstreams_healthy{") || strings.HasPrefix(line, "caddy_layer4_proxy_upstream_healthy{") {
			upstream := extractMetricLabel(line, "upstream")
			spaceIdx := strings.LastIndex(line, " ")
			var isHealthy float64
			if spaceIdx > 0 {
				fmt.Sscanf(line[spaceIdx+1:], "%f", &isHealthy)
			}
			if upstream != "" {
				result[upstream] = isHealthy == 1
			}
		}
	}

	log.Printf("Health metrics parsed: %v", result)
	return result
}

func extractMetricLabel(metricName string, label string) string {
	idx := strings.Index(metricName, label+`="`)
	if idx == -1 {
		return ""
	}
	start := idx + len(label) + 2
	end := strings.Index(metricName[start:], `"`)
	if end == -1 {
		return ""
	}
	return metricName[start : start+end]
}

// GenerateCaddyConfig generates Caddy configuration from database
type caddyConfigStore interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	Exec(string, ...any) (sql.Result, error)
}

func GenerateCaddyConfig(overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	return generateCaddyConfigFromStore(db.DB, overrides...)
}

func generateCaddyConfigFromStore(store caddyConfigStore, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	var filesSnapshot CertFilesSnapshot
	generationFailure := func(format string, args ...any) map[string]interface{} {
		err := fmt.Errorf(format, args...)
		log.Printf("Caddy 配置生成失败；状态：旧配置已保留（启动期则未加载）：%v", err)
		if filesSnapshot != nil {
			err = errors.Join(err, RestoreCertFiles(filesSnapshot))
			filesSnapshot = nil
		}
		return map[string]interface{}{caddyConfigGenerationErrorKey: err.Error()}
	}

	type lbRule struct {
		CaddyID                       string
		Name                          string
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		EnableDnsServer               bool
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
		ACMEEmail                     string
		TLSCert                       string
		TLSKey                        string
		TLSHTTPRedirect               bool
		Enabled                       bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		TCPHealthCheckPort            int
		TCPProxyProtocol              bool
		TCPTryDuration                int
		TCPTryInterval                int
		RequestBodyMaxSizeMB          int
		UpstreamKeepaliveTimeout      int
		ServerTokensHidden            int
		CustomRoutesEnabled           bool
		ProxyDialTimeout              int
		ProxyResponseHeaderTimeout    int
		ProxyReadTimeout              int
		ProxyWriteTimeout             int
		ProxyStreamTimeout            int
		ProxyFlushInterval            int
		ProxyStreamCloseDelay         int
		PathRules                     []PathRuleConfig
		HostHeader                    string
		LogEnabled                    bool
	}

	type upstream struct {
		Host           string
		Port           int
		Weight         int
		DynamicDNS     bool
		Enabled        bool
		Protocol       string
		MaxConnections int
	}

	type ruleWithUpstreams struct {
		rule      lbRule
		upstreams []upstream
	}

	// Load all enabled rules into memory first to avoid holding cursor while querying upstreams/global_config
	rows, err := store.Query(`
		SELECT COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       IIF(dynamic_dns IN ('1',1),1,0), IIF(enable_dns_server IN ('1',1),1,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       COALESCE(health_check_path,''), COALESCE(health_check_interval,10),
		       COALESCE(health_check_timeout,2), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		       IIF(enable_tls IN ('1',1),1,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       IIF(tls_http_redirect IN ('1',1),1,0),
		       IIF(enabled IN ('1',1),1,0), IIF(enable_compress IN ('1',1),1,0), COALESCE(compress_types,'gzip'),
		       IIF(enable_active_health_check IN ('1',1),1,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(host_header,''),
		       IIF(log_enabled IN ('1',1),1,0), IIF(custom_routes_enabled IN ('1',1),1,0),
		       COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0)
		FROM lb_rules WHERE enabled = 1
	`)
	if err != nil {
		return generationFailure("query enabled rules: %v", err)
	}

	var allRules []ruleWithUpstreams
	for rows.Next() {
		var r lbRule
		err := rows.Scan(&r.CaddyID, &r.Name, &r.Protocol, &r.Domain, &r.ListenPort, &r.Strategy,
			&r.DynamicDNS, &r.EnableDnsServer, &r.DnsServer, &r.DnsFamily, &r.HealthCheckPath, &r.HealthCheckInterval,
			&r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&r.EnableTLS, &r.TLSSource, &r.ACMEConfigID, &r.TLSCert, &r.TLSKey,
			&r.TLSHTTPRedirect, &r.Enabled, &r.EnableCompress, &r.CompressTypes,
			&r.EnableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPProxyProtocol, &r.TCPTryDuration, &r.TCPTryInterval,
			&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden, &r.HostHeader, &r.LogEnabled,
			&r.CustomRoutesEnabled, &r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout,
			&r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout, &r.ProxyFlushInterval, &r.ProxyStreamCloseDelay)

		if err != nil {
			closeErr := rows.Close()
			return generationFailure("scan enabled rule: %v", errors.Join(err, closeErr))
		}

		if r.Strategy == "" {
			r.Strategy = "weighted_round_robin"
		}

		if !r.Enabled {
			continue
		}

		allRules = append(allRules, ruleWithUpstreams{rule: r})
	}
	if err := rows.Err(); err != nil {
		closeErr := rows.Close()
		return generationFailure("iterate enabled rules: %v", errors.Join(err, closeErr))
	}
	if err := rows.Close(); err != nil {
		return generationFailure("close enabled rules: %v", err)
	}

	rulesByID := make(map[string]*ruleWithUpstreams, len(allRules))
	hasCustomRoutes := false
	hasACMETLS := false
	for i := range allRules {
		rulesByID[allRules[i].rule.CaddyID] = &allRules[i]
		hasCustomRoutes = hasCustomRoutes || allRules[i].rule.CustomRoutesEnabled
		hasACMETLS = hasACMETLS || (allRules[i].rule.EnableTLS && allRules[i].rule.TLSSource == "acme_dns")
	}

	upstreamRows, err := store.Query(`
		SELECT u.rule_id, u.host, u.port, COALESCE(u.weight,1), COALESCE(u.dynamic_dns,0), u.enabled, COALESCE(u.protocol,'http'), COALESCE(u.max_connections,0)
		FROM upstreams u JOIN lb_rules r ON r.caddy_id = u.rule_id
		WHERE u.enabled = 1 AND r.enabled = 1 ORDER BY u.rule_id, u.id
	`)
	if err != nil {
		return generationFailure("query enabled upstreams: %v", err)
	}
	for upstreamRows.Next() {
		var ruleID string
		var u upstream
		if err := upstreamRows.Scan(&ruleID, &u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
			closeErr := upstreamRows.Close()
			return generationFailure("scan upstream: %v", errors.Join(err, closeErr))
		}
		if r := rulesByID[ruleID]; r != nil {
			r.upstreams = append(r.upstreams, u)
		}
	}
	if err := upstreamRows.Err(); err != nil {
		closeErr := upstreamRows.Close()
		return generationFailure("iterate enabled upstreams: %v", errors.Join(err, closeErr))
	}
	if err := upstreamRows.Close(); err != nil {
		return generationFailure("close enabled upstreams: %v", err)
	}

	if hasCustomRoutes {
		pathRows, pathErr := store.Query(`
			SELECT p.rule_id, p.sort_order, p.match_type, p.path, p.upstreams_json
			FROM path_rules p JOIN lb_rules r ON r.caddy_id = p.rule_id
			WHERE r.enabled = 1 AND r.custom_routes_enabled = 1
			ORDER BY p.rule_id, p.sort_order, p.id
		`)
		if pathErr != nil {
			return generationFailure("query path rules: %v", pathErr)
		}
		for pathRows.Next() {
			var ruleID string
			var pathRule PathRuleConfig
			var upstreamsJSON sql.NullString
			if scanErr := pathRows.Scan(&ruleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &upstreamsJSON); scanErr != nil {
				closeErr := pathRows.Close()
				return generationFailure("scan path rule: %v", errors.Join(scanErr, closeErr))
			}
			r := rulesByID[ruleID]
			if r == nil || !r.rule.CustomRoutesEnabled {
				continue
			}
			if upstreamsJSON.Valid {
				pathUpstreams, unmarshalErr := decodePathUpstreams(upstreamsJSON.String)
				if unmarshalErr != nil {
					closeErr := pathRows.Close()
					return generationFailure("decode path upstreams for rule %s: %v", ruleID, errors.Join(unmarshalErr, closeErr))
				}
				pathRule.Upstreams = pathUpstreams
			}
			r.rule.PathRules = append(r.rule.PathRules, pathRule)
		}
		if err := pathRows.Err(); err != nil {
			closeErr := pathRows.Close()
			return generationFailure("iterate path rules: %v", errors.Join(err, closeErr))
		}
		if err := pathRows.Close(); err != nil {
			return generationFailure("close path rules: %v", err)
		}
	}

	for _, ru := range allRules {
		if len(ru.upstreams) == 0 {
			log.Printf("规则 %s (%s) 没有可用上游，已跳过该规则的配置生成", ru.rule.Name, ru.rule.CaddyID)
		}
	}

	acmeCerts := make(map[string][]CertificateCandidate)
	if hasACMETLS {
		certRows, certErr := store.Query(`
			SELECT rule_id, id, domain, status, cert_pem, key_pem,
			       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
			FROM cert_jobs
			WHERE cert_pem IS NOT NULL AND cert_pem <> ''
			  AND key_pem IS NOT NULL AND key_pem <> ''
			ORDER BY updated_at DESC, id DESC
		`)
		if certErr != nil {
			return generationFailure("读取 ACME 证书阶段查询失败: %v", certErr)
		}
		for certRows.Next() {
			var ruleID string
			var candidate CertificateCandidate
			if scanErr := certRows.Scan(&ruleID, &candidate.ID, &candidate.Domain, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); scanErr != nil {
				closeErr := certRows.Close()
				return generationFailure("读取 ACME 证书阶段解析失败: %v", errors.Join(scanErr, closeErr))
			}
			acmeCerts[ruleID] = append(acmeCerts[ruleID], candidate)
		}
		if rowsErr := certRows.Err(); rowsErr != nil {
			closeErr := certRows.Close()
			return generationFailure("读取 ACME 证书阶段遍历失败: %v", errors.Join(rowsErr, closeErr))
		}
		if closeErr := certRows.Close(); closeErr != nil {
			return generationFailure("读取 ACME 证书阶段关闭结果集失败: %v", closeErr)
		}
	}
	selectionNow := time.Now()
	resolveACMECert := func(ruleID, domain string) (CertMaterial, bool) {
		selected, ok := SelectCertificate(acmeCerts[ruleID], domain, selectionNow)
		if ok {
			return CertMaterial{RuleID: ruleID, CertPEM: selected.Candidate.CertPEM, KeyPEM: selected.Candidate.KeyPEM}, true
		}
		return CertMaterial{}, false
	}

	availableCerts := make(map[string]CertMaterial)
	materials := make([]CertMaterial, 0)
	for _, ru := range allRules {
		r := ru.rule
		if !r.EnableTLS {
			continue
		}
		if r.TLSSource == "manual" && r.TLSCert != "" && r.TLSKey != "" {
			material := CertMaterial{RuleID: r.CaddyID, CertPEM: r.TLSCert, KeyPEM: r.TLSKey}
			availableCerts[r.CaddyID] = material
			materials = append(materials, material)
			continue
		}
		if r.TLSSource == "acme_dns" {
			material, available := resolveACMECert(r.CaddyID, r.Domain)
			if available {
				availableCerts[r.CaddyID] = material
				materials = append(materials, material)
			}
		}
	}
	if len(materials) > 0 {
		filesSnapshot, err = MaterializeCertPairs(materials)
		if err != nil {
			return generationFailure("materialize certificate files: %v", err)
		}
	}

	var dnsProvider, acmeEmail string
	var isMaster bool
	var caddyLogLevel string
	var caddyLogSizeMB int
	var accessLogJSON bool
	var accessLogFormat string
	var global struct {
		requestBodyMaxSizeMB, httpReadTimeout, httpWriteTimeout, httpIdleTimeout, upstreamKeepaliveTimeout    int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout int
		proxyFlushInterval, proxyStreamCloseDelay                                                             int
		serverTokensHidden                                                                                    bool
	}
	if err := store.QueryRow(`
		SELECT COALESCE(dns_provider,''), COALESCE(acme_email,''), is_master,
		       COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
		       COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,0), COALESCE(http_write_timeout,0),
		       COALESCE(http_idle_timeout,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,FALSE),
		       COALESCE(access_log_json,TRUE), COALESCE(access_log_format,''), COALESCE(proxy_dial_timeout,0),
		       COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0)
		FROM global_config WHERE id = 1
	`).Scan(&dnsProvider, &acmeEmail, &isMaster, &caddyLogLevel, &caddyLogSizeMB,
		&global.requestBodyMaxSizeMB, &global.httpReadTimeout, &global.httpWriteTimeout, &global.httpIdleTimeout,
		&global.upstreamKeepaliveTimeout, &global.serverTokensHidden, &accessLogJSON, &accessLogFormat,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout,
		&global.proxyStreamTimeout, &global.proxyFlushInterval, &global.proxyStreamCloseDelay); err != nil {
		return generationFailure("load global config: %v", err)
	}

	if len(overrides) > 0 && overrides[0] != nil {
		o := overrides[0]
		if o.CaddyLogLevel != nil {
			caddyLogLevel = *o.CaddyLogLevel
		}
		if o.CaddyLogSizeMB != nil {
			caddyLogSizeMB = *o.CaddyLogSizeMB
		}
		if o.RequestBodyMaxSizeMB != nil {
			global.requestBodyMaxSizeMB = *o.RequestBodyMaxSizeMB
		}
		if o.HTTPReadTimeout != nil {
			global.httpReadTimeout = *o.HTTPReadTimeout
		}
		if o.HTTPWriteTimeout != nil {
			global.httpWriteTimeout = *o.HTTPWriteTimeout
		}
		if o.HTTPIdleTimeout != nil {
			global.httpIdleTimeout = *o.HTTPIdleTimeout
		}
		if o.UpstreamKeepaliveTimeout != nil {
			global.upstreamKeepaliveTimeout = *o.UpstreamKeepaliveTimeout
		}
		if o.ProxyDialTimeout != nil {
			global.proxyDialTimeout = *o.ProxyDialTimeout
		}
		if o.ProxyResponseHeaderTimeout != nil {
			global.proxyResponseHeaderTimeout = *o.ProxyResponseHeaderTimeout
		}
		if o.ProxyReadTimeout != nil {
			global.proxyReadTimeout = *o.ProxyReadTimeout
		}
		if o.ProxyWriteTimeout != nil {
			global.proxyWriteTimeout = *o.ProxyWriteTimeout
		}
		if o.ProxyStreamTimeout != nil {
			global.proxyStreamTimeout = *o.ProxyStreamTimeout
		}
		if o.ProxyFlushInterval != nil {
			global.proxyFlushInterval = *o.ProxyFlushInterval
		}
		if o.ProxyStreamCloseDelay != nil {
			global.proxyStreamCloseDelay = *o.ProxyStreamCloseDelay
		}
		if o.ServerTokensHidden != nil {
			global.serverTokensHidden = *o.ServerTokensHidden
		}
		if o.AccessLogJSON != nil {
			accessLogJSON = *o.AccessLogJSON
		}
		if o.AccessLogFormat != nil {
			accessLogFormat = *o.AccessLogFormat
		}
		if o.DNSProvider != nil {
			dnsProvider = *o.DNSProvider
		}
		if o.ACMEEmail != nil {
			acmeEmail = *o.ACMEEmail
		}
	}

	applyTimeouts := func(server map[string]interface{}) {
		if global.httpReadTimeout > 0 {
			server["read_timeout"] = fmt.Sprintf("%ds", global.httpReadTimeout)
		}
		if global.httpWriteTimeout > 0 {
			server["write_timeout"] = fmt.Sprintf("%ds", global.httpWriteTimeout)
		}
		if global.httpIdleTimeout > 0 {
			server["idle_timeout"] = fmt.Sprintf("%ds", global.httpIdleTimeout)
		}
	}

	servers := make(map[string]interface{})

	httpServersByPort := make(map[int][]ruleWithUpstreams)
	tcpServersByPort := make(map[int][]ruleWithUpstreams)

	for _, ru := range allRules {
		r := ru.rule
		ups := ru.upstreams

		var upstreamDial []string
		for _, u := range ups {
			if u.Enabled {
				upstreamDial = append(upstreamDial, joinUpstreamAddress(u.Host, u.Port))
			}
		}

		if len(upstreamDial) == 0 {
			log.Printf("规则 %s 没有可用的启用上游，已跳过该规则", r.CaddyID)
			continue
		}

		upstreamList := make([]interface{}, len(upstreamDial))
		for i, dial := range upstreamDial {
			upstreamList[i] = map[string]interface{}{"dial": dial}
		}

		if r.Protocol == "http" {
			httpServersByPort[r.ListenPort] = append(httpServersByPort[r.ListenPort], ru)
		} else {
			tcpServersByPort[r.ListenPort] = append(tcpServersByPort[r.ListenPort], ru)
		}
	}

	for port, rules := range httpServersByPort {
		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", port)},
		}
		applyTimeouts(server)

		var routes []interface{}

		for _, ru := range rules {
			r := ru.rule
			ups := ru.upstreams

			ruleConfig := SingleRuleConfig{
				CaddyID:                          r.CaddyID,
				Protocol:                         r.Protocol,
				Domain:                           r.Domain,
				ListenPort:                       r.ListenPort,
				Strategy:                         r.Strategy,
				DynamicDNS:                       r.DynamicDNS,
				EnableDnsServer:                  r.EnableDnsServer,
				DnsServer:                        r.DnsServer,
				DnsFamily:                        r.DnsFamily,
				HealthCheckPath:                  r.HealthCheckPath,
				HealthCheckInterval:              r.HealthCheckInterval,
				HealthCheckTimeout:               r.HealthCheckTimeout,
				HealthCheckUnhealthyThreshold:    r.HealthCheckUnhealthyThreshold,
				HealthCheckHealthyThreshold:      r.HealthCheckHealthyThreshold,
				EnableTLS:                        r.EnableTLS,
				TLSSource:                        r.TLSSource,
				ACMEConfigID:                     r.ACMEConfigID,
				TLSCert:                          r.TLSCert,
				TLSKey:                           r.TLSKey,
				TLSHTTPRedirect:                  r.TLSHTTPRedirect,
				EnableCompress:                   r.EnableCompress,
				CompressTypes:                    r.CompressTypes,
				EnableActiveHealthCheck:          r.EnableActiveHealthCheck,
				HostHeader:                       r.HostHeader,
				RequestBodyMaxSizeMB:             r.RequestBodyMaxSizeMB,
				UpstreamKeepaliveTimeout:         r.UpstreamKeepaliveTimeout,
				ServerTokensHidden:               r.ServerTokensHidden,
				GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
				GlobalUpstreamKeepaliveTimeout:   global.upstreamKeepaliveTimeout,
				GlobalServerTokensHidden:         global.serverTokensHidden,
				CustomRoutesEnabled:              r.CustomRoutesEnabled,
				PathRules:                        r.PathRules,
				ProxyDialTimeout:                 r.ProxyDialTimeout,
				ProxyResponseHeaderTimeout:       r.ProxyResponseHeaderTimeout,
				ProxyReadTimeout:                 r.ProxyReadTimeout,
				ProxyWriteTimeout:                r.ProxyWriteTimeout,
				ProxyStreamTimeout:               r.ProxyStreamTimeout,
				ProxyFlushInterval:               r.ProxyFlushInterval,
				ProxyStreamCloseDelay:            r.ProxyStreamCloseDelay,
				GlobalProxyDialTimeout:           global.proxyDialTimeout,
				GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
				GlobalProxyReadTimeout:           global.proxyReadTimeout,
				GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
				GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
				GlobalProxyFlushInterval:         global.proxyFlushInterval,
				GlobalProxyStreamCloseDelay:      global.proxyStreamCloseDelay,
			}
			for _, u := range ups {
				if u.Enabled {
					weight := u.Weight
					if weight == 0 {
						weight = 1
					}
					protocol := u.Protocol
					if protocol == "" {
						protocol = "http"
					}
					ruleConfig.Upstreams = append(ruleConfig.Upstreams, UpstreamConfig{
						Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
						MaxConnections: u.MaxConnections,
					})
				}
			}

			ruleRoutes, _, err := generateHTTPRouteObjects(ruleConfig)
			if err != nil {
				return generationFailure("generate HTTP routes for rule %s: %v", r.CaddyID, err)
			}
			for _, route := range ruleRoutes {
				routes = append(routes, route)
			}
		}

		server["routes"] = routes

		var errorRoutes []interface{}
		for _, ru := range rules {
			r := ru.rule
			if errorRoute := buildBlockPageErrorRoute(r.CaddyID, splitAndTrim(r.Domain)); errorRoute != nil {
				errorRoutes = append(errorRoutes, errorRoute)
			}
			if errorRoute := buildRateLimitErrorRoute(r.CaddyID, splitAndTrim(r.Domain)); errorRoute != nil {
				errorRoutes = append(errorRoutes, errorRoute)
			}
		}
		if len(errorRoutes) > 0 {
			server["errors"] = map[string]interface{}{"routes": errorRoutes}
		}

		// Configure TLS for manual and ACME certificates
		var tlsPolicies []interface{}
		for _, ru := range rules {
			r := ru.rule
			if _, hasCert := availableCerts[r.CaddyID]; hasCert {
				domainHosts := splitAndTrim(r.Domain)
				tlsPolicies = append(tlsPolicies, map[string]interface{}{
					"match": map[string]interface{}{
						"sni": domainHosts,
					},
					"certificate_selection": map[string]interface{}{
						"any_tag": []string{r.CaddyID},
					},
				})
			}
		}
		if len(tlsPolicies) > 0 {
			server["tls_connection_policies"] = tlsPolicies
		}

		// Add HTTPS server automatic HTTPS disable marker when using non-standard ports to avoid Caddy auto redirect conflicts
		if port != 443 && port != 80 {
			server["automatic_https"] = map[string]interface{}{
				"disable": true,
			}
		}

		servers[fmt.Sprintf("http_%d", port)] = server
	}

	// Collect HTTP->HTTPS redirect routes from all TLS-enabled rules and place them on the HTTP (port 80) server.
	var redirectRoutes []interface{}
	for _, ru := range allRules {
		r := ru.rule
		if len(ru.upstreams) == 0 {
			continue
		}
		if r.Protocol == "http" && r.EnableTLS && r.TLSHTTPRedirect {
			if r.TLSSource == "acme_dns" {
				if _, hasCert := availableCerts[r.CaddyID]; !hasCert {
					continue
				}
			}
			domainHosts := splitAndTrim(r.Domain)
			if len(domainHosts) > 0 {
				redirectRoutes = append(redirectRoutes, map[string]interface{}{
					"@id":      r.CaddyID + "_redirect",
					"terminal": true,
					"match": []interface{}{
						map[string]interface{}{
							"host": domainHosts,
						},
					},
					"handle": []interface{}{
						map[string]interface{}{
							"handler":     "static_response",
							"status_code": 301,
							"headers": map[string]interface{}{
								"Location": []string{httpsRedirectLocation(r.ListenPort)},
							},
						},
					},
				})
			}
		}
	}

	// Collect TLS certificate file paths for all rules (manual + ACME from cert_jobs)
	var tlsCertFiles []map[string]interface{}
	for _, ru := range allRules {
		r := ru.rule
		if !r.EnableTLS {
			continue
		}
		if _, hasCert := availableCerts[r.CaddyID]; hasCert {
			certPath, keyPath := CertFilePaths(r.CaddyID)
			tlsCertFiles = append(tlsCertFiles, map[string]interface{}{
				"certificate": certPath,
				"key":         keyPath,
				"tags":        []string{r.CaddyID},
			})
		}
	}

	layer4Servers := make(map[string]interface{})

	for port, rules := range tcpServersByPort {
		// Round 36 I-2: DynamicDNS 检测改为逐规则跳过（Round 35 误伤同端口其他规则）。
		filtered := rules[:0]
		for _, ru := range rules {
			if ru.rule.DynamicDNS {
				log.Printf("警告：TCP 规则 %s 启用了动态 DNS，但 TCP 协议暂不支持动态解析，已跳过该规则（不影响同端口其他规则）",
					ru.rule.CaddyID)
				continue
			}
			filtered = append(filtered, ru)
		}
		if len(filtered) == 0 {
			continue
		}
		rules = filtered

		// Round 36 I-3: TCP 同端口多规则禁止（用户决策）。Round 35 检测配置冲突跳过整个端口，
		// 但 upstreams 仍被盲目合并导致重复 upstream 双倍权重。改为直接拒绝并记告警。
		if len(rules) > 1 {
			ids := make([]string, 0, len(rules))
			for _, ru := range rules {
				ids = append(ids, ru.rule.CaddyID)
			}
			log.Printf("警告：端口 %d 上存在多条 TCP 规则（%s），TCP 协议要求每端口唯一规则，全部跳过。请删除多余规则或使用不同端口",
				port, strings.Join(ids, ", "))
			continue
		}

		r := rules[0].rule
		ruleConfig := SingleRuleConfig{
			CaddyID:                       r.CaddyID,
			Protocol:                      "tcp",
			ListenPort:                    r.ListenPort,
			Strategy:                      r.Strategy,
			HealthCheckInterval:           r.HealthCheckInterval,
			HealthCheckTimeout:            r.HealthCheckTimeout,
			HealthCheckUnhealthyThreshold: r.HealthCheckUnhealthyThreshold,
			HealthCheckHealthyThreshold:   r.HealthCheckHealthyThreshold,
			EnableActiveHealthCheck:       r.EnableActiveHealthCheck,
			TCPHealthCheckPort:            r.TCPHealthCheckPort,
			TCPProxyProtocol:              r.TCPProxyProtocol,
			TCPTryDuration:                r.TCPTryDuration,
			TCPTryInterval:                r.TCPTryInterval,
		}
		for _, ru := range rules {
			for _, u := range ru.upstreams {
				if !u.Enabled {
					continue
				}
				weight := u.Weight
				if weight <= 0 {
					weight = 1
				}
				ruleConfig.Upstreams = append(ruleConfig.Upstreams, UpstreamConfig{
					Host: u.Host, Port: u.Port, Weight: weight, Protocol: u.Protocol, Enabled: u.Enabled,
					MaxConnections: u.MaxConnections,
				})
			}
		}
		layer4Servers[fmt.Sprintf("tcp_%d", port)] = buildTCPServer(ruleConfig)
	}

	if len(servers) == 0 {
		servers = make(map[string]interface{})
	}

	defaultSite := map[string]interface{}{
		"listen": []string{":80"},
		"routes": []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					map[string]interface{}{
						"handler": "static_response",
						"body":    "Lazy Balancer V2 is running!",
					},
				},
			},
		},
	}
	applyTimeouts(defaultSite)

	if _, exists := servers["http_80"]; !exists {
		if len(redirectRoutes) > 0 {
			defaultSite["routes"] = append(redirectRoutes, defaultSite["routes"].([]interface{})...)
		}
		servers["http_80"] = defaultSite
	} else {
		server := servers["http_80"].(map[string]interface{})
		applyTimeouts(server)
		routes, ok := server["routes"].([]interface{})
		if !ok {
			routes = []interface{}{}
		}
		defaultRoute := map[string]interface{}{
			"handle": []interface{}{
				map[string]interface{}{
					"handler": "static_response",
					"body":    "Lazy Balancer V2 is running!",
				},
			},
		}
		// Ensure redirect routes come before the default catch-all route.
		if len(redirectRoutes) > 0 {
			routes = append(redirectRoutes, routes...)
		}
		routes = append(routes, defaultRoute)
		server["routes"] = routes
		servers["http_80"] = server
	}

	loggerNames := map[string]interface{}{}
	for _, ru := range allRules {
		r := ru.rule
		if !r.LogEnabled || r.Protocol != "http" || r.Domain == "" {
			continue
		}
		for _, d := range strings.Split(r.Domain, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				loggerNames[d] = "rule_" + r.CaddyID
			}
		}
	}
	if len(loggerNames) > 0 {
		for _, serverVal := range servers {
			srv, _ := serverVal.(map[string]interface{})
			if srv == nil {
				continue
			}
			srv["logs"] = map[string]interface{}{"logger_names": loggerNames}
		}
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"metrics": map[string]interface{}{
				"per_host":               true,
				"observe_catchall_hosts": true,
			},
			"servers": servers,
		},
	}

	if len(layer4Servers) > 0 {
		apps["layer4"] = map[string]interface{}{
			"servers": layer4Servers,
		}
	}

	// TLS app: load certificates from database (manual + ACME), no Caddy ACME automation.
	if len(tlsCertFiles) > 0 {
		tlsApp := map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_files": tlsCertFiles,
			},
		}
		apps["tls"] = tlsApp
	}

	logging := buildCaddyLogging(caddyLogLevel, caddyLogSizeMB)

	if logsMap, ok := logging["logs"].(map[string]interface{}); ok {
		var encoder map[string]interface{}
		if accessLogJSON {
			filterFields := parseAccessLogFormat(accessLogFormat)
			encoder = map[string]interface{}{
				"format": "filter",
				"wrap":   map[string]interface{}{"format": "json"},
				"fields": filterFields,
			}
		} else {
			encoder = map[string]interface{}{"format": "json"}
		}
		for _, ru := range allRules {
			r := ru.rule
			if !r.LogEnabled || r.Protocol != "http" {
				continue
			}
			os.MkdirAll(ruleLogDir, 0755)
			logsMap["rule_"+r.CaddyID] = map[string]interface{}{
				"writer": map[string]interface{}{
					"output":       "file",
					"filename":     RuleLogPath(r.CaddyID),
					"roll_size_mb": caddyLogSizeMB,
					"roll_keep":    5,
				},
				"encoder": encoder,
				"include": []string{"http.log.access.rule_" + r.CaddyID},
			}
		}
	}

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "127.0.0.1:2019",
		},
		"apps":    apps,
		"logging": logging,
	}
	if filesSnapshot != nil {
		conf[caddyCertFilesSnapshotKey] = filesSnapshot
	}
	if _, transactional := store.(*sql.Tx); transactional {
		conf[caddyConfigStoreKey] = store
	}

	return conf
}

func parseAccessLogFormat(format string) map[string]interface{} {
	fields := map[string]interface{}{}
	for _, line := range strings.Split(format, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "->", 2)
		if len(parts) != 2 {
			continue
		}
		path := strings.TrimSpace(parts[0])
		action := strings.TrimSpace(parts[1])
		if path == "" {
			continue
		}
		if action == "delete" {
			fields[path] = map[string]interface{}{"filter": "delete"}
		} else if action != "" {
			fields[path] = map[string]interface{}{"filter": "rename", "name": action}
		}
	}
	return fields
}

func buildCaddyLogging(level string, sizeMB int) map[string]interface{} {
	if level == "" {
		level = "info"
	}
	level = strings.ToUpper(level)
	if sizeMB <= 0 {
		sizeMB = 100
	}
	consoleEncoder := map[string]interface{}{"format": "console"}
	fileWriter := func(filename string) map[string]interface{} {
		return map[string]interface{}{
			"output":       "file",
			"filename":     filename,
			"roll_size_mb": sizeMB,
			"roll_keep":    5,
		}
	}
	return map[string]interface{}{
		"logs": map[string]interface{}{
			"default": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy.log"),
				"encoder": consoleEncoder,
				"exclude": []string{"http", "tls", "http.log.access"},
			},
			"caddy_tls": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy-tls.log"),
				"encoder": consoleEncoder,
				"include": []string{"tls"},
			},
			"caddy_server": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy-server.log"),
				"encoder": consoleEncoder,
				"exclude": []string{"admin", "tls", "events", "http.log.access", "http.handlers.reverse_proxy"},
			},
			"caddy_proxy": map[string]interface{}{
				"level":   level,
				"writer":  fileWriter("/app/logs/caddy-proxy.log"),
				"encoder": consoleEncoder,
				"include": []string{"http.handlers.reverse_proxy"},
			},
		},
	}
}

// loadACMECertificate reads the issued ACME certificate and key from cert_jobs
// for the given rule and domain. Returns (certPEM, keyPEM, true) if issued.
func loadACMECertificateFromStore(store caddyConfigStore, caddyID, domain string) (string, string, bool) {
	rows, err := store.Query(`
		SELECT id, domain, status, cert_pem, key_pem,
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
		FROM cert_jobs
		WHERE rule_id=?
		  AND cert_pem IS NOT NULL AND cert_pem <> ''
		  AND key_pem IS NOT NULL AND key_pem <> ''
		ORDER BY updated_at DESC, id DESC`, caddyID)
	if err != nil {
		log.Printf("loadACMECertificate: query failed for rule %s: %v", caddyID, err)
		return "", "", false
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Domain, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); err != nil {
			return "", "", false
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return "", "", false
	}
	selected, ok := SelectCertificate(candidates, domain, time.Now())
	if ok {
		return selected.Candidate.CertPEM, selected.Candidate.KeyPEM, true
	}
	return "", "", false
}

// IsACMECertIssued returns true if cert_jobs has an issued certificate for the
// given rule (by caddy_id) and domain.
func IsACMECertIssued(caddyID, domain string) bool {
	return isACMECertIssuedFromStore(db.DB, caddyID, domain)
}

func isACMECertIssuedFromStore(store caddyConfigStore, caddyID, domain string) bool {
	_, _, issued := loadACMECertificateFromStore(store, caddyID, domain)
	return issued
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// httpsRedirectLocation 构造 HTTP→HTTPS 跳转的 Location 头。
// 使用 {http.request.host} 占位符而非首个域名字面量：Caddy static_response
// 的 headers 会在运行时经过 replacer 替换（v2.11.4 modules/caddyhttp/staticresp.go），
// 因此多域名规则（a.com,b.com）访问 b.com 时会跳回 b.com，而不是被劫持到首个域名。
func httpsRedirectLocation(listenPort int) string {
	if listenPort != 443 {
		return fmt.Sprintf("https://{http.request.host}:%d", listenPort)
	}
	return "https://{http.request.host}"
}

type SingleRuleConfig struct {
	CaddyID                          string
	Protocol                         string
	Domain                           string
	ListenPort                       int
	Strategy                         string
	DynamicDNS                       bool
	EnableDnsServer                  bool
	DnsServer                        string
	DnsFamily                        string
	HealthCheckPath                  string
	HealthCheckInterval              int
	HealthCheckTimeout               int
	HealthCheckUnhealthyThreshold    int
	HealthCheckHealthyThreshold      int
	EnableTLS                        bool
	TLSSource                        string
	ACMEConfigID                     int
	TLSCert                          string
	TLSKey                           string
	TLSHTTPRedirect                  bool
	EnableCompress                   bool
	CompressTypes                    string
	EnableActiveHealthCheck          bool
	TCPHealthCheckPort               int
	TCPProxyProtocol                 bool
	TCPTryDuration                   int
	TCPTryInterval                   int
	RequestBodyMaxSizeMB             int
	UpstreamKeepaliveTimeout         int
	ServerTokensHidden               int
	GlobalRequestBodyMaxSizeMB       int
	GlobalUpstreamKeepaliveTimeout   int
	GlobalServerTokensHidden         bool
	HostHeader                       string
	CustomRoutesEnabled              bool
	PathRules                        []PathRuleConfig
	ProxyDialTimeout                 int
	ProxyResponseHeaderTimeout       int
	ProxyReadTimeout                 int
	ProxyWriteTimeout                int
	ProxyStreamTimeout               int
	ProxyFlushInterval               int
	ProxyStreamCloseDelay            int
	GlobalProxyDialTimeout           int
	GlobalProxyResponseHeaderTimeout int
	GlobalProxyReadTimeout           int
	GlobalProxyWriteTimeout          int
	GlobalProxyStreamTimeout         int
	GlobalProxyFlushInterval         int
	GlobalProxyStreamCloseDelay      int
	Upstreams                        []UpstreamConfig
}

type PathRuleConfig struct {
	SortOrder int
	MatchType string
	Path      string
	Upstreams []UpstreamConfig
}

type proxyTimeouts struct {
	dial             int
	responseHeader   int
	read             int
	write            int
	stream           int
	flushInterval    int
	streamCloseDelay int
}

type UpstreamConfig struct {
	Host           string
	Port           int
	Weight         int
	Protocol       string
	Enabled        bool
	MaxConnections int
}

func resolveRuleOverrides(rule SingleRuleConfig) (requestBodyMaxSizeMB int, upstreamKeepalive int, hideServer bool) {
	requestBodyMaxSizeMB = rule.RequestBodyMaxSizeMB
	if requestBodyMaxSizeMB <= 0 {
		requestBodyMaxSizeMB = rule.GlobalRequestBodyMaxSizeMB
	}

	upstreamKeepalive = rule.UpstreamKeepaliveTimeout
	if upstreamKeepalive <= 0 {
		upstreamKeepalive = rule.GlobalUpstreamKeepaliveTimeout
	}

	hideServer = rule.GlobalServerTokensHidden
	if rule.ServerTokensHidden == 1 {
		hideServer = true
	} else if rule.ServerTokensHidden == 2 {
		hideServer = false
	}

	return requestBodyMaxSizeMB, upstreamKeepalive, hideServer
}

func resolveProxyTimeouts(rule SingleRuleConfig) proxyTimeouts {
	resolve := func(ruleValue, globalValue int) int {
		if ruleValue > 0 {
			return ruleValue
		}
		if globalValue > 0 {
			return globalValue
		}
		return 0
	}
	// flush_interval treats -1 as a meaningful "immediate flush" sentinel, not "unset".
	// Any non-zero rule value wins; otherwise fall back to a non-zero global value.
	resolveFlush := func(ruleValue, globalValue int) int {
		if ruleValue != 0 {
			return ruleValue
		}
		if globalValue != 0 {
			return globalValue
		}
		return 0
	}

	return proxyTimeouts{
		dial:             resolve(rule.ProxyDialTimeout, rule.GlobalProxyDialTimeout),
		responseHeader:   resolve(rule.ProxyResponseHeaderTimeout, rule.GlobalProxyResponseHeaderTimeout),
		read:             resolve(rule.ProxyReadTimeout, rule.GlobalProxyReadTimeout),
		write:            resolve(rule.ProxyWriteTimeout, rule.GlobalProxyWriteTimeout),
		stream:           resolve(rule.ProxyStreamTimeout, rule.GlobalProxyStreamTimeout),
		flushInterval:    resolveFlush(rule.ProxyFlushInterval, rule.GlobalProxyFlushInterval),
		streamCloseDelay: resolve(rule.ProxyStreamCloseDelay, rule.GlobalProxyStreamCloseDelay),
	}
}

// formatFlushInterval renders proxy_flush_interval for Caddy JSON:
// -1 → "-1s" (immediate flush, disables buffering); N>0 → "Ns".
func formatFlushInterval(v int) string {
	if v < 0 {
		return "-1s"
	}
	return fmt.Sprintf("%ds", v)
}

func GenerateSingleRuleCaddyConfig(rule SingleRuleConfig) map[string]interface{} {
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
	}

	enabledUpstreams := make([]UpstreamConfig, 0)
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreams = append(enabledUpstreams, u)
		}
	}

	if len(enabledUpstreams) == 0 {
		return map[string]interface{}{
			"error": "no enabled upstreams",
		}
	}
	if rule.DynamicDNS && len(enabledUpstreams) > 1 {
		return map[string]interface{}{
			"error": fmt.Sprintf("dynamic DNS requires exactly one enabled upstream, got %d", len(enabledUpstreams)),
		}
	}

	servers := make(map[string]interface{})

	if rule.Protocol == "http" {
		domainHosts := splitAndTrim(rule.Domain)

		// 委托生产路径的构建器生成路由对象（GeoIP + 路径路由 + 主路由），
		// 避免与 generateCaddyConfigFromStore 的逻辑分叉。
		routes, _, err := generateHTTPRouteObjects(rule)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}

		// HTTP→HTTPS 跳转路由插在 GeoIP 路由之后、路径/主路由之前：地区拦截
		// 优先级高于跳转。generateHTTPRouteObjects 已将 GeoIP 路由前置到头部。
		if rule.EnableTLS && rule.TLSHTTPRedirect && len(domainHosts) > 0 {
			geoipCount := 0
			if policy := GetSecurityPolicyForRule(rule.CaddyID); PolicyHasGeoIP(policy) {
				geoipCount = 2 // pass route + block route
			}
			redirectRoute := map[string]interface{}{
				"match": []interface{}{
					map[string]interface{}{
						"host": domainHosts,
					},
				},
				"handle": []interface{}{
					map[string]interface{}{
						"handler":     "static_response",
						"status_code": 301,
						"headers": map[string]interface{}{
							"Location": []string{httpsRedirectLocation(rule.ListenPort)},
						},
					},
				},
				"terminal": true,
			}
			tagRuleRoute(redirectRoute, rule.CaddyID, "redirect")
			withRedirect := make([]map[string]interface{}, 0, len(routes)+1)
			withRedirect = append(withRedirect, routes[:geoipCount]...)
			withRedirect = append(withRedirect, redirectRoute)
			withRedirect = append(withRedirect, routes[geoipCount:]...)
			routes = withRedirect
		}

		routeValues := make([]interface{}, len(routes))
		for i, r := range routes {
			routeValues[i] = r
		}

		serverName := fmt.Sprintf("http_%d", rule.ListenPort)

		server := map[string]interface{}{
			"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
			"routes": routeValues,
		}

		// Add TLS configuration for manual certificates
		if rule.EnableTLS && rule.TLSSource == "manual" && rule.TLSCert != "" && rule.TLSKey != "" {
			server["tls_connection_policies"] = []interface{}{
				map[string]interface{}{
					"match": map[string]interface{}{
						"sni": domainHosts,
					},
					"certificate_selection": map[string]interface{}{
						"any_tag": []string{rule.CaddyID},
					},
				},
			}
		}

		if rule.ListenPort != 443 && rule.ListenPort != 80 {
			server["automatic_https"] = map[string]interface{}{
				"disable": true,
			}
		}

		servers[serverName] = server
	} else {
		apps := map[string]interface{}{
			"layer4": map[string]interface{}{
				"servers": map[string]interface{}{
					fmt.Sprintf("tcp_%d", rule.ListenPort): buildTCPServer(rule),
				},
			},
		}

		conf := map[string]interface{}{
			"admin": map[string]interface{}{
				"listen": "127.0.0.1:2019",
			},
			"apps": apps,
		}

		return conf
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"servers": servers,
		},
	}

	// Add TLS certificates configuration for manual certificates
	if rule.EnableTLS && rule.TLSSource == "manual" && rule.TLSCert != "" && rule.TLSKey != "" {
		apps["tls"] = map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_pem": []map[string]interface{}{
					{
						"certificate": rule.TLSCert,
						"key":         rule.TLSKey,
						"tags":        []string{rule.CaddyID},
					},
				},
			},
		}
	}

	conf := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "127.0.0.1:2019",
		},
		"apps": apps,
	}

	return conf
}

// GenerateRouteObject generates a Caddy route object (not full config) for a single rule.
func GenerateRouteObject(rule SingleRuleConfig) (map[string]interface{}, error) {
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
	}
	if rule.Protocol == "tcp" {
		return buildTCPProxyRoute(rule), nil
	}
	if rule.Protocol != "http" && rule.Protocol != "https" {
		return nil, fmt.Errorf("unsupported protocol: %s", rule.Protocol)
	}

	routes, mainRoute, err := generateHTTPRouteObjects(rule)
	if err != nil {
		return nil, err
	}
	if len(routes) == 1 {
		return mainRoute, nil
	}

	for _, route := range routes {
		delete(route, "@id")
	}
	nestedRoutes := make([]interface{}, len(routes))
	for i, route := range routes {
		nestedRoutes[i] = route
	}
	domainHosts := splitAndTrim(rule.Domain)
	wrapper := map[string]interface{}{
		"match": []interface{}{map[string]interface{}{"host": domainHosts}},
		"handle": []interface{}{
			map[string]interface{}{
				"handler": "subroute",
				"routes":  nestedRoutes,
			},
		},
	}
	if rule.CaddyID != "" {
		wrapper["@id"] = rule.CaddyID
	}
	return wrapper, nil
}

func generateHTTPRouteObjects(rule SingleRuleConfig) ([]map[string]interface{}, map[string]interface{}, error) {
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
	}
	domainHosts := splitAndTrim(rule.Domain)
	mainHandle, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		return nil, nil, err
	}

	mainMatcher := map[string]interface{}{"host": domainHosts}
	mainRoute := map[string]interface{}{
		"match":    []interface{}{mainMatcher},
		"handle":   mainHandle,
		"terminal": true,
	}
	if rule.CaddyID != "" {
		mainRoute["@id"] = rule.CaddyID
	}

	routes := make([]map[string]interface{}, 0, len(rule.PathRules)+4)
	// GeoIP routes run before path rules and the main route: the pass route
	// populates the region placeholders, then the block route rejects matches.
	if policy := GetSecurityPolicyForRule(rule.CaddyID); PolicyHasGeoIP(policy) {
		routes = append(routes, buildGeoipPassRoute(domainHosts, policy))
		statusCode := policy.BlockStatusCode
		if statusCode == 0 {
			statusCode = 403
		}
		if blockRoute := buildGeoipBlockRoute(rule, policy, statusCode); blockRoute != nil {
			routes = append(routes, blockRoute)
		}
	}
	if rule.CustomRoutesEnabled {
		pathRules := append([]PathRuleConfig(nil), rule.PathRules...)
		sort.SliceStable(pathRules, func(i, j int) bool {
			return pathRules[i].SortOrder < pathRules[j].SortOrder
		})
		for pathIndex, pathRule := range pathRules {
			upstreams := pathRule.Upstreams
			if upstreams == nil {
				upstreams = rule.Upstreams
			}
			handle, handleErr := buildHTTPHandleChain(rule, upstreams)
			if handleErr != nil {
				return nil, nil, handleErr
			}
			matcher := map[string]interface{}{
				"host": domainHosts,
				"path": pathMatcherSpecs(pathRule),
			}
			pathRoute := map[string]interface{}{
				"match":    []interface{}{matcher},
				"handle":   handle,
				"terminal": true,
			}
			tagRuleRoute(pathRoute, rule.CaddyID, fmt.Sprintf("path_%d", pathIndex))
			routes = append(routes, pathRoute)
		}
	}
	routes = append(routes, mainRoute)
	return routes, mainRoute, nil
}

func tagRuleRoute(route map[string]interface{}, ruleID, suffix string) {
	if ruleID != "" {
		route["@id"] = ruleID + "_" + suffix
	}
}

func pathMatcherSpecs(pathRule PathRuleConfig) []string {
	if pathRule.MatchType != "prefix" {
		return []string{pathRule.Path}
	}
	root := strings.TrimRight(pathRule.Path, "/*")
	if root == "" {
		return []string{"/*"}
	}
	return []string{root, root + "/*"}
}

func joinUpstreamAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func decodePathUpstreams(raw string) ([]UpstreamConfig, error) {
	var stored []struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Weight   int    `json:"weight"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil, err
	}
	upstreams := make([]UpstreamConfig, 0, len(stored))
	for _, item := range stored {
		protocol := item.Protocol
		if protocol == "" {
			protocol = "http"
		}
		upstreams = append(upstreams, UpstreamConfig{
			Host: item.Address, Port: item.Port, Weight: item.Weight, Protocol: protocol, Enabled: true,
		})
	}
	return upstreams, nil
}

// buildBlockPageErrorRoute returns a server-level error route rendering the
// branded block page of the rule's bound active policy, or nil when the rule
// has no policy, no block page, or the stored page has no content.
func buildBlockPageErrorRoute(ruleCaddyID string, domainHosts []string) map[string]interface{} {
	if db.DB == nil {
		return nil
	}
	var content string
	var statusCode int
	err := db.DB.QueryRow(`SELECT bp.content, COALESCE(NULLIF(p.block_status_code, 0), 403)
		FROM security_policy_bindings b
		JOIN security_policies p ON p.id = b.policy_id AND p.enabled = 1
		JOIN security_block_pages bp ON bp.id = p.block_page_id
		WHERE b.rule_caddy_id = ? AND p.block_page_id > 0
		ORDER BY b.policy_id DESC LIMIT 1`, ruleCaddyID).Scan(&content, &statusCode)
	if err != nil || content == "" {
		return nil
	}
	// coraza 命中恒以 403 + "interruption triggered" 中断；GeoIP 拦截链经 error
	// handler 以 block_status_code + "GeoIP blocked" 中断。两者共用同一品牌拦截页，
	// 故匹配表达式需同时覆盖两种状态码与消息。
	expression := fmt.Sprintf("({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered') || ({http.error.status_code} == %d && {http.error.message} == 'GeoIP blocked')", statusCode)
	return map[string]interface{}{
		"match": []interface{}{
			map[string]interface{}{
				"host":       domainHosts,
				"expression": expression,
			},
		},
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"body":        content,
				"status_code": statusCode,
				"headers": map[string]interface{}{
					"Content-Type": []string{"text/html; charset=utf-8"},
				},
			},
		},
		"terminal": true,
	}
}

// buildRateLimitErrorRoute returns a server-level error route rendering the
// bound policy's block page for rate-limited (429) requests, or nil when the
// rule's bound active policy has no block page.
// caddy-ratelimit rejects via caddyhttp.Error(429), so handle_errors fires.
func buildRateLimitErrorRoute(ruleCaddyID string, domainHosts []string) map[string]interface{} {
	if db.DB == nil {
		return nil
	}
	var content string
	var statusCode int
	err := db.DB.QueryRow(`SELECT bp.content, COALESCE(NULLIF(p.block_status_code, 0), 429)
		FROM security_policy_bindings b
		JOIN security_policies p ON p.id = b.policy_id AND p.enabled = 1
		JOIN security_block_pages bp ON bp.id = p.block_page_id
		WHERE b.rule_caddy_id = ? AND p.block_page_id > 0 AND p.rate_limit_enabled = 1
		ORDER BY b.policy_id DESC LIMIT 1`, ruleCaddyID).Scan(&content, &statusCode)
	if err != nil || content == "" {
		return nil
	}
	return map[string]interface{}{
		"match": []interface{}{
			map[string]interface{}{
				"host":       domainHosts,
				"expression": "{http.error.status_code} == 429",
			},
		},
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"body":        content,
				"status_code": statusCode,
				"headers": map[string]interface{}{
					"Content-Type": []string{"text/html; charset=utf-8"},
				},
			},
		},
		"terminal": true,
	}
}

// buildRateLimitHandler returns the rate_limit handler for a rule whose bound
// active policy enables rate limiting, or nil otherwise. Zones are logical AND:
// with burst > 0 a per-second zone caps instantaneous rate at rps+burst while a
// per-minute zone caps sustained rate at rps; without burst a single per-second
// zone caps at rps.
func buildRateLimitHandler(ruleCaddyID string) map[string]interface{} {
	if db.DB == nil {
		return nil
	}
	policy := GetSecurityPolicyForRule(ruleCaddyID)
	if policy == nil || !policy.RateLimitEnabled || policy.RateLimitRPS <= 0 {
		return nil
	}
	rateLimits := map[string]interface{}{
		ruleCaddyID: map[string]interface{}{
			"key":            "{http.request.remote.host}",
			"window":         "1s",
			"max_events":     policy.RateLimitRPS,
			"sweep_interval": "10m",
		},
	}
	if policy.RateLimitBurst > 0 {
		rateLimits = map[string]interface{}{
			ruleCaddyID + "-sec": map[string]interface{}{
				"key":            "{http.request.remote.host}",
				"window":         "1s",
				"max_events":     policy.RateLimitRPS + policy.RateLimitBurst,
				"sweep_interval": "10m",
			},
			ruleCaddyID + "-min": map[string]interface{}{
				"key":            "{http.request.remote.host}",
				"window":         "60s",
				"max_events":     policy.RateLimitRPS * 60,
				"sweep_interval": "10m",
			},
		}
	}
	return map[string]interface{}{
		"handler":     "rate_limit",
		"rate_limits": rateLimits,
	}
}

// buildGeoipHandler returns the geoip2region handler, or nil when geoip is disabled.
func buildGeoipHandler(policy *models.SecurityPolicy) map[string]interface{} {
	if !PolicyHasGeoIP(policy) {
		return nil
	}
	return map[string]interface{}{"handler": "geoip2region"}
}

// buildGeoipPassRoute populates the region placeholders before the block matcher evaluates.
func buildGeoipPassRoute(domainHosts []string, policy *models.SecurityPolicy) map[string]interface{} {
	return map[string]interface{}{
		"match":  []interface{}{map[string]interface{}{"host": domainHosts}},
		"handle": []interface{}{buildGeoipHandler(policy)},
	}
}

// geoipPrivateRanges 内网/回环/链路本地 CIDR 集合。这些地址无法经 ip2region 解析到国家，
// fail-closed 会将其误判为“海外”而拦截，故在 GeoIP 拦截链中一律放行（无论 deny/allow 模式）。
// ::ffff: 前缀条目仅为 IPv4 映射的私网/回环/链路本地地址（双栈 RemoteAddr 的 16 字节形态），
// 而非整个 ::ffff:0:0/96 映射空间——否则公网映射地址（如 ::ffff:8.8.8.8）也会被误放行。
var geoipPrivateRanges = []string{
	"10.0.0.0/8",             // RFC1918 私网 A 类
	"172.16.0.0/12",          // RFC1918 私网 B 类
	"192.168.0.0/16",         // RFC1918 私网 C 类
	"127.0.0.0/8",            // IPv4 回环
	"169.254.0.0/16",         // IPv4 链路本地
	"::ffff:10.0.0.0/104",    // IPv4 映射私网 A 类（10.0.0.0/8）
	"::ffff:172.16.0.0/108",  // IPv4 映射私网 B 类（172.16.0.0/12）
	"::ffff:192.168.0.0/112", // IPv4 映射私网 C 类（192.168.0.0/16）
	"::ffff:127.0.0.0/104",   // IPv4 映射回环（127.0.0.0/8）
	"::ffff:169.254.0.0/112", // IPv4 映射链路本地（169.254.0.0/16）
	"::1/128",                // IPv6 回环
	"fc00::/7",               // IPv6 唯一本地地址 (ULA)
	"fe80::/10",              // IPv6 链路本地
}

// buildGeoipBlockRoute returns a terminal error route for matched (deny) or non-matched (allow)
// regions. statusCode 为策略拦截状态码（block_status_code 非零时取之，否则 403），与
// buildBlockPageErrorRoute 的匹配表达式保持一致，从而复用品牌拦截页。
func buildGeoipBlockRoute(rule SingleRuleConfig, policy *models.SecurityPolicy, statusCode int) map[string]interface{} {
	if !PolicyHasGeoIP(policy) {
		return nil
	}
	expr := buildGeoipMatchExpression(policy)
	if expr == "" {
		return nil
	}
	// Caddy match 数组语义：数组内各元素是“集合”，集合之间按 OR 组合；同一集合内的
	// 各匹配器（host/expression/not）按 AND 组合。内网放行（not remote_ip in 内网）
	// 必须并入 host/expression 所在的同一集合：若拆成第二个集合，集合间 OR 会让
	// “非内网”对公网请求恒为真，导致 GeoIP 开启即拦截全部公网流量（内网放行意图
	// 也一并失效）。三者 AND 后，仅当 host 命中且表达式命中且非内网时才会拦截。
	return map[string]interface{}{
		"match": []interface{}{
			map[string]interface{}{
				"host":       splitAndTrim(rule.Domain),
				"expression": expr,
				"not": []interface{}{
					map[string]interface{}{
						"remote_ip": map[string]interface{}{
							"ranges": geoipPrivateRanges,
						},
					},
				},
			},
		},
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "error",
				"status_code": statusCode,
				"error":       "GeoIP blocked",
			},
		},
		"terminal": true,
	}
}

// buildGeoipMatchExpression compiles geoip countries into a CEL expression over placeholders.
func buildGeoipMatchExpression(policy *models.SecurityPolicy) string {
	countries := geoipCountries(policy)
	if len(countries) == 0 {
		return ""
	}
	parts := make([]string, 0, len(countries))
	for _, country := range countries {
		if country == "海外" {
			parts = append(parts, `{http.vars.geoip.country_name} != "中国"`)
			continue
		}
		parts = append(parts, fmt.Sprintf(`{http.vars.geoip.province} == %q`, country))
	}
	expr := strings.Join(parts, " || ")
	if policy.GeoIPMode == "allow" {
		expr = "!(" + expr + ")"
	}
	return expr
}

func buildHTTPHandleChain(rule SingleRuleConfig, upstreams []UpstreamConfig) ([]interface{}, error) {
	enabledUpstreams := make([]UpstreamConfig, 0, len(upstreams))
	for _, upstream := range upstreams {
		if upstream.Enabled {
			enabledUpstreams = append(enabledUpstreams, upstream)
		}
	}
	if len(enabledUpstreams) == 0 {
		return nil, fmt.Errorf("no enabled upstreams")
	}
	if rule.DynamicDNS && len(enabledUpstreams) > 1 {
		return nil, fmt.Errorf("dynamic DNS requires exactly one enabled upstream, got %d", len(enabledUpstreams))
	}

	var handleChain []interface{}
	// Rate limiting runs before WAF inspection, body parsing, and proxying.
	if rateLimitHandler := buildRateLimitHandler(rule.CaddyID); rateLimitHandler != nil {
		handleChain = append(handleChain, rateLimitHandler)
	}
	// WAF inspection must run before body parsing and proxying.
	if wafHandler := buildWafHandler(rule.CaddyID); wafHandler != nil {
		handleChain = append(handleChain, wafHandler)
	}
	effectiveRequestBodyMaxSizeMB, effectiveUpstreamKeepaliveTimeout, effectiveServerTokensHidden := resolveRuleOverrides(rule)
	if effectiveRequestBodyMaxSizeMB > 0 {
		handleChain = append(handleChain, map[string]interface{}{
			"handler":  "request_body",
			"max_size": int64(effectiveRequestBodyMaxSizeMB) * 1024 * 1024,
		})
	}

	upstreamList := make([]interface{}, 0, len(enabledUpstreams))
	upstreamWeights := make([]int, 0, len(enabledUpstreams))
	hasHTTPSUpstream := false
	for _, upstream := range enabledUpstreams {
		weight := upstream.Weight
		if weight <= 0 {
			weight = 1
		}
		upstreamWeights = append(upstreamWeights, weight)
		if rule.DynamicDNS {
			versions := map[string]bool{"ipv4": false, "ipv6": false}
			switch rule.DnsFamily {
			case "ipv4":
				versions["ipv4"] = true
			case "ipv6":
				versions["ipv6"] = true
			case "both":
				versions["ipv4"] = true
				versions["ipv6"] = true
			}
			upstreamEntry := map[string]interface{}{
				"source":   "a",
				"name":     upstream.Host,
				"port":     fmt.Sprintf("%d", upstream.Port),
				"versions": versions,
			}
			if rule.EnableDnsServer && rule.DnsServer != "" {
				upstreamEntry["resolver"] = map[string]interface{}{
					"addresses": []string{rule.DnsServer},
				}
			}
			upstreamList = append(upstreamList, upstreamEntry)
		} else {
			entry := map[string]interface{}{"dial": joinUpstreamAddress(upstream.Host, upstream.Port)}
			if upstream.MaxConnections > 0 {
				entry["max_requests"] = upstream.MaxConnections
			}
			upstreamList = append(upstreamList, entry)
		}
		if upstream.Protocol == "https" {
			hasHTTPSUpstream = true
		}
	}

	if rule.EnableCompress && rule.CompressTypes != "" {
		encodings := make(map[string]interface{})
		for _, contentType := range splitAndTrim(rule.CompressTypes) {
			if contentType == "gzip" || contentType == "zstd" {
				encodings[contentType] = map[string]interface{}{}
			}
		}
		if len(encodings) > 0 {
			handleChain = append(handleChain, map[string]interface{}{
				"handler":        "encode",
				"encodings":      encodings,
				"minimum_length": 512,
			})
		}
	}

	proxyConfig := map[string]interface{}{"handler": "reverse_proxy"}
	if rule.DynamicDNS {
		proxyConfig["dynamic_upstreams"] = upstreamList[0]
	} else {
		proxyConfig["upstreams"] = upstreamList
	}
	if rule.Strategy != "" {
		selectionPolicy := map[string]interface{}{"policy": rule.Strategy}
		if rule.Strategy == "cookie" {
			selectionPolicy["name"] = "lb_sticky"
		}
		if rule.Strategy == "weighted_round_robin" {
			selectionPolicy["weights"] = normalizeWeights(upstreamWeights)
		}
		proxyConfig["load_balancing"] = map[string]interface{}{
			"selection_policy": selectionPolicy,
			"try_duration":     "5s",
			"try_interval":     "250ms",
		}
	}

	if rule.Protocol == "http" {
		hcInterval := rule.HealthCheckInterval
		if hcInterval <= 0 {
			hcInterval = 10
		}
		hcThreshold := rule.HealthCheckUnhealthyThreshold
		if hcThreshold <= 0 {
			hcThreshold = 3
		}
		healthChecks := map[string]interface{}{
			"passive": map[string]interface{}{
				"fail_duration":    fmt.Sprintf("%ds", hcInterval*3),
				"max_fails":        hcThreshold,
				"unhealthy_status": []int{5},
			},
		}
		if rule.EnableActiveHealthCheck {
			hcPath := rule.HealthCheckPath
			if hcPath == "" {
				hcPath = "/"
			}
			hcPasses := rule.HealthCheckHealthyThreshold
			if hcPasses <= 0 {
				hcPasses = 2
			}
			active := map[string]interface{}{
				"uri":      hcPath,
				"timeout":  fmt.Sprintf("%ds", rule.HealthCheckTimeout),
				"interval": fmt.Sprintf("%ds", rule.HealthCheckInterval),
				"passes":   hcPasses,
				"fails":    hcThreshold,
			}
			if rule.HostHeader != "" {
				active["headers"] = map[string]interface{}{"Host": []string{rule.HostHeader}}
			}
			healthChecks["active"] = active
		}
		proxyConfig["health_checks"] = healthChecks
	}

	timeouts := resolveProxyTimeouts(rule)
	if timeouts.stream > 0 {
		proxyConfig["stream_timeout"] = fmt.Sprintf("%ds", timeouts.stream)
	}
	if timeouts.flushInterval != 0 {
		proxyConfig["flush_interval"] = formatFlushInterval(timeouts.flushInterval)
	}
	if timeouts.streamCloseDelay > 0 {
		proxyConfig["stream_close_delay"] = fmt.Sprintf("%ds", timeouts.streamCloseDelay)
	}
	needsTransport := hasHTTPSUpstream || rule.EnableDnsServer || effectiveUpstreamKeepaliveTimeout > 0 || timeouts.dial > 0 || timeouts.responseHeader > 0 || timeouts.read > 0 || timeouts.write > 0
	if needsTransport {
		transportConfig := map[string]interface{}{"protocol": "http"}
		if hasHTTPSUpstream {
			transportConfig["tls"] = map[string]interface{}{
				"insecure_skip_verify": true,
				"server_name":          rule.HostHeader,
			}
		}
		if rule.EnableDnsServer && rule.DnsServer != "" {
			transportConfig["resolver"] = map[string]interface{}{"addresses": []string{rule.DnsServer}}
		}
		if timeouts.dial > 0 {
			transportConfig["dial_timeout"] = fmt.Sprintf("%ds", timeouts.dial)
		}
		if timeouts.responseHeader > 0 {
			transportConfig["response_header_timeout"] = fmt.Sprintf("%ds", timeouts.responseHeader)
		}
		if timeouts.read > 0 {
			transportConfig["read_timeout"] = fmt.Sprintf("%ds", timeouts.read)
		}
		if timeouts.write > 0 {
			transportConfig["write_timeout"] = fmt.Sprintf("%ds", timeouts.write)
		}
		if effectiveUpstreamKeepaliveTimeout > 0 {
			transportConfig["keep_alive"] = map[string]interface{}{
				"idle_timeout": fmt.Sprintf("%ds", effectiveUpstreamKeepaliveTimeout),
			}
		}
		proxyConfig["transport"] = transportConfig
	}
	if rule.HostHeader != "" {
		proxyConfig["headers"] = map[string]interface{}{
			"request": map[string]interface{}{
				"set": map[string]interface{}{"Host": []string{rule.HostHeader}},
			},
		}
	}
	if effectiveServerTokensHidden {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "headers",
			// deferred 必须为 true：非 deferred 的 response 头操作在路由调度阶段
			// （reverse_proxy 执行之前）应用，reverseproxy 的 copyHeader 复制上游
			// 响应头时会把上游的 Server 头重新写回，隐藏永远不生效；deferred 使
			// 删除推迟到上游响应写入之后（Caddy v2.11.4 headers.go + reverseproxy.go）。
			"response": map[string]interface{}{"deferred": true, "delete": []string{"Server"}},
		})
	}
	handleChain = append(handleChain, proxyConfig)
	return handleChain, nil
}

// ApplyConfigFromTx renders the Caddy config from an uncommitted transaction
// and applies it, keeping the database unchanged when Caddy rejects the config.
func (s *CaddyService) ApplyConfigFromTx(tx *sql.Tx) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLocked(generateCaddyConfigFromStore(tx))
}

func normalizeWeights(weights []int) []int {
	g := 0
	for _, w := range weights {
		if w <= 0 {
			continue
		}
		if g == 0 {
			g = w
		} else {
			for w > 0 {
				g, w = w, g%w
			}
		}
	}
	if g <= 1 {
		return weights
	}
	out := make([]int, len(weights))
	for i, w := range weights {
		if w > 0 {
			out[i] = w / g
		}
	}
	return out
}

// buildTCPProxyRoute generates the layer4 proxy handler and route for a TCP rule.
func buildTCPProxyRoute(rule SingleRuleConfig) map[string]interface{} {
	upstreamList := make([]interface{}, 0)
	for _, u := range rule.Upstreams {
		if !u.Enabled {
			continue
		}
		dial := joinUpstreamAddress(u.Host, u.Port)
		upstreamEntry := map[string]interface{}{
			"dial": []string{dial},
		}
		weight := u.Weight
		if weight > 1 {
			upstreamEntry["weight"] = weight
		}
		if u.Protocol == "https" || u.Protocol == "tls" {
			upstreamEntry["tls"] = map[string]interface{}{
				"insecure_skip_verify": true,
			}
		}
		if u.MaxConnections > 0 {
			upstreamEntry["max_connections"] = u.MaxConnections
		}
		upstreamList = append(upstreamList, upstreamEntry)
	}

	strategy := rule.Strategy
	if strategy == "" {
		strategy = "weighted_round_robin"
	}
	if strategy == "cookie" {
		strategy = "weighted_round_robin"
	}

	proxyHandler := map[string]interface{}{
		"handler":   "proxy",
		"upstreams": upstreamList,
	}
	if rule.TCPProxyProtocol {
		proxyHandler["proxy_protocol"] = "v2"
	}

	loadBalancing := map[string]interface{}{
		"selection": map[string]interface{}{
			"policy": strategy,
		},
	}
	// Default to retrying on other upstreams so a connection routed to a
	// dead upstream fails over transparently instead of erroring to the
	// client; rule-level values override when set.
	tryDuration := rule.TCPTryDuration
	if tryDuration <= 0 {
		tryDuration = 5000
	}
	tryInterval := rule.TCPTryInterval
	if tryInterval <= 0 {
		tryInterval = 250
	}
	loadBalancing["try_duration"] = fmt.Sprintf("%dms", tryDuration)
	loadBalancing["try_interval"] = fmt.Sprintf("%dms", tryInterval)
	if len(upstreamList) > 1 || rule.TCPTryDuration > 0 || rule.TCPTryInterval > 0 {
		proxyHandler["load_balancing"] = loadBalancing
	}

	healthCheckInterval := rule.HealthCheckInterval
	if healthCheckInterval <= 0 {
		healthCheckInterval = 10
	}
	unhealthyThreshold := rule.HealthCheckUnhealthyThreshold
	if unhealthyThreshold <= 0 {
		unhealthyThreshold = 3
	}
	healthChecks := map[string]interface{}{
		"passive": map[string]interface{}{
			"fail_duration": fmt.Sprintf("%ds", healthCheckInterval*3),
			"max_fails":     unhealthyThreshold,
		},
	}
	if rule.EnableActiveHealthCheck {
		healthCheckTimeout := rule.HealthCheckTimeout
		if healthCheckTimeout <= 0 {
			healthCheckTimeout = 5
		}
		healthyThreshold := rule.HealthCheckHealthyThreshold
		if healthyThreshold <= 0 {
			healthyThreshold = 2
		}
		active := map[string]interface{}{
			"interval": fmt.Sprintf("%ds", healthCheckInterval),
			"timeout":  fmt.Sprintf("%ds", healthCheckTimeout),
			"rise":     healthyThreshold,
			"fall":     unhealthyThreshold,
		}
		if rule.TCPHealthCheckPort > 0 {
			active["port"] = rule.TCPHealthCheckPort
		}
		healthChecks["active"] = active
	}
	proxyHandler["health_checks"] = healthChecks

	route := map[string]interface{}{
		"handle": []interface{}{proxyHandler},
	}
	if rule.CaddyID != "" {
		route["@id"] = rule.CaddyID
	}
	return route
}

// buildTCPServer generates a layer4 server entry (listen + routes) for a TCP rule.
func buildTCPServer(rule SingleRuleConfig) map[string]interface{} {
	return map[string]interface{}{
		"listen": []string{fmt.Sprintf(":%d", rule.ListenPort)},
		"routes": []interface{}{buildTCPProxyRoute(rule)},
	}
}
