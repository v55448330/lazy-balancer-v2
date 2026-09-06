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
)

// ErrNoEnabledUpstreams 规则（或路径规则）没有启用上游时生成的哨兵错误。
// 生成侧两处产出点（GenerateSingleRuleCaddyConfig 直返、buildHTTPHandleChain
// %w 包装）统一引用；handlers 侧以 errors.Is 特判零上游为「跳过而非失败」
// 语义，未来追加规则上下文包装后特判不会静默失效。
var ErrNoEnabledUpstreams = errors.New("no enabled upstreams")

// ErrDynamicDNSUpstreamCount 动态 DNS 模式配置了多个启用上游时的哨兵错误
// （动态解析仅支持单一上游）。产出点与 ErrNoEnabledUpstreams 相同两处，消费点
// （rule_features.go 预校验）以 errors.Is 命中，避免脆弱的字符串匹配。
var ErrDynamicDNSUpstreamCount = errors.New("dynamic DNS requires exactly one enabled upstream")

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
	return s.applyConfigLocked(config)
}

func (s *CaddyService) GenerateAndApplyConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLocked(generateCaddyConfigFromStore(db.DB))
}

// GenerateAndApplyConfigForce 强制重载变体：POST /load 带 Cache-Control:
// must-revalidate，绕过 Caddy 对字节相同配置的跳过（caddy v2.11.4 changeConfig
// 对相同 JSON 短路返回 errSameConfig、不执行 provision）。xdb/CRS/证书文件是
// 配置 JSON 之外的磁盘数据（geoip handler 恒为 {"handler":"geoip2region"}，
// CRS include 只嵌路径），替换后 JSON 不变——不强制重载时 Caddy 插件
// （geoip searcher / coraza WAF / TLS 证书）内存仍停留旧库，更新流程却已报
// 成功。所有「磁盘数据变化」的重载入口（IP 库/CRS/CA 证书队列）必须走本变体。
func (s *CaddyService) GenerateAndApplyConfigForce() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLockedOpt(generateCaddyConfigFromStore(db.DB), true)
}

func (s *CaddyService) applyConfigLocked(config map[string]interface{}) (err error) {
	return s.applyConfigLockedOpt(config, false)
}

// ApplyConfigForce 与 ApplyConfig 同语义，但强制 Caddy 重载（Cache-Control:
// must-revalidate）——供数据类更新路径与测试使用。
func (s *CaddyService) ApplyConfigForce(config map[string]interface{}) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLockedOpt(config, true)
}

func (s *CaddyService) applyConfigLockedOpt(config map[string]interface{}, force bool) (err error) {
	if message, ok := config[caddyConfigGenerationErrorKey].(string); ok {
		return errors.New(message)
	}
	snapshot, hasSnapshot := config[caddyCertFilesSnapshotKey].(CertFilesSnapshot)
	// R72 二十六次 W1-1：本次生成实际写盘了证书文件（MaterializeCertPairs 检出
	// 内容/权限差异，快照非空）而证书路径确定性意味着 JSON 可能字节相同——
	// 不强制重载时 errSameConfig 短路会让 Caddy 内存里继续用旧证书（重传证书
	// 静默不生效，DB/UI 全报成功）。快照非空即自动升级为强制。
	if hasSnapshot && len(snapshot) > 0 {
		force = true
	}
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

	req, err := http.NewRequest(http.MethodPost, s.adminURL+"/load", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to build config apply request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if force {
		// Caddy admin 官方逃生口（admin.go: forceReload := Header "Cache-Control"
		// == "must-revalidate"）：相同 JSON 也执行完整 provision，磁盘数据
		//（xdb/CRS/证书）的变化得以进入插件内存。
		req.Header.Set("Cache-Control", "must-revalidate")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("config apply failed: %s", string(readCaddyErrorBody(resp.Body)))
	}

	log.Println("Caddy config applied successfully")
	return nil
}

// readCaddyErrorBody 读取 Caddy 管理接口错误响应体并截断到 1KB 内。Caddy 错误体被
// 完整嵌入 error 后，会经 apply_ok_reload_failed 标记、集群 last_sync_error、证书
// 任务 message 等有界通道传播（Round 34 F-R34-1）；按字节截断后回退到合法 UTF-8
// 边界，避免多字节字符残片乱码（复用 cluster_sync.go 的 truncateValidUTF8Tail 模式）。
func readCaddyErrorBody(body io.Reader) []byte {
	limited, _ := io.ReadAll(io.LimitReader(body, caddyErrorBodyMaxBytes))
	return truncateValidUTF8Tail(limited)
}

// caddyErrorBodyMaxBytes 限制嵌入 error 的 Caddy 管理接口错误响应体大小。
const caddyErrorBodyMaxBytes = 1024

// ValidateConfig validates Caddy configuration using the /load API with validate=true
func (s *CaddyService) ValidateConfig(config map[string]interface{}) (err error) {
	// R69：validate=true 实为真实加载（Caddy 以校验模式执行完整的 provision/
	// 加载路径，coraza 等插件照常编译并持有资源），与 apply 同为写操作——必须
	// 持写锁串行化，避免与并发 apply/证书快照恢复竞态（对照 ValidateRouteMergedConfig）。
	s.mu.Lock()
	defer s.mu.Unlock()
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
		return fmt.Errorf("validation failed: %s", string(readCaddyErrorBody(resp.Body)))
	}

	return nil
}

func caddyPayload(config map[string]interface{}) map[string]interface{} {
	payload := make(map[string]interface{}, len(config))
	for key, value := range config {
		if key != caddyCertFilesSnapshotKey {
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

// ValidateTCPServerMergedConfig 以「候选 server 并入运行配置副本」的口径校验
// TCP 规则（R69 C-N3）：Caddy admin /load 无 validate-only 语义（v2.11.4
// handleLoad 无视 validate 参数、无条件 caddy.Load），此前对
// GenerateSingleRuleCaddyConfig（仅含单个 layer4 server 的独立配置）直接
// ValidateConfig 等于把运行中配置整体替换为单规则配置——全部 HTTP 及其他 TCP
// 规则在 validate 窗口内下线；后续真 apply 失败时补偿快照又摄于该副作用之后，
// 恢复的是单规则配置，全停持续。与 HTTP 侧 ValidateRouteMergedConfig 同口径：
// 候选 server 替换/插入运行配置副本的同名条目后校验，运行面零中断。
func (s *CaddyService) ValidateTCPServerMergedConfig(serverName string, serverConfig map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullConfig, err := s.GetConfig()
	if err != nil {
		return fmt.Errorf("无法连接 Caddy 管理接口，未能校验配置: %w", err)
	}
	apps, ok := fullConfig["apps"].(map[string]interface{})
	if !ok {
		apps = map[string]interface{}{}
		fullConfig["apps"] = apps
	}
	layer4, ok := apps["layer4"].(map[string]interface{})
	if !ok {
		layer4 = map[string]interface{}{}
		apps["layer4"] = layer4
	}
	servers, ok := layer4["servers"].(map[string]interface{})
	if !ok {
		servers = map[string]interface{}{}
		layer4["servers"] = servers
	}
	servers[serverName] = serverConfig
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
		return fmt.Errorf("validation failed: %s", string(readCaddyErrorBody(resp.Body)))
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
		return nil, fmt.Errorf("get config failed: %s", string(readCaddyErrorBody(resp.Body)))
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

		if existingID, hasID := routeMap["@id"].(string); hasID && RouteIDBelongsToRule(existingID, caddyID) {
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

// RouteIDBelongsToRule 判断运行配置中的路由 @id 是否归属某规则：主路由
// （@id == ruleID）或其带后缀的兄弟路由（ruleID_ 前缀：path_N / geoip /
// redirect 等）。DeleteRouteByID 的临时路由清理与 handlers 侧
// GetRuleCaddyConfig 的兄弟路由收集（LB-13）共用本口径。
func RouteIDBelongsToRule(routeID, ruleID string) bool {
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
		return fmt.Errorf("config apply failed: %s", string(readCaddyErrorBody(resp.Body)))
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

	// R65 C-2：健康表全量打印降为 debug——该函数被规则指标/总览轮询周期调用，
	// 上游多时单行数 KB，INFO 级放大日志滚动。
	Logf("debug", "Health metrics parsed: %v", result)
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

// securityPolicyContext 是生成期批量预载的安全策略状态：每个规则绑定的全部
// 启用策略（policy_id ASC，v2.2.0 多策略绑定，与 GetSecurityPoliciesForRule
// 同口径）以及策略引用的品牌拦截页内容。经与规则/上游同一 store（事务时即 tx）
// 预载，事务内生成可读到未提交的策略变更，替代此前逐规则走全局 db.DB 的 N+1 查询。
type securityPolicyContext struct {
	policyByRule  map[string][]*models.SecurityPolicy
	blockPageByID map[int]string
	// store 是预载所用 caddyConfigStore（事务内生成即 tx）：A-I1——
	// BuildCorazaDirectives → resolvePolicyCustomRules 必须沿同一 store 读取
	// security_custom_rules，否则 v2 导入事务内重插的规则在渲染期静默丢失。
	store caddyConfigStore
}

// loadSecurityPolicyContext 一次性查询 security_policy_bindings +
// security_policies（仅启用策略）+ security_block_pages，构建
// ruleCaddyID → 启用策略切片（policy_id ASC）映射与 block_page_id → content
// 映射。查询次数与规则数无关（常数级：最多 3 次 Query）。
// v2.2.0 多策略绑定：与 GetSecurityPoliciesForRule 严格同构——绑定按
// policy_id ASC 全量取出，策略按 id 批量查询并过滤 enabled，逐规则按 ASC
// 顺序收集启用策略（禁用绑定仅占位，不产生元素）。
func loadSecurityPolicyContext(store caddyConfigStore) (*securityPolicyContext, error) {
	ctx := &securityPolicyContext{
		policyByRule:  make(map[string][]*models.SecurityPolicy),
		blockPageByID: make(map[int]string),
		store:         store,
	}
	bindingRows, err := store.Query(`SELECT rule_caddy_id, policy_id FROM security_policy_bindings ORDER BY rule_caddy_id, policy_id ASC`)
	if err != nil {
		return nil, err
	}
	rulePolicyIDs := make(map[string][]int)
	distinctPolicyIDs := make([]int, 0)
	seenPolicyIDs := make(map[int]struct{})
	for bindingRows.Next() {
		var ruleCaddyID string
		var policyID int
		if err := bindingRows.Scan(&ruleCaddyID, &policyID); err != nil {
			_ = bindingRows.Close()
			return nil, err
		}
		rulePolicyIDs[ruleCaddyID] = append(rulePolicyIDs[ruleCaddyID], policyID)
		if _, seen := seenPolicyIDs[policyID]; !seen {
			seenPolicyIDs[policyID] = struct{}{}
			distinctPolicyIDs = append(distinctPolicyIDs, policyID)
		}
	}
	if err := bindingRows.Err(); err != nil {
		_ = bindingRows.Close()
		return nil, err
	}
	if err := bindingRows.Close(); err != nil {
		return nil, err
	}
	policiesByID := make(map[int]*models.SecurityPolicy, len(distinctPolicyIDs))
	if len(distinctPolicyIDs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(distinctPolicyIDs)), ",")
		args := make([]interface{}, len(distinctPolicyIDs))
		for i, policyID := range distinctPolicyIDs {
			args[i] = policyID
		}
		rows, err := store.Query(`
			SELECT id, name, COALESCE(description,''), COALESCE(mode,'off'), COALESCE(anomaly_threshold,5),
			       COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_whitelist,'[]'), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_blacklist,'[]'),
			       COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0),
			       COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(custom_rules,'[]'),
		COALESCE(block_page_id,0), COALESCE(block_status_code,0), enabled, COALESCE(created_at,''), COALESCE(updated_at,''),
			       COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(waf_check_response,0), COALESCE(log_request_body,0),
			       COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]')
		FROM security_policies WHERE id IN (`+placeholders+`) AND enabled = 1`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p models.SecurityPolicy
			var ipWhitelist, ipBlacklist, crsRuleGroups, crsExcludedRules, customRules, geoipCountries string
			if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.AnomalyThreshold,
				&p.IPACLMode, &p.IPACLList, &p.IPACLEnabled, &ipWhitelist, &p.IPWhitelistEnabled, &ipBlacklist,
				&p.RateLimitEnabled, &p.RateLimitRPS, &p.RateLimitBurst,
				&crsRuleGroups, &crsExcludedRules, &customRules,
				&p.BlockPageID, &p.BlockStatusCode, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
				&geoipCountries, &p.GeoIPMode, &p.WAFCheckResponse, &p.LogRequestBody, &p.IPACLListRefs, &p.IPWhitelistRefs); err != nil {
				_ = rows.Close()
				return nil, err
			}
			p.IPWhitelist = json.RawMessage(ipWhitelist)
			p.IPBlacklist = json.RawMessage(ipBlacklist)
			p.CRSRuleGroups = json.RawMessage(crsRuleGroups)
			p.CRSExcludedRules = json.RawMessage(crsExcludedRules)
			p.CustomRules = json.RawMessage(customRules)
			p.GeoIPCountries = json.RawMessage(geoipCountries)
			policiesByID[p.ID] = &p
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		// 引用 IP 列表批量解析（与策略预载同一 store——事务内重插的列表行仅 tx
		// 可见；跨整个批次一次查询，预算与策略数无关），合并集附加到各策略。
		batch := make([]*models.SecurityPolicy, 0, len(policiesByID))
		for _, policy := range policiesByID {
			batch = append(batch, policy)
		}
		resolvePolicyIPListRefs(batch, store)
		// 审计 I-4：自定义规则按去重策略在此解析一次（缓存于策略对象），
		// BuildCorazaDirectives 对同策略的多次调用（多规则绑定同策略）零重复查询。
		for _, bp := range batch {
			if bp != nil {
				policyCustomRulesCached(bp, store)
			}
		}
	}
	for ruleCaddyID, policyIDs := range rulePolicyIDs {
		for _, policyID := range policyIDs {
			if policy := policiesByID[policyID]; policy != nil {
				ctx.policyByRule[ruleCaddyID] = append(ctx.policyByRule[ruleCaddyID], policy)
			}
		}
	}
	var referencedPage bool
	for _, policies := range ctx.policyByRule {
		for _, policy := range policies {
			if policy.BlockPageID > 0 {
				referencedPage = true
				break
			}
		}
		if referencedPage {
			break
		}
	}
	if !referencedPage {
		return ctx, nil
	}
	pageRows, err := store.Query(`SELECT id, COALESCE(content,'') FROM security_block_pages`)
	if err != nil {
		return nil, err
	}
	for pageRows.Next() {
		var id int
		var content string
		if err := pageRows.Scan(&id, &content); err != nil {
			_ = pageRows.Close()
			return nil, err
		}
		ctx.blockPageByID[id] = content
	}
	if err := pageRows.Err(); err != nil {
		_ = pageRows.Close()
		return nil, err
	}
	if err := pageRows.Close(); err != nil {
		return nil, err
	}
	return ctx, nil
}

// policiesForRule 返回规则绑定的全部启用安全策略（policy_id ASC）：批量预载
// 上下文存在时查映射，否则回退单规则查询（GenerateSingleRuleCaddyConfig/
// GenerateRouteObject 等非批量路径）。无绑定或全部禁用时返回 nil。
func policiesForRule(ctx *securityPolicyContext, ruleCaddyID string) []*models.SecurityPolicy {
	if ctx != nil {
		return ctx.policyByRule[ruleCaddyID]
	}
	return GetSecurityPoliciesForRule(ruleCaddyID)
}

func GenerateCaddyConfig(overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	return generateCaddyConfigFromStore(db.DB, overrides...)
}

// acmeCertCandidatesQuery 只取「启用 + TLS + acme_dns」规则名下未禁用任务的
// 证书候选（与 db 迁移的 legacyHTTPSHasCertPredicate 及 SelectCertificate 的
// 跳过口径同源）。R47 前为全库全量拉取：已删除规则的残留行、disabled 任务与
// 非 acme 规则的历史 PEM 都会在每次全量生成时载入内存，而后置消费方
// （resolveACMECert 仅按 allRules 中 acme_dns 规则查表、SelectCertificate
// 跳过 disabled）根本不会使用这些行——过滤前移只减 IO/内存，不改变候选集语义。
const acmeCertCandidatesQuery = `
	SELECT rule_id, id, domain, status, cert_pem, key_pem,
	       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
	FROM cert_jobs
	WHERE cert_pem IS NOT NULL AND cert_pem <> ''
	  AND key_pem IS NOT NULL AND key_pem <> ''
	  AND status != 'disabled'
	  AND rule_id IN (SELECT caddy_id FROM lb_rules WHERE enabled = 1 AND enable_tls = 1 AND tls_source = 'acme_dns')
	ORDER BY updated_at DESC, id DESC
`

// generateCaddyConfigFromStore 以已提交连接（db.DB）为证书候选源渲染配置（C-2.1
// 默认语义）；规则/安全段读传入 store。
func generateCaddyConfigFromStore(store caddyConfigStore, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
	return generateCaddyConfigWithCertSource(store, db.DB, overrides...)
}

// generateCaddyConfigWithCertSource 渲染配置，证书候选源可指定（R65 A-N1）：
//   - certSource=db.DB（默认）：C-2.1 防护——UpdateConfig 类纯 global_config 事务
//     的 tx 视角对 cert_jobs 纯陈旧性，已提交连接恒见最新证书。
//   - certSource=tx（ApplyConfigFromTxCertAwareForce，v2 导入专用）：导入事务全量
//     deleteOrder+重插 cert_jobs（restoreTable 保留原 id，PEM 可更新），已提交
//     视图会返回将被替换的旧行——MaterializeCertPairs 用旧 PEM 覆写
//     materializeImportCertificates 刚写入的新文件，DB=新证/磁盘=旧证静默分叉。
//
// 导入期 CA 队列已 PauseAndDrain，无并发证书提交，tx 视图即最新真相。
func generateCaddyConfigWithCertSource(store, certSource caddyConfigStore, overrides ...*models.UpdateConfigRequest) map[string]interface{} {
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
		ORDER BY id
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
		SELECT u.rule_id, u.host, u.port, COALESCE(u.weight,1), COALESCE(u.dynamic_dns,0), IIF(u.enabled IN ('1',1),1,0), COALESCE(u.protocol,'http'), COALESCE(u.max_connections,0)
		FROM upstreams u JOIN lb_rules r ON r.caddy_id = u.rule_id
		WHERE IIF(u.enabled IN ('1',1),1,0) = 1 AND r.enabled = 1 ORDER BY u.rule_id, u.id
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

	acmeCerts := make(map[string][]CertificateCandidate)
	if hasACMETLS {
		// R64 C-2.1：证书候选固定走已提交连接（db.DB）而非传入 store——UpdateConfig 的
		// ApplyConfigFromTx 会把 global_config 事务传入此处，该事务不写 cert_jobs，
		// tx 视角对证书零信息增益、纯陈旧性：在途 ACME 部署（certissuer 不持 caddyOpMu，
		// transitionJob 独立连接提交新证书）若在 tx 快照固定后落库，本查询经 tx 会读到
		// 旧 PEM，MaterializeCertPairs 内容比对 miss 即用旧证书覆写磁盘新证书——
		// DB=issued 新证、磁盘/Caddy=旧证的静默分叉（reconcile 只查存在不查内容），
		// 持续到下次 apply/重启。规则/安全段仍走 store（规则 CRUD 全程持 caddyOpMu，
		// 与 UpdateConfig 互斥，无并发写入可见性；安全段有意读 tx 内未提交状态）。
		certRows, certErr := certSource.Query(acmeCertCandidatesQuery)
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
		// R65 A-N1（谓词 miss 补查）：主候选查询的 lb_rules 子查询在 certSource 的
		// 视图上执行——tx 渲染路径中，事务对 lb_rules 的写入（UpdateRule 切换
		// tls_source manual→acme_dns、EnableRule 置 enabled=1、导入插入新规则）使
		// allRules（tx 视图）含 acme 规则而已提交视图的子查询将其排除，候选为空，
		// 该规则按无证书渲染（TLS 静默丢失）。此时经 store（tx）做无子查询的
		// per-rule 补查——补查读的是事务视图（R67 修正、R71 F-A5 校正举例：tx 内
		// 写 cert_jobs 的调用点是 DisableRule 置 disabled、DeleteRule 删行、
		// UpdateRule tcp 切换删除；UpdateRule 域名迁移的证书 UPDATE 在 commit 后
		// 独立 certTx。对 tx 内写者，事务视图恰是渲染目标状态，行为正确）；
		// SelectCertificate 仍按 status 过滤 disabled。
		// UpdateConfig（tx 只写 global_config）不产生谓词 miss，C-2.1 防护不受影响。
		// R66（C 域改进项）：门控收紧为 certSource != store——补查仅在「子查询
		// 视图 ≠ allRules 视图」时需要；CertAware 路径两者同为 tx（主查询已完备），
		// 不再为每个无候选 acme 规则空跑一次 per-rule 查询。
		if certSource != store {
			for _, ru := range allRules {
				r := ru.rule
				if !r.EnableTLS || r.TLSSource != "acme_dns" || len(acmeCerts[r.CaddyID]) > 0 {
					continue
				}
				acmeCerts[r.CaddyID] = acmeCertCandidatesForRule(store, r.CaddyID)
			}
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

	// Round 33 N-1: 安全策略经同一 store 批量预载（常数级查询），替代逐规则走
	// 全局 db.DB 的 N+1——事务内生成（ApplyConfigFromTx）由此读到未提交的策略。
	securityCtx, err := loadSecurityPolicyContext(store)
	if err != nil {
		return generationFailure("preload security policy context: %v", err)
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

			ruleRoutes, _, err := generateHTTPRouteObjects(ruleConfig, securityCtx)
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
			if errorRoute := buildBlockPageErrorRoute(r.CaddyID, splitAndTrim(r.Domain), securityCtx); errorRoute != nil {
				errorRoutes = append(errorRoutes, errorRoute)
			}
			if errorRoute := buildRateLimitErrorRoute(r.CaddyID, splitAndTrim(r.Domain), securityCtx); errorRoute != nil {
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

		// 证书签发/续期由 cert_jobs（DNS-01）全权管理：禁止 Caddy 自动 HTTPS 为路由
		// 域名自建 ACME automation（v2.11.4 autohttps.go：TLS 服务器 host matcher 中的
		// 域名若无已加载证书即纳入默认自动化策略，acme_dns 签发期会绕开 cert_jobs 自行签发）。
		// disable_certificates 仅关自动化证书管理，自动跳转与既有 TLS 策略行为不变；
		// 非 443/80 端口维持整体 disable 以避免自动跳转冲突。
		autoHTTPS := map[string]interface{}{"disable_certificates": true}
		if port != 443 && port != 80 {
			autoHTTPS["disable"] = true
		}
		server["automatic_https"] = autoHTTPS

		servers[fmt.Sprintf("http_%d", port)] = server
	}

	// Collect HTTP->HTTPS redirect routes from all TLS-enabled rules and place them on the HTTP (port 80) server.
	var redirectRoutes []interface{}
	for _, ru := range allRules {
		r := ru.rule
		// R43 F-A: 与规则渲染跳过同口径（上方按启用上游数 continue）——全部上游
		// 被禁用的启用规则不生成任何端口路由，同样不得生成 301 跳转，否则域名
		// 被跳到无服务的 TLS 端口（此前按上游裸计数，禁用上游也被计入）。
		// M1：判定提为闭包，供 r 自身与下方 other 遮蔽复核共用同款口径。
		hasEnabledUpstream := func(ups []upstream) bool {
			for _, u := range ups {
				if u.Enabled {
					return true
				}
			}
			return false
		}
		if !hasEnabledUpstream(ru.upstreams) {
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
				// Round 29 G-2: 签发完成/重载时刻复核——acme_dns 规则在证书签发前不生成
				// 跳转（上方 continue），签发后跳转才出现；若此刻存在同域名直接监听 80 的
				// 启用规则，terminal 301 会将其静默遮蔽为死规则。保存/启用路径已由
				// queryRedirectShadowConflict 拦截，此处纯内存复核兜住存量/导入/签发迟滞
				// 窗口，命中即跳过该域名跳转生成。
				// Round 30 F-2: 比较双方均过规范化（db.CanonicalDomains 同源口径），
				// 导入态非规范化域名（"Example.COM"）不再失配。
				// Round 30 F-3: 按域名粒度过滤——仅跳过与 80 端口规则冲突的域名，
				// 其余兄弟域名仍生成跳转（保存侧 queryRedirectShadowConflict 保持整规则
				// 400 语义，报错含冲突域名，用户可拆规则）。
				wantedDomains := normalizedDomainSet(r.Domain)
				blockedDomains := make(map[string]struct{})
				shadowedBy := ""
				for _, other := range allRules {
					otherRule := other.rule
					if otherRule.CaddyID == r.CaddyID || otherRule.Protocol != "http" || otherRule.ListenPort != 80 {
						continue
					}
					// M1（审计）：遮蔽复核的比对方也过启用上游门——零启用上游的
					// 规则不生成 80 端口路由（死规则），不得作为遮蔽方压制兄弟
					// 域名的 HTTPS 跳转。
					if !hasEnabledUpstream(other.upstreams) {
						continue
					}
					for existingDomain := range normalizedDomainSet(otherRule.Domain) {
						if _, hit := wantedDomains[existingDomain]; hit {
							blockedDomains[existingDomain] = struct{}{}
							if shadowedBy == "" {
								shadowedBy = existingDomain
							}
						}
					}
				}
				if len(blockedDomains) > 0 {
					filtered := make([]string, 0, len(domainHosts))
					for _, host := range domainHosts {
						if _, isBlocked := blockedDomains[normalizeHostForMatcher(host)]; !isBlocked {
							filtered = append(filtered, normalizeHostForMatcher(host))
						}
					}
					if len(filtered) == 0 {
						Logf("warn", "跳转规则 %s（%s）的域名 %s 已有启用规则直接监听 80 端口，该规则所有域名的 HTTPS 跳转均被遮蔽，整条跳转不生成（避免遮蔽 80 端口规则）", r.Name, r.CaddyID, shadowedBy)
						continue
					}
					Logf("warn", "跳转规则 %s（%s）的域名 %s 已有启用规则直接监听 80 端口，已从跳转中移除（其余域名仍生成跳转）", r.Name, r.CaddyID, shadowedBy)
					domainHosts = filtered
				}
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

	// R57 C-4：logger_names 按 server（端口）拆分——同域名跨端口双规则时全局
	// 共享映射会让后写覆盖先写（先建规则的日志文件永无条目），且任一端口上的
	// 同域名请求（含 80 默认站跳转）都被误记入映射命中规则的日志。
	loggerNamesByPort := map[int]map[string]interface{}{}
	for _, ru := range allRules {
		r := ru.rule
		if !r.LogEnabled || r.Protocol != "http" || r.Domain == "" {
			continue
		}
		perPort := loggerNamesByPort[r.ListenPort]
		if perPort == nil {
			perPort = map[string]interface{}{}
			loggerNamesByPort[r.ListenPort] = perPort
		}
		for _, d := range strings.Split(r.Domain, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				perPort[d] = "rule_" + r.CaddyID
			}
		}
	}
	if len(loggerNamesByPort) > 0 {
		for serverName, serverVal := range servers {
			srv, _ := serverVal.(map[string]interface{})
			if srv == nil || !strings.HasPrefix(serverName, "http_") {
				continue
			}
			port, err := strconv.Atoi(strings.TrimPrefix(serverName, "http_"))
			if err != nil {
				continue
			}
			if perPort, ok := loggerNamesByPort[port]; ok && len(perPort) > 0 {
				srv["logs"] = map[string]interface{}{"logger_names": perPort}
			}
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

// acmeCertCandidatesForRule 无 lb_rules 子查询的 per-rule 证书候选查询（R65 A-N1
// 谓词 miss 补查专用）：查询形态与 acmeCertCandidatesQuery 的行过滤一致（PEM
// 非空），但绕过 enabled/enable_tls/tls_source 谓词——调用方已确保规则在 allRules
// （tx 视图）中为启用 acme 规则。status 过滤交由 SelectCertificate 后置执行。
// 查询/解析失败仅记日志返回 nil（与调用点的空候选语义一致：按无证书渲染）。
func acmeCertCandidatesForRule(store caddyConfigStore, ruleID string) []CertificateCandidate {
	rows, err := store.Query(`
		SELECT id, domain, status, cert_pem, key_pem,
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0)
		FROM cert_jobs
		WHERE rule_id=?
		  AND cert_pem IS NOT NULL AND cert_pem <> ''
		  AND key_pem IS NOT NULL AND key_pem <> ''
		ORDER BY updated_at DESC, id DESC`, ruleID)
	if err != nil {
		Logf("warn", "ACME 证书候选补查失败（规则 %s，按无证书渲染）: %v", ruleID, err)
		return nil
	}
	defer rows.Close()
	candidates := make([]CertificateCandidate, 0)
	for rows.Next() {
		var candidate CertificateCandidate
		if err := rows.Scan(&candidate.ID, &candidate.Domain, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt); err != nil {
			Logf("warn", "ACME 证书候选补查解析失败（规则 %s）: %v", ruleID, err)
			return nil
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		Logf("warn", "ACME 证书候选补查遍历失败（规则 %s）: %v", ruleID, err)
		return nil
	}
	return candidates
}

// loadACMECertificateFromStore reads the issued ACME certificate and key from
// cert_jobs (via store) for the given rule and domain. Returns
// (certPEM, keyPEM, true) if issued.
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

// normalizedDomainSet 返回逗号分隔域名的规范化集合（小写+punycode），与保存侧
// db.CanonicalDomains（normalizedRuleDomains）同源。Round 30 F-2：渲染层遮蔽比较
// 必须与保存侧口径一致，否则导入态非规范化域名（"Example.COM" vs "example.com"）
// 比较失配——Caddy host matcher 大小写不敏感，遮蔽漏洞会经导入路径复发。
// 整串无法规范化（手造脏数据）时回退小写拆分结果，渲染不因脏数据中断。
func normalizedDomainSet(value string) map[string]struct{} {
	if canonical, err := db.CanonicalDomains(value); err == nil {
		result := make(map[string]struct{})
		for _, domain := range strings.Split(canonical, ",") {
			result[domain] = struct{}{}
		}
		return result
	}
	result := make(map[string]struct{})
	for _, domain := range splitAndTrim(value) {
		result[strings.ToLower(domain)] = struct{}{}
	}
	return result
}

// normalizeHostForMatcher 将单个域名规范化后用于 host matcher；无法规范化时
// 回退小写原值，保证 matcher 仍按 Caddy 大小写不敏感语义工作。
func normalizeHostForMatcher(host string) string {
	if canonical, err := db.CanonicalDomains(host); err == nil {
		return canonical
	}
	return strings.ToLower(host)
}

// httpsRedirectLocation 构造 HTTP→HTTPS 跳转的 Location 头。
// 使用 {http.request.host} 占位符而非首个域名字面量：Caddy static_response
// 的 headers 会在运行时经过 replacer 替换（v2.11.4 modules/caddyhttp/staticresp.go），
// 因此多域名规则（a.com,b.com）访问 b.com 时会跳回 b.com，而不是被劫持到首个域名。
func httpsRedirectLocation(listenPort int) string {
	// R72 二十七次 N2（补正重写）：Location 必须追加 {http.request.uri}（path+query）
	// ——Caddy static_response 不会自动保留原 URI（原生 auto-HTTPS 重定向会保留），
	// 缺失时 http://a.com/page?x=1 会被跳到根路径。首版实施因脚本断言中止丢失。
	if listenPort != 443 {
		return fmt.Sprintf("https://{http.request.host}:%d{http.request.uri}", listenPort)
	}
	return "https://{http.request.host}{http.request.uri}"
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

	// 2026-09-06 裁定（T-3）：Server 头隐藏仅暴露全局开关（基础设置），规则级
	// server_tokens_hidden 0/1/2 覆盖为 API/MCP 预留字段——无 UI 入口、不作为
	// 产品功能维护，UI 编辑透传保留 API 已设值。
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

// GenerateRuleServerContext builds a Caddy-config-shaped map containing only
// the server context hosting a single rule: the deterministic server identity
// for its listen port, the same-port TLS connection policies (mirroring
// generateCaddyConfigFromStore's available-cert semantics), and the rule's own
// certificate files. GetRuleCaddyConfig uses this instead of a full
// GenerateCaddyConfig, which re-queried the whole database and re-read
// certificate files on every request.
func GenerateRuleServerContext(caddyID string, listenPort int, protocol, domain string) map[string]interface{} {
	serverName := fmt.Sprintf("http_%d", listenPort)
	if protocol != "http" {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
	}
	server := map[string]interface{}{
		"listen": []string{fmt.Sprintf(":%d", listenPort)},
		"routes": []interface{}{map[string]interface{}{"@id": caddyID}},
	}
	apps := map[string]interface{}{}
	hasCert := false
	if protocol == "http" {
		var tlsSource string
		var certPresent, keyPresent, enableTLS bool
		// Round 34 F-3: 查询失败必须留痕，对话框不得静默显示"无证书"。
		// N+12 G8-S3：仅需存在性判断，投影 COALESCE!='' 布尔，不搬运 PEM 正文。
		if err := db.DB.QueryRow(`SELECT COALESCE(tls_source,'manual'), COALESCE(tls_cert,'') != '', COALESCE(tls_key,'') != '', COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&tlsSource, &certPresent, &keyPresent, &enableTLS); err != nil {
			log.Printf("GenerateRuleServerContext: 读取规则 %s TLS 字段失败: %v", caddyID, err)
		} else if enableTLS {
			// Round 34 F-2: 与全量渲染 availableCerts 同口径（caddy.go 全量路径
			// 要求 EnableTLS），未开 TLS 的规则不加载证书。
			if tlsSource == "manual" && certPresent && keyPresent {
				hasCert = true
			} else if tlsSource == "acme_dns" {
				hasCert = isACMECertIssuedFromStore(db.DB, caddyID, domain)
			}
		}
		var policies []interface{}
		// Round 34 F-2: 与全量渲染 httpServersByPort 同口径——仅 enable_tls=1 且
		// 存在启用上游的规则进入 TLS 策略（无上游/关 TLS 规则在真实配置中不存在）。
		// N+12 G8-S3：证书仅有无的判断在 SQL 侧完成，不再把整列 PEM 拉进进程。
		rows, err := db.DB.Query(`SELECT COALESCE(caddy_id,''), COALESCE(domain,''), COALESCE(tls_source,'manual'), COALESCE(tls_cert,'') != '' AND COALESCE(tls_key,'') != ''
			FROM lb_rules WHERE enabled = 1 AND protocol = 'http' AND listen_port = ? AND enable_tls = 1
			AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id = lb_rules.caddy_id AND IIF(u.enabled IN ('1',1),1,0) = 1)
			ORDER BY id`, listenPort)
		if err != nil {
			log.Printf("GenerateRuleServerContext: 读取端口 %d TLS 策略失败: %v", listenPort, err)
		} else {
			for rows.Next() {
				var ruleID, ruleDomain, tlsSource string
				var hasManualCert bool
				if rows.Scan(&ruleID, &ruleDomain, &tlsSource, &hasManualCert) != nil {
					log.Printf("GenerateRuleServerContext: 扫描端口 %d 规则 TLS 字段失败", listenPort)
					continue
				}
				available := (tlsSource == "manual" && hasManualCert) || (tlsSource == "acme_dns" && isACMECertIssuedFromStore(db.DB, ruleID, ruleDomain))
				if !available {
					continue
				}
				domainHosts := splitAndTrim(ruleDomain)
				if len(domainHosts) == 0 {
					continue
				}
				policies = append(policies, map[string]interface{}{
					"match": map[string]interface{}{
						"sni": domainHosts,
					},
					"certificate_selection": map[string]interface{}{
						"any_tag": []string{ruleID},
					},
				})
			}
			// Round 35 F-4: 遍历中途 DB 错误会截断 TLS 策略且此前静默（仅关行），
			// 与规则主循环（:990-993）同口径显式留痕。
			if err := rows.Err(); err != nil {
				log.Printf("GenerateRuleServerContext: 遍历端口 %d TLS 策略失败: %v", listenPort, err)
			}
			_ = rows.Close()
		}
		server["tls_connection_policies"] = policies
		apps["http"] = map[string]interface{}{"servers": map[string]interface{}{serverName: server}}
	} else {
		apps["layer4"] = map[string]interface{}{"servers": map[string]interface{}{serverName: server}}
	}
	if hasCert {
		certPath, keyPath := CertFilePaths(caddyID)
		apps["tls"] = map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_files": []interface{}{
					map[string]interface{}{
						"certificate": certPath,
						"key":         keyPath,
						"tags":        []string{caddyID},
					},
				},
			},
		}
	}
	return map[string]interface{}{"apps": apps}
}

func GenerateSingleRuleCaddyConfig(rule SingleRuleConfig) map[string]interface{} {
	// R45 F-5: 与 GenerateRouteObject 的硬错误（caddy.go:2312）对齐——https 等
	// 非法协议不再静默按 TCP 渲染（遗留 https 行由 db 迁移归一为 http）。
	if rule.Protocol != "http" && rule.Protocol != "tcp" {
		return map[string]interface{}{
			"error": fmt.Errorf("unsupported protocol: %s", rule.Protocol),
		}
	}
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
			"error": ErrNoEnabledUpstreams,
		}
	}
	if rule.DynamicDNS && len(enabledUpstreams) > 1 {
		return map[string]interface{}{
			"error": fmt.Errorf("%w, got %d", ErrDynamicDNSUpstreamCount, len(enabledUpstreams)),
		}
	}

	servers := make(map[string]interface{})

	if rule.Protocol == "http" {
		domainHosts := splitAndTrim(rule.Domain)

		// 委托生产路径的构建器生成路由对象（GeoIP + 路径路由 + 主路由），
		// 避免与 generateCaddyConfigFromStore 的逻辑分叉。
		routes, _, err := generateHTTPRouteObjects(rule)
		if err != nil {
			return map[string]interface{}{"error": err}
		}

		// HTTP→HTTPS 跳转路由插在 GeoIP 路由之后、路径/主路由之前。generateHTTPRouteObjects
		// 已将 GeoIP pass 路由前置到头部（v2.2.0 地域拦截改走 coraza 后仅剩 pass 路由，
		// 至多一条；无 Caddy 原生 block 路由）。
		//
		// 可达性说明（防止误用）：此单规则跳转形态当前并无调用方会触发——
		// handlers.go 的规则验证中 HTTP 协议走 GenerateRouteObject（合并进既有端口验证），
		// 仅 TCP 协议调用 GenerateSingleRuleCaddyConfig；rule_features.go 的
		// validateRuleConfigGeneration 也不填 EnableTLS/TLSHTTPRedirect 字段。
		// 生产环境的 HTTP→HTTPS 跳转由 generateCaddyConfigFromStore 的 redirectRoutes
		// 统一生成（端口 443 时 Location 不带自引用端口，见 httpsRedirectLocation）。
		// 若未来需要在单规则配置里启用此分支，请先确认与全量生成逻辑保持一致。
		//
		// 已知口径差异（R47 C-发现4 记录，当前因分支不可达而无影响）：全量分支的
		// automatic_https 对 80/443 端口写 {disable_certificates: true}（保留自动
		// 跳转、仅禁 Caddy 自建证书自动化，防绕开 cert_jobs 的 DNS-01 签发），非
		// 80/443 端口写 {disable: true}；本分支仅对非 80/443 端口写 {disable: true}，
		// 80/443 端口不写 automatic_https。若未来启用此分支，必须补齐 80/443 的
		// disable_certificates 例外，否则 Caddy 会为路由域名自建 ACME automation。
		if rule.EnableTLS && rule.TLSHTTPRedirect && len(domainHosts) > 0 {
			// 与 generateHTTPRouteObjects 同口径：任一启用策略带 geoip 时仅一条
			// pass 路由（地域拦截已改走 coraza，无逐策略 block 路由）。
			geoipCount := 0
			for _, policy := range GetSecurityPoliciesForRule(rule.CaddyID) {
				if PolicyHasGeoIP(policy) {
					geoipCount = 1
					break
				}
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
	// R44 B1: 与全量渲染「非 http 即 TCP」（caddy.go:1276）及写侧白名单
	// （rule_features.go validateRuleFeatures）对齐——https 不再被当作 HTTP 通过，
	// 遗留 https 行由 db 迁移归一为 http+enable_tls=1。
	if rule.Protocol != "http" {
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

func generateHTTPRouteObjects(rule SingleRuleConfig, securityCtx ...*securityPolicyContext) ([]map[string]interface{}, map[string]interface{}, error) {
	if rule.Strategy == "" {
		rule.Strategy = "weighted_round_robin"
	}
	var ctx *securityPolicyContext
	if len(securityCtx) > 0 {
		ctx = securityCtx[0]
	}
	domainHosts := splitAndTrim(rule.Domain)
	mainHandle, err := buildHTTPHandleChain(rule, rule.Upstreams, ctx)
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

	routes := make([]map[string]interface{}, 0, len(rule.PathRules)+2)
	// GeoIP pass route runs before path rules and the main route: it resolves the
	// client region into {http.vars.geoip.*} placeholders AND X-GeoIP-* request
	// headers. v2.2.0 地域拦截改走 coraza——BuildCorazaDirectives 的 GeoIP
	// SecRule（id:8）读取 X-GeoIP-Loc，被拦请求产生 audit.log → 安全事件管线
	// （此前 Caddy 原生 block 路由 CEL+static_response 完全绕过 coraza，事件
	// 盲区）。pass 路由必须保留且先于主路由的 coraza 处理器执行，否则 headers
	// 未设置、地域规则恒不命中。至多一条（任一绑定启用策略带 geoip 即存在，
	// v2.2.0 多策略语义）。
	var geoipPassPolicy *models.SecurityPolicy
	for _, policy := range policiesForRule(ctx, rule.CaddyID) {
		if PolicyHasGeoIP(policy) {
			geoipPassPolicy = policy
			break
		}
	}
	if geoipPassPolicy != nil {
		// LB-13：GeoIP pass 路由补挂 @id（caddyID_geoip）——此前无 @id，
		// GetRuleCaddyConfig 的兄弟路由收集与 DeleteRouteByID 清理均无法识别。
		geoipRoute := buildGeoipPassRoute(domainHosts, geoipPassPolicy)
		tagRuleRoute(geoipRoute, rule.CaddyID, "geoip")
		routes = append(routes, geoipRoute)
	}
	if rule.CustomRoutesEnabled {
		pathRules := append([]PathRuleConfig(nil), rule.PathRules...)
		sort.SliceStable(pathRules, func(i, j int) bool {
			return pathRules[i].SortOrder < pathRules[j].SortOrder
		})
		for pathIndex, pathRule := range pathRules {
			upstreams := pathRule.Upstreams
			// Round 32 F-3: 空数组与 nil 统一回退主上游——DB 中 upstreams_json="[]"
			// 的存量路径规则此前因 `upstreams == nil` 不成立而走 buildHTTPHandleChain
			// 硬失败（预校验特判放行、全量渲染失败的不对称），修复后两者语义一致。
			if len(upstreams) == 0 {
				upstreams = rule.Upstreams
			}
			handle, handleErr := buildHTTPHandleChain(rule, upstreams, ctx)
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
// branded block page of the rule's first-bound (lowest policy_id) enabled
// policy that configures one, or nil when no bound enabled policy has a block
// page or the stored page has no content. The policies and block-page content
// come from the batch-preloaded securityCtx, so transactional generation
// observes uncommitted policy changes.
func buildBlockPageErrorRoute(ruleCaddyID string, domainHosts []string, securityCtx *securityPolicyContext) map[string]interface{} {
	policies := policiesForRule(securityCtx, ruleCaddyID)
	var pagePolicy *models.SecurityPolicy
	for _, policy := range policies {
		if policy.BlockPageID > 0 {
			pagePolicy = policy
			break
		}
	}
	if pagePolicy == nil {
		return nil
	}
	content := securityCtx.blockPageByID[pagePolicy.BlockPageID]
	if content == "" {
		return nil
	}
	statusCode := pagePolicy.BlockStatusCode
	if statusCode == 0 {
		statusCode = 403
	}
	// 全部 coraza 命中（CRS/自定义/IP ACL/GeoIP 地域拦截）恒以 403 +
	// "interruption triggered" 中断，共用本子句 → 品牌拦截页按策略配置状态码
	// 渲染（v2.2.0 GeoIP 改走 coraza 后不再有独立的 "GeoIP blocked" 中断形态，
	// 逐策略 geoip 状态码并集子句随之移除）。
	expression := "({http.error.status_code} == 403 && {http.error.message} == 'interruption triggered')"
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
// block page of the rule's first-bound enabled policy that configures one for
// rate-limited (429) requests, or nil when no bound enabled policy enables
// rate limiting or none has a block page.
// caddy-ratelimit rejects via caddyhttp.Error(429), so handle_errors fires.
func buildRateLimitErrorRoute(ruleCaddyID string, domainHosts []string, securityCtx *securityPolicyContext) map[string]interface{} {
	policies := policiesForRule(securityCtx, ruleCaddyID)
	rateLimited := false
	var pagePolicy *models.SecurityPolicy
	for _, policy := range policies {
		if policy.RateLimitEnabled {
			rateLimited = true
		}
		if pagePolicy == nil && policy.BlockPageID > 0 {
			pagePolicy = policy
		}
	}
	if !rateLimited || pagePolicy == nil {
		return nil
	}
	content := securityCtx.blockPageByID[pagePolicy.BlockPageID]
	if content == "" {
		return nil
	}
	// 限流拦截恒 429（不再取策略 BlockStatusCode）：429 Too Many Requests 是
	// 限流的语义正确状态码，且使 caddy_http_requests_total{code="429"} 可单独
	// 计量——Wave 6 状态统一后 403 与 WAF 拦截在指标中同形不可区分（实测：
	// 错误路由响应继承主路由 handler 标签，无任何其他区分维度）。拦截页正文
	// 不变（客户端体验一致），Retry-After 按限流 1s 窗口给出重试契约。
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
				"status_code": 429,
				"headers": map[string]interface{}{
					"Content-Type": []string{"text/html; charset=utf-8"},
					"Retry-After":  []string{"1"},
				},
			},
		},
		"terminal": true,
	}
}

// buildRateLimitHandler returns the rate_limit handler for one bound policy of
// a rule, or nil when that policy does not enable rate limiting. Zones are
// logical AND: with burst > 0 a per-second zone caps instantaneous rate at
// rps+burst while a per-minute zone caps sustained rate at rps; without burst a
// single per-second zone caps at rps.
// zone 键必须嵌入 policy_id：caddy-ratelimit 的 UsagePool 按 zone 名进程级共享
// 计数器，同规则多策略（v2.2.0）若共用 {ruleID} 前缀会静默合并计数。
func buildRateLimitHandler(ruleCaddyID string, policy *models.SecurityPolicy) map[string]interface{} {
	if policy == nil || !policy.RateLimitEnabled || policy.RateLimitRPS <= 0 {
		return nil
	}
	// R61 C-N1：sweep_interval 是 caddy-ratelimit Handler 层字段（默认 1m），
	// 不是 zone 字段——Caddy v2.11.4 对模块载荷 StrictUnmarshalJSON+
	// DisallowUnknownFields，zone 级未知字段会使整个配置加载 400（开启限流
	// 即配置停摆）。移到 handler 层（合法字段，10m 扫描周期语义保留）。
	zonePrefix := fmt.Sprintf("%s-p%d", ruleCaddyID, policy.ID)
	rateLimits := map[string]interface{}{
		zonePrefix: map[string]interface{}{
			"key":        "{http.request.remote.host}",
			"window":     "1s",
			"max_events": policy.RateLimitRPS,
		},
	}
	if policy.RateLimitBurst > 0 {
		rateLimits = map[string]interface{}{
			zonePrefix + "-sec": map[string]interface{}{
				"key":        "{http.request.remote.host}",
				"window":     "1s",
				"max_events": policy.RateLimitRPS + policy.RateLimitBurst,
			},
			zonePrefix + "-min": map[string]interface{}{
				"key":        "{http.request.remote.host}",
				"window":     "60s",
				"max_events": policy.RateLimitRPS * 60,
			},
		}
	}
	return map[string]interface{}{
		"handler":        "rate_limit",
		"rate_limits":    rateLimits,
		"sweep_interval": "10m",
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
// fail-closed 会将其误判为“海外”而拦截，故在 GeoIP 拦截中一律放行（无论 deny/allow 模式）。
// v2.2.0 地域拦截改走 coraza 后由 BuildCorazaDirectives 的 GeoIP SecRule 链首
// REMOTE_ADDR !@ipMatch 引用（语义不变）。
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

func buildHTTPHandleChain(rule SingleRuleConfig, upstreams []UpstreamConfig, securityCtx ...*securityPolicyContext) ([]interface{}, error) {
	var ctx *securityPolicyContext
	if len(securityCtx) > 0 {
		ctx = securityCtx[0]
	}
	enabledUpstreams := make([]UpstreamConfig, 0, len(upstreams))
	for _, upstream := range upstreams {
		if upstream.Enabled {
			enabledUpstreams = append(enabledUpstreams, upstream)
		}
	}
	if len(enabledUpstreams) == 0 {
		return nil, fmt.Errorf("%w", ErrNoEnabledUpstreams)
	}
	if rule.DynamicDNS && len(enabledUpstreams) > 1 {
		return nil, fmt.Errorf("%w, got %d", ErrDynamicDNSUpstreamCount, len(enabledUpstreams))
	}

	policies := policiesForRule(ctx, rule.CaddyID)
	// A-I1：WAF 发射读取 security_custom_rules 必须与策略预载同 store——
	// 无 ctx（非批量路径）时传 nil，由 resolvePolicyCustomRules 回退 db.DB。
	var policyStore caddyConfigStore
	if ctx != nil {
		policyStore = ctx.store
	}
	var handleChain []interface{}
	// F3（v2.2.3）：链首注入 X-LB-Rule-ID——安全事件归因的一等信号（摄入侧优先
	// 读头、回退 host 反查，同域名多规则/通配符场景归因从概率正确到确定正确）。
	// 置于 IP 预检之前，预检与各策略 coraza 事务均可见；set 覆盖客户端伪造值；
	// reverse_proxy 前无条件剥离（见 proxyRequestHeaders 删除清单），不直达上游。
	if rule.Protocol == "http" && len(policies) > 0 {
		handleChain = append(handleChain, map[string]interface{}{
			"handler": "headers",
			"request": map[string]interface{}{"set": map[string]interface{}{"X-LB-Rule-ID": []string{rule.CaddyID}}},
		})
	}
	// 多策略 IP ACL 优先（IP 预检）：多策略绑定时把全部绑定策略的 deny 侧 IP
	// 控制合并为极简 coraza 预检查器置于链首（先于全部 rate_limit/waf）——被拒
	// IP 在任何策略的 CRS/自定义规则评估前即中断，不再产生前置策略的检测事件。
	// 单策略绑定不发射：自身 coraza 内 IP 控制本就先于其 CRS，发射形状不变。
	if rule.Protocol == "http" && len(policies) > 1 {
		if precheckHandler := buildIPPrecheckHandler(policies); precheckHandler != nil {
			handleChain = append(handleChain, precheckHandler)
		}
	}
	// v2.2.0 多策略：按绑定启用策略 policy_id ASC 依次编入各策略的
	// [rate_limit?, waf?] 处理器组；限流先于 WAF 检查、body 解析与代理。
	// 审计 B5-F2 + M4：CRS 池指纹在单次链构建内不变——按链计算一次透传给各
	// 策略，替代逐 (规则×策略) 对的 DB 查询+stat（200 规则×3 策略 ≈600 查询→
	// 200）；取值惰性化——零安全策略/非 http 链不发射任何 waf handler 时不再
	// 空付指纹计算（SELECT+2×stat），仅首个 waf handler 发射前计算。
	var chainFingerprint string
	needFingerprint := func() string {
		if chainFingerprint == "" {
			chainFingerprint = crsPoolFingerprintForChain()
		}
		return chainFingerprint
	}
	for _, policy := range policies {
		if rateLimitHandler := buildRateLimitHandler(rule.CaddyID, policy); rateLimitHandler != nil {
			handleChain = append(handleChain, rateLimitHandler)
		}
		if rule.Protocol == "http" {
			if wafHandler := buildWafHandlerWithPolicy(rule.CaddyID, policy, policyStore, needFingerprint()); wafHandler != nil {
				handleChain = append(handleChain, wafHandler)
			}
		}
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
		// R63 C-N2：DynamicDNS 规则恰有 1 个启用上游（保存/启用/导入三链强制），
		// weighted_round_robin 会发射 weights=[1]——Caddy 的 WeightedRoundRobinSelection
		// 对 len(Weights)<2 直接早退返回 pool[0]（不做可用性检查，reverseproxy.go:637
		// 传入的动态解析池亦不过滤不可用主机，重试无失败记忆）→ 流量恒打解析列表
		// 首个 IP，其余 A 记录零流量、首 IP 宕机时 try_duration 内重试全撞同一 IP
		// 后 502。动态解析池与静态权重表天然错配——改用内建 random（按 Available()
		// 过滤后蓄水池随机），多 A 记录均衡与跨记录故障切换真正生效。
		if rule.DynamicDNS && rule.Strategy == "weighted_round_robin" {
			selectionPolicy = map[string]interface{}{"policy": "random"}
		} else if rule.Strategy == "weighted_round_robin" {
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
				"fail_duration": fmt.Sprintf("%ds", hcInterval*3),
				"max_fails":     hcThreshold,
				// 5 是 Caddy 官方类码语义（StatusCodeMatches：configured<100 匹配整百段，
				// Caddyfile "5xx" 亦折叠为 5）——覆盖全部 500-599 服务端错误计入被动失败。
				// 2026-09 复审裁定 1：曾误改为显式 [500..504] 收窄覆盖（505-599 漏计），已恢复。
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
			// R39 C-4: interval/timeout 与 passive/TCP 路径同口径默认化——导入路径
			// 可达 0 值（validateV2BackupRules 不校验该组合），裸值会生成 "0s"。
			hcTimeout := rule.HealthCheckTimeout
			if hcTimeout <= 0 {
				// LB-04：默认与写侧（CreateRule/校验副本）及读取 COALESCE 统一为 2。
				hcTimeout = 2
			}
			active := map[string]interface{}{
				"uri":      hcPath,
				"timeout":  fmt.Sprintf("%ds", hcTimeout),
				"interval": fmt.Sprintf("%ds", hcInterval),
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
	// X-GeoIP-* 是 caddygeoip→coraza 的进程内控制头（coraza 在本 handler 之前
	// 执行，已消费完毕），绝不允许透传上游后端。无条件剥离：geoip 关闭的规则
	// 同时防客户端伪造同名头直达后端。头名清单与 caddygeoip/handler.go 的
	// headerNames 同源，变更需双侧同步。X-LB-Rule-ID 同型：链首注入的归因头
	//（F3）仅供 coraza 事务内消费，同口径无条件剥离。
	proxyRequestHeaders := map[string]interface{}{
		"delete": []string{
			"X-GeoIP-Country", "X-GeoIP-Country-Code", "X-GeoIP-Region",
			"X-GeoIP-Province", "X-GeoIP-City", "X-GeoIP-Loc",
			"X-LB-Rule-ID",
		},
	}
	if rule.HostHeader != "" {
		proxyRequestHeaders["set"] = map[string]interface{}{"Host": []string{rule.HostHeader}}
	}
	proxyConfig["headers"] = map[string]interface{}{"request": proxyRequestHeaders}
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

// ApplyConfigFromTxCertAwareForce：证书候选改读事务自身（R65 A-N1，restoreTable
// 保留原 id 重插证书行，已提交视图的旧行会经 MaterializeCertPairs 用旧 PEM 覆写
// 导入刚落盘的新证书文件）+ 强制重载（R72 二十六次 W1-1：v2 导入在 apply 之前
// 已把新 PEM 落盘，生成期 MaterializeCertPairs 内容比对相等 → 快照为空 → 自动
// 强制不触发，必须显式强制，否则同 JSON 导入新证书会被 errSameConfig 短路、
// 旧证书继续服务）。非强制的 ApplyConfigFromTxCertAware 已于 R72 二十七次删除
// （唯一生产调用方即本函数的调用点，保留旧版只会让未来调用方重新引入静默
// 旧证书缺陷）。
func (s *CaddyService) ApplyConfigFromTxCertAwareForce(tx *sql.Tx) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyConfigLockedOpt(generateCaddyConfigWithCertSource(tx, tx), true)
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
	// 2026-09 渲染审计：UI 语义「重试窗口 0=不重试」——0 不再兜底 5s，直接
	// 不发射 try_duration/try_interval（故障切换窗口关闭）；>0 时 interval 缺省 250ms。
	tryDuration := rule.TCPTryDuration
	if tryDuration > 0 {
		tryInterval := rule.TCPTryInterval
		if tryInterval <= 0 {
			tryInterval = 250
		}
		loadBalancing["try_duration"] = fmt.Sprintf("%dms", tryDuration)
		loadBalancing["try_interval"] = fmt.Sprintf("%dms", tryInterval)
	}
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
