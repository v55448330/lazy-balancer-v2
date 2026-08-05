package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

type ruleFeatureInput struct {
	Protocol                   string
	Strategy                   string
	DynamicDNS                 bool
	EnabledUpstreamCount       int
	HealthCheckInterval        int
	HealthCheckTimeout         int
	EnableCompress             bool
	CompressTypes              string
	IPACLMode                  string
	IPACLList                  []string
	CustomRoutesEnabled        bool
	PathRules                  []models.PathRule
	ProxyDialTimeout           int
	ProxyResponseHeaderTimeout int
	ProxyReadTimeout           int
	ProxyWriteTimeout          int
	ProxyStreamTimeout         int
}

type pathRuleQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func createRuleFeatures(req models.CreateRuleRequest) ruleFeatureInput {
	enabledUpstreams := 0
	for _, u := range req.Upstreams {
		if u.Enabled {
			enabledUpstreams++
		}
	}
	return ruleFeatureInput{
		Protocol:                   req.Protocol,
		Strategy:                   req.Strategy,
		DynamicDNS:                 req.DynamicDNS,
		EnabledUpstreamCount:       enabledUpstreams,
		HealthCheckInterval:        req.HealthCheckInterval,
		HealthCheckTimeout:         req.HealthCheckTimeout,
		EnableCompress:             req.EnableCompress,
		CompressTypes:              req.CompressTypes,
		IPACLMode:                  req.IPACLMode,
		IPACLList:                  req.IPACLList,
		CustomRoutesEnabled:        req.CustomRoutesEnabled,
		PathRules:                  normalizePathRules(req.PathRules),
		ProxyDialTimeout:           req.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: req.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           req.ProxyReadTimeout,
		ProxyWriteTimeout:          req.ProxyWriteTimeout,
		ProxyStreamTimeout:         req.ProxyStreamTimeout,
	}
}

func updateRuleFeatures(req models.UpdateRuleRequest, existing models.LbRule) ruleFeatureInput {
	enabledUpstreams := 0
	if req.Upstreams != nil {
		for _, u := range req.Upstreams {
			if u.Enabled {
				enabledUpstreams++
			}
		}
	} else {
		for _, u := range existing.Upstreams {
			if u.Enabled {
				enabledUpstreams++
			}
		}
	}
	// Round 38 B2: 对非指针字段（handler 已在调用前完成 merge），直接使用 req 值。
	// 对指针字段，nil 时用 existing 值，非 nil 时解引用。
	input := ruleFeatureInput{
		Protocol:                   existing.Protocol,
		Strategy:                   req.Strategy,
		DynamicDNS:                 existing.DynamicDNS,
		EnabledUpstreamCount:       enabledUpstreams,
		HealthCheckInterval:        req.HealthCheckInterval,
		HealthCheckTimeout:         req.HealthCheckTimeout,
		EnableCompress:             existing.EnableCompress,
		CompressTypes:              req.CompressTypes,
		IPACLMode:                  existing.IPACLMode,
		IPACLList:                  existing.IPACLList,
		CustomRoutesEnabled:        existing.CustomRoutesEnabled,
		PathRules:                  existing.PathRules,
		ProxyDialTimeout:           existing.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: existing.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           existing.ProxyReadTimeout,
		ProxyWriteTimeout:          existing.ProxyWriteTimeout,
		ProxyStreamTimeout:         existing.ProxyStreamTimeout,
	}
	if req.DynamicDNS != nil {
		input.DynamicDNS = *req.DynamicDNS
	}
	if req.EnableCompress != nil {
		input.EnableCompress = *req.EnableCompress
	}
	if req.IPACLMode != nil {
		input.IPACLMode = *req.IPACLMode
	}
	if req.IPACLList != nil {
		input.IPACLList = *req.IPACLList
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
	return input
}

func normalizePathRules(pathRules []models.PathRule) []models.PathRule {
	normalized := append([]models.PathRule(nil), pathRules...)
	for index := range normalized {
		if normalized[index].MatchType == "" {
			normalized[index].MatchType = "prefix"
		}
	}
	return normalized
}

func toPathRuleConfigs(pathRules []models.PathRule) []services.PathRuleConfig {
	configs := make([]services.PathRuleConfig, 0, len(pathRules))
	for _, pathRule := range pathRules {
		config := services.PathRuleConfig{
			SortOrder: pathRule.SortOrder,
			MatchType: pathRule.MatchType,
			Path:      pathRule.Path,
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

func encodeIPACLList(ipACLList []string) (string, error) {
	if ipACLList == nil {
		ipACLList = []string{}
	}
	encoded, err := json.Marshal(ipACLList)
	if err != nil {
		return "", fmt.Errorf("序列化 IP 访问控制列表: %w", err)
	}
	return string(encoded), nil
}

func decodeIPACLList(encoded string) ([]string, error) {
	ipACLList := make([]string, 0)
	if err := json.Unmarshal([]byte(encoded), &ipACLList); err != nil {
		return nil, fmt.Errorf("解析 IP 访问控制列表: %w", err)
	}
	return ipACLList, nil
}

func validateRuleFeatures(input ruleFeatureInput) error {
	// Round 37 I-5: strategy 白名单校验，非法值不再透传到 Caddy。
	if input.Strategy != "" {
		validStrategies := map[string]bool{
			"weighted_round_robin": true, "least_conn": true,
			"ip_hash": true, "cookie": true,
			"random": true, "first": true,
		}
		if !validStrategies[input.Strategy] {
			return fmt.Errorf("负载均衡策略 %q 不支持，支持的策略：weighted_round_robin / least_conn / ip_hash / cookie / random / first", input.Strategy)
		}
	}
	// Round 37 I-6: 健康检查超时必须小于检查间隔（两者都 > 0 时）。
	if input.HealthCheckInterval > 0 && input.HealthCheckTimeout > 0 && input.HealthCheckTimeout >= input.HealthCheckInterval {
		return fmt.Errorf("健康检查超时时间（%d 秒）必须小于检查间隔（%d 秒）", input.HealthCheckTimeout, input.HealthCheckInterval)
	}
	// Round 37 I-7: compress_types 白名单校验，不支持编码不再静默丢弃。
	if input.EnableCompress && input.CompressTypes != "" {
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
	// Round 37 I-8: dynamic_dns + 多 upstream 前置校验（原仅在 Caddy 渲染阶段检查，规则已入库）。
	if input.DynamicDNS && input.EnabledUpstreamCount > 1 {
		return fmt.Errorf("动态上游模式仅允许一个启用的上游服务器，当前有 %d 个", input.EnabledUpstreamCount)
	}
	switch input.IPACLMode {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("IP 访问控制模式只能为空、allow 或 deny")
	}
	if input.IPACLMode != "" && len(input.IPACLList) == 0 {
		return fmt.Errorf("白名单/黑名单模式需要至少一条 CIDR")
	}
	if input.IPACLMode == "" && len(input.IPACLList) > 0 {
		return fmt.Errorf("IP 访问控制模式为空时列表必须为空")
	}
	for _, cidr := range input.IPACLList {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("IP 访问控制列表中的 %q 不是有效 CIDR", cidr)
		}
	}
	if input.Protocol == "tcp" {
		if input.CustomRoutesEnabled || len(input.PathRules) > 0 {
			return fmt.Errorf("TCP 规则不支持自定义路径规则")
		}
		if input.ProxyDialTimeout > 0 || input.ProxyResponseHeaderTimeout > 0 || input.ProxyReadTimeout > 0 || input.ProxyWriteTimeout > 0 || input.ProxyStreamTimeout > 0 {
			return fmt.Errorf("TCP 规则不支持 HTTP 代理超时配置")
		}
	}
	if !input.CustomRoutesEnabled && len(input.PathRules) > 0 {
		return fmt.Errorf("自定义路径规则未启用，不能提交路径规则")
	}
	seenPaths := make(map[string]int, len(input.PathRules))
	for index, pathRule := range input.PathRules {
		if !strings.HasPrefix(pathRule.Path, "/") {
			return fmt.Errorf("第 %d 条路径规则的路径必须以 / 开头", index+1)
		}
		if strings.ContainsAny(pathRule.Path, "*?{}") {
			return fmt.Errorf("第 %d 条路径规则的路径不能包含 * ? { } 通配字符", index+1)
		}
		duplicateKey := pathRule.MatchType + ":" + strings.TrimSpace(pathRule.Path)
		if seenAt, exists := seenPaths[duplicateKey]; exists {
			return fmt.Errorf("第 %d 条路径规则与第 %d 条重复（%s）", index+1, seenAt, pathRule.Path)
		}
		seenPaths[duplicateKey] = index + 1
		switch pathRule.MatchType {
		case "prefix", "exact":
		default:
			return fmt.Errorf("第 %d 条路径规则的匹配类型只能是 prefix 或 exact", index+1)
		}
		for upstreamIndex, upstream := range pathRule.Upstreams {
			if strings.TrimSpace(upstream.Address) == "" {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游地址不能为空", index+1, upstreamIndex+1)
			}
			if upstream.Port < 1 || upstream.Port > 65535 {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游端口必须在 1-65535 之间", index+1, upstreamIndex+1)
			}
			if upstream.Weight < 0 {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游权重不能为负数", index+1, upstreamIndex+1)
			}
			if upstream.Protocol != "" && upstream.Protocol != "http" && upstream.Protocol != "https" {
				return fmt.Errorf("第 %d 条路径规则的第 %d 个上游协议只能是 http 或 https", index+1, upstreamIndex+1)
			}
		}
	}
	if input.ProxyDialTimeout < 0 || input.ProxyResponseHeaderTimeout < 0 || input.ProxyReadTimeout < 0 || input.ProxyWriteTimeout < 0 || input.ProxyStreamTimeout < 0 {
		return fmt.Errorf("代理超时时间不能为负数")
	}
	return nil
}

func replacePathRulesTx(ctx context.Context, tx *sql.Tx, ruleID string, pathRules []models.PathRule) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM path_rules WHERE rule_id = ?", ruleID); err != nil {
		return fmt.Errorf("删除规则 %s 的路径规则: %w", ruleID, err)
	}
	for _, pathRule := range pathRules {
		var upstreamsJSON any
		if pathRule.Upstreams != nil {
			encoded, err := json.Marshal(pathRule.Upstreams)
			if err != nil {
				return fmt.Errorf("序列化路径规则 %s 的上游: %w", pathRule.Path, err)
			}
			upstreamsJSON = string(encoded)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json,updated_at) VALUES (?,?,?,?,?,datetime('now'))`, ruleID, pathRule.SortOrder, pathRule.MatchType, pathRule.Path, upstreamsJSON); err != nil {
			return fmt.Errorf("写入规则 %s 的路径规则 %s: %w", ruleID, pathRule.Path, err)
		}
	}
	return nil
}

func loadPathRules(ctx context.Context, queryer pathRuleQueryer, ruleID string) ([]models.PathRule, error) {
	return db.LoadPathRules(ctx, queryer, ruleID)
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

func (h *Handlers) UpdateRuleACL(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var req struct {
		IPACLMode string   `json:"ip_acl_mode"`
		IPACLList []string `json:"ip_acl_list"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误: " + err.Error()})
		return
	}

	// 与 UpdateRule 同一锁序：读旧值→写入→应用全程持锁，避免被全量更新覆盖丢失
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var protocol string
	if err := db.DB.QueryRow("SELECT protocol FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol); dbQueryNotFound(c, err, "规则不存在", "UpdateRuleACL query rule") {
		return
	}
	input := ruleFeatureInput{Protocol: protocol, IPACLMode: req.IPACLMode, IPACLList: req.IPACLList}
	if err := validateRuleFeatures(input); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := validateStoredRuleConfig(c.Request.Context(), caddyID); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败: " + err.Error()})
		return
	}
	newListJSON, err := encodeIPACLList(input.IPACLList)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				log.Printf("UpdateRuleACL transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	if _, err := tx.Exec("UPDATE lb_rules SET ip_acl_mode = ?, ip_acl_list = ?, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", input.IPACLMode, newListJSON, userIDInt, caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新访问控制失败"})
		return
	}
	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置验证失败: " + errors.Join(validationErr, restoreErr).Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy 配置应用失败，数据库未写入: %v", errors.Join(err, restoreErr))})
		return
	}
	if err := tx.Commit(); err != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("提交访问控制失败: %v", errors.Join(err, restoreErr))})
		return
	}
	committed = true

	aclModeText := map[string]string{"allow": "白名单", "deny": "黑名单", "": "已关闭"}[input.IPACLMode]
	recordAudit(c, "更新", "访问控制", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("模式：%s", aclModeText), fmt.Sprintf("CIDR 数：%d", len(input.IPACLList))))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "访问控制已保存"})
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
				log.Printf("restoreRuleSnapshot rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
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

// JWT 中间件存 float64，API Key 中间件存 int，统一在此收敛
func contextUserID(c *gin.Context) int64 {
	v, ok := c.Get("user_id")
	if !ok || v == nil {
		return 0
	}
	switch id := v.(type) {
	case float64:
		return int64(id)
	case int:
		return int64(id)
	case int64:
		return id
	}
	return 0
}

// Round 38 I-9: 列表查询不加载 tls_cert/tls_key 正文，减少大字段 I/O。
// 列顺序与 lbRuleColumns 完全一致，scanLbRules 无需修改。
const lbRuleListColumns = `COALESCE(id,0), COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, COALESCE(strategy,''),
	COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
	COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,2), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
	COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
	COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
	COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
	COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), '', '',
	COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), COALESCE(enabled,1), COALESCE(log_enabled,0),
	created_by, created_at, updated_at, updated_by, COALESCE(host_header,'')`

const lbRuleColumns = `COALESCE(id,0), COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, COALESCE(strategy,''),
	COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
	COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,2), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
	COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
	COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
	COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
	COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
	COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), COALESCE(enabled,1), COALESCE(log_enabled,0),
	created_by, created_at, updated_at, updated_by, COALESCE(host_header,'')`

// 规范化规则行扫描：ListRules/GetRule/DuplicateRule 共用，避免列清单多处漂移
func scanLbRules(rows *sql.Rows) ([]models.LbRule, error) {
	rules := make([]models.LbRule, 0)
	for rows.Next() {
		var r models.LbRule
		var description, domain, strategy, dnsFamily, ipACLListJSON, tlsSource, tlsCert, tlsKey, compressTypes, hostHeader string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect, enableCompress bool
		var acmeConfigID, caProviderID int
		var createdBy, updatedBy sql.NullInt64
		var createdAt, updatedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&enableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPProxyProtocol, &r.TCPTryDuration, &r.TCPTryInterval,
			&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden,
			&r.IPACLMode, &ipACLListJSON, &r.CustomRoutesEnabled,
			&r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout, &r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout,
			&enableTLS, &tlsSource, &acmeConfigID, &caProviderID, &tlsCert, &tlsKey, &tlsHTTPRedirect,
			&enableCompress, &compressTypes, &r.Enabled, &r.LogEnabled,
			&createdBy, &createdAt, &updatedAt, &updatedBy, &hostHeader); err != nil {
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
		ipACLList, err := decodeIPACLList(ipACLListJSON)
		if err != nil {
			return nil, fmt.Errorf("规则 %s 的 IP 访问控制列表: %w", r.CaddyID, err)
		}
		r.IPACLList = ipACLList
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

func loadUpstreamsBatch(ctx context.Context, ruleIDs []string) (map[string][]models.Upstream, error) {
	result := make(map[string][]models.Upstream, len(ruleIDs))
	if len(ruleIDs) == 0 {
		return result, nil
	}
	placeholders := make([]string, len(ruleIDs))
	args := make([]any, len(ruleIDs))
	for i, id := range ruleIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := db.DB.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), COALESCE(enabled,1), COALESCE(protocol,'http'), COALESCE(max_connections,0)
		FROM upstreams WHERE rule_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY id`, args...)
	if err != nil {
		return nil, fmt.Errorf("批量读取上游: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u models.Upstream
		if err := rows.Scan(&u.ID, &u.RuleID, &u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
			return nil, err
		}
		result[u.RuleID] = append(result[u.RuleID], u)
	}
	return result, rows.Err()
}

func loadPathRulesBatch(ctx context.Context, ruleIDs []string) (map[string][]models.PathRule, error) {
	result := make(map[string][]models.PathRule, len(ruleIDs))
	if len(ruleIDs) == 0 {
		return result, nil
	}
	placeholders := make([]string, len(ruleIDs))
	args := make([]any, len(ruleIDs))
	for i, id := range ruleIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := db.DB.QueryContext(ctx, `SELECT id,rule_id,sort_order,match_type,path,upstreams_json
		FROM path_rules WHERE rule_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY rule_id, sort_order, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("批量读取路径规则: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pathRule models.PathRule
		var upstreamsJSON sql.NullString
		if err := rows.Scan(&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &upstreamsJSON); err != nil {
			return nil, err
		}
		if upstreamsJSON.Valid {
			if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
				return nil, fmt.Errorf("解析路径规则 %d 的上游: %w", pathRule.ID, err)
			}
		}
		result[pathRule.RuleID] = append(result[pathRule.RuleID], pathRule)
	}
	return result, rows.Err()
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

func validateStoredRuleConfig(ctx context.Context, caddyID string) error {
	rules, err := loadRulesForConfigValidation(ctx, " WHERE caddy_id = ?", caddyID)
	if err != nil {
		return err
	}
	if len(rules) != 1 {
		return fmt.Errorf("规则不存在")
	}
	rule := rules[0]
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource != "manual" && rule.TLSSource != "acme_dns" {
		return &configValidationError{message: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"}
	}
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource == "manual" &&
		(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
		return &configValidationError{message: "手动证书模式下必须提供 TLS 证书和私钥"}
	}
	return validateRuleConfigGeneration(rule)
}

func validateEnabledStoredRuleConfigs(ctx context.Context) error {
	rules, err := loadRulesForConfigValidation(ctx, " WHERE enabled = 1")
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := validateRuleConfigGeneration(rule); err != nil {
			return err
		}
	}
	return nil
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

func validateRuleConfigGeneration(rule models.LbRule) error {
	upstreams := make([]services.UpstreamConfig, 0, len(rule.Upstreams))
	for _, upstream := range rule.Upstreams {
		upstreams = append(upstreams, services.UpstreamConfig{
			Host: upstream.Host, Port: upstream.Port, Weight: upstream.Weight,
			Protocol: upstream.Protocol, Enabled: upstream.Enabled, MaxConnections: upstream.MaxConnections,
		})
	}
	config := services.GenerateSingleRuleCaddyConfig(services.SingleRuleConfig{
		CaddyID: rule.CaddyID, Protocol: rule.Protocol, Domain: rule.Domain, ListenPort: rule.ListenPort,
		Strategy: rule.Strategy, DynamicDNS: rule.DynamicDNS, EnableDnsServer: rule.EnableDnsServer,
		DnsServer: rule.DnsServer, DnsFamily: rule.DnsFamily, CustomRoutesEnabled: rule.CustomRoutesEnabled,
		PathRules: toPathRuleConfigs(rule.PathRules), Upstreams: upstreams,
	})
	message, invalid := config["error"].(string)
	if !invalid {
		return nil
	}
	if !strings.Contains(message, "dynamic DNS requires exactly one enabled upstream") {
		return nil
	}
	return &configValidationError{message: "动态 DNS 模式仅支持一个启用的上游"}
}
