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
	return ruleFeatureInput{
		Protocol:                   req.Protocol,
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
	input := ruleFeatureInput{
		Protocol:                   existing.Protocol,
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
	rows, err := queryer.QueryContext(ctx, `SELECT id,rule_id,sort_order,match_type,path,upstreams_json FROM path_rules WHERE rule_id=? ORDER BY sort_order,id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("读取规则 %s 的路径规则: %w", ruleID, err)
	}
	defer rows.Close()

	pathRules := make([]models.PathRule, 0)
	for rows.Next() {
		var pathRule models.PathRule
		var upstreamsJSON sql.NullString
		if err := rows.Scan(&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &upstreamsJSON); err != nil {
			return nil, fmt.Errorf("扫描规则 %s 的路径规则: %w", ruleID, err)
		}
		if upstreamsJSON.Valid {
			if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
				return nil, fmt.Errorf("解析路径规则 %d 的上游: %w", pathRule.ID, err)
			}
		}
		pathRules = append(pathRules, pathRule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历规则 %s 的路径规则: %w", ruleID, err)
	}
	return pathRules, nil
}

func dumpRowsByKey(ctx context.Context, table, keyColumn string, keyValue any) ([]map[string]any, error) {
	rows, err := db.DB.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s WHERE %s = ?", table, keyColumn), keyValue)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 快照: %w", table, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, fmt.Errorf("扫描 %s 快照: %w", table, err)
		}
		row := map[string]any{}
		for i, column := range columns {
			if bytes, ok := values[i].([]byte); ok {
				row[column] = string(bytes)
			} else {
				row[column] = values[i]
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
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

	var protocol, oldMode, oldListJSON string
	if err := db.DB.QueryRow("SELECT protocol, COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol, &oldMode, &oldListJSON); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	input := ruleFeatureInput{Protocol: protocol, IPACLMode: req.IPACLMode, IPACLList: req.IPACLList}
	if err := validateRuleFeatures(input); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	newListJSON, err := encodeIPACLList(input.IPACLList)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	if _, err := db.DB.Exec("UPDATE lb_rules SET ip_acl_mode = ?, ip_acl_list = ?, updated_at = datetime('now') WHERE caddy_id = ?", input.IPACLMode, newListJSON, caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新访问控制失败"})
		return
	}

	if err := h.applyCaddyConfigWithRollbackLocked(); err != nil {
		if _, restoreErr := db.DB.Exec("UPDATE lb_rules SET ip_acl_mode = ?, ip_acl_list = ?, updated_at = datetime('now') WHERE caddy_id = ?", oldMode, oldListJSON, caddyID); restoreErr != nil {
			log.Printf("CRITICAL: UpdateRuleACL Caddy apply and DB restore failed for caddy_id=%s: caddy=%v db=%v", caddyID, err, restoreErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy 与 DB 恢复均失败: Caddy: %v; DB: %v", err, restoreErr)})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy 配置应用失败，已回滚: %v", err)})
		return
	}

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

const lbRuleColumns = `COALESCE(id,0), COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, COALESCE(strategy,''),
	COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
	COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
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
			r.UpdatedAt = updatedAt
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
	rows, err := db.DB.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), COALESCE(enabled,1), COALESCE(protocol,'http'), COALESCE(max_connections,0)
		FROM upstreams WHERE rule_id IN (`+strings.Join(placeholders, ",")+`) ORDER BY id`, args...)
	if err != nil {
		return nil, fmt.Errorf("批量读取上游: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u models.Upstream
		if err := rows.Scan(&u.ID, &u.RuleID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
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
