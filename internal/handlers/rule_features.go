package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

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
	EnabledUpstreamCount       int
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
		ListenPort:                 req.ListenPort,
		EnableTLS:                  req.EnableTLS,
		TLSHTTPRedirect:            req.TLSHTTPRedirect,
		DynamicDNS:                 req.DynamicDNS,
		EnabledUpstreamCount:       enabledUpstreams,
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
		ListenPort:                 req.ListenPort,
		EnableTLS:                  existing.EnableTLS,
		TLSHTTPRedirect:            existing.TLSHTTPRedirect,
		DynamicDNS:                 existing.DynamicDNS,
		EnabledUpstreamCount:       enabledUpstreams,
		HealthCheckInterval:        req.HealthCheckInterval,
		HealthCheckTimeout:         req.HealthCheckTimeout,
		EnableCompress:             existing.EnableCompress,
		CompressTypes:              req.CompressTypes,
		CustomRoutesEnabled:        existing.CustomRoutesEnabled,
		PathRules:                  existing.PathRules,
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
	return input
}

func normalizePathRules(pathRules []models.PathRule) []models.PathRule {
	normalized := append([]models.PathRule(nil), pathRules...)
	for index := range normalized {
		if normalized[index].MatchType == "" {
			normalized[index].MatchType = "prefix"
		}
		// Round 29 G-6: 存储前 TrimSpace，与校验侧（validateRuleFeatures 277 行先 TrimSpace
		// 再归一）及渲染侧 pathMatcherSpecs 对齐，避免空格路径校验误报冲突。
		normalized[index].Path = strings.TrimSpace(normalized[index].Path)
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

func validateRuleFeatures(input ruleFeatureInput) error {
	// R43 F-B: 协议白名单。此前 Create/Update 仅拒绝空协议（rules.go:564），
	// "https" 等未知值可经 API/MCP 落库，全量渲染按「非 http 即 TCP」处理
	// （caddy.go:1276）——域名匹配静默丢失、TLS 字段被忽略。统一在特性校验入口
	// 拒绝未知协议，Create/Update/复制/导入全链路复用；保存校验 GenerateRouteObject
	// 亦仅放行 http/tcp（R44 B1 对齐），存量 https 行由 db 迁移归一为 http+TLS。
	if input.Protocol != "http" && input.Protocol != "tcp" {
		return fmt.Errorf("协议仅支持 http 或 tcp")
	}
	// Round 37 I-5: strategy 白名单校验，非法值不再透传到 Caddy。
	// 协议感知：cookie 仅 HTTP 支持，TCP 规则拒绝，与 handlers.go validateCaddyConfigBeforeSave 对齐。
	if input.Strategy != "" {
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
		switch input.Protocol {
		case "http":
			if !httpStrategies[input.Strategy] {
				return fmt.Errorf("无效的负载策略：HTTP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first / cookie")
			}
		case "tcp":
			if !tcpStrategies[input.Strategy] {
				return fmt.Errorf("无效的负载策略：TCP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first")
			}
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
	// C-F2: 80 端口 + TLS 跳转自环：跳转目标 https://host:80 与来源同为 80 端口，
	// 请求会被跳回自身监听器形成循环，必须在保存前拒绝。
	if input.Protocol == "http" && input.ListenPort == 80 && input.EnableTLS && input.TLSHTTPRedirect {
		return fmt.Errorf("80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转")
	}
	if input.Protocol == "tcp" {
		if input.CustomRoutesEnabled || len(input.PathRules) > 0 {
			return fmt.Errorf("TCP 规则不支持自定义路径规则")
		}
		if input.ProxyDialTimeout > 0 || input.ProxyResponseHeaderTimeout > 0 || input.ProxyReadTimeout > 0 || input.ProxyWriteTimeout > 0 || input.ProxyStreamTimeout > 0 || input.ProxyFlushInterval != 0 || input.ProxyStreamCloseDelay > 0 {
			return fmt.Errorf("TCP 规则不支持 HTTP 代理超时配置")
		}
	}
	if !input.CustomRoutesEnabled && len(input.PathRules) > 0 {
		return fmt.Errorf("自定义路径规则未启用，不能提交路径规则")
	}
	seenPaths := make(map[string]int, len(input.PathRules))
	// C-F3: prefix 会渲染为 [路径, 路径/*] 双 matcher，同一路径再配 exact 必被遮蔽
	// （路由按 SortOrder 排序、首条终结匹配），在保存前整组拒绝。
	// C-F2: 查重/查遮蔽必须与渲染侧 pathMatcherSpecs 同源归一（TrimRight 尾 / 与 *），
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
		// C-F4: 空数组虽在生成阶段已回退主上游（Round 32 F-3，与 nil 同语义），
		// 仍禁止写入上游表占位的空 upstreams_json——保存前拒绝保持数据整洁。
		if pathRule.Upstreams != nil && len(pathRule.Upstreams) == 0 {
			return fmt.Errorf("第 %d 条路径规则至少需要配置一个上游", index+1)
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
	// proxy_flush_interval: 0 = 自动（仅 text/event-stream 触发立即刷新），-1 = 立即刷新所有响应，>0 = 每 N 秒刷新一次
	if input.ProxyFlushInterval < -1 {
		return fmt.Errorf("代理刷新间隔不能小于 -1")
	}
	if input.ProxyStreamCloseDelay < 0 {
		return fmt.Errorf("代理流关闭延迟不能为负数")
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
	COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
	COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
	COALESCE(custom_routes_enabled,0),
	COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
	COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), '', '',
	COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), IIF(enabled IN ('1',1),1,0), COALESCE(log_enabled,0),
	created_by, created_at, updated_at, updated_by, COALESCE(host_header,'')`

const lbRuleColumns = `COALESCE(id,0), COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, COALESCE(strategy,''),
	COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
	COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
	COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
	COALESCE(custom_routes_enabled,0),
	COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
	COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
	COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), IIF(enabled IN ('1',1),1,0), COALESCE(log_enabled,0),
	created_by, created_at, updated_at, updated_by, COALESCE(host_header,'')`

// 规范化规则行扫描：ListRules/GetRule/DuplicateRule 共用，避免列清单多处漂移
func scanLbRules(rows *sql.Rows) ([]models.LbRule, error) {
	rules := make([]models.LbRule, 0)
	for rows.Next() {
		var r models.LbRule
		var description, domain, strategy, dnsFamily, tlsSource, tlsCert, tlsKey, compressTypes, hostHeader string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect, enableCompress bool
		var acmeConfigID, caProviderID int
		var createdBy, updatedBy sql.NullInt64
		var createdAt, updatedAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&enableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPProxyProtocol, &r.TCPTryDuration, &r.TCPTryInterval,
			&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden,
			&r.CustomRoutesEnabled,
			&r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout, &r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout, &r.ProxyFlushInterval, &r.ProxyStreamCloseDelay,
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
	// Round 35: 与渲染侧同口径（IIF(enabled IN ('1',1),1,0)，NULL 视禁用）——
	// 此前 COALESCE(enabled,1) 将遗留 NULL 行视为启用，UI 显示与生成配置分裂。
	rows, err := db.DB.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), IIF(enabled IN ('1',1),1,0), COALESCE(protocol,'http'), COALESCE(max_connections,0)
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
	// C-F2: 与 validateRuleFeatures 同口径，兜住历史存量/导入的 80 端口 + TLS 跳转自环规则。
	if rule.Protocol == "http" && rule.ListenPort == 80 && rule.EnableTLS && rule.TLSHTTPRedirect {
		return &configValidationError{message: "80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转"}
	}
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource != "manual" && rule.TLSSource != "acme_dns" {
		return &configValidationError{message: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"}
	}
	// R52 F-2：与 R51 Create/Update 写侧 400 口径对齐——导入残留的
	// acme_dns+0 坏规则不得经 EnableRule 投入运行（签发必败且明文服务）。
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource == "acme_dns" && rule.ACMEConfigID == 0 {
		return &configValidationError{message: "使用 ACME 签发时必须选择 DNS 提供商配置"}
	}
	if rule.Protocol == "http" && rule.EnableTLS && rule.TLSSource == "manual" &&
		(strings.TrimSpace(rule.TLSCert) == "" || strings.TrimSpace(rule.TLSKey) == "") {
		return &configValidationError{message: "手动证书模式下必须提供 TLS 证书和私钥"}
	}
	return validateRuleConfigGeneration(rule)
}

// Round 30 F-4: 收集全部坏规则错误聚合返回（每条含规则名+caddy_id），
// 避免首错即 return 导致多条坏规则需重启多次逐一暴露；errors.Join 保持
// 与 configValidationError 的 errors.As 兼容（UpdateConfig/EnableRule 类型断言路径）。
func validateEnabledStoredRuleConfigs(ctx context.Context) error {
	rules, err := loadRulesForConfigValidation(ctx, " WHERE enabled = 1")
	if err != nil {
		return err
	}
	problems := make([]error, 0)
	for _, rule := range rules {
		// 存量规则可能建于校验上线前：80 端口 + TLS 跳转生成自环 Location，
		// 启动再生配置前按保存路径同口径拦截并指出具体规则。
		if rule.Protocol == "http" && rule.ListenPort == 80 && rule.EnableTLS && rule.TLSHTTPRedirect {
			problems = append(problems, &configValidationError{message: fmt.Sprintf("规则 %s（%s）80 端口开启 TLS 跳转无意义（目标与来源相同端口），请改用 443 端口或关闭跳转", rule.Name, rule.CaddyID)})
			continue
		}
		if err := validateRuleConfigGeneration(rule); err != nil {
			problems = append(problems, fmt.Errorf("规则 %s（%s）配置无效：%w", rule.Name, rule.CaddyID, err))
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
	genErr, hasErr := config["error"].(error)
	if !hasErr {
		return nil
	}
	// Round 31 C-2: 仅特判零上游——全量渲染路径对零上游规则是跳过而非失败
	// （caddy.go 按启用上游数 continue），该特判是有意的，保持与渲染侧一致；
	// 其余生成错误（含 generateHTTPRouteObjects 的硬错误）一律返回，
	// 避免 F4 聚合与 EnableRule 预校验漏报（此前全被吞掉）。
	// Round 32 F-3: 精确串比较改哨兵 errors.Is——生成侧两处产出点
	// （GenerateSingleRuleCaddyConfig 直返 / buildHTTPHandleChain %w 包装）
	// 统一引用 services.ErrNoEnabledUpstreams，未来加规则上下文包装仍能命中。
	if errors.Is(genErr, services.ErrNoEnabledUpstreams) {
		return nil
	}
	// Round 33 N-3: 动态 DNS 多上游同样哨兵化（ErrDynamicDNSUpstreamCount），
	// 不再依赖文案 Contains——文案调整即静默漏报。
	if errors.Is(genErr, services.ErrDynamicDNSUpstreamCount) {
		return &configValidationError{message: "动态 DNS 模式仅支持一个启用的上游"}
	}
	return fmt.Errorf("生成规则配置失败: %s", genErr.Error())
}
