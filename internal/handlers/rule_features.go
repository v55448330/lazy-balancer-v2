package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
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
				config.Upstreams = append(config.Upstreams, services.UpstreamConfig{
					Host: upstream.Address, Port: upstream.Port, Weight: upstream.Weight, Protocol: "http", Enabled: true,
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
	for index, pathRule := range input.PathRules {
		if !strings.HasPrefix(pathRule.Path, "/") {
			return fmt.Errorf("第 %d 条路径规则的路径必须以 / 开头", index+1)
		}
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
