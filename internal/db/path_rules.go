package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"lazy-balancer-v2/internal/models"
)

type PathRuleQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// pathRuleColumnsTemplate 是 path_rules 读投影单源（%[1]s 为表别名前缀，
// JOIN 查询传 "p"，单表查询传空串）。顺序与 ScanPathRule 的扫描目标逐一对应。
// 此前 12 列清单在逐规则读取、批量读取、集群快照、cluster_version 触发器
// OF 登记多处手抄且已分叉（快照侧多两时间列）——新增列只改一侧即静默缺列
// 或漏 bump。新增响应字段只改这里 + 在 ScanPathRule 接住。
const pathRuleColumnsTemplate = "%[1]sid, %[1]srule_id, %[1]ssort_order, %[1]smatch_type, %[1]spath, %[1]supstream_path, %[1]supstreams_json, %[1]sresponse_mode, %[1]sresponse_status, %[1]sresponse_body, %[1]sresponse_content_type, %[1]sredirect_to"

// PathRuleSelectColumns 返回 path_rules 列清单（写入 `SELECT ` 之后）。
// alias 非空时逐列加表别名前缀（多表 JOIN 必须限定列归属）。
func PathRuleSelectColumns(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return fmt.Sprintf(pathRuleColumnsTemplate, prefix)
}

// ErrPathRuleUpstreamsDecode 标记 ScanPathRule 内 upstreams_json 解码失败：
// 读侧（LoadPathRules/批量装载）按整批硬失败；集群快照侧按行隔离（warn+skip）。
var ErrPathRuleUpstreamsDecode = errors.New("path rule upstreams decode")

// ScanPathRule 按 PathRuleSelectColumns 的顺序扫描一行路径规则；extra 依次
// 追加在清单末尾（调用方在 PathRuleSelectColumns 之后 SELECT 的附加列，如
// 快照侧的 created_at/updated_at）。upstreams_json 的解码同在此收口
// （NULL=路径不携带上游），调用方无需各自重复 NullString 解包。解码失败时
// 返回值仍携带已扫描的行（含 ID，供快照侧点名隔离），错误以
// ErrPathRuleUpstreamsDecode 标记。
func ScanPathRule(scanner interface{ Scan(dest ...any) error }, extra ...any) (models.PathRule, error) {
	var pathRule models.PathRule
	var upstreamsJSON sql.NullString
	dest := []any{
		&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &pathRule.UpstreamPath, &upstreamsJSON,
		&pathRule.ResponseMode, &pathRule.ResponseStatus, &pathRule.ResponseBody, &pathRule.ResponseContentType, &pathRule.RedirectTo,
	}
	dest = append(dest, extra...)
	if err := scanner.Scan(dest...); err != nil {
		return models.PathRule{}, err
	}
	if upstreamsJSON.Valid {
		if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
			return pathRule, fmt.Errorf("decode path rule %d upstreams: %w: %w", pathRule.ID, ErrPathRuleUpstreamsDecode, err)
		}
	}
	return pathRule, nil
}

func LoadPathRules(ctx context.Context, queryer PathRuleQueryer, ruleID string) ([]models.PathRule, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT `+PathRuleSelectColumns("")+` FROM path_rules WHERE rule_id=? ORDER BY sort_order,id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("read path rules for %s: %w", ruleID, err)
	}
	defer rows.Close()
	pathRules := make([]models.PathRule, 0)
	for rows.Next() {
		pathRule, err := ScanPathRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan path rules for %s: %w", ruleID, err)
		}
		pathRules = append(pathRules, pathRule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate path rules for %s: %w", ruleID, err)
	}
	return pathRules, nil
}
