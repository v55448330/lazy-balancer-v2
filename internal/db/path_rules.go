package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"lazy-balancer-v2/internal/models"
)

type PathRuleQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func LoadPathRules(ctx context.Context, queryer PathRuleQueryer, ruleID string) ([]models.PathRule, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT id,rule_id,sort_order,match_type,path,upstreams_json FROM path_rules WHERE rule_id=? ORDER BY sort_order,id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("read path rules for %s: %w", ruleID, err)
	}
	defer rows.Close()
	pathRules := make([]models.PathRule, 0)
	for rows.Next() {
		var pathRule models.PathRule
		var upstreamsJSON sql.NullString
		if err := rows.Scan(&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &upstreamsJSON); err != nil {
			return nil, fmt.Errorf("scan path rules for %s: %w", ruleID, err)
		}
		if upstreamsJSON.Valid {
			if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
				return nil, fmt.Errorf("decode path rule %d upstreams: %w", pathRule.ID, err)
			}
		}
		pathRules = append(pathRules, pathRule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate path rules for %s: %w", ruleID, err)
	}
	return pathRules, nil
}
