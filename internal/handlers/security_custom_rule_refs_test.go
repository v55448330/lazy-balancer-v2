package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

type customRuleListRefDTO struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type customRuleListRowDTO struct {
	ID              int                    `json:"id"`
	Name            string                 `json:"name"`
	RefCount        int                    `json:"ref_count"`
	RefCountEnabled int                    `json:"ref_count_enabled"`
	RefPolicies     []customRuleListRefDTO `json:"ref_policies"`
}

// 自定义规则列表必须披露引用它的安全策略，字段与 IP 名单同形：
// ref_count 含禁用策略（展示面），ref_count_enabled 与删除 409 门同口径
// （仅启用策略、仅 ID 数组引用形态）。
func TestListSecurityCustomRules_reportsPolicyReferences(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/custom-rules", h.ListSecurityCustomRules)

	// Given：规则 7 被启用策略 900 与禁用策略 901 同时引用；规则 8 无引用；
	// 策略 902 以内嵌对象形态携带同名规则（不构成 ID 引用）。
	for _, stmt := range []string{
		`INSERT INTO security_custom_rules (id, name, conditions, action, enabled) VALUES (7, '被两条策略引用', '[]', 'block', 1)`,
		`INSERT INTO security_custom_rules (id, name, conditions, action, enabled) VALUES (8, '无引用规则', '[]', 'block', 1)`,
		`INSERT INTO security_policies (id, name, mode, enabled, custom_rules) VALUES (900, '启用引用策略', 'blocking', 1, '[7]')`,
		`INSERT INTO security_policies (id, name, mode, enabled, custom_rules) VALUES (901, '禁用引用策略', 'blocking', 0, '[7]')`,
		`INSERT INTO security_policies (id, name, mode, enabled, custom_rules) VALUES (902, '内嵌对象策略', 'blocking', 1, '[{"name":"被两条策略引用","action":"block","conditions":[]}]')`,
	} {
		if _, err := db.DB.Exec(stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	rec := getRequest(t, router, "/security/custom-rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []customRuleListRowDTO `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	byID := map[int]customRuleListRowDTO{}
	for _, row := range resp.Data {
		byID[row.ID] = row
	}

	referenced, ok := byID[7]
	if !ok {
		t.Fatalf("响应缺少规则 7: %s", rec.Body.String())
	}
	if referenced.RefCount != 2 {
		t.Fatalf("规则 7 ref_count=%d want 2（含禁用策略）", referenced.RefCount)
	}
	if referenced.RefCountEnabled != 1 {
		t.Fatalf("规则 7 ref_count_enabled=%d want 1（与删除 409 门同口径）", referenced.RefCountEnabled)
	}
	if len(referenced.RefPolicies) != 2 {
		t.Fatalf("规则 7 ref_policies=%v want 2 条", referenced.RefPolicies)
	}
	names := map[string]bool{}
	for _, ref := range referenced.RefPolicies {
		names[ref.Name] = ref.Enabled
	}
	if enabled, ok := names["启用引用策略"]; !ok || !enabled {
		t.Fatalf("ref_policies 缺少启用态引用策略: %v", referenced.RefPolicies)
	}
	if enabled, ok := names["禁用引用策略"]; !ok || enabled {
		t.Fatalf("ref_policies 缺少禁用态引用策略（enabled 须为 false）: %v", referenced.RefPolicies)
	}
	if names["内嵌对象策略"] {
		t.Fatalf("内嵌对象形态不构成 ID 引用，不得计入: %v", referenced.RefPolicies)
	}

	unreferenced, ok := byID[8]
	if !ok {
		t.Fatalf("响应缺少规则 8")
	}
	if unreferenced.RefCount != 0 || unreferenced.RefCountEnabled != 0 {
		t.Fatalf("规则 8 ref_count=%d ref_count_enabled=%d want 0/0", unreferenced.RefCount, unreferenced.RefCountEnabled)
	}
	if unreferenced.RefPolicies == nil || len(unreferenced.RefPolicies) != 0 {
		t.Fatalf("规则 8 ref_policies=%v want 空数组（非 null）", unreferenced.RefPolicies)
	}
}
