package handlers

// 第 57 轮 P5 修复 RED/钉测试（用户裁定全部修复）：
// ①总览「活跃策略」计数改按特征口径（P5-1）——stage1/stage2 策略 mode 恒
//   归一 off，旧 `mode!='off'` 口径使纯 stage1/2 部署显示 0。

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestGetSecurityOverview_activePoliciesCountsFeatureBearingStages(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	// Given：三条启用策略——stage1 纯 ACL、stage2 纯限流、stage3 WAF、
	// 另有一条无任何特征的 off 空策略（不应计入）
	seed := func(name string, acl int, aclList string, rl int, rps int, mode string, custom string) {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_list, rate_limit_enabled, rate_limit_rps, custom_rules, policy_type)
			VALUES (?, ?, 1, ?, ?, ?, ?, ?, '')`,
			name, mode, acl, aclList, rl, rps, custom); err != nil {
			t.Fatal(err)
		}
	}
	seed("s1-纯ACL", 1, `["1.1.1.1"]`, 0, 0, "off", "[]")
	seed("s2-纯限流", 0, "[]", 1, 100, "off", "[]")
	seed("s3-纯WAF", 0, "[]", 0, 0, "blocking", "[]")
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type) VALUES ('空策略', 'off', 1, 'stage3')`); err != nil {
		t.Fatal(err)
	}

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// Then：三条特征策略全部计入（旧口径 mode!='off' 只数到 s3 一条）
	if resp.Data.ActivePolicies != 3 {
		t.Fatalf("active_policies=%d, want 3（特征口径：stage1/2/3 各 1，空策略不计）", resp.Data.ActivePolicies)
	}
}
