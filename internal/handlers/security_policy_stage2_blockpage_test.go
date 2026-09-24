package handlers

// stage2 限流策略拦截页（2026-09-25 用户裁定开放）：创建/更新可携带
// block_page_id（不再归一清零）；block_status_code 仍归一 0——限流拦截
// 恒 429（渲染 buildRateLimitErrorRoute 硬编码，指标单独计量）。

import (
	"fmt"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestStage2Policy_blockPageIDRoundTrip(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// Given：一个 stage2 策略创建请求携带 block_page_id（引用限流内置页 9001）
	create := postJSON(t, router, "/security/policies", map[string]any{
		"name": "限流带页策略", "policy_type": "stage2", "enabled": true,
		"rate_limit_enabled": true, "rate_limit_rps": 100, "rate_limit_burst": 50,
		"block_page_id": 9001,
	})
	if create.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 200", create.Code, create.Body.String())
	}

	// Then：block_page_id 落库保留（不归一清零）；block_status_code 归一 0（恒 429 语义）
	var pageID, statusCode int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0), COALESCE(block_status_code,0) FROM security_policies WHERE name='限流带页策略'`).Scan(&pageID, &statusCode); err != nil {
		t.Fatal(err)
	}
	if pageID != 9001 {
		t.Fatalf("block_page_id=%d, want 9001（stage2 允许配置拦截页）", pageID)
	}
	if statusCode != 0 {
		t.Fatalf("block_status_code=%d, want 0（限流恒 429）", statusCode)
	}

	// When：更新该策略改选维护页 9002
	var policyID int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='限流带页策略'`).Scan(&policyID); err != nil {
		t.Fatal(err)
	}
	update := putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{
		"block_page_id": 9002,
	})
	if update.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", update.Code, update.Body.String())
	}

	// Then：更新路径同样保留
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE id=?`, policyID).Scan(&pageID); err != nil {
		t.Fatal(err)
	}
	if pageID != 9002 {
		t.Fatalf("更新后 block_page_id=%d, want 9002", pageID)
	}
}
