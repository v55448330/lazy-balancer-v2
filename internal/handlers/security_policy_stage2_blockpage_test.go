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

	// Then：阶段 2 拦截页/状态码随配额限流下线一并归零（CC ban 为插件固定 403）
	var pageID, statusCode int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0), COALESCE(block_status_code,0) FROM security_policies WHERE name='限流带页策略'`).Scan(&pageID, &statusCode); err != nil {
		t.Fatal(err)
	}
	if pageID != 0 {
		t.Fatalf("block_page_id=%d, want 0（阶段 2 不再消费拦截页）", pageID)
	}
	if statusCode != 0 {
		t.Fatalf("block_status_code=%d, want 0", statusCode)
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

// 写侧拦截状态码归一对齐：状态码只在「非 stage2 ∧ 已绑定自定义拦截页」时被
// 渲染消费（stage2 限流恒 429；无页策略的 deny 恒 403）。Create 已归一，
// 但 Update 的部分更新（只提交 block_status_code）曾原样落库——同一条 DB 形态
// 只能经 PUT 产生，详情/列表于是宣称一个不生效的状态码。
func TestUpdateSecurityPolicy_blockStatusCodeNormalization(t *testing.T) {
	t.Run("非 stage2 无拦截页时归零", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "acl-no-page", "policy_type": "stage1"})

		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"block_status_code": 404})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}

		var pageID, status int
		if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0), COALESCE(block_status_code,0) FROM security_policies WHERE id=?`, id).Scan(&pageID, &status); err != nil {
			t.Fatal(err)
		}
		if pageID != 0 || status != 0 {
			t.Fatalf("(block_page_id, block_status_code)=(%d,%d), want (0,0)（无页即无码，与 Create 同口径）", pageID, status)
		}
	})

	t.Run("有拦截页时保留状态码", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "acl-with-page", "policy_type": "stage1"})

		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"block_page_id": 9001, "block_status_code": 404})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}

		var pageID, status int
		if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0), COALESCE(block_status_code,0) FROM security_policies WHERE id=?`, id).Scan(&pageID, &status); err != nil {
			t.Fatal(err)
		}
		if pageID != 9001 || status != 404 {
			t.Fatalf("(block_page_id, block_status_code)=(%d,%d), want (9001,404)", pageID, status)
		}
	})

	t.Run("stage2 限流恒 429（状态码归零）", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "rl-page", "policy_type": "stage2", "rate_limit_enabled": true, "rate_limit_rps": 100, "rate_limit_burst": 50, "block_page_id": 9001})

		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"block_status_code": 404})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}

		var status int
		if err := db.DB.QueryRow(`SELECT COALESCE(block_status_code,0) FROM security_policies WHERE id=?`, id).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != 0 {
			t.Fatalf("stage2 block_status_code=%d, want 0（限流拦截恒 429）", status)
		}
	})
}
