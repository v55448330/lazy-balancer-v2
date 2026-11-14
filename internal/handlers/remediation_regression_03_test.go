package handlers

// 契约：stage2 子策略拆分时必须继承原策略的可配拦截页与拦截状态码
// （2026-09-25 用户裁定 stage2 可配拦截页）——G0+G2 组合 mixed 拆分时拦截页
// 不得丢失。stage2 子策略继承原策略 block_page_id 与 block_status_code
// （与 Create/Update 保留口径对齐：无页归零、有页保留）；stage0 无拦截页概念，恒 0。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestSplitSecurityPolicy_stage2ChildInheritsBlockPage(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)

	// Given：内置页种子 + mixed 策略（仅信任条目 + CC 挑战特征）配拦截页
	pageRes, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, content_type, is_default) VALUES ('拆分测试页', '<p>x</p>', 'text/html; charset=utf-8', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := pageRes.LastInsertId()
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection,
		ip_whitelist, ip_whitelist_enabled, human_verify_mode, human_verify_type, block_page_id)
		VALUES ('拆分母策略', 'off', 1, 'mixed', 1, '["1.1.1.1"]', 1, 'force', 'slider', ?)`, pageID)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()

	// When：一键拆分
	splitBody := strings.NewReader(`{}`)
	splitReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/security/policies/%d/split", policyID), splitBody)
	splitReq.Header.Set("Content-Type", "application/json")
	split := httptest.NewRecorder()
	router.ServeHTTP(split, splitReq)
	if split.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", split.Code, split.Body.String())
	}

	// Then：stage2 子策略继承原策略拦截页；stage0 不携带
	var stage2Page, stage0Page int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE name='拆分母策略（阶段 2）'`).Scan(&stage2Page); err != nil {
		t.Fatalf("stage2 子策略未创建: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE name='拆分母策略（阶段 0）'`).Scan(&stage0Page); err != nil {
		t.Fatalf("stage0 子策略未创建: %v", err)
	}
	if stage2Page != int(pageID) {
		t.Fatalf("stage2 子策略 block_page_id=%d, want %d（继承原策略拦截页）", stage2Page, pageID)
	}
	// stage2 子策略的拦截状态码与 Create/Update 保留口径对齐（继承原策略值；
	// 本 fixture 原策略未配码 → 0）。
	var stage2Status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_status_code,0) FROM security_policies WHERE name='拆分母策略（阶段 2）'`).Scan(&stage2Status); err != nil {
		t.Fatal(err)
	}
	if stage2Status != 0 {
		t.Fatalf("stage2 子策略 block_status_code=%d, want 0（原策略未配码）", stage2Status)
	}
	if stage0Page != 0 {
		t.Fatalf("stage0 子策略 block_page_id=%d, want 0（阶段 0 无拦截页概念）", stage0Page)
	}
}

// stage2 子策略继承原策略已配置的拦截状态码（与 Create/Update 保留口径对齐）：
// 原策略有页且配码 404 时，拆分产物不得把码归零（详情/列表宣称的配码在迁移后
// 静默变脸）。
func TestSplitSecurityPolicy_stage2ChildInheritsBlockStatusCode(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	pageRes, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, content_type, is_default) VALUES ('拆分配码页', '<p>x</p>', 'text/html; charset=utf-8', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := pageRes.LastInsertId()
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection,
		ip_whitelist, ip_whitelist_enabled, human_verify_mode, human_verify_type, block_page_id, block_status_code)
		VALUES ('配码母策略', 'off', 1, 'mixed', 1, '["1.1.1.1"]', 1, 'force', 'slider', ?, 404)`, pageID)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()

	split := postSplit(t, router, int(policyID))
	if split.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", split.Code, split.Body.String())
	}
	var stage2Status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_status_code,0) FROM security_policies WHERE name='配码母策略（阶段 2）'`).Scan(&stage2Status); err != nil {
		t.Fatalf("stage2 子策略未创建: %v", err)
	}
	if stage2Status != 404 {
		t.Fatalf("stage2 子策略 block_status_code=%d, want 404（继承原策略配码，与 Create/Update 同口径）", stage2Status)
	}
}
