package handlers

// 第 54 轮 P5-2 RED：SplitSecurityPolicy 的 stage2 子策略此前恒落
// block_page_id=0，与 stage2 可配拦截页口径（2026-09-25 用户裁定）不一致
// ——G0+G2 组合 mixed 拆分时限流页丢失。修复后 stage2 子策略继承原策略
// block_page_id（block_status_code 保持归一 0，阶段 2 恒 429 自动语义）。

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

	// Given：内置页种子 + mixed 策略（仅 G0 信任条目 + G2 限流特征）配拦截页
	pageRes, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, content_type, is_default) VALUES ('拆分测试页', '<p>x</p>', 'text/html; charset=utf-8', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := pageRes.LastInsertId()
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection,
		ip_whitelist, ip_whitelist_enabled, rate_limit_enabled, rate_limit_rps, block_page_id)
		VALUES ('拆分母策略', 'off', 1, 'mixed', 1, '["1.1.1.1"]', 1, 1, 100, ?)`, pageID)
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

	// Then：stage2 子策略继承拦截页；stage0 子策略不携带
	var stage2Page, stage0Page int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE name='拆分母策略（阶段 2）'`).Scan(&stage2Page); err != nil {
		t.Fatalf("stage2 子策略未创建: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE name='拆分母策略（阶段 0）'`).Scan(&stage0Page); err != nil {
		t.Fatalf("stage0 子策略未创建: %v", err)
	}
	if stage2Page != int(pageID) {
		t.Fatalf("stage2 子策略 block_page_id=%d, want %d（拆分不得丢限流页）", stage2Page, pageID)
	}
	if stage0Page != 0 {
		t.Fatalf("stage0 子策略 block_page_id=%d, want 0（阶段 0 无拦截页概念）", stage0Page)
	}
}
