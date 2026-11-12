package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 配额限流彻底下线：旧客户端携带 rate_limit_* 一律忽略，数据库不得再有该列，
// 详情响应也不得暴露相关字段（旧备份字段由 backup 导入裁剪覆盖）。
func TestSecurityPolicy_ignoresRetiredRateLimitFields(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	id := createTestPolicy(t, router, map[string]any{
		"name":               "限流已下线",
		"policy_type":        "stage2",
		"rate_limit_enabled": true,
		"rate_limit_rps":     120,
		"rate_limit_burst":   40,
		"human_verify_mode":  "force",
	})
	var columns int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_policies') WHERE name IN ('rate_limit_enabled','rate_limit_rps','rate_limit_burst')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 0 {
		t.Fatalf("rate_limit_* 列必须物理删除，仍存在 %d 个", columns)
	}

	recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), map[string]any{
		"rate_limit_enabled": true,
		"rate_limit_rps":     999,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update with retired fields must be ignored, status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	detail := getRequest(t, router, "/security/policies/"+strconv.Itoa(id))
	if detail.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", detail.Code, detail.Body.String())
	}
	var payload struct {
		Data struct {
			Policy map[string]json.RawMessage `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	for _, key := range []string{"rate_limit_enabled", "rate_limit_rps", "rate_limit_burst"} {
		if _, exists := payload.Data.Policy[key]; exists {
			t.Fatalf("详情不得再暴露已删除字段 %s: %s", key, detail.Body.String())
		}
	}
}

// cc_response 退役（2026-11-13 用户裁定：CC 统一走挑战页，封禁由自动封禁管线
// 承载）：列已物理删除，详情不暴露该字段，提交携带时被忽略（不报错、不落库）。
func TestSecurityPolicy_ccResponseRetired(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name": "CC挑战", "policy_type": "stage2",
		"human_verify_mode": "force", "human_verify_type": "slider",
		"cc_detect_enabled": true, "cc_response": "ban",
	})
	var colCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_policies') WHERE name='cc_response'`).Scan(&colCount); err != nil {
		t.Fatal(err)
	}
	if colCount != 0 {
		t.Fatal("cc_response 列必须已物理删除")
	}
	detail := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))
	var payload struct {
		Data struct {
			Policy map[string]any `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if _, exists := payload.Data.Policy["cc_response"]; exists {
		t.Fatalf("详情不得再暴露已删除字段 cc_response: %s", detail.Body.String())
	}
}
