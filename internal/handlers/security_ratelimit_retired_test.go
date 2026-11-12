package handlers

import (
	"encoding/json"
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

// cc_response（verify|ban）策略级贯通：创建/详情回读一致，非法值归一 verify。
func TestSecurityPolicy_ccResponseRoundTrip(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name": "CC封禁", "policy_type": "stage2",
		"human_verify_mode": "force", "human_verify_type": "slider",
		"cc_detect_enabled": true, "cc_response": "ban",
	})
	assertMode := func(want string) {
		var got string
		if err := db.DB.QueryRow(`SELECT COALESCE(cc_response,'') FROM security_policies WHERE id=?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("cc_response=%q, want %q", got, want)
		}
	}
	assertMode("ban")
	invalidID := createTestPolicy(t, router, map[string]any{
		"name": "CC非法响应", "policy_type": "stage2", "human_verify_mode": "force",
		"cc_response": "block",
	})
	var got string
	if err := db.DB.QueryRow(`SELECT cc_response FROM security_policies WHERE id=?`, invalidID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "verify" {
		t.Fatalf("非法 cc_response 应归一 verify，got %q", got)
	}
}
