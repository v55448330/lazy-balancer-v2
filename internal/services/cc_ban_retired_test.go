package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CC「封禁」响应选项退役（2026-11-13 用户裁定）：CC 统一走挑战页，真正的封禁
// 由自动封禁管线承载。渲染层不再下发 cc_response/ban_status_code/ban_page_*。
func TestBuildHumanHandler_noBanResponseKeys(t *testing.T) {
	installAutobanFixture(t, "2026-11-13 10:00:00")
	if _, err := db.DB.Exec(`INSERT INTO global_config (id,human_secret) VALUES (1,'test-secret') ON CONFLICT(id) DO UPDATE SET human_secret='test-secret'`); err != nil {
		t.Fatal(err)
	}
	policies := []*models.SecurityPolicy{{
		ID: 1, Enabled: true, HumanVerifyMode: "force", HumanVerifyType: "slider",
		HumanVerifyTTL: 30, CCDetectEnabled: true, CCRPSLimit: 40, CCRPSWindow: 10,
		CC4xxRatio: 70, CCSessionUAThreshold: 5,
	}}
	h := buildHumanHandler("lb_cc", policies, "<html>{{human_verify_widget}}</html>")
	if h == nil {
		t.Fatal("human handler missing")
	}
	for _, key := range []string{"cc_response", "ban_status_code", "ban_page_html", "ban_page_type"} {
		if _, ok := h[key]; ok {
			t.Fatalf("退役键 %s 不得再下发: %v", key, h)
		}
	}
	// 挑战页内容仍须下发（挑战页选择不变）。
	if h["challenge_page_html"] != "<html>{{human_verify_widget}}</html>" {
		t.Fatalf("challenge_page_html 必须保留: %v", h["challenge_page_html"])
	}
}
