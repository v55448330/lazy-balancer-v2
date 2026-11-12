package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

// F1（安全评审）：面板侧运行态不得回传原始挑战凭据（puzzle_id/JS token）——
// 任何登录用户可拿他人 waiting 凭据提交错误答案烧掉尝试次数（griefing）。
// 监控视图只需稳定行标识，代理层必须打码；原始 id 仅留在 loopback admin 端点。
func TestGetHumanLiveChallenges_masksRawCredentialID(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	const rawID = "abcdef0123456789abcdef"
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"now_ms":1786447300123,"active_count":1,"sessions":[{"id":"` + rawID + `","kind":"slider","status":"waiting","rule_id":"lb-live","client_ip":"203.0.113.40","method":"GET","uri":"/live","user_agent":"Mask/1.0","issued_at_ms":1786447300000,"expires_at_ms":1786447420000,"remaining_ms":120000,"attempts":0,"max_attempts":3}]}`))
	}))
	defer admin.Close()

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	router := gin.New()
	router.GET("/security/human/live", h.GetHumanLiveChallenges)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/human/live?scope=active", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			Sessions []struct {
				ID string `json:"id"`
			} `json:"sessions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Sessions) != 1 {
		t.Fatalf("sessions=%d, want 1", len(payload.Data.Sessions))
	}
	got := payload.Data.Sessions[0].ID
	if got == rawID {
		t.Fatal("面板侧不得回传原始挑战凭据 id（可被用于 griefing）")
	}
	if got == "" {
		t.Fatal("打码后仍须保留稳定行标识（非空）")
	}
}
