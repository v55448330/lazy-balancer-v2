package handlers

// SEC40-B1-4:安全域文本字段长度封顶——策略名 ≤100 rune、描述 ≤500 rune、
// 自定义规则名 ≤100 rune、自定义规则描述 ≤500 rune（SEC-U1 第 69 轮补齐）、
// 拦截页 content ≤64KB;DB 列无长度约束,超长串随审计详情/列表响应/发射文本放大。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func newSecurityLengthRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	return router
}

func TestSecurityInputs_lengthLimits(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityLengthRouter(t)

	t.Run("policy name over 100 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/policies", map[string]any{"name": strings.Repeat("名", 101)})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "100") {
			t.Fatalf("101-rune name must 400, got %d %s", rec.Code, rec.Body.String())
		}
		rec = postJSON(t, router, "/security/policies", map[string]any{"name": strings.Repeat("名", 100)})
		if rec.Code != http.StatusOK {
			t.Fatalf("100-rune name must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("policy description over 500 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/policies", map[string]any{"name": "d", "description": strings.Repeat("描", 501)})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "500") {
			t.Fatalf("501-rune description must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("policy update name over 100 runes rejected", func(t *testing.T) {
		rec := putJSON(t, router, "/security/policies/1", map[string]any{"name": strings.Repeat("名", 101)})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("update 101-rune name must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("custom rule name over 100 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/custom-rules", map[string]any{
			"name": strings.Repeat("规", 101), "action": "block", "score": 5, "conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "100") {
			t.Fatalf("101-rune rule name must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	// SEC-U1（第 69 轮）：自定义规则 description 补封顶（SEC40-B1-4 家族漏收敛
	// ——策略描述同口径 500 rune；DB 列无约束，超长串随列表响应/审计详情放大）。
	t.Run("custom rule description over 500 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/custom-rules", map[string]any{
			"name": "d", "description": strings.Repeat("描", 501), "action": "block", "score": 5,
			"conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "500") {
			t.Fatalf("501-rune rule description must 400, got %d %s", rec.Code, rec.Body.String())
		}
		// 边界回归：恰好 500 rune 放行
		rec = postJSON(t, router, "/security/custom-rules", map[string]any{
			"name": "d2", "description": strings.Repeat("描", 500), "action": "block", "score": 5,
			"conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("500-rune rule description must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("block page content over 64KB rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/block-pages", map[string]any{
			"name": "p", "content": strings.Repeat("a", 64*1024+1),
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "64KB") {
			t.Fatalf("64KB+1 content must 400, got %d %s", rec.Code, rec.Body.String())
		}
		rec = postJSON(t, router, "/security/block-pages", map[string]any{
			"name": "p", "content": strings.Repeat("a", 64*1024),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("exactly 64KB content must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})
}
