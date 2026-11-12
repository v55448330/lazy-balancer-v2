package lbhuman

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 用户裁定（2026-11-13）：JS 挑战此前无条件渲染内置页，策略所选拦截页永不生效；
// 且前端强制 JS 模式也带滑块占位符。修复=JS 专用占位符 {{human_js_widget}}，
// 与滑块 {{human_verify_widget}} 并列、互不干扰。

// 策略选了含 JS 占位符的自定义页 → 必须注入 JS 组件（不得回落内置页）。
func TestServeJSChallenge_customTemplateInjectsJSWidget(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{
		Type: "js", RuleID: "lb-js-page", Secret: "test-secret", TTLMinutes: 30,
		ChallengePageHTML: `<html lang="en"><body><div id="brand">custom</div>{{human_js_widget}}</body></html>`,
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected?a=1&b=2", nil)
	h.serveJSChallenge(rec, req, "203.0.113.120")
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(body, "custom") {
		t.Fatalf("自定义页内容未生效（JS 挑战忽略所选拦截页）: %s", body[:min(300, len(body))])
	}
	if strings.Contains(body, "{{human_js_widget}}") {
		t.Fatal("JS 占位符未被替换")
	}
	if !strings.Contains(body, "lb-hv-js") {
		t.Fatalf("未注入 JS 验证组件: %s", body[:min(300, len(body))])
	}
	// 组件必须带真实 token 与校验端点，且 redirect 用 JSON 编码（& 不得变实体）。
	if !strings.Contains(body, humanVerifyPath) {
		t.Fatal("JS 组件缺少校验端点")
	}
	if strings.Contains(body, "&amp;") {
		t.Fatal("redirect 不得用 HTML 实体注入 JS 字符串")
	}
	if !strings.Contains(body, "crypto.subtle") {
		t.Fatal("JS 组件必须执行 PoW 计算")
	}
}

// 未配页/缺 JS 占位符 → 回退内置页（英文、直角、含 PoW 组件）。
func TestServeJSChallenge_fallbackBuiltinIsEnglishSquare(t *testing.T) {
	resetLiveSessionsForTest()
	for _, page := range []string{"", "<html><body>no-placeholder</body></html>"} {
		h := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-js-fallback", Secret: "test-secret", TTLMinutes: 30, ChallengePageHTML: page}}
		rec := httptest.NewRecorder()
		h.serveJSChallenge(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "203.0.113.121")
		body := rec.Body.String()
		if !strings.Contains(body, "Security Check") {
			t.Fatalf("缺占位符必须回退内置 JS 页: %s", body[:min(200, len(body))])
		}
		if strings.Contains(body, "安全验证") {
			t.Fatal("内置 JS 页必须英文（与内置拦截页口径一致）")
		}
		if !strings.Contains(body, `<html lang="en">`) {
			t.Fatal("内置 JS 页文档语言必须 en")
		}
		if strings.Contains(body, "border-radius: 8px") || strings.Contains(body, "border-radius: 50%") {
			t.Fatal("内置 JS 页必须直角（全站直角铁律：不得圆角卡片/圆形 spinner）")
		}
		if !strings.Contains(body, "crypto.subtle") {
			t.Fatal("内置 JS 页必须含 PoW 计算")
		}
	}
}

// 滑块占位符与 JS 占位符互不串味：滑块页不得被 JS 模式注入，反之亦然。
func TestChallengeWidgets_placeholdersDoNotCross(t *testing.T) {
	resetLiveSessionsForTest()
	sliderPage := `<html><body>{{human_verify_widget}}</body></html>`
	jsPage := `<html><body>{{human_js_widget}}</body></html>`

	js := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-cross-js", Secret: "s", TTLMinutes: 30, ChallengePageHTML: sliderPage}}
	rec := httptest.NewRecorder()
	js.serveJSChallenge(rec, httptest.NewRequest(http.MethodGet, "/x", nil), "203.0.113.122")
	if strings.Contains(rec.Body.String(), "{{human_verify_widget}}") {
		t.Fatal("JS 模式不得把滑块占位符原样吐给访客（应回退内置 JS 页）")
	}

	slider := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-cross-slider", Secret: "s", TTLMinutes: 30, ChallengePageHTML: jsPage}}
	rec2 := httptest.NewRecorder()
	slider.serveSliderChallenge(rec2, httptest.NewRequest(http.MethodGet, "/x", nil), "203.0.113.123")
	if strings.Contains(rec2.Body.String(), "{{human_js_widget}}") {
		t.Fatal("滑块模式不得把 JS 占位符原样吐给访客（应回退内置滑块页）")
	}
}
