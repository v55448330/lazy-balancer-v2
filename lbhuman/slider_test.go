package lbhuman

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 自定义拦截页模板：{{human_verify_widget}} 必须替换为带 token 的滑块组件；
// 缺少占位符时回退内置挑战页（不让站点因模板错误无法验证）。
func TestServeSliderChallenge_customTemplateWidget(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{
		Type: "slider", RuleID: "lb-test",
		ChallengePageHTML: "<html><body><div id=\"style\">custom</div>{{human_verify_widget}}</body></html>",
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	h.serveSliderChallenge(recorder, request, "203.0.113.9")
	body := recorder.Body.String()
	if !strings.Contains(body, "custom") || !strings.Contains(body, "lb-hv-widget") {
		t.Fatalf("自定义模板未注入滑块组件: %s", body[:min(200, len(body))])
	}
	if strings.Contains(body, "{{human_verify_widget}}") {
		t.Fatal("占位符未被替换")
	}

	h.ChallengePageHTML = "<html><body>no-widget</body></html>"
	recorder = httptest.NewRecorder()
	h.serveSliderChallenge(recorder, request, "203.0.113.9")
	if !strings.Contains(recorder.Body.String(), "安全验证") {
		t.Fatalf("缺占位符必须回退内置挑战页: %s", recorder.Body.String()[:min(200, len(recorder.Body.String()))])
	}
}
