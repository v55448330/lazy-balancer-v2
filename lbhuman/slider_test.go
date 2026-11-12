package lbhuman

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	if !strings.Contains(recorder.Body.String(), "Security Check") {
		t.Fatalf("缺占位符必须回退内置挑战页（英文）: %s", recorder.Body.String()[:min(200, len(recorder.Body.String()))])
	}
}

func TestSliderWidgetFixedGeometryMatchesPuzzle(t *testing.T) {
	rendered := fmt.Sprintf(sliderWidgetHTML, "", pieceSVG(), "", "")
	for _, want := range []string{
		"width:240px;max-width:100%;margin:18px auto 0",
		".lb-hv-puzzle{position:relative;width:240px;height:134px",
		`id="lbHvPiece" style="top:60px;left:6px"`,
		".lb-hv-track{position:relative;width:240px",
		"<rect x=\"1\" y=\"1\" width=\"32\" height=\"32\"",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("滑块组件几何缺失: %q", want)
		}
	}
}

// 用户裁定（2026-11-13）：限流日志≠限流请求，发放限流无实际防护意义——
// 挑战发放/通过/失败全部逐请求上报，事件日志与实时运行态口径一致。
func TestHumanEventReportsEveryRequest(t *testing.T) {
	p := &humanEventPoster{}
	now := time.Now()
	for i := range 5 {
		if !p.shouldReport("203.0.113.9", "challenge", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("第 %d 次挑战发放必须逐条上报（发放限流已取消）", i+1)
		}
	}
	if !p.shouldReport("203.0.113.9", "pass", now) {
		t.Fatal("挑战通过必须逐条上报")
	}
	if !p.shouldReport("203.0.113.9", "fail", now) {
		t.Fatal("挑战失败必须逐条上报")
	}
}

func TestSliderPolishInsetToleranceAndEnglishFailure(t *testing.T) {
	if sliderTolerance > 3 {
		t.Fatalf("滑块容差过大: %d", sliderTolerance)
	}
	rendered := fmt.Sprintf(sliderWidgetHTML, "", pieceSVG(), "", "")
	for _, want := range []string{"left:2px;transform:translateY(-50%);width:34px", "Verification failed"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("滑块样式/文案缺失: %q", want)
		}
	}
	if strings.Contains(rendered, "验证失败") {
		t.Fatal("失败提示必须只保留英文")
	}
}

func TestSliderPieceInsetAndVerticalCenter(t *testing.T) {
	rendered := fmt.Sprintf(sliderWidgetHTML, "", pieceSVG(), "", "")
	for _, want := range []string{
		"top:60px;left:6px",
		"top:50%;left:2px;transform:translateY(-50%)",
		`pc.style.left=(cx+6)+"px"`,
		`"&x="+(cx+6)`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("滑块居中/留边缺失: %q", want)
		}
	}
}
