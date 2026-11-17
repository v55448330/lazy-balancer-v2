package lbhuman

// 滑块键盘可达（2026-11-13 用户裁定：方向键/Enter 可达）与服务端反脚本门的
// 协调：方向键步进产生匀速轨迹（deltas 恒 2/8，加速度方差=0），若与鼠标拖动
// 同受方差门约束，键盘-only/读屏用户永不可过（3 次耗尽→reload 循环）。
// 键盘提交显式携带 input_method=keyboard：服务端仅豁免轨迹方差门，其余门
// （TTL/x 容差/点数下限/时长窗）全保留；鼠标/触摸路径方差门不变。
// 取舍披露：input_method 由客户端声明，脚本伪造成本与伪造鼠标轨迹同级——
// 反脚本门本就是启发式而非密码学边界（真实拦截力在自动封禁计数）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 键盘方向键 ×50 的匀速轨迹（widget keydown 形态：cx 步进 2）。
func keyboardUniformTrack() []int {
	track := make([]int, 0, 50)
	cx := 0
	for range 50 {
		cx += 2
		track = append(track, cx)
	}
	return track
}

func trackCSV(track []int) string {
	parts := make([]string, len(track))
	for i, v := range track {
		parts[i] = itoa(v)
	}
	return strings.Join(parts, ",")
}

// postSliderVerifyWith 自定义轨迹/时长/输入方式的校验提交（复用既有端点形态）。
func postSliderVerifyWith(t *testing.T, h *HumanHandler, pid string, x int, track string, durationMs int, inputMethod string) *httptest.ResponseRecorder {
	t.Helper()
	body := url.Values{}
	body.Set("puzzle_id", pid)
	body.Set("x", itoa(x))
	body.Set("track", track)
	body.Set("duration_ms", itoa(durationMs))
	if inputMethod != "" {
		body.Set("input_method", inputMethod)
	}
	req := httptest.NewRequest(http.MethodPost, humanSliderVerifyPath, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.serveSliderVerify(rec, req, "203.0.113.80")
	return rec
}

// Given 有效拼图，键盘匀速轨迹（50 点 deltas 恒 2，方差=0），x 在容差内、
// 时长合法，提交显式携带 input_method=keyboard。
// When serveSliderVerify。
// Then 必须通过（200+cookie）——键盘可达裁定不得被方差门恒拒。
func TestServeSliderVerify_keyboardUniformTrackPasses(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-kb", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()

	rec := postSliderVerifyWith(t, h, pid, gapX, trackCSV(keyboardUniformTrack()), 1500, "keyboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("键盘匀速轨迹应通过（input_method=keyboard 豁免方差门）: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), cookieName+"=") {
		t.Fatal("键盘通过必须签发放行 cookie")
	}
}

// 对照：同一匀速轨迹不带 input_method（鼠标/触摸路径）必须仍被方差门拒绝
// ——豁免不得扩散到未声明键盘的提交。
func TestServeSliderVerify_uniformTrackWithoutKeyboardStillRejected(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-kb-mouse", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()

	rec := postSliderVerifyWith(t, h, pid, gapX, trackCSV(keyboardUniformTrack()), 1500, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("鼠标路径匀速轨迹必须仍被方差门拒绝: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// 边界：keyboard 声明只豁免方差门——x 超容差/时长过短/点数不足仍必须拒绝。
func TestServeSliderVerify_keyboardKeepsOtherGates(t *testing.T) {
	cases := []struct {
		name     string
		xOffset  int // 相对 gapX 的偏移
		track    []int
		duration int
	}{
		{"x超容差", sliderTolerance + 5, keyboardUniformTrack(), 1500},
		{"时长过短", 0, keyboardUniformTrack(), 100},
		{"时长超限", 0, keyboardUniformTrack(), 10001},
		{"点数不足", 0, []int{2, 4, 6}, 1500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetLiveSessionsForTest()
			h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-kb-gates", Secret: "test-secret", TTLMinutes: 30}}
			pid := issueSliderPuzzle(t, h)
			sliderPuzzlesMu.Lock()
			gapX := sliderPuzzles[pid].gapX
			sliderPuzzlesMu.Unlock()
			rec := postSliderVerifyWith(t, h, pid, gapX+tc.xOffset, trackCSV(tc.track), tc.duration, "keyboard")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("keyboard 声明不得豁免其余门: status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// 接线钉：widget 键盘提交必须携带 input_method=keyboard，鼠标/触摸提交不得
// 携带（否则鼠标匀速脚本可借键盘标志绕过方差门）。
func TestSliderWidget_keyboardSubmitCarriesInputMethod(t *testing.T) {
	rendered := fmt.Sprintf(sliderWidgetHTML, "", pieceSVG(), "pid", `"/"`)
	if !strings.Contains(rendered, `"&input_method="+(kbStart?"keyboard":"")`) {
		t.Fatal("widget 提交必须按 kbStart 携带 input_method=keyboard（键盘路径声明）")
	}
	if !strings.Contains(rendered, "function down(e){if(busy)return;kbStart=0;") {
		t.Fatal("指针按下必须清零 kbStart（鼠标/触摸提交不得携带键盘标志）")
	}
}
