package lbhuman

// 排队等待页客户端指数退避语义钉：倒计时自然结束必须保留退避计数——下一张
// 等待页读计数翻倍等待（N→2N→4N 封顶 300s）；仅手动 Retry now 清零回基础
// 等待。跳转前无条件清零会让每张等待页都从 n=0 起算，退避恒为 base，
// 重试风暴防护失效（服务端零队列状态，退避是唯一客户端节流）。

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func queueWidgetScript(t *testing.T) string {
	t.Helper()
	html := fmt.Sprintf(queueWidgetHTML, 10, 10, `"/page"`)
	i := strings.Index(html, "<script>")
	j := strings.Index(html, "</script>")
	if i < 0 || j < 0 || j <= i {
		t.Fatalf("queue 组件缺少 script 块: %s", html)
	}
	return html[i+len("<script>") : j]
}

// Given 页面加载时退避计数已递增（n+1 写入 sessionStorage）。
// When 倒计时自然结束触发跳转。
// Then 不得清零计数——removeItem 只允许出现在手动分支内，自然结束调用
// 不带手动标记的 go()，下一张等待页等待翻倍。
func TestQueueWidget_backoffSurvivesNaturalExpiry(t *testing.T) {
	script := queueWidgetScript(t)
	if !strings.Contains(script, `sessionStorage.setItem(key,String(n+1));`) {
		t.Fatal("页面加载必须递增退避计数（下一张等待页的翻倍依据）")
	}
	if !regexp.MustCompile(`function go\(manual\)\{if\(manual\)\{sessionStorage\.removeItem\(key\);\}`).MatchString(script) {
		t.Fatal("go() 必须带 manual 参数且仅在手动分支清零退避计数（自然结束保留计数，退避才能 N→2N→4N）")
	}
	if !regexp.MustCompile(`left<=0\)\{clearInterval\(t\);go\(\);`).MatchString(script) {
		t.Fatal("倒计时自然结束必须调用不带手动标记的 go()（保留退避计数）")
	}
	if n := strings.Count(script, "removeItem"); n != 1 {
		t.Fatalf("清零点必须唯一（仅手动分支），removeItem 出现 %d 次: %s", n, script)
	}
}

// Given 退避计数已累积。
// When 用户点击 Retry now（显式放弃等待）。
// Then 清零计数——下一张等待页回到基础等待秒数。
func TestQueueWidget_manualRetryResetsBackoff(t *testing.T) {
	script := queueWidgetScript(t)
	if !regexp.MustCompile(`onclick=function\(\)\{clearInterval\(t\);go\(true\);\}`).MatchString(script) {
		t.Fatal("Retry now 必须调用 go(true) 清零退避计数（手动重试=显式重置）")
	}
}
