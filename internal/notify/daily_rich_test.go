package notify

// 日报富项渲染钉测：新增明细项（TOP IP/临期证书/运行时长/威胁库）进入分节渲染，
// items 裁剪仍生效；markdown/text/html 三形态口径一致。

import (
	"strings"
	"testing"
)

func richValues() map[string]string {
	return map[string]string{
		"requests":      "1200",
		"blocked":       "34",
		"top_ips":       "45.33.32.9 ×321；1.2.3.4 ×120",
		"cert_expiring": "a.com · 2026-11-25；b.com · 2026-11-28",
		"uptime":        "32 天 4 小时",
		"threat_db":     "CRS 4.0 · IP库 2026-11",
		"login_status":  "成功 40 / 失败 3 / MFA失败 1",
	}
}

func TestRenderDailyRich_itemsAndTrim(t *testing.T) {
	items := []string{"requests", "top_ips", "cert_expiring", "uptime", "threat_db", "login_status"}
	md := renderDailyFromValues("2026-11-19", richValues(), items, "markdown")
	for _, want := range []string{"45.33.32.9 ×321", "a.com · 2026-11-25", "32 天 4 小时", "CRS 4.0", "MFA失败 1", "| 请求数 | 1200 |"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown 缺富项 %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "拦截次数") {
		t.Fatalf("items 裁剪失效（blocked 未选却渲染）:\n%s", md)
	}

	txt := renderDailyFromValues("2026-11-19", richValues(), items, "text")
	if strings.Contains(txt, "<") || strings.Contains(txt, "|") {
		t.Fatalf("text 应为纯文本无标记:\n%s", txt)
	}
	if !strings.Contains(txt, "45.33.32.9 ×321") {
		t.Fatalf("text 缺 TOP IP 明细:\n%s", txt)
	}

	html := renderDailyFromValues("2026-11-19", richValues(), items, "html")
	if !strings.Contains(html, "<table") || !strings.Contains(html, "a.com") {
		t.Fatalf("html 应为表格且含临期证书:\n%s", html)
	}
}

func TestDailyItemIDs_labelsComplete(t *testing.T) {
	for _, id := range DailyItemIDs {
		if _, ok := DailyItemLabels[id]; !ok {
			t.Fatalf("DailyItemIDs %q 缺标签", id)
		}
	}
	// 分节引用的项目必须都在 IDs 白名单（渲染裁剪一致性）。
	inIDs := map[string]bool{}
	for _, id := range DailyItemIDs {
		inIDs[id] = true
	}
	for _, sec := range dailySections {
		for _, it := range sec.items {
			if !inIDs[it] {
				t.Fatalf("分节 %q 引用未登记项目 %q", sec.title, it)
			}
		}
	}
}