package handlers

// v2.4.5：手动发起事件的正文是「发起了 %s 手动更新」，库名不得再带「更新」
// 动作后缀（否则出现「发起了 CRS 更新 手动更新」）。

import "testing"

func TestLibUpdateEventLabel(t *testing.T) {
	cases := map[string]string{
		"CRS 更新":       "CRS",
		"IP2Region 更新": "IP2Region",
		"威胁情报库更新":      "威胁情报库",
		"爬虫地址库更新":      "爬虫地址库",
		"威胁情报库":        "威胁情报库",
		"":             "安全库",
	}
	for in, want := range cases {
		if got := libUpdateEventLabel(in); got != want {
			t.Errorf("libUpdateEventLabel(%q)=%q, want %q", in, got, want)
		}
	}
}
