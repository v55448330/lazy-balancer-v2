package handlers

import "testing"

// 归一函数：空/非法值回退 auto，避免脏值产生「无路由」形态。
func TestNormalizeBlockResponseMode(t *testing.T) {
	cases := map[string]string{"": "auto", "AUTO": "auto", "html": "html", " json ": "json", "xml": "auto"}
	for in, want := range cases {
		if got := normalizeBlockResponseMode(in); got != want {
			t.Fatalf("normalizeBlockResponseMode(%q)=%q, want %q", in, got, want)
		}
	}
}
