package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// U7c-2（第 66 轮）：面板页面与 API 响应缺 X-Content-Type-Options/
// X-Frame-Options——点击劫持表面。基线钉：全局中间件恒施加 nosniff+DENY。

func TestSetupRouter_setsSecurityHeadersOnAllResponses(t *testing.T) {
	// Given 完整路由（匿名 /health 即可观测）。
	router := newMiddlewareTestRouter(t)

	// When
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	// Then
	if rec.Code != http.StatusOK {
		t.Fatalf("/health status=%d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options=%q, want DENY", got)
	}
}

// SYSMW-U3（第 69 轮 P3）：/ui 挂载壳 index.html 与根路径缓存策略对齐——此前
// 仅 GET / 显式 no-cache，/ui 壳由 http.FileServer 直出只有 Last-Modified
// （浏览器启发式缓存 10% 规则：升级后旧壳引用已删哈希资产 → 白屏）。
func TestSetupRouter_uiShellIndexNoCacheHeader(t *testing.T) {
	// Given 完整路由（测试 StaticDir 为空目录：/ui 壳响应码非 200，但缓存头
	// 由全局静态中间件在静态处理器之前设置，与响应码无关；裸 /ui 是 gin
	// 尾斜杠 301 重定向，不经中间件链，不在断言面）。
	router := newMiddlewareTestRouter(t)

	for _, path := range []string{"/ui/", "/ui/index.html"} {
		// When
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		// Then：壳页面恒 no-cache（与 GET / 同策略）
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("GET %s Cache-Control=%q, want no-cache", path, got)
		}
	}

	// And 回归形状：/ui/assets/ 哈希资产保持 immutable 长缓存不变
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/assets/app-abc123.js", nil))
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("GET /ui/assets/... Cache-Control=%q, want immutable", got)
	}
}
