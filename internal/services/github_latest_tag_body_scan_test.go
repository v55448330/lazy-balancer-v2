package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Given：代理直接返回 200 页面（无跳转），页面里真实 tag 之前混入路由模板
// 产物「/releases/tag/*name」（GitHub 页面 JS 模板通配符，形状非法）。
// When：body 扫描解析最新 tag。
// Then：跳过形状非法匹配，取首个通过白名单校验的真实 tag——首个原始匹配
// 优先会让整次查询被模板产物毒化（重试 3 次全败）。
func TestFetchGitHubLatestTagViaProxy_skipsInvalidTagMatches(t *testing.T) {
	newTestCRSManager(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 模板产物在前、真实 tag 在后——复现线上首个匹配被毒化的页面形态
		_, _ = w.Write([]byte(`<html><a href="/lionsoul2014/ip2region/releases/tag/*name">模板</a>` +
			`<a href="/lionsoul2014/ip2region/releases/tag/v3.18.0">v3.18.0</a></html>`))
	}))
	defer srv.Close()
	oldProxy := ghFastProxy
	ghFastProxy = srv.URL + "/"
	t.Cleanup(func() { ghFastProxy = oldProxy })

	tag, err := fetchGitHubLatestTagViaProxy(context.Background(), crsRepoSlug)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if tag != "v3.18.0" {
		t.Fatalf("tag=%q, want v3.18.0（非法匹配必须跳过而非整体失败）", tag)
	}
}

// Given：页面里只有形状非法的匹配（无任何合法 tag）。
// Then：维持 fail-closed——报形状非法错误，不得放水返回空/非法值。
func TestFetchGitHubLatestTagViaProxy_allInvalidMatchesStillFailClosed(t *testing.T) {
	newTestCRSManager(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><a href="/lionsoul2014/ip2region/releases/tag/*name">模板</a></html>`))
	}))
	defer srv.Close()
	oldProxy := ghFastProxy
	ghFastProxy = srv.URL + "/"
	t.Cleanup(func() { ghFastProxy = oldProxy })

	tag, err := fetchGitHubLatestTagViaProxy(context.Background(), crsRepoSlug)
	if err == nil {
		t.Fatalf("tag=%q, want 形状非法错误（fail-closed）", tag)
	}
	if tag != "" {
		t.Fatalf("tag=%q, want 空", tag)
	}
}
