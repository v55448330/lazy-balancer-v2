package services

// GitHub API 令牌与 User-Agent（2026-09-25 用户裁定，第 51 轮审计 P2-4 修复）：
// 未认证 GitHub API 限流 60 次/小时/IP——共享出口 IP 常被打满致 CRS/IP2Region
// 自动更新连日 403；可选 GITHUB_TOKEN（global_config.github_token）提升至
// 5000/h，UA 为 GitHub 要求的请求卫生。令牌仅随 api.github.com 直连发送——
// 绝不发往第三方加速代理（fetchGitHubLatestTagViaProxy 防泄漏）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given：配置了 GITHUB_TOKEN。When：直连 API 查询。
// Then：请求带 User-Agent 与 Authorization: Bearer。
func TestFetchGitHubLatestTagFromAPI_sendsUserAgentAndToken(t *testing.T) {
	newTestCRSManager(t) // db.Initialize + 版本行
	if _, err := db.DB.Exec(`UPDATE global_config SET github_token='ghp_test123' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var gotUA, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v4.29.0"}`))
	}))
	defer srv.Close()

	tag, err, _ := fetchGitHubLatestTagFromAPI(context.Background(), srv.Client(), srv.URL)
	if err != nil || tag != "v4.29.0" {
		t.Fatalf("tag=%q err=%v", tag, err)
	}
	if gotUA != "lazy-balancer-v2" {
		t.Fatalf("User-Agent=%q, want lazy-balancer-v2", gotUA)
	}
	if gotAuth != "Bearer ghp_test123" {
		t.Fatalf("Authorization=%q, want Bearer ghp_test123", gotAuth)
	}
}

// Given：未配置令牌。Then：无 Authorization 头（未认证形态），UA 仍带。
func TestFetchGitHubLatestTagFromAPI_noTokenNoAuthHeader(t *testing.T) {
	newTestCRSManager(t)
	var gotUA, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"tag_name":"v4.29.0"}`))
	}))
	defer srv.Close()

	if _, err, _ := fetchGitHubLatestTagFromAPI(context.Background(), srv.Client(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if gotUA != "lazy-balancer-v2" {
		t.Fatalf("User-Agent=%q, want lazy-balancer-v2", gotUA)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization=%q, want 空（未配置令牌）", gotAuth)
	}
}

// Given：配置了令牌。When：经第三方加速代理回退查询。
// Then：代理请求带 UA 但绝不携带 Authorization（防令牌泄漏给第三方）。
func TestFetchGitHubLatestTagViaProxy_neverLeaksToken(t *testing.T) {
	newTestCRSManager(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET github_token='ghp_test123' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var gotUA, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, "https://github.com/coreruleset/coreruleset/releases/tag/v4.29.0", http.StatusFound)
	}))
	defer srv.Close()
	oldProxy := ghFastProxy
	ghFastProxy = srv.URL + "/"
	t.Cleanup(func() { ghFastProxy = oldProxy })

	tag, err := fetchGitHubLatestTagViaProxy(context.Background(), crsRepoSlug)
	if err != nil || tag != "v4.29.0" {
		t.Fatalf("tag=%q err=%v", tag, err)
	}
	if gotUA != "lazy-balancer-v2" {
		t.Fatalf("User-Agent=%q, want lazy-balancer-v2", gotUA)
	}
	if gotAuth != "" {
		t.Fatalf("代理请求 Authorization=%q, want 空（令牌不得泄漏给第三方代理）", gotAuth)
	}
}
