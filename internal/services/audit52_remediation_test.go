package services

// 第 52 轮 P2 渲染侧/回退侧 RED（用户裁定按建议处理）：
// ① blockPageContentType 白名单双保险——带外通道（备份导入/集群快照）写入的
//    白名单外值必须归一默认 text/html; charset=utf-8，不得原样渲染进响应头；
// ② fetchGitHubLatestTagFromAPI 对 401 纳入代理回退（transport=true）——失效
//    令牌直连恒败且不回退时，自动更新比无令牌更糟。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestBlockPageContentType_normalizesNonWhitelist(t *testing.T) {
	// Given：白名单四型原样保留
	for _, ok := range models.BlockPageContentTypes {
		if got := blockPageContentType(ok); got != ok {
			t.Fatalf("合法 content_type=%q 被改为 %q, want 原样保留", ok, got)
		}
	}
	// When：带外脏值（CRLF 注入形态与白名单外普通值）
	for _, bad := range []string{"text/html\r\nX-Injected: 1", "text/css", "application/pdf"} {
		// Then：归一默认
		if got := blockPageContentType(bad); got != models.DefaultBlockPageContentType {
			t.Fatalf("非白名单 content_type=%q 渲染为 %q, want 归一 %q", bad, got, models.DefaultBlockPageContentType)
		}
	}
}

func TestFetchGitHubLatestTagFromAPI_401TriggersProxyFallback(t *testing.T) {
	newTestCRSManager(t)
	// Given：GitHub 返回 401（令牌失效/作废形态）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	// When
	_, err, transport := fetchGitHubLatestTagFromAPI(context.Background(), srv.Client(), srv.URL)

	// Then：错误在册，且按认证面失败纳入代理回退（与 403 同口径）
	if err == nil {
		t.Fatal("401 应返回错误")
	}
	if !transport {
		t.Fatal("401 transport=false, want true（失效令牌必须走代理回退，否则自动更新比无令牌更糟）")
	}
}
