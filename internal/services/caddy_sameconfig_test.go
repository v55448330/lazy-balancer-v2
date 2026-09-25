package services

// 审计真实性门（2026-09-25 用户裁定：审计事件必须真实有效）：渲染产物与
// 运行配置字节相同时跳过 /load 并返回 errSameConfig——Caddy changeConfig
// 本就短路零 provision，调用方据此不落「重载」审计。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given：fake Caddy admin（GET /config/ 回显最近一次 /load 载荷）。
// When：连续两次渲染应用同一 DB 视图。Then：首次真 /load；第二次
// errSameConfig 且零新增 POST（同字节短路）。
func TestApplyConfig_skipsLoadWhenByteIdentical(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	posts := 0
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write(lastBody) // 初始为空 → 字节不等 → 首次照常 /load
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			posts++
			lastBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	s := NewCaddyService(srv.URL)

	// When：首次应用（运行配置为空 → 字节不等 → 真 /load）
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	mu.Lock()
	if posts != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", posts)
	}
	mu.Unlock()

	// When：同 DB 视图二次应用（渲染字节与运行配置相同）
	err := s.GenerateAndApplyConfig()

	// Then：errSameConfig + 零新增 POST
	if !IsSameConfig(err) {
		t.Fatalf("err=%v, want errSameConfig（同字节短路）", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Fatalf("同字节后 /load 次数=%d, want 仍 1（未发起多余 /load）", posts)
	}
}

// Given：fake Caddy admin 的 GET /config/ 返回非 200（比对失败）。
// Then：fail-open 照常 /load（不阻断写入，与 Caddy 自身短路同向）。
func TestApplyConfig_failsOpenWhenRunningConfigUnreadable(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			posts++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // GET /config/ 不可读
	}))
	defer srv.Close()
	s := NewCaddyService(srv.URL)

	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("比对失败应 fail-open 照常应用: %v", err)
	}
	if posts != 1 {
		t.Fatalf("/load 次数=%d, want 1（比对失败不阻断）", posts)
	}
}
