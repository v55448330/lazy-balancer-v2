package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

// 此前回落默认值(20/50)——用户显式要 150 条时拿到 20 条,翻页次数凭空放大。
// 改钳到上限(100/50);低于 1 仍回默认。CRS 上限同时由 100 收紧到 50(与
// 默认页大小一致,前端单页渲染边界)。
func TestListSecurityEvents_pageSizeClampsToCap(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	get := func(query string) int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/events?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("query=%s status=%d body=%s", query, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				PageSize int `json:"page_size"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Data.PageSize
	}

	// When / Then:超上限钳到 100(现行回落默认 20)
	if got := get("page_size=150"); got != 100 {
		t.Fatalf("page_size=150 → %d, want clamp to cap 100", got)
	}
	// 回归:低于 1 回默认 20;合法值原样
	if got := get("page_size=0"); got != 20 {
		t.Fatalf("page_size=0 → %d, want default 20", got)
	}
	if got := get("page_size=50"); got != 50 {
		t.Fatalf("page_size=50 → %d, want 50", got)
	}
}

// 事件列表 page 上限 1000：深翻页（page=100000 × page_size=100 → OFFSET 近
// 千万）在百万~千万行事件表上单请求秒级扫描，任意登录用户可触发——钳到
// cap 而非放行。
func TestListSecurityEvents_pageClampsToCap(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	get := func(query string) int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/events?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("query=%s status=%d body=%s", query, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Page int `json:"page"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Data.Page
	}
	if got := get("page=100000"); got != 1000 {
		t.Fatalf("page=100000 → %d, want clamp to cap 1000", got)
	}
	if got := get("page=0"); got != 1 {
		t.Fatalf("page=0 → %d, want default 1", got)
	}
	if got := get("page=7"); got != 7 {
		t.Fatalf("page=7 → %d, want 7", got)
	}
}

func TestListCRSRules_pageSizeClampsToCap(t *testing.T) {
	withIsolatedGlobal(t)
	// Given:经 crsRulesDir 测试缝挂一条 stub 规则
	oldDir := crsRulesDir
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf"), []byte("# stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/crs/rules", (&Handlers{}).ListCRSRules)
	get := func(query string) int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/crs/rules?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("query=%s status=%d body=%s", query, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				PageSize int `json:"page_size"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Data.PageSize
	}

	// When / Then:超上限钳到 50(现行 80 经旧 100 上限原样放行)
	if got := get("page_size=150"); got != 50 {
		t.Fatalf("page_size=150 → %d, want clamp to cap 50", got)
	}
	if got := get("page_size=80"); got != 50 {
		t.Fatalf("page_size=80 → %d, want clamp to cap 50", got)
	}
	// 回归:低于 1 回默认 50
	if got := get("page_size=0"); got != 50 {
		t.Fatalf("page_size=0 → %d, want default 50", got)
	}
}

// 分页非法值必须 400（与事件列表同口径）：CRS 列表旧实现丢弃 fmt.Sscanf
// 错误静默回落第 1 页/50 条——调用方拼写错误完全无信号，而同面板事件列表
// 对同样输入返回 400。
func TestListCRSRules_invalidPaginationRejected(t *testing.T) {
	withIsolatedGlobal(t)
	oldDir := crsRulesDir
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf"), []byte("# stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/crs/rules", (&Handlers{}).ListCRSRules)

	for _, query := range []string{"page=abc", "page_size=abc", "page=1.5", "page_size=ten"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/crs/rules?"+query, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("query=%s status=%d body=%s, want 400（与事件列表同口径）", query, recorder.Code, recorder.Body.String())
		}
	}
}
