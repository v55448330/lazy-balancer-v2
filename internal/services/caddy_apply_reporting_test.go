package services

// ApplyConfigReporting* 的 loaded 语义：「发生了成功的真实 /load」。
// 失败分支（被拒/传输失败/生成失败）一律 false——曾返回 true，按注释写
// `if loaded { audit }` 的调用方会把失败应用记成真实重载（审计真实性的反面）。

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newFailingLoadAdmin(t *testing.T) *CaddyService {
	t.Helper()
	newClusterTestService(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			_, _ = w.Write([]byte(`{"apps":{"running":true}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(server.Close)
	return NewCaddyService(server.URL)
}

// Given /load 返回 500（Caddy 内部错误）
// When ApplyConfigReporting
// Then 错误上抛且 loaded=false（不得把失败应用报成真实重载）
func TestApplyConfigReporting_loadFailureReportsNotLoaded(t *testing.T) {
	service := newFailingLoadAdmin(t)
	loaded, err := service.ApplyConfigReporting(map[string]interface{}{"apps": map[string]interface{}{"candidate": true}})
	if err == nil {
		t.Fatal("/load 500 必须上抛错误")
	}
	if loaded {
		t.Fatal("失败 /load 不得报告 loaded=true（审计真实性：失败应用不是重载）")
	}
}

// Given 同一失败形态
// When ApplyConfigReportingForCommit
// Then loaded=false（applied 字节可返回，但不得声称发生过成功重载）
func TestApplyConfigReportingForCommit_loadFailureReportsNotLoaded(t *testing.T) {
	service := newFailingLoadAdmin(t)
	_, loaded, err := service.ApplyConfigReportingForCommit(map[string]interface{}{"apps": map[string]interface{}{"candidate": true}})
	if err == nil {
		t.Fatal("/load 500 必须上抛错误")
	}
	if loaded {
		t.Fatal("失败 /load 不得报告 loaded=true")
	}
}
