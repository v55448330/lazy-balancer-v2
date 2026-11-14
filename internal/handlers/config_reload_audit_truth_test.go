package handlers

// 审计真实性（2026-09-25 用户裁定：审计事件必须真实有效）：DB 字段变化但
// Caddy JSON 字节不变的保存，不再产生「保存配置后自动重载」审计——该次
// /load 被同字节短路，记录即虚假事件。真重载（字节变化）审计照常。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// reinitAuditDBForTest 在既有夹具之上重开审计库并登记新句柄的 Close：
// setupSecurityPolicyTestDB 已经 db.Initialize 装配了一个 AuditDB，二次
// InitializeAuditDB 直换句柄若不 Close 新句柄，每用例泄漏一个连接池（≤5
// 连接）连同 fd 至进程退出。复位到旧句柄由 setupSecurityPolicyTestDB 的
// cleanup 承担（注册更早、执行更晚），此处只负责关闭本用例新开的句柄。
func reinitAuditDBForTest(t *testing.T) {
	t.Helper()
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	newAudit := db.AuditDB
	t.Cleanup(func() { _ = newAudit.Close() })
}

func TestUpdateConfig_skipsReloadAuditWhenRenderUnchanged(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	reinitAuditDBForTest(t)
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			if len(lastBody) == 0 {
				_, _ = w.Write([]byte("{}"))
			} else {
				_, _ = w.Write(lastBody)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			lastBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	reloadAuditCount := func() int {
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// When：改一个渲染消费但无规则时不影响字节的字段（全局代理连接超时 10→11）
	// ——DB 真变、渲染字节变（首存时运行配置为空，字节不等 → 真 /load → 重载审计一条）
	if r := put(`{"source":"basic","proxy_dial_timeout":10}`); r.Code != http.StatusOK {
		t.Fatalf("首存 status=%d body=%s, want 200", r.Code, r.Body.String())
	}
	if n := reloadAuditCount(); n != 1 {
		t.Fatalf("首存后重载审计=%d 条, want 1（真重载照记）", n)
	}

	// When：再改同字段（11→12）——DB 真变，但无规则时全局超时不进 Caddy JSON →
	// 渲染字节与运行配置相同 → 同字节短路 → 零真实重载
	if r := put(`{"source":"basic","proxy_dial_timeout":12}`); r.Code != http.StatusOK {
		t.Fatalf("次存 status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：零新增重载审计（无真实重载不得记录）
	if n := reloadAuditCount(); n != 1 {
		t.Fatalf("同字节次存后重载审计=%d 条, want 仍 1（同字节不落审计）", n)
	}
}

// PutCaddyConfig 同款门：自定义配置与运行配置同字节时，「保存配置后自动
// 重载」审计不得落笔（ApplyConfigReporting.loaded=false）。
func TestPutCaddyConfig_skipsReloadAuditWhenByteIdentical(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	reinitAuditDBForTest(t)
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			if len(lastBody) == 0 {
				_, _ = w.Write([]byte(`{"old":true}`))
			} else {
				_, _ = w.Write(lastBody)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			lastBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.PUT("/caddy", h.PutCaddyConfig)
	put := func(content string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/caddy", strings.NewReader(content))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	reloadAuditCount := func() int {
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// When：首次 PUT 自定义配置（与运行配置不同 → 真 /load → 审计一条）
	if r := put(`{"content":"{\"apps\":{\"http\":{}}}"}`); r.Code != http.StatusOK {
		t.Fatalf("首 PUT status=%d body=%s, want 200", r.Code, r.Body.String())
	}
	if n := reloadAuditCount(); n != 1 {
		t.Fatalf("首 PUT 后重载审计=%d, want 1（真重载照记）", n)
	}

	// When：再次 PUT 同一内容（渲染字节与运行配置相同 → 同字节短路）
	if r := put(`{"content":"{\"apps\":{\"http\":{}}}"}`); r.Code != http.StatusOK {
		t.Fatalf("次 PUT status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：零新增重载审计
	if n := reloadAuditCount(); n != 1 {
		t.Fatalf("同字节次 PUT 后重载审计=%d, want 仍 1（同字节不落审计）", n)
	}
}
