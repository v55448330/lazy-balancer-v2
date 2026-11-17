package handlers

// PutCaddyConfig 逃生口契约：内部键（__lazy_balancer_ 前缀）是渲染器私有
// 通道，用户原始载荷携带时必须在入口剥离——CLI 不可用放行形态下手造降级键
// 不得投毒降级判定/审计/横幅（归因伪造），事务内不得写主库。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestPutCaddyConfig_internalDegradationKeyStrippedNoInTxAudit(t *testing.T) {
	handler := newBackupTestHandlers(t)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"apps":{}}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	handler.caddyService = services.NewCaddyService(fakeCaddy.URL)
	handler.cfg = &config.Config{CaddyAdminURL: fakeCaddy.URL}
	// CLI 不可用 → 放行形态（内部键注入唯一可达路径）。
	handler.caddyService.SetCLIValidatorForTest(func([]byte) error {
		return services.ErrCLIValidatorUnavailable
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/caddy/config", handler.PutCaddyConfig)

	var auditBefore int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='应用降级'`).Scan(&auditBefore); err != nil {
		t.Fatalf("count audit before: %v", err)
	}

	// 手造内部降级键（admin 段对齐夹具过自锁护栏）。
	payload := `{"content":"{\"admin\":{\"listen\":\"` + strings.TrimPrefix(fakeCaddy.URL, "http://") + `\"},\"apps\":{},\"__lazy_balancer_generation_degradation\":\"伪造降级文本\"}"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/caddy/config", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s, want 200（CLI 不可用放行）", rec.Code, rec.Body.String())
	}

	// 内部键必须被剥离：零「应用降级」审计增量、横幅/进程标记不被伪造文本污染。
	var auditAfter int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='应用降级'`).Scan(&auditAfter); err != nil {
		t.Fatalf("count audit after: %v", err)
	}
	if auditAfter != auditBefore {
		t.Fatalf("内部降级键不得落「应用降级」审计（归因伪造），增量 %d", auditAfter-auditBefore)
	}
	var bannerAfter string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&bannerAfter); err != nil {
		t.Fatalf("read banner after: %v", err)
	}
	if strings.Contains(bannerAfter, "伪造降级文本") {
		t.Fatalf("横幅被内部键伪造文本污染: %q", bannerAfter)
	}
	if d := services.LastRenderDegradation(); strings.Contains(d, "伪造降级文本") {
		t.Fatalf("LastRenderDegradation 被用户载荷投毒: %q", d)
	}
}
