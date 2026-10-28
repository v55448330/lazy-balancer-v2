package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// 导入核心体必须在会话建立后与请求取消脱钩：客户端断连/反代超时落在写库段时，
// 已在锁内、已暂停引擎、已持 CA 队列 hold 的导入不能被静默放弃——整体回滚会
// 让管理员对整个分钟级导入重试，而「会话建立后不受断连影响」是协调器的书面
// 契约（session.ctx = WithoutCancel(request)）。
func TestImportConfigBackupCore_survivesRequestCancellationDuringApply(t *testing.T) {
	// Given：一份可导入的规则库备份 + 在 begin 阶段就已断连的请求
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	dir := t.TempDir()
	restoreWafDir := services.OverrideThreatWafDirForTest(dir)
	defer restoreWafDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	if _, err := db.DB.Exec(`DELETE FROM security_threat_sources; DELETE FROM security_crs_version; DELETE FROM security_ip2region_version`); err != nil {
		t.Fatalf("clear rule library rows: %v", err)
	}
	backupJSON := backupJSONFixture(t, map[string][]map[string]any{
		"security_threat_sources": {threatRowShared("ustc")},
	}, nil, []string{"security"})
	payload := buildLbbakWithExtraThreatEntry(t, string(backupJSON), []byte("5.6.7.8\n"))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	configImportAfterSessionHook = cancel
	t.Cleanup(func() { configImportAfterSessionHook = nil })
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil).WithContext(ctx)

	// When
	h.importConfigBackupCore(c, payload, "", "导入")

	// Then：导入照常完成并落库（会话 ctx 承担写入，请求 ctx 只用于排空/取锁）
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（请求断连不得中止已开始的导入）", rec.Code, rec.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources`).Scan(&name); err != nil {
		t.Fatalf("read imported threat source: %v", err)
	}
	if name != "ustc" {
		t.Fatalf("imported threat source name=%q, want ustc", name)
	}
}
