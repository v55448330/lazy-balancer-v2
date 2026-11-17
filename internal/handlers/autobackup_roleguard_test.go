package handlers

// requireAutoBackupMaster 的「角色查询失败」必须与
// 「确认是从节点」分状态——修复前 err!=nil 与 !isMaster 同走 403「仅主节点
// 支持管理自动备份」，把 DB 故障误报为角色语义（且断言了并不掌握的角色信息）。

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRequireMasterResult_truthTable(t *testing.T) {
	options := masterGateOptions{queryFailure: "节点角色查询失败", forbidden: "仅主节点支持管理自动备份"}
	for _, tc := range []struct {
		name        string
		isMaster    bool
		err         error
		wantAllowed bool
		wantStatus  int
		wantMessage string
		wantCode    string
	}{
		{name: "master", isMaster: true, wantAllowed: true, wantStatus: http.StatusOK},
		{name: "slave", wantStatus: http.StatusForbidden, wantMessage: "仅主节点支持管理自动备份", wantCode: "master_required"},
		{name: "query error even when boolean master", isMaster: true, err: errors.New("role db down"), wantStatus: http.StatusInternalServerError, wantMessage: "节点角色查询失败"},
		{name: "query error on slave", err: errors.New("role db down"), wantStatus: http.StatusInternalServerError, wantMessage: "节点角色查询失败"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/settings/auto-backup", nil)
			allowed := requireMasterResult(ctx, tc.isMaster, tc.err, options)
			if allowed != tc.wantAllowed || recorder.Code != tc.wantStatus {
				t.Fatalf("allowed=%v status=%d, want %v/%d; body=%s", allowed, recorder.Code, tc.wantAllowed, tc.wantStatus, recorder.Body.String())
			}
			if tc.wantMessage != "" && !strings.Contains(recorder.Body.String(), tc.wantMessage) {
				t.Fatalf("body=%s, want %q", recorder.Body.String(), tc.wantMessage)
			}
			if got := recorder.Header().Get("X-LB-Error-Code"); got != tc.wantCode {
				t.Fatalf("X-LB-Error-Code=%q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestAutoBackupSettings_roleQueryFailureReturns500(t *testing.T) {
	// Given：主节点实例，随后破坏角色查询面（global_config 缺席 → IsMaster 报错）
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_broken`); err != nil {
		t.Fatalf("break role query: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/settings/auto-backup", h.AutoBackupSettings)

	// When
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/settings/auto-backup", nil))

	// Then：500「节点角色查询失败」，而非 403 角色语义误报
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（角色查询失败≠从节点）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "节点角色查询失败") {
		t.Fatalf("body=%s, want 「节点角色查询失败」", recorder.Body.String())
	}
}
