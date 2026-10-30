package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 自动备份「还原」在进入导入核心之前的文件面失败（目标文件缺失 404、超限
// 413、读取失败 500）此前只有裸 c.JSON：同一高危操作族的审计只覆盖了导入
// 核心内部（failImportValidation/failImportBegin），前置阶段零留痕，运维无法
// 回答「谁在何时尝试还原哪个备份、为什么失败」。本文件钉住三条分支的
// 「warn + 失败审计 + 原响应」形态，并确认不产生虚假的成功审计。

func restoreRejectionAuditRows(t *testing.T, action string) []string {
	t.Helper()
	rows, err := db.AuditDB.Query("SELECT COALESCE(detail,'') FROM audit_log WHERE action=? ORDER BY id", action)
	if err != nil {
		t.Fatalf("query audit rows (%s): %v", action, err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		details = append(details, detail)
	}
	return details
}

func restoreRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/auto-backup/:id/restore", h.RestoreAutoBackup)
	return router
}

// seedManualBackup 生成一条真实手动备份行并返回行视图字段。
func seedManualBackup(t *testing.T, h *Handlers) (int64, string) {
	t.Helper()
	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	rows := autoBackupRows(t, "WHERE trigger_type='manual'")
	if len(rows) != 1 {
		t.Fatalf("manual rows=%d, want 1", len(rows))
	}
	return rows[0]["id"].(int64), rows[0]["filename"].(string)
}

func assertRestoreRejectionAudited(t *testing.T, filename string, wantStatus int, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status=%d body=%s, want %d", rec.Code, rec.Body.String(), wantStatus)
	}
	failures := restoreRejectionAuditRows(t, "还原失败")
	if len(failures) != 1 {
		t.Fatalf("还原失败 审计行=%d, want 1", len(failures))
	}
	if !strings.Contains(failures[0], filename) {
		t.Fatalf("审计 detail=%q 必须含备份文件名 %q", failures[0], filename)
	}
	if successes := restoreRejectionAuditRows(t, "还原"); len(successes) != 0 {
		t.Fatalf("被拒绝的还原不得留下成功审计: %v", successes)
	}
}

// Given 备份行在而目标文件已被外部清理。
// When POST restore。
// Then 404 + 恰一条「还原失败」审计（含文件名），无成功审计。
func TestRestoreAutoBackup_missingFileAuditsRejection(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := restoreRouter(h)
	id, filename := seedManualBackup(t, h)
	if err := os.Remove(filepath.Join(h.cfg.BackupDir, filename)); err != nil {
		t.Fatalf("remove backup file: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/auto-backup/%d/restore", id), nil))
	assertRestoreRejectionAudited(t, filename, http.StatusNotFound, rec)
}

// Given 目标文件大于导入上限（稀疏文件，不占实际磁盘）。
// When POST restore。
// Then 413 + 恰一条「还原失败」审计。
func TestRestoreAutoBackup_oversizeFileAuditsRejection(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := restoreRouter(h)
	id, filename := seedManualBackup(t, h)
	path := filepath.Join(h.cfg.BackupDir, filename)
	if err := os.Truncate(path, maxConfigImportBytes+1); err != nil {
		t.Fatalf("truncate backup file: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/auto-backup/%d/restore", id), nil))
	assertRestoreRejectionAudited(t, filename, http.StatusRequestEntityTooLarge, rec)
}

// Given 目标路径是目录（读取阶段失败——os.Open/Stat 均可成功）。
// When POST restore。
// Then 500 + 恰一条「还原失败」审计。
func TestRestoreAutoBackup_readFailureAuditsRejection(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := restoreRouter(h)
	id, filename := seedManualBackup(t, h)
	path := filepath.Join(h.cfg.BackupDir, filename)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove backup file: %v", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("replace backup file with directory: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/auto-backup/%d/restore", id), nil))
	assertRestoreRejectionAudited(t, filename, http.StatusInternalServerError, rec)
}
