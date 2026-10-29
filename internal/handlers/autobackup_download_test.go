package handlers

import (
	"context"
	"errors"
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

// 备份下载 Stat→FileAttachment 的 TOCTOU（备份完成
// prune 掉在下载文件→Stat 过打开失败 panic/500+审计先于交付虚记）。
// 修复=句柄先行（os.Open 成功后才审计+流式交付）。竞态形态不可确定性
// 注入——以下为交付形状基线钉+缺失文件回归钉（结构修复见实现）。

func downloadAuditCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='备份下载'").Scan(&n); err != nil {
		t.Fatalf("count download audits: %v", err)
	}
	return n
}

// Given 一条真实自动备份行与文件。
// When GET download。
// Then 200 + attachment 头 + 审计落「备份下载」。
func TestDownloadAutoBackup_streamsFileAndAuditsAfterOpen(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auto-backup/:id/download", h.DownloadAutoBackup)

	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 0); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	rows := autoBackupRows(t, "WHERE trigger_type='manual'")
	if len(rows) != 1 {
		t.Fatalf("manual rows=%d, want 1", len(rows))
	}
	id := rows[0]["id"].(int64)
	filename := rows[0]["filename"].(string)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/auto-backup/%d/download", id), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("download status=%d body=%s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "attachment; filename=\""+filename+"\"" {
		t.Fatalf("Content-Disposition=%q, want attachment 形态", cd)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("下载体不应为空")
	}
	if n := downloadAuditCount(t); n < 1 {
		t.Fatalf("备份下载审计行=%d, want ≥1（句柄成功后落账）", n)
	}
}

// Given 行在而文件已消失（prune 竞态后形态）。
// When GET download。
// Then 404 且**不落成功交付审计**（虚记交付），但必须落恰一条「下载失败」
// 拒绝审计——下载是敏感文件交付，被拒尝试同样要能复盘「谁在何时试过」。
func TestDownloadAutoBackup_missingFileAuditsRejectionNotDelivery(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auto-backup/:id/download", h.DownloadAutoBackup)

	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 0); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	rows := autoBackupRows(t, "WHERE trigger_type='manual'")
	id := rows[0]["id"].(int64)
	if err := os.Remove(filepath.Join(h.cfg.BackupDir, rows[0]["filename"].(string))); err != nil {
		t.Fatalf("remove file: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/auto-backup/%d/download", id), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing file status=%d, want 404", rec.Code)
	}
	if n := downloadAuditCount(t); n != 0 {
		t.Fatalf("缺失文件下载成功审计行=%d, want 0（未交付不得记成功）", n)
	}
	failures := restoreRejectionAuditRows(t, "下载失败")
	if len(failures) != 1 {
		t.Fatalf("下载失败 审计行=%d, want 1", len(failures))
	}
	if filename := rows[0]["filename"].(string); !strings.Contains(failures[0], filename) {
		t.Fatalf("审计 detail=%q 必须含备份文件名 %q", failures[0], filename)
	}
}

type interruptedDownloadWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (w *interruptedDownloadWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDownloadAutoBackupDoesNotAuditSuccessWhenDeliveryFails(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auto-backup/:id/download", h.DownloadAutoBackup)
	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 0); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	rows := autoBackupRows(t, "WHERE trigger_type='manual'")
	if len(rows) != 1 {
		t.Fatalf("manual rows=%d, want 1", len(rows))
	}
	id := rows[0]["id"].(int64)
	before := downloadAuditCount(t)
	rec := &interruptedDownloadWriter{ResponseRecorder: httptest.NewRecorder(), err: errors.New("client disconnected")}
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/auto-backup/%d/download", id), nil))
	if got := downloadAuditCount(t); got != before {
		t.Fatalf("successful delivery audits before=%d after=%d, want unchanged", before, got)
	}
}
