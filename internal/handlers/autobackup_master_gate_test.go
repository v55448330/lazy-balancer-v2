package handlers

// 自动备份角色门与文件名分配器的故障语义钉：
//  1. requireAutoBackupMaster 的角色读必须脱离客户端生命周期（与
//     requireMasterNode 同口径）——请求 ctx 已取消时不得把「客户端断开」
//     记成「节点角色查询失败」500。
//  2. nextAutoBackupFilename 的占名检查遇非取消类 DB 失败必须 fail-visible
//     （此前按「名可用」放行 fail-open——两行共享一份文件，裁剪误删）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRequireAutoBackupMaster_roleReadIndependentOfClientCancel(t *testing.T) {
	h := newBackupTestHandlers(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/auto-backup/run", nil)
	clientCtx, cancel := context.WithCancel(request.Context())
	cancel() // 客户端在角色读之前断开
	ctx.Request = request.WithContext(clientCtx)

	if !h.requireAutoBackupMaster(ctx) {
		t.Fatalf("status=%d body=%s, want 主节点放行（角色读不得被客户端取消影响）", recorder.Code, recorder.Body.String())
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("gate returned non-200 write: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

// Given 占名查询恒失败（真实列缺失故障）且 ctx 未取消。
// When 分配备份文件名。Then 显式报错，不得按「名可用」放行。
func TestNextAutoBackupFilename_dbFailureIsNotAvailable(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)
	// 真实故障注入：auto_backups.filename 列改名 → 占名 SELECT 恒失败。
	if _, err := db.DB.Exec(`ALTER TABLE auto_backups RENAME COLUMN filename TO filename_unavailable`); err != nil {
		t.Fatalf("注入列故障: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`ALTER TABLE auto_backups RENAME COLUMN filename_unavailable TO filename`)
	})

	_, err := nextAutoBackupFilename(context.Background(), h.cfg.BackupDir, "auto", now)
	if err == nil || !strings.Contains(err.Error(), "检查备份文件名占用") {
		t.Fatalf("err=%v, want 显式占名检查失败（非取消类 DB 失败不得按名可用放行）", err)
	}
}

// Given 同样的 DB 故障但 ctx 已取消。When 分配文件名。
// Then 按取消返回（取消语义优先，不落 failed 行）。
func TestNextAutoBackupFilename_cancelledContextReturnsCancelError(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)
	if _, err := db.DB.Exec(`ALTER TABLE auto_backups RENAME COLUMN filename TO filename_unavailable`); err != nil {
		t.Fatalf("注入列故障: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`ALTER TABLE auto_backups RENAME COLUMN filename_unavailable TO filename`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := nextAutoBackupFilename(ctx, h.cfg.BackupDir, "auto", now)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err=%v, want context.Canceled（取消态优先于 DB 故障文案）", err)
	}
}
