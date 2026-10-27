package handlers

// 自动备份并发删除的审计真实性：DELETE 影响 0 行（同读一行、先到者已删）时
// 必须 404 且不记「备份删除」成功审计、不删文件（文件归属先到者收尾）。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestDeleteAutoBackup_skipsAuditAndFileWhenRowAlreadyGone(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	dir := h.cfg.BackupDir
	filename := "lbbak-manual-delete-race.lbbak"
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("seed backup file: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, size_bytes, trigger_type) VALUES (?, datetime('now'), 'success', 7, 'manual')`, filename)
	if err != nil {
		t.Fatalf("seed auto_backups row: %v", err)
	}
	backupID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// Given 先到者已删行（同请求窗口内的并发删除形态：行仍被本次 SELECT 读到，
	// 但 DELETE 影响 0 行）。
	if _, err := db.DB.Exec(`CREATE TRIGGER auto_backups_delete_race BEFORE DELETE ON auto_backups BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create delete-race trigger: %v", err)
	}
	auditBefore := countAutoBackupAudit(t, "备份删除")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE("/auto-backup/:id", h.DeleteAutoBackup)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/auto-backup/"+strconv.FormatInt(backupID, 10), nil))

	// Then 404（不得谎报删除成功）。
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "备份不存在") {
		t.Fatalf("body=%s, want 备份不存在 文案", recorder.Body.String())
	}
	// Then 不记成功审计、不删文件。
	if auditAfter := countAutoBackupAudit(t, "备份删除"); auditAfter != auditBefore {
		t.Fatalf("0 行删除仍记「备份删除」审计 %d 条", auditAfter-auditBefore)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("0 行删除仍删除了文件: %v", err)
	}
	// 被拒尝试必须留痕：0 行（并发先到者已删）恰一条「删除失败」。
	if got := countAutoBackupAudit(t, "删除失败"); got != 1 {
		t.Fatalf("删除失败审计=%d, want 1（并发删除的 404 必须经 failAutoBackupAccess 留痕）", got)
	}

	// When 并发窗口关闭（行照常可删）。
	if _, err := db.DB.Exec(`DROP TRIGGER auto_backups_delete_race`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/auto-backup/"+strconv.FormatInt(backupID, 10), nil))

	// Then 正常删除：行与文件同删，记一条成功审计。
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("成功删除后文件仍存在: %v", err)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE id=?`, backupID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("成功删除后行仍存在 rows=%d", rows)
	}
	if auditAfter := countAutoBackupAudit(t, "备份删除"); auditAfter != auditBefore+1 {
		t.Fatalf("成功删除审计=%d, want %d", auditAfter, auditBefore+1)
	}
}
