package handlers

// 自动备份删除的提交失败面：文件先于提交删除，提交失败时行随回滚恢复、
// 文件已亡——这是本端点最坏的分叉。断言必须证明三件事：①恰一条「删除失败」
// 审计（不记成功）；②响应文案显式说明已删除的文件与保留的记录（可自助恢复）；
// ③行仍在、文件已不在（分叉事实与文案一致）。

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestDeleteAutoBackup_commitFailureDisclosesDeletedFileAndKeepsRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-commit-fail.lbbak"
	path := filepath.Join(h.cfg.BackupDir, name)
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	// 延迟约束在 COMMIT 阶段才失败（模拟 IO/确认丢失型提交错误）。
	if _, err := db.DB.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE auto_backup_commit_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_auto_backup_delete_commit AFTER DELETE ON auto_backups BEGIN INSERT INTO auto_backup_commit_guard(parent_id) VALUES (999); END`); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}

	// When
	response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", fmt.Sprintf("/auto-backup/%d", id), "", h.DeleteAutoBackup)

	// Then：500 且文案点名「文件已删除、记录已恢复保留」。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"提交失败", "备份文件已删除", "记录已恢复保留"} {
		if !strings.Contains(body, want) {
			t.Fatalf("提交失败文案 body=%s, want 含 %q（必须披露已发生的副作用与下一步）", body, want)
		}
	}
	// Then：行随回滚恢复，文件已删除（分叉事实）。
	if rows := autoBackupRows(t, "WHERE id=?", id); len(rows) != 1 {
		t.Fatalf("提交失败后行必须随回滚保留: %v", rows)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("提交失败前文件已删除，实际 stat=%v", err)
	}
	// Then：恰一条「删除失败」审计，无成功审计。
	if got := countAutoBackupAudit(t, "备份删除"); got != 0 {
		t.Fatalf("提交失败仍记成功审计=%d, want 0", got)
	}
	if got := countAutoBackupAudit(t, "删除失败"); got != 1 {
		t.Fatalf("删除失败审计=%d, want 1", got)
	}
	detail := autoBackupAuditDetail(t, "删除失败")
	for _, want := range []string{fmt.Sprintf("#%d", id), name, "提交"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("删除失败 detail=%q, want 含 %q", detail, want)
		}
	}
}

func TestDeleteAutoBackup_commitFailureUsesSharedSeam(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-shared-commit-seam.lbbak"
	path := filepath.Join(h.cfg.BackupDir, name)
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	forceCommitFailure(t)

	response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", fmt.Sprintf("/auto-backup/%d", id), "", h.DeleteAutoBackup)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want injected commit failure 500", response.Code, response.Body.String())
	}
	if rows := autoBackupRows(t, "WHERE id=?", id); len(rows) != 1 {
		t.Fatalf("提交失败后行必须恢复保留: %v", rows)
	}
}
