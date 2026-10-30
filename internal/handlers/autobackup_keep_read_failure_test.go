package handlers

// 自动备份保留份数读取失败时必须跳过本轮裁剪（保守方向：未知保留意愿下不得
// 删文件）——此前读失败回退默认 7 并照常裁剪，用户配置 30 份时库抖动一轮就会
// 把 7 份之外的备份连文件一起删掉。下一轮读通后自然按 keep 收敛。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedAutoBackupSuccessFiles(t *testing.T, dir string, count int) {
	t.Helper()
	for i := 1; i <= count; i++ {
		name := fmt.Sprintf("lbbak-auto-keep%d.lbbak", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("payload"), 0o600); err != nil {
			t.Fatalf("seed backup file: %v", err)
		}
		if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, size_bytes, trigger_type) VALUES (?, datetime('2026-09-0'+?+' 03:00:00'), 'success', 7, 'schedule')`, name, string(rune('0'+i))); err != nil {
			t.Fatalf("seed backup row: %v", err)
		}
	}
}

func countAutoBackupSuccessFiles(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "lbbak-auto-*.lbbak"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

func TestRunAutoBackupOnce_skipsPruneWhenKeepSettingUnreadable(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	dir := h.cfg.BackupDir
	// 存量份数必须多于读失败回退值（默认 7）：旧实现按 7 裁剪会删掉多出的文件，
	// 正确实现必须一个都不删。
	seedAutoBackupSuccessFiles(t, dir, 9)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_keep=2 WHERE id=1`); err != nil {
		t.Fatalf("seed keep: %v", err)
	}

	// Given 保留份数列不可读（库故障/迁移窗口形态：同表其他列照常）。
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME COLUMN auto_backup_keep TO auto_backup_keep_unavailable`); err != nil {
		t.Fatalf("simulate keep read failure: %v", err)
	}

	// When 跑一轮备份。
	if _, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1); err != nil {
		t.Fatalf("备份失败（读取保留份数失败不得阻断备份本体）: %v", err)
	}

	// Then 本轮跳过裁剪：9 个存量文件 + 1 个新文件全部保留。
	if files := countAutoBackupSuccessFiles(t, dir); files != 10 {
		t.Fatalf("success files=%d, want 10（读失败必须跳过裁剪，不删任何文件）", files)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='success'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 10 {
		t.Fatalf("success rows=%d, want 10（读失败不得删行）", rows)
	}

	// When 配置恢复可读后跑下一轮。
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME COLUMN auto_backup_keep_unavailable TO auto_backup_keep`); err != nil {
		t.Fatalf("restore keep column: %v", err)
	}
	if _, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1); err != nil {
		t.Fatalf("恢复后备份失败: %v", err)
	}

	// Then 按 keep=2 收敛（文件与行同删）。
	if files := countAutoBackupSuccessFiles(t, dir); files != 2 {
		t.Fatalf("success files=%d, want 2（读通后按 keep 裁剪）", files)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='success'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("success rows=%d, want 2", rows)
	}
}
