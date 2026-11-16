package handlers

// 自动备份裁剪的非法文件名分支：带外改库写入路径穿越形态的文件名时，
// 裁剪不得静默删行——行是残留文件/篡改的唯一可见证据，删行即孤儿化。
// 与「文件删除失败保留行+warn」同口径。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestPruneAutoBackupStatus_illegalFilenameKeepsRowWithWarn(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	dir := h.cfg.BackupDir
	logs := captureLog(t)

	// Given：keep=1，最新行合法（保留窗口内），两条过期行——一条非法
	// 文件名（路径穿越），一条合法且带真实文件（对照：照常裁剪）。
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, size_bytes, trigger_type) VALUES
		('lbbak-keep.lbbak', datetime('now','+2 minutes'), 'success', 1, 'schedule'),
		('../escape.lbbak', datetime('now','+1 minutes'), 'success', 1, 'schedule'),
		('lbbak-old.lbbak', datetime('now'), 'success', 1, 'schedule')`); err != nil {
		t.Fatalf("seed rows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lbbak-old.lbbak"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// When
	removed := pruneAutoBackupStatus(context.Background(), dir, "success", 1)

	// Then：合法过期行文件+行同删；非法名行保留且 warn 点名。
	if removed != 1 {
		t.Fatalf("removed=%d, want 1（仅合法过期行被裁剪）", removed)
	}
	rows := autoBackupRows(t, "WHERE status='success' ORDER BY created_at DESC")
	if len(rows) != 2 {
		t.Fatalf("rows after prune=%d, want 2（保留窗口行+非法名行）", len(rows))
	}
	if rows[1]["filename"] != "../escape.lbbak" {
		t.Fatalf("非法名行被删或错位: %v", rows[1])
	}
	if !strings.Contains(logs.String(), "文件名非法") || !strings.Contains(logs.String(), "../escape.lbbak") {
		t.Fatalf("非法名必须 warn 留痕点名文件, logs=%q", logs.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "lbbak-old.lbbak")); !os.IsNotExist(err) {
		t.Fatalf("合法过期行文件必须被删除, stat err=%v", err)
	}
}
