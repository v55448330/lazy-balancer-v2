package handlers

import (
	"context"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 备份成功路径的行视图回读失败时，返回/通知用的视图必须由已知局部事实
// 构造（id/filename/status/大小/范围/触发…），不得退化为零值：
// 「备份完成」通知取 row.Filename，零值=订阅者收到空文件名的完成消息。
//
// 失败注入走真实 DB 机制（AFTER INSERT 触发器把 size_bytes 写成不可扫描
// 为整数的文本），令 scanAutoBackupRowView 在 Scan 阶段真实失败——不使用
// mock 返回值。
func TestRunAutoBackupOnce_viewScanFailureKeepsFilename(t *testing.T) {
	withIsolatedGlobal(t)
	h := newAutoBackupTestHandlers(t)

	if _, err := db.DB.Exec(`CREATE TRIGGER autobackup_corrupt_size AFTER INSERT ON auto_backups
		BEGIN UPDATE auto_backups SET size_bytes='corrupt' WHERE id=NEW.id; END`); err != nil {
		t.Fatalf("create failure-injection trigger: %v", err)
	}

	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	row, err := h.RunAutoBackupOnce(context.Background(), "manual", "tester", 1)
	if err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}

	var filename string
	if err := db.DB.QueryRow(`SELECT filename FROM auto_backups WHERE status='success' ORDER BY id DESC LIMIT 1`).Scan(&filename); err != nil {
		t.Fatalf("读取成功行文件名: %v", err)
	}
	if filename == "" {
		t.Fatal("未落成功行——失败注入夹具失效，用例无法判别")
	}
	// 反空转：必须确认走的是「视图回读失败」分支（否则本用例退化成正路径断言）。
	if !strings.Contains(logs.String(), "自动备份行视图扫描失败") {
		t.Fatalf("失败注入未命中视图回读分支（用例空转）: %q", logs.String())
	}
	if row.Filename != filename {
		t.Fatalf("视图回读失败后 row.Filename=%q, want %q（备份完成通知取该字段）", row.Filename, filename)
	}
	if row.ID == 0 {
		t.Fatal("row.ID=0——调用方失去定位该备份行的能力")
	}
	if row.Status != "success" {
		t.Fatalf("row.Status=%q, want success", row.Status)
	}
}
