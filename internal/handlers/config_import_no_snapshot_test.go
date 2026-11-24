package handlers

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 导入/还原是「确认后直接覆盖」：覆盖前不额外落备份行。是否留退路由管理员
// 自己的自动备份设置决定，不得在写路径上隐式产生备份（否则每次导入都会在
// 备份列表里多出一份没人要的条目）。
func TestImportConfigBackup_doesNotCreateBackupRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_no_snapshot','rule','http','no-snapshot.example.test',18081,1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	response := importBackupShared(h, t, buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true}))
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	if rows := autoBackupRows(t, ""); len(rows) != 0 {
		t.Fatalf("导入不得生成备份行，实际 %d 行: %v", len(rows), rows)
	}
	for _, warning := range decodeImportWarnings(t, response) {
		if strings.Contains(warning, "覆盖前") {
			t.Fatalf("导入响应不得披露覆盖前备份: %q", warning)
		}
	}
	if failures := countAutoBackupAudit(t, "备份失败"); failures != 0 {
		t.Fatalf("导入不得落备份失败审计，实际 %d 条", failures)
	}
}
