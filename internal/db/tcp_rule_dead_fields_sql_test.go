package db

import (
	"strings"
	"testing"
)

// 单规则版死值归一 SQL 的 SET 投影必须与批量版逐字相同（同源
// tcpDeadFieldsResetSetProjection 单源拼装）——投影分叉即「启用单条规则时
// 清零列集 ≠ 导入归一/启动迁移清零列集」的静默口径分裂。WHERE 收敛为
// protocol+caddy_id，不改其他行。
func TestTCPRuleDeadFieldsResetForRuleSQL_setProjectionMatchesBatch(t *testing.T) {
	batch := TCPRuleDeadFieldsResetSQL
	single := TCPRuleDeadFieldsResetForRuleSQL("?")

	const setMarker = " SET "
	setEnd := strings.Index(batch, " WHERE ")
	if setEnd < 0 {
		t.Fatalf("批量版缺少 WHERE 段: %q", batch)
	}
	batchSet := batch[:setEnd]
	if !strings.HasPrefix(batchSet, "UPDATE lb_rules"+setMarker[:len(setMarker)-1]) {
		t.Fatalf("批量版形态异常: %q", batchSet)
	}
	singleSet := single[:strings.Index(single, " WHERE ")]
	if batchSet != singleSet {
		t.Fatalf("单规则版 SET 投影与批量版分叉:\n批量=%q\n单规=%q", batchSet, singleSet)
	}
	// WHERE 收敛到单规则：不得复用批量谓词（否则启用一条会清零全部 TCP 行）。
	if !strings.HasSuffix(single, "WHERE protocol='tcp' AND caddy_id = ?") {
		t.Fatalf("单规则版 WHERE=%q, want protocol+caddy_id 收敛", single[strings.Index(single, " WHERE ")+1:])
	}
	if strings.Contains(single, tcpDeadFieldsStalePredicate[:32]) {
		t.Fatal("单规则版不得拼入批量探测谓词（否则归一越出单行）")
	}
}

// 行为验收：单规则版只清零目标 TCP 行的 HTTP 专属死值，同库其他 TCP 行
// （含禁用行）与 HTTP 行不受影响。
func TestTCPRuleDeadFieldsResetForRuleSQL_scopedToTargetRow(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	seed := func(id int, caddyID, protocol, host string) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, host_header, listen_port, enabled)
			VALUES (?, ?, ?, ?, '', ?, 8000, 0)`, id, caddyID, caddyID, protocol, host); err != nil {
			t.Fatalf("seed %s: %v", caddyID, err)
		}
	}
	seed(1, "tcp_target", "tcp", "stale.example.test")
	seed(2, "tcp_other", "tcp", "stale.example.test")
	seed(3, "http_row", "http", "stale.example.test")

	if _, err := database.Exec(TCPRuleDeadFieldsResetForRuleSQL("?"), "tcp_target"); err != nil {
		t.Fatalf("exec single-rule reset: %v", err)
	}

	hostOf := func(caddyID string) string {
		t.Helper()
		var host string
		if err := database.QueryRow(`SELECT COALESCE(host_header,'') FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&host); err != nil {
			t.Fatalf("read %s: %v", caddyID, err)
		}
		return host
	}
	if got := hostOf("tcp_target"); got != "" {
		t.Fatalf("目标行 host_header=%q, want 已清零", got)
	}
	if got := hostOf("tcp_other"); got != "stale.example.test" {
		t.Fatalf("其他 TCP 行 host_header=%q, want 原样（归一不得越出目标行）", got)
	}
	if got := hostOf("http_row"); got != "stale.example.test" {
		t.Fatalf("HTTP 行 host_header=%q, want 原样", got)
	}
}
