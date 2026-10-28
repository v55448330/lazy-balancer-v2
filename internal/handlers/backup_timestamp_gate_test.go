package handlers

// 时间列门的两条口径：
//   - 字符串逐字校验（不 TrimSpace）——驱动常规布局直接 time.Parse，首尾空白
//     串通过宽松校验后落库即不可解析；
//   - 门覆盖面 = 声明面：可空时间列（users.last_login / api_keys.last_used /
//     api_keys.expires_at / cert_jobs.expires_at）的非 NULL 值同样必须可解析，
//     NULL 合法。

import (
	"strings"
	"testing"
)

func TestValidateV2BackupTimestamps_rejectsWhitespacePaddedValues(t *testing.T) {
	for _, padded := range []string{" 2026-01-01 00:00:00", "2026-01-01 00:00:00 ", "\t2026-01-01"} {
		tables := map[string][]map[string]any{
			"users": {{"created_at": padded}},
		}
		if err := validateV2BackupTimestamps(tables); err == nil {
			t.Fatalf("%q 必须被拒（首尾空白串在驱动侧不可解析）", padded)
		}
	}
	// 合法形态与 NULL 均通过（门只拦不可解析值，不改写值）。
	valid := map[string][]map[string]any{
		"users":      {{"created_at": "2026-01-01 00:00:00", "last_login": nil}},
		"api_keys":   {{"created_at": "2026-01-01T00:00:00Z", "last_used": "2026-01-02 03:04:05", "expires_at": nil}},
		"cert_jobs":  {{"created_at": "2026-01-01", "expires_at": nil}},
		"lb_rules":   {{"created_at": "2026-01-01 00:00", "updated_at": "2026-01-01 00:00:00.123456789"}},
		"path_rules": {{}},
	}
	if err := validateV2BackupTimestamps(valid); err != nil {
		t.Fatalf("合法时间串被拒: %v", err)
	}
}

func TestValidateV2BackupTimestamps_coversDeclaredTimeColumns(t *testing.T) {
	// 直接遍历生产声明面：新增时间列只改 backupTimeColumns 也会自动获得
	// 畸形值用例，不再依赖测试侧手抄四列表格同步。
	for table, columns := range backupTimeColumns {
		for _, column := range columns {
			t.Run(table+"."+column, func(t *testing.T) {
				tables := map[string][]map[string]any{table: {{column: "garbage"}}}
				err := validateV2BackupTimestamps(tables)
				if err == nil {
					t.Fatalf("%s.%s 的不可解析值必须被拒（落库后列表/登录扫描 500）", table, column)
				}
				if !strings.Contains(err.Error(), column) {
					t.Fatalf("err=%v, want 点名列 %s", err, column)
				}
			})
		}
	}
}
