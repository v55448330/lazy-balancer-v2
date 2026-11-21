package handlers

// 备份/同步面表分类守卫：schema 里每张表必须显式归入「随备份导出」或
// 「运行时/本地态（不随备份）」之一——新表未归类即红。此前新表默认落在
// 两者的缝隙里：既不导出也不登记理由，用户只能从「备份了但没恢复出来」
// 或「导入后本地运行态被覆盖」的现场反推。
//
// 归类源=internal/db 三个建表文件里的 `CREATE TABLE IF NOT EXISTS <name>`
// 字面量（含延迟建表路径，如 autoban_recidivism/cluster_applied_sections），
// 不用运行期 sqlite_master：延迟表在建表前不可见，正是最容易漏归类的一类。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var dbDDLTablePattern = regexp.MustCompile(`CREATE TABLE IF NOT EXISTS ([a-z_0-9]+)`)

func scanSchemaTables(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "db", "*.go"))
	if err != nil {
		t.Fatalf("枚举 internal/db 源文件: %v", err)
	}
	tables := map[string]string{} // 表名 → 首个声明文件
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取 %s: %v", path, err)
		}
		for _, m := range dbDDLTablePattern.FindAllStringSubmatch(string(raw), -1) {
			if _, seen := tables[m[1]]; !seen {
				tables[m[1]] = filepath.Base(path)
			}
		}
	}
	if len(tables) < 40 {
		t.Fatalf("扫描到的建表字面量过少（%d 张）——DDL 形态变更导致守卫空转", len(tables))
	}
	return tables
}

func TestConfigBackupTableClassificationCoversSchema(t *testing.T) {
	schema := scanSchemaTables(t)

	exported := make(map[string]bool, len(configBackupTables))
	for _, table := range configBackupTables {
		if exported[table] {
			t.Fatalf("configBackupTables 重复登记表 %s", table)
		}
		exported[table] = true
		if _, ok := schema[table]; !ok {
			t.Fatalf("configBackupTables 含 schema 中不存在的表 %s（改名/删表后未同步备份清单）", table)
		}
	}
	for table, reason := range configBackupRuntimeTables {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("运行时表 %s 缺少「不随备份」理由", table)
		}
		if exported[table] {
			t.Fatalf("表 %s 同时出现在备份清单与运行时清单", table)
		}
		if _, ok := schema[table]; !ok {
			t.Fatalf("configBackupRuntimeTables 含 schema 中不存在的表 %s（删表后未清理登记）", table)
		}
	}
	var unclassified []string
	for table, file := range schema {
		if exported[table] {
			continue
		}
		if _, ok := configBackupRuntimeTables[table]; ok {
			continue
		}
		unclassified = append(unclassified, table+" ("+file+")")
	}
	if len(unclassified) > 0 {
		t.Fatalf("schema 表未归类（必须显式归入 configBackupTables 或 configBackupRuntimeTables 并写明理由）: %s",
			strings.Join(unclassified, ", "))
	}
	// 反向完备：分类并集==schema 全集（导出+运行时两清单之外不得有第三态）。
	if got := len(exported) + len(configBackupRuntimeTables); got != len(schema) {
		t.Fatalf("分类并集=%d 表, schema=%d 表（存在重复或漏项）", got, len(schema))
	}
}
