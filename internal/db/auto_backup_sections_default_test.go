package db

import (
	"os"
	"strings"
	"testing"
)

// 自动备份分类范围的默认值必须三处同源（fresh DDL / 迁移补列 / 集群快照装载）：
// 三分类与四分类并存会让带外 NULL 行下发三分类，从端升主后自动备份静默缺
// cluster（节点拓扑）节。值钉测只证明当前数字相等，覆盖不到「是否引用常量」，
// 故此处对源码与真实 DDL 形状同时断言。
func TestAutoBackupSectionsDefault_isSingleSource(t *testing.T) {
	source, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	text := string(source)
	// 只统计代码行：注释里提到常量名不构成第二套默认值。
	var code strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	codeText := code.String()
	literal := `["users","rules","security","cluster"]`
	if got := strings.Count(codeText, literal); got != 1 {
		t.Fatalf("分类默认字面量出现 %d 次, want 1（仅常量定义；其余处须引用 DefaultAutoBackupSections）", got)
	}
	// 常量定义 + fresh DDL + newColumns 补列 + 解析 helper = 4 处引用（迁移经
	// helper 按值复用单源）。迁移此前手抄四分类字面量：改常量后只升级存量
	// 用户的默认范围，新库/带外 NULL 行仍是旧口径。
	if got := strings.Count(codeText, "DefaultAutoBackupSections"); got != 4 {
		t.Fatalf("DefaultAutoBackupSections 代码引用次数=%d, want 4（常量定义 + fresh DDL + 补列 + 解析 helper）", got)
	}

	// 行为面：fresh 表的列默认值必须等于常量（串接错误会在建表期静默落空）。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var gotDefault string
	if err := database.QueryRow(`SELECT COALESCE(dflt_value,'') FROM pragma_table_info('global_config') WHERE name='auto_backup_sections'`).Scan(&gotDefault); err != nil {
		t.Fatalf("read global_config.auto_backup_sections default: %v", err)
	}
	if want := "'" + DefaultAutoBackupSections + "'"; gotDefault != want {
		t.Fatalf("fresh DDL default=%q, want %q", gotDefault, want)
	}
}
