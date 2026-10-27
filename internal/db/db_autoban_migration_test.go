package db

import (
	"database/sql"
	"fmt"
	"testing"
)

// 自动封禁迁移钉：六项配置列 + 预置名单行。
// 六列不在 fresh CREATE 里——fresh 与存量库同走 newColumns 补列通道；
// 预置名单行由 runMigrations→SeedSystemIPLists 播种（schema 段不播种子，
// 见 db.go schema 注释），Initialize/runMigrations 幂等补齐。

// autobanColumnsExpected 全部六列的期望默认值（与 newColumns 登记逐字对齐）。
var autobanColumnsExpected = []struct{ column, dflt string }{
	{"autoban_enabled", "0"},
	{"autoban_threshold", "100"},
	{"autoban_window_minutes", "5"},
	{"autoban_duration", "'1h'"},
	{"autoban_scope", "'all'"},
	{"autoban_dry_run", "1"},
}

// AutobanPresetListName 预置名单行名（services 层常量的镜像锚点——迁移侧
// 独立声明避免 db→services 反向依赖；两处不一致时本测试红）。
const autobanPresetListName = "自动封禁名单"

// TestInitialize_freshSchemaCarriesAutobanColumnsAndSeed：
// 全新安装即携带六列（NOT NULL+默认值）与预置 security_ip_lists 行（system=1）。
func TestInitialize_freshSchemaCarriesAutobanColumnsAndSeed(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)

	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	for _, tc := range autobanColumnsExpected {
		var notNull int
		var dflt string
		query := fmt.Sprintf(`SELECT "notnull", COALESCE(dflt_value,'') FROM pragma_table_info('global_config') WHERE name='%s'`, tc.column)
		if err := DB.QueryRow(query).Scan(&notNull, &dflt); err != nil {
			t.Fatalf("read global_config.%s schema: %v", tc.column, err)
		}
		if notNull != 1 || dflt != tc.dflt {
			t.Fatalf("global_config.%s notnull=%d default=%q, want notnull=1 default=%q", tc.column, notNull, dflt, tc.dflt)
		}
	}

	var system, entriesSet int
	var entries string
	if err := DB.QueryRow(`SELECT COALESCE(system,0), entries <> '', COALESCE(entries,'') FROM security_ip_lists WHERE name=?`, autobanPresetListName).Scan(&system, &entriesSet, &entries); err != nil {
		t.Fatalf("preset ip list row missing: %v", err)
	}
	if system != 1 {
		t.Fatalf("preset list system=%d, want 1", system)
	}
	if entriesSet != 1 || entries != "[]" {
		t.Fatalf("preset list entries=%q (set=%d), want '[]'", entries, entriesSet)
	}
}

// TestRunMigrations_addsAutobanColumnsAndSeedToLegacyDB：存量库（无六列/无预置
// 行）经迁移补齐，存量行读回默认值；重复迁移幂等（预置行不重复）。
func TestRunMigrations_addsAutobanColumnsAndSeedToLegacyDB(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global_config: %v", err)
	}
	// RED 期列尚不存在跳过 DROP；GREEN 期已存在则还原为「存量旧库」形状
	for _, tc := range autobanColumnsExpected {
		var cnt int
		if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, tc.column).Scan(&cnt); err != nil {
			t.Fatalf("inspect global_config.%s: %v", tc.column, err)
		}
		if cnt == 1 {
			if _, err := database.Exec(`ALTER TABLE global_config DROP COLUMN ` + tc.column); err != nil {
				t.Fatalf("simulate legacy global_config.%s: %v", tc.column, err)
			}
		}
	}
	var preset int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, autobanPresetListName).Scan(&preset); err != nil {
		t.Fatalf("count preset: %v", err)
	}
	if preset > 0 {
		if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name=?`, autobanPresetListName); err != nil {
			t.Fatalf("clear preset: %v", err)
		}
	}
	// 生产升级序列=Initialize 每次启动先 createTables 再 runMigrations——
	// 预置行由 runMigrations→SeedSystemIPLists 播种（schema 段只做结构，
	// 不播种子），这里按真实顺序重放 schema 段（模拟存量旧库升级到新版后
	// 的首个启动）。
	if err := createTables(); err != nil {
		t.Fatalf("replay createTables: %v", err)
	}

	// When 迁移跑两遍（幂等）
	for range 2 {
		if err := runMigrations(); err != nil {
			t.Fatalf("run migrations: %v", err)
		}
	}

	// Then 六列补出且存量行读回默认值
	for _, tc := range autobanColumnsExpected {
		var got sql.NullString
		if err := database.QueryRow(`SELECT ` + tc.column + ` FROM global_config WHERE id=1`).Scan(&got); err != nil {
			t.Fatalf("read global_config.%s: %v", tc.column, err)
		}
		if !got.Valid {
			t.Fatalf("global_config.%s is NULL, want column default", tc.column)
		}
	}
	// 预置行恰好一条（幂等种子不得重复）
	var rows int
	var system int
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(MAX(system),0) FROM security_ip_lists WHERE name=?`, autobanPresetListName).Scan(&rows, &system); err != nil {
		t.Fatalf("read preset rows: %v", err)
	}
	if rows != 1 || system != 1 {
		t.Fatalf("preset rows=%d system=%d, want exactly 1 row with system=1", rows, system)
	}
}

// TestInitialize_normalizesAutobanPresetDescription：存量预置行携带旧描述
// （「可手动追加或解封」）时，启动迁移归一为「删除条目」口径（2026-10-15
// 用户裁定：删除即解封，说明文案去「解封」操作词）。仅命中旧文案的种子行
// ——预置行描述禁改（UpdateIPList 400 守卫），不存在用户自定义形态；
// 威胁名单描述不受影响。
func TestInitialize_normalizesAutobanPresetDescription(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)

	// 先旧版建库+种出预置行，再回写旧文案（模拟存量部署）。
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := DB.Exec(`UPDATE security_ip_lists SET description='自动封禁命中 IP（自动封禁任务维护；可手动追加或解封）' WHERE name=?`, autobanPresetListName); err != nil {
		t.Fatalf("stamp legacy description: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 重启 Initialize → 描述归一。
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize: %v", err)
	}
	var got string
	if err := DB.QueryRow(`SELECT description FROM security_ip_lists WHERE name=?`, autobanPresetListName).Scan(&got); err != nil {
		t.Fatalf("read description: %v", err)
	}
	if got != "自动封禁命中 IP（自动封禁任务维护；可手动追加或删除条目）" {
		t.Fatalf("description=%q, want 删除条目口径归一", got)
	}
}
