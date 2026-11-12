package db

import "testing"

// 口径单选→多选一次性迁移（2026-11-13 用户裁定）：旧 scope+count_human_failed
// 开关映射为四维集合，marker 幂等，旧列删除。映射语义镜像
// services.MigrateLegacyAutobanScope（db 不反向依赖 services）。

func TestLegacyAutobanScopeToSet_mapping(t *testing.T) {
	for _, tc := range []struct {
		scope      string
		countHuman bool
		want       string
	}{
		{"blocked", false, "blocked"},
		{"blocked", true, "blocked"},
		{"logged", false, "logged"},
		{"all", false, "blocked,logged"},
		{"all", true, "blocked,logged,challenge_failed"},
		{"", false, ""},           // 空串原样返回，交启动回填收敛默认
		{"bogus", false, "bogus"}, // 非法值原样返回，不伪装成合法默认
		// 已是新集合形态原样保留
		{"blocked,logged", false, "blocked,logged"},
		{"challenge_issued,challenge_failed", true, "challenge_issued,challenge_failed"},
		{"blocked,logged,challenge_issued,challenge_failed", false, "blocked,logged,challenge_issued,challenge_failed"},
	} {
		if got := legacyAutobanScopeToSet(tc.scope, tc.countHuman); got != tc.want {
			t.Errorf("legacyAutobanScopeToSet(%q,%v)=%q, want %q", tc.scope, tc.countHuman, got, tc.want)
		}
	}
}

// 端到端：存量库（旧单值 scope + 开关列）经 Initialize 迁移为集合，旧列删除，
// marker 置位；二次启动幂等不触碰运行期写值。
func TestInitialize_migratesAutobanScopeMultiselect(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	// 模拟存量旧形态：单值 all + 开关开 + marker 复位 + 旧列复活。
	if _, err := DB.Exec(`ALTER TABLE global_config ADD COLUMN autoban_count_human_failed BOOLEAN NOT NULL DEFAULT FALSE`); err != nil {
		t.Fatalf("re-add legacy column: %v", err)
	}
	if _, err := DB.Exec(`UPDATE global_config SET autoban_scope='all', autoban_count_human_failed=1, autoban_scope_multiselect_v1=0 WHERE id=1`); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	if err := migrateAutobanScopeMultiselect(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var scope string
	var marker int
	if err := DB.QueryRow(`SELECT autoban_scope, autoban_scope_multiselect_v1 FROM global_config WHERE id=1`).Scan(&scope, &marker); err != nil {
		t.Fatal(err)
	}
	if scope != "blocked,logged,challenge_failed" || marker != 1 {
		t.Fatalf("迁移后 scope=%q marker=%d, want blocked,logged,challenge_failed / 1", scope, marker)
	}
	var colCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='autoban_count_human_failed'`).Scan(&colCount); err != nil {
		t.Fatal(err)
	}
	if colCount != 0 {
		t.Fatal("退役列 autoban_count_human_failed 必须被删除")
	}
	// 幂等：运行期改值后二次迁移不触碰。
	if _, err := DB.Exec(`UPDATE global_config SET autoban_scope='logged' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := migrateAutobanScopeMultiselect(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	if err := DB.QueryRow(`SELECT autoban_scope FROM global_config WHERE id=1`).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != "logged" {
		t.Fatalf("二次迁移不得触碰运行期写值，scope=%q", scope)
	}
}
