package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func seedSetupAdminFixture(t *testing.T, statements string) *sql.DB {
	t.Helper()
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if statements != "" {
		if _, err := database.Exec(statements); err != nil {
			t.Fatalf("seed users: %v", err)
		}
	}
	return database
}

func setupAdminFlags(t *testing.T, database *sql.DB) map[int]int {
	t.Helper()
	rows, err := database.Query(`SELECT id, COALESCE(is_setup_admin,0) FROM users ORDER BY id`)
	if err != nil {
		t.Fatalf("read flags: %v", err)
	}
	defer rows.Close()
	flags := map[int]int{}
	for rows.Next() {
		var id, flag int
		if err := rows.Scan(&id, &flag); err != nil {
			t.Fatalf("scan flag: %v", err)
		}
		flags[id] = flag
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate flags: %v", err)
	}
	return flags
}

func TestEnsureSetupAdminFlag_marksLowestEnabledAdmin(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'plain-user','h','user',1),
		(3,'admin-disabled','h','admin',0),
		(7,'admin-enabled','h','admin',1),
		(9,'admin-later','h','admin',1)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	flags := setupAdminFlags(t, database)
	if flags[7] != 1 {
		t.Fatalf("flags=%v, want 最低 id 的启用管理员(7) 被标记", flags)
	}
	for _, id := range []int{1, 3, 9} {
		if flags[id] != 0 {
			t.Fatalf("flags=%v, want id=%d 未标记", flags, id)
		}
	}
	if ok, err := IsSetupAdmin(context.Background(), database, 7); err != nil || !ok {
		t.Fatalf("IsSetupAdmin(7)=(%v,%v), want true", ok, err)
	}
	if ok, err := IsSetupAdmin(context.Background(), database, 9); err != nil || ok {
		t.Fatalf("IsSetupAdmin(9)=(%v,%v), want false", ok, err)
	}

	// 幂等：稳态再跑一次不改标记行。
	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag (idempotent): %v", err)
	}
	if flags := setupAdminFlags(t, database); flags[7] != 1 {
		t.Fatalf("flags=%v, want 标记保持 7", flags)
	}
}

func TestEnsureSetupAdminFlag_movesStaleMarker(t *testing.T) {
	// 标记落在被禁用的管理员行（带外改库/手工编辑备份的坏形）：必须先清除，
	// 再落到当前最低 id 的启用管理员，避免保护落到不可登录的账号。
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(2,'stale-disabled-admin','h','admin',0,1),
		(4,'enabled-admin','h','admin',1,0)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	flags := setupAdminFlags(t, database)
	if flags[2] != 0 || flags[4] != 1 {
		t.Fatalf("flags=%v, want 陈旧标记清除并落到 4", flags)
	}
}

func TestEnsureSetupAdminFlag_noEnabledAdminIsNoop(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'only-user','h','user',1),
		(2,'disabled-admin','h','admin',0)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	for id, flag := range setupAdminFlags(t, database) {
		if flag != 0 {
			t.Fatalf("id=%d flag=%d, want 无启用管理员时零标记", id, flag)
		}
	}
}

// 多名启用管理员同时带标记（导入带外改过的备份/集群快照逐行写列的形态）必须
// 收敛为单条；否则补标分支（要求「没有任何启用管理员带标记」）不命中，标记永久
// 滞留——被标记的账号在 handlers 里都判为「初始管理员不可删除/禁用/降级」。
func TestEnsureSetupAdminFlag_collapsesDuplicateMarkers(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(3,'admin-enabled','h','admin',1,0),
		(7,'admin-flagged-a','h','admin',1,1),
		(9,'admin-flagged-b','h','admin',1,1)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	flags := setupAdminFlags(t, database)
	if flags[3] != 1 || flags[7] != 0 || flags[9] != 0 {
		t.Fatalf("flags=%v, want 仅最低 id 的启用管理员(3) 带标记", flags)
	}

	// 最低 id 已带标记、更高 id 也带标记：只清多余，不动最低 id。
	second := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(4,'admin-flagged-low','h','admin',1,1),
		(8,'admin-flagged-high','h','admin',1,1)`)
	if err := EnsureSetupAdminFlag(context.Background(), second); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	if flags := setupAdminFlags(t, second); flags[4] != 1 || flags[8] != 0 {
		t.Fatalf("flags=%v, want 4 保持标记且 8 清零", flags)
	}
}

// recordingSetupAdminExecer 统计「实际改动了行的语句数」——稳态（恰一个启用
// 管理员带标记）归一的语义是零行改写，重启不得反复重写标记列。
type recordingSetupAdminExecer struct {
	*sql.DB
	changedRows int
}

func (r *recordingSetupAdminExecer) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := r.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		r.changedRows++
	}
	return result, nil
}

func TestEnsureSetupAdminFlag_steadyStateWritesNoRows(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(2,'plain-user','h','user',1,0),
		(5,'admin-entry','h','admin',1,1),
		(6,'admin-other','h','admin',1,0)`)

	recorder := &recordingSetupAdminExecer{DB: database}
	if err := EnsureSetupAdminFlag(context.Background(), recorder); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	if recorder.changedRows != 0 {
		t.Fatalf("changed rows=%d, want 0（稳态零行改写）", recorder.changedRows)
	}
	if flags := setupAdminFlags(t, database); flags[5] != 1 || flags[2] != 0 || flags[6] != 0 {
		t.Fatalf("flags=%v, want 标记保持 5", flags)
	}
}

// 单标记不迁移：集群快照/备份载荷显式把标记落在非最低 id 的管理员上（id=4，
// 最低启用管理员是 id=1）时，归一无权改写——载荷即主端事实，清零后再补标到
// 最低 id 等于篡改还原结果。
func TestEnsureSetupAdminFlag_keepsSingleExplicitMarkerOffLowestID(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(1,'plain-admin','h','admin',1,0),
		(4,'setup-admin','h','admin',1,1)`)

	recorder := &recordingSetupAdminExecer{DB: database}
	if err := EnsureSetupAdminFlag(context.Background(), recorder); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	if flags := setupAdminFlags(t, database); flags[4] != 1 || flags[1] != 0 {
		t.Fatalf("flags=%v, want 显式标记保持 4（不得迁移到最低 id 1）", flags)
	}
	if recorder.changedRows != 0 {
		t.Fatalf("changed rows=%d, want 0（单标记稳态零行改写）", recorder.changedRows)
	}
}

func TestIsSetupAdmin_fallsBackWhenNoMarker(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'first-admin','h','admin',1),
		(2,'second-admin','h','admin',1)`)

	// 标记缺失（升级窗口/直连旧库）：回落 setup 首个用户 id。
	if ok, err := IsSetupAdmin(context.Background(), database, SetupAdminFallbackUserID); err != nil || !ok {
		t.Fatalf("IsSetupAdmin(fallback)=(%v,%v), want true", ok, err)
	}
	if ok, err := IsSetupAdmin(context.Background(), database, 2); err != nil || ok {
		t.Fatalf("IsSetupAdmin(2)=(%v,%v), want false", ok, err)
	}
	// 不存在的用户：未标记且无标记行 → 仍按 id 缺省判定（不得误保护）。
	if ok, err := IsSetupAdmin(context.Background(), database, 99); err != nil || ok {
		t.Fatalf("IsSetupAdmin(99)=(%v,%v), want false", ok, err)
	}
}

func TestInitialize_backfillsSetupAdminFlagOnLegacyDatabase(t *testing.T) {
	preserveDatabaseHandles(t)

	// Given 旧库：users 无 is_setup_admin 列，已有启用管理员。
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		display_name VARCHAR(100),
		is_enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	)`); err != nil {
		t.Fatalf("create legacy users: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'legacy-user','h','user',1), (5,'legacy-admin','h','admin',1)`); err != nil {
		t.Fatalf("seed legacy users: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// When 真实升级路径（补列 + 回填 + 启动归一）。
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then 最低 id 的启用管理员成为受保护入口。
	flags := setupAdminFlags(t, DB)
	if flags[5] != 1 || flags[1] != 0 {
		t.Fatalf("flags=%v, want id=5 标记且 id=1 未标记", flags)
	}
}

// 启动探测门必须覆盖全部三种归一形态（S1 陈旧标记 / S2 多标记并存 / S3 无标记
// 补标），且收敛库二次启动零写事务——探测 SQL 与三条 UPDATE 现在共用同一组
// 谓词常量（setupAdminPredicateParity 启动期自检看守），任一侧改判据都会让
// 本表驱动测试红。
func TestEnsureSetupAdminFlagAtStartup_probeCoversEveryNormalization(t *testing.T) {
	cases := []struct {
		name string
		seed string
		want map[int]int
	}{
		{
			name: "S1 陈旧标记（账号已降级）",
			seed: `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
				(1,'demoted','h','user',1,1),
				(7,'admin','h','admin',1,0)`,
			want: map[int]int{1: 0, 7: 1},
		},
		{
			name: "S2 多标记并存",
			seed: `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
				(3,'admin-low','h','admin',1,1),
				(9,'admin-high','h','admin',1,1),
				(11,'user','h','user',1,0)`,
			want: map[int]int{3: 1, 9: 0, 11: 0},
		},
		{
			name: "S3 无标记补标",
			seed: `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
				(5,'admin-a','h','admin',1,0),
				(8,'admin-b','h','admin',1,0)`,
			want: map[int]int{5: 1, 8: 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := seedSetupAdminFixture(t, tc.seed)
			if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')`); err != nil {
				t.Fatalf("seed global config: %v", err)
			}

			writeBase := startupMigrationWriteTx.Load()
			if err := runMigrations(); err != nil {
				t.Fatalf("first migrations: %v", err)
			}
			if got := startupMigrationWriteTx.Load() - writeBase; got < 1 {
				t.Fatalf("探测命中的启动写事务=%d, want >=1（归一必须真实执行，否则标记滞留）", got)
			}
			flags := setupAdminFlags(t, database)
			for id, want := range tc.want {
				if flags[id] != want {
					t.Fatalf("首轮 flags=%v, id=%d want %d", flags, id, want)
				}
			}

			// 收敛库二次启动：探测必须 false（零写事务）——探测漏掉的形态会静默
			// 跳过归一且没有任何错误信号。
			writeBase = startupMigrationWriteTx.Load()
			if err := runMigrations(); err != nil {
				t.Fatalf("second migrations: %v", err)
			}
			if got := startupMigrationWriteTx.Load() - writeBase; got != 0 {
				t.Fatalf("收敛库二次启动写事务=%d, want 0（探测门未覆盖稳态）", got)
			}
			flags = setupAdminFlags(t, database)
			for id, want := range tc.want {
				if flags[id] != want {
					t.Fatalf("二次启动后标记漂移 flags=%v, id=%d want %d", flags, id, want)
				}
			}
		})
	}
}
