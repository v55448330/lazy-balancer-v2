package db

// ensureNewColumns 的 ADD COLUMN 与一次性回填必须
// 原子——此前各自自动提交，ALTER 成功后回填失败/进程被杀会让「列已存在」
// 成为下次启动的跳过判据，回填永久丢失（mfa_challenges.password_version
// 会让存量挑战按 0 校验；upstream_keepalive_timeout 残留旧默认 60）。

import (
	"strings"
	"testing"
)

func TestEnsureNewColumns_alterAndBackfillAreAtomic(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE probe (id INTEGER PRIMARY KEY, value INTEGER)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO probe (id,value) VALUES (1,5)`); err != nil {
		t.Fatalf("seed probe row: %v", err)
	}

	columns := map[string]string{"probe.added": "INTEGER DEFAULT 0"}
	brokenBackfill := map[string]string{"probe.added": "UPDATE no_such_table SET x=1"}

	// When：回填失败（模拟 ALTER 后崩溃/回填语句错误）。
	if err := ensureNewColumns(columns, brokenBackfill); err == nil {
		t.Fatal("回填失败必须向上返回错误")
	}

	// Then：ALTER 随事务回滚——列不存在，下次启动可原样重试。
	var columnCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probe') WHERE name='added'`).Scan(&columnCount); err != nil {
		t.Fatalf("inspect probe columns: %v", err)
	}
	if columnCount != 0 {
		t.Fatal("回填失败后列仍存在——ADD COLUMN 未与回填同事务，回填将永久跳过")
	}

	// And：重试（有效回填）后列存在且回填生效。
	if err := ensureNewColumns(columns, map[string]string{"probe.added": "UPDATE probe SET added=7"}); err != nil {
		t.Fatalf("retry ensureNewColumns: %v", err)
	}
	var added int
	if err := database.QueryRow(`SELECT added FROM probe WHERE id=1`).Scan(&added); err != nil {
		t.Fatalf("read backfilled column: %v", err)
	}
	if added != 7 {
		t.Fatalf("backfilled value=%d, want 7", added)
	}
}

// 跨表回填依赖（mfa_challenges.password_version ← users.password_version）：
// 回填 SQL 引用另一张表同批新增的列，执行顺序必须把被引用列排在前面
// （map 随机迭代序下乱序执行在旧 SQLite 上以 no such column 启动失败；
// 当前 SQLite 经外层作用域绑定静默吞掉但语义错误）。排序键 + 跨表回填
// 第二趟的确定性顺序由纯函数 orderNewColumnKeys 承担。
func TestOrderNewColumnKeys_crossTableBackfillRunsSecondPass(t *testing.T) {
	columns := map[string]string{
		"users.password_version":          "INTEGER NOT NULL DEFAULT 0",
		"mfa_challenges.password_version": "INTEGER NOT NULL DEFAULT 0",
		"nodes.server_map_lat":            "REAL NOT NULL DEFAULT 0",
	}
	backfills := map[string]string{
		"mfa_challenges.password_version": "UPDATE mfa_challenges SET password_version=COALESCE((SELECT COALESCE(password_version,0) FROM users WHERE users.id=mfa_challenges.user_id),0)",
	}
	ordered, err := orderNewColumnKeys(columns, backfills)
	if err != nil {
		t.Fatalf("orderNewColumnKeys: %v", err)
	}
	index := map[string]int{}
	for i, key := range ordered {
		index[key] = i
	}
	if len(ordered) != 3 {
		t.Fatalf("ordered=%v, want 全部 3 键", ordered)
	}
	if index["mfa_challenges.password_version"] < index["users.password_version"] {
		t.Fatalf("ordered=%v, 跨表回填键必须排在被引用列 users.password_version 之后", ordered)
	}
	// 同趟内键序确定（字典序），重排不再依赖 map 迭代序。
	again, err := orderNewColumnKeys(columns, backfills)
	if err != nil {
		t.Fatalf("orderNewColumnKeys second call: %v", err)
	}
	for i := range ordered {
		if ordered[i] != again[i] {
			t.Fatalf("两次排序结果不同：%v vs %v", ordered, again)
		}
	}
	// 畸形登记键仍在排序期响亮失败（与执行期同口径）。
	if _, err := orderNewColumnKeys(map[string]string{"malformed": "INTEGER"}, nil); err == nil {
		t.Fatal("畸形键（缺表名段）必须返回错误")
	}
}

// 回归形状：users.password_version 已在位（更早版本补过）、mfa_challenges
// 缺列——回填必须把用户当前密码版本拷到存量挑战（不是写 0）。
func TestEnsureNewColumns_crossTableBackfillCopiesCurrentValue(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_version INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("create users: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE mfa_challenges (id INTEGER PRIMARY KEY, user_id INTEGER)`); err != nil {
		t.Fatalf("create mfa_challenges: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_version) VALUES (1,'u',7)`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO mfa_challenges (id,user_id) VALUES (1,1)`); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	columns := map[string]string{"mfa_challenges.password_version": "INTEGER NOT NULL DEFAULT 0"}
	backfills := map[string]string{
		"mfa_challenges.password_version": "UPDATE mfa_challenges SET password_version=COALESCE((SELECT COALESCE(password_version,0) FROM users WHERE users.id=mfa_challenges.user_id),0)",
	}
	if err := ensureNewColumns(columns, backfills); err != nil {
		t.Fatalf("ensureNewColumns: %v", err)
	}
	var pv int
	if err := database.QueryRow(`SELECT password_version FROM mfa_challenges WHERE id=1`).Scan(&pv); err != nil {
		t.Fatalf("read backfill: %v", err)
	}
	if pv != 7 {
		t.Fatalf("backfilled password_version=%d, want 7（存量挑战按用户当前密码版本回填）", pv)
	}
}

// newColumnBackfills 中未登记到 newColumns 的键必须启动期响亮失败：该键的
// 回填 SQL 永不执行且零错误（列没补、派生值没落，读侧按零值运行），与本函数
// 对畸形键「启动期响亮失败」的基调相反。当前三个键均已登记，属防御门。
func TestOrderNewColumnKeys_rejectsBackfillKeyWithoutColumn(t *testing.T) {
	columns := map[string]string{"users.password_version": "INTEGER NOT NULL DEFAULT 0"}
	backfills := map[string]string{
		"users.password_verison": "UPDATE users SET password_verison=0", // 拼写漂移
	}
	if _, err := orderNewColumnKeys(columns, backfills); err == nil {
		t.Fatal("未登记的 backfill 键必须返回错误（否则回填永不执行且无信号）")
	} else if !strings.Contains(err.Error(), "backfill") {
		t.Fatalf("error=%v, want 点名 backfill 登记漂移", err)
	}
	// 已登记键不受影响。
	if _, err := orderNewColumnKeys(columns, map[string]string{"users.password_version": "UPDATE users SET password_version=0"}); err != nil {
		t.Fatalf("已登记 backfill 键不得报错: %v", err)
	}
}

// 同表依赖回填只对「本次新增」的列执行：列已存在时回填视为已完成。此前第二趟
// 不区分新增/存量，无条件重跑——api_keys.api_read_only/mcp_read_only 的回填
// （=read_only）会在每次启动把用户设置的非对称只读压平（回归）。
func TestEnsureNewColumns_deferredBackfillRunsOnlyForNewlyAddedColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE probe (id INTEGER PRIMARY KEY, base INTEGER DEFAULT 0, derived INTEGER DEFAULT 0)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO probe (id,base,derived) VALUES (1,5,9)`); err != nil {
		t.Fatalf("seed probe row: %v", err)
	}
	columns := map[string]string{
		"probe.base":    "INTEGER DEFAULT 0",
		"probe.derived": "INTEGER DEFAULT 0",
	}
	backfills := map[string]string{
		"probe.base":    "UPDATE probe SET base=5",
		"probe.derived": "UPDATE probe SET derived=base",
	}

	before := startupMigrationWriteStatements.Load()
	if err := ensureNewColumns(columns, backfills); err != nil {
		t.Fatalf("ensureNewColumns: %v", err)
	}

	// Then 存量列不被回填覆盖（运行期值 9 保留），也不产生写语句。
	var derived int
	if err := database.QueryRow(`SELECT derived FROM probe WHERE id=1`).Scan(&derived); err != nil {
		t.Fatalf("read derived: %v", err)
	}
	if derived != 9 {
		t.Fatalf("derived=%d, want 9（列已存在时不得重跑一次性回填）", derived)
	}
	if got := startupMigrationWriteStatements.Load() - before; got != 0 {
		t.Fatalf("存量列回填写语句=%d, want 0", got)
	}
}

// 第二趟裸 DB.Exec 回填必须计入零写口径：否则「二次启动零写」测试看不见重跑
// 回填，（回归） 这类每启动重写用户值的回归会被静默放过（回归）。
func TestEnsureNewColumns_deferredBackfillCountsWriteStatement(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE probe (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO probe (id) VALUES (1)`); err != nil {
		t.Fatalf("seed probe row: %v", err)
	}
	columns := map[string]string{
		"probe.base":    "INTEGER DEFAULT 0",
		"probe.derived": "INTEGER DEFAULT 0",
	}
	backfills := map[string]string{
		"probe.base":    "UPDATE probe SET base=5",
		"probe.derived": "UPDATE probe SET derived=base",
	}

	before := startupMigrationWriteStatements.Load()
	if err := ensureNewColumns(columns, backfills); err != nil {
		t.Fatalf("ensureNewColumns: %v", err)
	}

	// Then 新列回填生效（derived=base=5），写语句计数 +1（可被零写门观测）。
	var derived int
	if err := database.QueryRow(`SELECT derived FROM probe WHERE id=1`).Scan(&derived); err != nil {
		t.Fatalf("read derived: %v", err)
	}
	if derived != 5 {
		t.Fatalf("derived=%d, want 5（新列回填必须执行）", derived)
	}
	if got := startupMigrationWriteStatements.Load() - before; got != 1 {
		t.Fatalf("新列回填写语句=%d, want 1（裸 Exec 必须计入零写口径）", got)
	}
}

// 端到端回归（回归）：升级后重启不得把非对称只读配置压平为 read_only。
func TestInitialize_restartPreservesAsymmetricAPIReadOnly(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,api_enabled,read_only,api_read_only,mcp_read_only)
		VALUES ('asymmetric','hash-asym','lb_sk_asym',1,1,1,1,1,0,1)`); err != nil {
		t.Fatalf("seed asymmetric api key: %v", err)
	}

	// When 进程重启（Close → Initialize，走第二趟回填路径）。
	if err := Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("reinitialize: %v", err)
	}

	// Then 非对称只读原样保留：REST 可写（api_read_only=0）、MCP 只读=1。
	var apiRO, mcpRO int
	if err := DB.QueryRow(`SELECT COALESCE(api_read_only,0), COALESCE(mcp_read_only,0) FROM api_keys WHERE name='asymmetric'`).Scan(&apiRO, &mcpRO); err != nil {
		t.Fatalf("read api key read-only axes: %v", err)
	}
	if apiRO != 0 || mcpRO != 1 {
		t.Fatalf("api_read_only=%d mcp_read_only=%d, want 0/1（重启不得把非对称只读压平为 read_only）", apiRO, mcpRO)
	}
}
