package db

// cookie 签名密钥（global_config.human_secret）启动播种钉测：
//   - 新装/升级库经 Initialize 迁移期播种非空密钥（渲染事务不再惰性写入——
//     渲染链在写事务内，池外连接自写撞 WAL 单写者锁 → busy_timeout 硬等）；
//   - 幂等：非空密钥（含集群 apply/备份导入写入的值）跨重启保留；
//   - 写失败（真实触发器 RAISE）必须阻断启动，不得静默留下空密钥。

import (
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func readHumanSecretForTest(t *testing.T, database *sql.DB) string {
	t.Helper()
	var secret string
	if err := database.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&secret); err != nil {
		t.Fatalf("read human_secret: %v", err)
	}
	return secret
}

func assertSeededHumanSecretShape(t *testing.T, secret string) {
	t.Helper()
	raw, err := hex.DecodeString(secret)
	if err != nil {
		t.Fatalf("human_secret=%q 不是合法 hex: %v", secret, err)
	}
	if len(raw) != 32 {
		t.Fatalf("human_secret 解码后 %d 字节, want 32", len(raw))
	}
}

// Given 全新数据目录。When Initialize。Then 迁移期即播种 32 字节 hex 密钥——
// 首次人机渲染无需在写事务内自写 global_config。
func TestInitialize_seedsHumanSecretOnFreshDatabase(t *testing.T) {
	preserveDatabaseHandles(t)
	dir := t.TempDir()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	secret := readHumanSecretForTest(t, DB)
	if secret == "" {
		t.Fatal("human_secret 为空：新库启动必须播种 cookie 签名密钥（渲染事务内只读）")
	}
	assertSeededHumanSecretShape(t, secret)
}

// Given 空密钥库（升级形态）+ 已存在的非空密钥库。When 重启。
// Then 空值被补齐；非空值（集群/导入写入）绝不覆盖。
func TestInitialize_humanSecretSeedIsIdempotentAndPreservesExisting(t *testing.T) {
	preserveDatabaseHandles(t)
	dir := t.TempDir()
	reopenDatabaseForTest(t, dir)
	first := readHumanSecretForTest(t, DB)
	if first == "" {
		t.Fatal("首启未播种 human_secret")
	}

	// 升级形态：带外清空密钥（历史库无播种路径时的空值形态）。
	if _, err := DB.Exec(`UPDATE global_config SET human_secret='' WHERE id=1`); err != nil {
		t.Fatalf("clear human_secret: %v", err)
	}
	reopenDatabaseForTest(t, dir)
	refilled := readHumanSecretForTest(t, DB)
	if refilled == "" {
		t.Fatal("重启未回填空 human_secret")
	}
	assertSeededHumanSecretShape(t, refilled)

	// 已存在的非空密钥（主从同步/备份导入携带）跨重启原样保留。
	const carried = "carried-secret-value"
	if _, err := DB.Exec(`UPDATE global_config SET human_secret=? WHERE id=1`, carried); err != nil {
		t.Fatalf("seed carried human_secret: %v", err)
	}
	reopenDatabaseForTest(t, dir)
	if got := readHumanSecretForTest(t, DB); got != carried {
		t.Fatalf("human_secret=%q, want %q（非空密钥不得被播种覆盖）", got, carried)
	}
}

// Given 真实写失败注入（BEFORE UPDATE 触发器 RAISE(ABORT) 拦截密钥写入）。
// When Initialize。Then 启动响亮失败——空密钥静默放行会让首次人机渲染退化。
func TestInitialize_humanSecretSeedWriteFailureBlocksStartup(t *testing.T) {
	preserveDatabaseHandles(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "lazy-balancer.db")

	// 先建出收敛 schema（含 human_secret 列）并清空密钥，再安装失败触发器
	//（模拟升级库带病重启）。
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	DB = legacy
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')`); err != nil {
		t.Fatalf("seed config singleton: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations for converged schema: %v", err)
	}
	if _, err := legacy.Exec(`UPDATE global_config SET human_secret='' WHERE id=1`); err != nil {
		t.Fatalf("clear human_secret: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TRIGGER block_human_secret_seed BEFORE UPDATE OF human_secret ON global_config
		BEGIN SELECT RAISE(ABORT, 'injected human_secret write failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	DB = nil

	if err := Initialize(dir); err == nil {
		t.Fatal("密钥播种写失败必须阻断启动（fail-loud），不得静默放行")
	}
}
