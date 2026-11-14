package services

// cookie 签名密钥（global_config.human_secret）渲染链契约钉测：
//   - 渲染事务内只读：写事务持锁期间取密钥不得自写 global_config
//     （WAL 单写者 + busy_timeout 硬等 → 首次人机渲染卡死/密钥仅存内存）；
//   - 惰性兼容路径写失败必须 fail-visible 留痕（不再静默吞错）；
//   - 导入面缓存失效入口 ResetHumanSecretCache：改写库值后下次渲染读新值。

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func resetHumanSecretCacheForTest(t *testing.T) {
	t.Helper()
	humanSecretMu.Lock()
	humanSecretCache = ""
	humanSecretMu.Unlock()
	t.Cleanup(func() {
		humanSecretMu.Lock()
		humanSecretCache = ""
		humanSecretMu.Unlock()
	})
}

// Given 新库（启动播种密钥）+ 一条未提交写事务持写锁。When 渲染链取密钥。
// Then 立即返回库内密钥——不得在渲染事务外自写 global_config（写锁冲突硬等）。
func TestGetHumanSecret_readsSeededSecretWhileWriteTxHoldsLock(t *testing.T) {
	database := setupIsolatedDB(t)
	resetHumanSecretCacheForTest(t)

	var seeded string
	if err := database.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatalf("read seeded human_secret: %v", err)
	}
	if seeded == "" {
		t.Fatal("新库启动必须播种 human_secret（渲染事务内只读的前提）")
	}

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin write tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 未提交写：_txlock=immediate 已持 WAL 写锁，模拟配置保存事务渲染窗口。
	if _, err := tx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
		t.Fatalf("hold write lock in tx: %v", err)
	}

	done := make(chan string, 1)
	go func() { done <- getHumanSecret() }()
	select {
	case got := <-done:
		if got != seeded {
			t.Fatalf("getHumanSecret()=%q, want 库内播种值 %q", got, seeded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("写事务持锁期间取密钥阻塞：渲染链在事务内自写 human_secret 撞 WAL 单写者锁")
	}
}

// Given 空密钥库 + 真实写失败注入（BEFORE UPDATE 触发器 RAISE(ABORT)）。
// When 惰性兼容路径取密钥。Then 返回进程内密钥保当次渲染可用，且 warn 留痕
// 点名落库失败（重启后 cookie 全失效的风险必须可观测）。
func TestGetHumanSecret_lazyWriteFailureWarns(t *testing.T) {
	database := setupIsolatedDB(t)
	resetHumanSecretCacheForTest(t)
	if _, err := database.Exec(`UPDATE global_config SET human_secret='' WHERE id=1`); err != nil {
		t.Fatalf("clear human_secret: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER block_human_secret_write BEFORE UPDATE OF human_secret ON global_config
		BEGIN SELECT RAISE(ABORT, 'injected human_secret write failure'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	logs := captureLogf(t)

	got := getHumanSecret()
	if got == "" {
		t.Fatal("写失败时仍须返回进程内密钥（当次渲染可用）")
	}
	raw, err := hex.DecodeString(got)
	if err != nil || len(raw) != 32 {
		t.Fatalf("getHumanSecret()=%q, want 32 字节 hex", got)
	}
	if !strings.Contains(logs.String(), "human_secret") {
		t.Fatalf("写失败必须 warn 留痕（fail-visible），logs=%q", logs.String())
	}

	// 终态断言：写确实未落库——重启（缓存清空）后不得读到该进程内密钥。
	var persisted string
	if err := database.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&persisted); err != nil {
		t.Fatalf("read persisted human_secret: %v", err)
	}
	if persisted != "" {
		t.Fatalf("触发器拦截后 human_secret=%q, want 空（写失败不得假装落库）", persisted)
	}
}

// Given 运行中缓存旧密钥（渲染已消费）。When 导入面改写库值并调用
// ResetHumanSecretCache。Then 下次渲染读到新密钥（不再分叉至重启）。
func TestResetHumanSecretCache_importRewriteTakesEffectOnNextRead(t *testing.T) {
	database := setupIsolatedDB(t)
	resetHumanSecretCacheForTest(t)
	first := getHumanSecret()
	if first == "" {
		t.Fatal("首次取密钥为空")
	}

	const imported = "imported-secret-value"
	if _, err := database.Exec(`UPDATE global_config SET human_secret=? WHERE id=1`, imported); err != nil {
		t.Fatalf("rewrite human_secret: %v", err)
	}
	ResetHumanSecretCache()
	if got := getHumanSecret(); got != imported {
		t.Fatalf("缓存失效后 getHumanSecret()=%q, want 导入新值 %q", got, imported)
	}
}

// Given 空密钥库 + 写事务持锁（渲染窗口）。When 走完整渲染链
// buildHumanHandler。Then 立即产出携带播种密钥的 lb_human——
// 修复前惰性自写撞写锁，渲染硬等 busy_timeout。
func TestBuildHumanHandler_rendersInsideWriteTxWithoutSecretWrite(t *testing.T) {
	database := setupIsolatedDB(t)
	resetHumanSecretCacheForTest(t)

	var seeded string
	if err := database.QueryRow(`SELECT COALESCE(human_secret,'') FROM global_config WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatalf("read seeded human_secret: %v", err)
	}
	if seeded == "" {
		t.Fatal("新库启动必须播种 human_secret")
	}

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin write tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
		t.Fatalf("hold write lock in tx: %v", err)
	}

	policies := []*models.SecurityPolicy{{
		ID: 1, Name: "human", Mode: "off",
		HumanVerifyMode: "force", HumanVerifyType: "slider", HumanVerifyTTL: 30,
	}}
	done := make(chan map[string]interface{}, 1)
	go func() { done <- buildHumanHandler("lb_human_tx", policies) }()
	select {
	case cfg := <-done:
		if cfg == nil {
			t.Fatal("写事务持锁期间 lb_human 渲染缺席（密钥读取被写锁阻塞后吞错）")
		}
		if cfg["secret"] != seeded {
			t.Fatalf("lb_human.secret=%v, want 库内播种值 %q", cfg["secret"], seeded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("写事务持锁期间 lb_human 渲染阻塞：密钥惰性自写撞 WAL 单写者锁")
	}
}
