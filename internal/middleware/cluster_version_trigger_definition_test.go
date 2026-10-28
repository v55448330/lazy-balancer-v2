package middleware

// 就绪探测必须比对触发器**定义**，而不只是名字：同名但 WHEN/OF 子句陈旧
// （库由旧版本安装、升级后新语义未生效）的触发器若被判为就绪，重装撞写锁的
// 回退路径会据此跳过 fail-closed，同步正确性问题被静默保留。
// 生产启动门无条件重装（失败即拒绝启动），故本探测只覆盖「回退判据」这一窄窗口。

import (
	"database/sql"
	"strings"
	"testing"
)

const divergentTriggerName = "cluster_version_security_crs_version_update"

// replaceTriggerWithDivergentDefinition 用同名、错误语义的定义替换一条触发器：
// WHEN 恒真且与集群版本无关，bump 语义完全丢失。
func replaceTriggerWithDivergentDefinition(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec("DROP TRIGGER IF EXISTS " + divergentTriggerName); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER ` + divergentTriggerName + `
		AFTER UPDATE ON security_crs_version
		WHEN 0
		BEGIN
			SELECT 1;
		END`); err != nil {
		t.Fatalf("create divergent trigger: %v", err)
	}
}

func TestClusterVersionTriggersPresent_installedDefinitionsAreReady(t *testing.T) {
	// Given：启动门装好全部触发器
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}

	// When / Then：定义与安装器一致 → 就绪（空白/大小写归一不得造成假否定）
	present, err := clusterVersionTriggersPresent(database)
	if err != nil || !present {
		t.Fatalf("探测=%v/%v, want true（已安装的正确定义必须判就绪）", present, err)
	}
}

func TestClusterVersionTriggersPresent_sameNameDivergentDefinitionIsNotReady(t *testing.T) {
	// Given：全部触发器齐备，但其中一条被换成同名不同定义
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	replaceTriggerWithDivergentDefinition(t, database)

	// When
	present, err := clusterVersionTriggersPresent(database)

	// Then：名字齐备不代表定义齐备
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if present {
		t.Fatal("同名陈旧定义被判为就绪——重装失败时回退路径会跳过 fail-closed")
	}
}

func TestEnsureClusterVersionTriggers_divergentDefinitionIsNotTreatedAsReady(t *testing.T) {
	// Given：触发器定义陈旧，且此刻重装必然因写锁失败
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	replaceTriggerWithDivergentDefinition(t, database)

	path := mainDBFilePath(t, database)
	assemblyHandle, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(50)")
	if err != nil {
		t.Fatalf("open assembly handle: %v", err)
	}
	t.Cleanup(func() { _ = assemblyHandle.Close() })
	lockTx, err := database.Begin()
	if err != nil {
		t.Fatalf("begin write tx: %v", err)
	}
	if _, err := lockTx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0) WHERE id=1`); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}
	defer lockTx.Rollback()
	if err := InstallClusterVersionTriggers(assemblyHandle); err == nil {
		t.Fatalf("夹具前提不成立：持有写锁时重装应失败")
	}

	// When
	err = ensureClusterVersionTriggers(assemblyHandle)

	// Then：定义陈旧 → 不得按「已就绪」放行（必须上抛安装错误，HTTP 侧 fail-closed）
	if err == nil {
		t.Fatal("定义陈旧的触发器被按已就绪继续——bump 语义实际缺失")
	}
}

func TestEnsureClusterVersionTriggers_repairsDivergentDefinitionWhenUnblocked(t *testing.T) {
	// Given：定义陈旧，但本次重装不受阻
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	replaceTriggerWithDivergentDefinition(t, database)

	// When：装配期就绪流程（先重装）
	if err := ensureClusterVersionTriggers(database); err != nil {
		t.Fatalf("ensure triggers: %v", err)
	}

	// Then：定义已被修复回安装器版本，且 bump 语义恢复
	present, err := clusterVersionTriggersPresent(database)
	if err != nil || !present {
		t.Fatalf("修复后探测=%v/%v, want true", present, err)
	}
	var definition string
	if err := database.QueryRow(`SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='trigger' AND name=?`, divergentTriggerName).Scan(&definition); err != nil {
		t.Fatalf("read repaired definition: %v", err)
	}
	if !strings.Contains(normalizeTriggerDefinition(definition), "cluster_version=coalesce(cluster_version,0)+1") {
		t.Fatalf("修复后的定义未恢复 bump 语义: %q", definition)
	}
	// 语义面同样恢复：写该表业务列必须重新 bump 版本（旧定义 WHEN 0 永不 bump）。
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version) VALUES (1, '4.28.0')`); err != nil {
		t.Fatalf("seed crs version: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=1, cluster_version=0 WHERE id=1`); err != nil {
		t.Fatalf("reset version: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_crs_version SET version='4.29.0' WHERE id=1`); err != nil {
		t.Fatalf("update crs version: %v", err)
	}
	if got := clusterVersion(t, database); got != 1 {
		t.Fatalf("修复后写同步列 cluster_version=%d, want 1（触发器未恢复 bump 语义）", got)
	}
}
