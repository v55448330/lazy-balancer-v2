package middleware

// 装配期触发器就绪的回退门钉测：重装（全量 DROP/CREATE，BEGIN IMMEDIATE）
// 撞上后台写事务时，库内触发器已齐备 → 必须按「已就绪」继续，不得把一次
// 瞬时 SQLITE_BUSY 变成进程内永久 500（分类写与主端登录 fail-closed 到重启）。
// 触发器确实不可判定（库不可读）时仍须 fail-closed。

import (
	"database/sql"
	"testing"
)

// mainDBFilePath 取主库文件路径（PRAGMA database_list 的 main 行）。
func mainDBFilePath(t *testing.T, database *sql.DB) string {
	t.Helper()
	rows, err := database.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatalf("pragma database_list: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan pragma database_list: %v", err)
		}
		if name == "main" && file != "" {
			return file
		}
	}
	t.Fatalf("未取到主库文件路径")
	return ""
}

func TestEnsureClusterVersionTriggers_transientBusyStaysReady(t *testing.T) {
	// Given：库内触发器已由启动门安装完毕
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatalf("install triggers: %v", err)
	}
	present, err := clusterVersionTriggersPresent(database)
	if err != nil || !present {
		t.Fatalf("夹具前提不成立：触发器清单探测=%v/%v", present, err)
	}
	// 装配期重装走独立短超时句柄（模拟就绪门成功后、装配期撞上后台写事务）。
	path := mainDBFilePath(t, database)
	assemblyHandle, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(50)")
	if err != nil {
		t.Fatalf("open assembly handle: %v", err)
	}
	t.Cleanup(func() { _ = assemblyHandle.Close() })

	// 主句柄持有写锁（等价后台写者：CRS 安装写库/批量导入前奏）。
	lockTx, err := database.Begin()
	if err != nil {
		t.Fatalf("begin write tx: %v", err)
	}
	if _, err := lockTx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0) WHERE id=1`); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}
	defer lockTx.Rollback()

	// 夹具前提：此刻重装必然失败（否则下方的回退断言无区分力）。
	if err := InstallClusterVersionTriggers(assemblyHandle); err == nil {
		t.Fatalf("夹具前提不成立：持有写锁时重装应失败")
	}

	// When：装配期就绪判定
	// Then：触发器齐备 → 按已就绪继续（不再 fail-closed 到永久 500）
	if err := ensureClusterVersionTriggers(assemblyHandle); err != nil {
		t.Fatalf("瞬时写锁忙不得判为触发器不可用: %v", err)
	}
}

func TestEnsureClusterVersionTriggers_missingTriggersStaysFatal(t *testing.T) {
	// Given：库内触发器缺失（未安装）且库句柄不可用（无法补齐）
	database := newClusterVersionTestDB(t)
	if present, err := clusterVersionTriggersPresent(database); err != nil || present {
		t.Fatalf("夹具前提不成立：新库不应已有触发器（present=%v err=%v）", present, err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	// When
	err := ensureClusterVersionTriggers(database)

	// Then：不可判定 → 必须上抛（HTTP 侧 fail-closed）
	if err == nil {
		t.Fatalf("触发器缺失/不可判定时不得按已就绪继续")
	}
}

func TestEnsureClusterVersionTriggers_installsWhenMissing(t *testing.T) {
	// 测试/嵌入形态（不跑 cmd/server 就绪门）必须自足安装。
	database := newClusterVersionTestDB(t)
	if err := ensureClusterVersionTriggers(database); err != nil {
		t.Fatalf("ensure triggers: %v", err)
	}
	present, err := clusterVersionTriggersPresent(database)
	if err != nil || !present {
		t.Fatalf("安装后探测=%v/%v，want true", present, err)
	}
	// 期望触发器集合与安装器同源：数量=同步表×3 + global_config 1。
	if want := len(clusterSyncedTables)*3 + 1; len(clusterVersionTriggerStatements()) != want {
		t.Fatalf("期望触发器数=%d，want %d", len(clusterVersionTriggerStatements()), want)
	}
}
