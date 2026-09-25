package services

// 第 55 轮 P3 修复 RED（用户裁定按建议处理）：
// ①markSourceSuccess 无 rawHash 变参时不得覆写 raw_hash（快路径自我失效根因）；
// ②空名单源的升级窗口补跑附条件：连续失败>0 时按排程门控（永久失败源不再
//   每分钟整任务重跑）；连续失败=0（升级窗口/还原清空形态）保持立即补跑。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestMarkSourceSuccess_preservesRawHashWhenAbsent(t *testing.T) {
	newClusterTestService(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET raw_hash='abc' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// When：快路径形态（无 rawHash 变参）
	markSourceSuccess(id, 10, "2026.09.25")

	// Then：raw_hash 保留（注释「空=不写」的应有语义）
	var raw string
	if err := db.DB.QueryRow(`SELECT raw_hash FROM security_threat_sources WHERE name='ustc'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "abc" {
		t.Fatalf("raw_hash=%q, want 保留 abc（快路径自我失效根因）", raw)
	}

	// And：慢路径形态（带 rawHash）正常写入
	markSourceSuccess(id, 11, "2026.09.25", "def")
	if err := db.DB.QueryRow(`SELECT raw_hash FROM security_threat_sources WHERE name='ustc'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "def" {
		t.Fatalf("raw_hash=%q, want def", raw)
	}
}

func TestThreatDueSources_persistentlyFailedEmptyListGatedBySchedule(t *testing.T) {
	newClusterTestService(t)
	future := time.Now().UTC().Add(24 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=?, consecutive_failures=3`, future); err != nil {
		t.Fatal(err)
	}

	// Given：名单全空 + 连续失败 3 次 + next_update 在未来 → 按排程门控（不再每分钟重跑）
	due, err := threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Fatalf("连续失败源应按排程门控, got %d 到期（每分钟重跑缺陷未闭合）", len(due))
	}

	// When：失败清零（升级窗口/还原清空/用户干预形态）→ 保持立即补跑
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET consecutive_failures=0`); err != nil {
		t.Fatal(err)
	}
	due, err = threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 3 {
		t.Fatalf("未失败空名单应保持立即补跑, got %d", len(due))
	}
}
