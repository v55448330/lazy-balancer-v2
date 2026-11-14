package middleware

// 自动封禁累犯表与第七列的集群版本触发器钉测——
//   - autoban_recidivism 随 security 节同步：INSERT/UPDATE/DELETE 必须 bump
//     cluster_version（引擎周期写无中间件兜底，触发器是唯一版本传播通道）；
//   - 从端写不 bump（WHEN is_master 守卫——快照 apply 形态）；
//   - autoban_escalation 独立 UPDATE 必须 bump（补列遗漏 OF 清单的回归钉）。

import "testing"

// Given 触发器已装配、主节点形态。
// When 累犯表 INSERT/UPDATE/DELETE。
// Then 每次写 bump cluster_version；从端写不 bump。
func TestClusterVersionTrigger_recidivismWritesBump(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	for i, stmt := range []string{
		`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('45.33.32.10', 1, '2026-11-15 10:00:00', '1h')`,
		`UPDATE autoban_recidivism SET offense_count=2, escalated_duration='24h' WHERE identity='45.33.32.10'`,
		`DELETE FROM autoban_recidivism WHERE identity='45.33.32.10'`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatal(err)
		}
		if got := clusterVersion(t, database); got != i+1 {
			t.Fatalf("%q should bump cluster_version to %d, got %d（累犯表须登记同步表清单）", stmt, i+1, got)
		}
	}
	// 从端写入不 bump（快照 apply 整表替换形态不得反向扰动版本）。
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('45.33.32.11', 1, '2026-11-15 10:00:00', '1h')`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 3 {
		t.Fatalf("slave recidivism write must not bump, got %d", got)
	}
}

// Given 触发器已装配、主节点形态。
// When 仅写第七列（col=col 同值写，OF 按 SET 列出现即触发）。
// Then 该列独立 bump cluster_version（漏列时稳态变更经 304 门滞留主节点）。
func TestClusterVersionTrigger_autobanEscalationColumnBump(t *testing.T) {
	for _, column := range []string{"autoban_escalation"} {
		t.Run(column, func(t *testing.T) {
			database := newClusterVersionTestDB(t)
			if err := InstallClusterVersionTriggers(database); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec("UPDATE global_config SET " + column + " = " + column + " WHERE id=1"); err != nil {
				t.Fatalf("update %s: %v", column, err)
			}
			if got := clusterVersion(t, database); got != 101 {
				t.Fatalf("cluster_version=%d after updating %s, want 101 (column missing from OF list)", got, column)
			}
		})
	}
}
