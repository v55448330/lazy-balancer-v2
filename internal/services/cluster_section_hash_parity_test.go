package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// security 节哈希口径必须与 apply 落库口径一致：主端 payload 的原始行经同一组
// 归一函数处理后再哈希，从端 apply 落库后重建的哈希才与主端相等。此前哈希直接
// 照抄原始载荷（策略值/派生列/活动态/多余默认页的归一只在 apply 侧发生），
// 主从哈希长期不等——节点列表该节永久显示「滞后」，且每次相关版本 bump 多出
// 一轮全量重放。

func TestSecuritySectionHash_matchesSlaveRebuildAfterApply(t *testing.T) {
	cluster, database := newClusterTestService(t)
	ctx := context.Background()

	// 主端携带「待归一」形态：写侧校验拦截后的带外值 + 旧库缺省策略类型。
	if _, err := database.Exec(`INSERT INTO security_policies
		(id,name,mode,anomaly_threshold,rate_limit_enabled,rate_limit_rps,rate_limit_burst,block_status_code,enabled,geoip_mode,policy_type,trust_detection)
		VALUES (7,'anomalous','blocking',0,1,50,-3,999,1,'deny','',1)`); err != nil {
		t.Fatal(err)
	}
	// 源表活动态：从端不执行该任务，apply 归为 failed。
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_status='running', message='', last_checked='2026-10-24 10:00:00', finished_at='' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	// 主端并存两个默认拦截页，apply 只保留 MIN(id)。
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,content,is_default,is_builtin) VALUES (901,'extra-default','x',1,0),(902,'kept-default','y',1,0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_block_pages SET is_default=0 WHERE id<>901 AND id<>902`); err != nil {
		t.Fatal(err)
	}

	snapshot, _, err := cluster.Snapshot(ctx, 0, "", "cluster-token")
	if err != nil {
		t.Fatal(err)
	}
	masterHash := snapshot.SectionHashes["security"]
	if masterHash == "" {
		t.Fatal("security 节哈希缺失")
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySecurityTables(ctx, tx, snapshot, true); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply security tables: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// 从端（同库）apply 后按本地库重建 security 节哈希。
	local, err := cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if local["security"] != masterHash {
		t.Fatalf("security 节哈希主从不一致：master=%s local=%s（apply 归一口径与哈希口径分裂）", masterHash, local["security"])
	}

	// 幂等：归一后的行再次参与哈希不产生变化（从端每轮重建的稳定性）。
	localAgain, err := cluster.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if localAgain["security"] != local["security"] {
		t.Fatalf("归一后哈希不稳定：%s != %s", localAgain["security"], local["security"])
	}
}

// users 节里的安全事件保留/采样三列也必须「下发值 / 主端哈希输入 / 从端落库值」
// 三面同源：写侧拒绝 0/越界（handlers/caddy.go），脏值只能带外直写，而启动
// 回填 marker 置位后运行期不再改写——主端若按脏值算哈希，从端 apply 归一后
// 主从哈希恒不等，每同步周期强制重放 users 节并重载 Caddy。
func TestUsersSectionHash_matchesSlaveRebuildAfterApplyingOutOfRangeRetention(t *testing.T) {
	cases := []struct {
		name                  string
		retentionDays, rowCap int
		trafficSample         int
	}{
		{name: "zero-values", retentionDays: 0, rowCap: 0, trafficSample: 7},
		{name: "above-limits", retentionDays: 999999, rowCap: db.MaxSecurityEventsRowCap + 1, trafficSample: -5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster, database := newClusterTestService(t)
			ctx := context.Background()
			if _, err := database.Exec(`UPDATE global_config SET security_events_retention_days=?, security_events_row_cap=?, threat_traffic_sample_n=? WHERE id=1`,
				tc.retentionDays, tc.rowCap, tc.trafficSample); err != nil {
				t.Fatal(err)
			}

			// When 主端构建快照（装载侧归一）
			snapshot, _, err := cluster.Snapshot(ctx, 0, "", "cluster-token")
			if err != nil {
				t.Fatal(err)
			}
			masterHash := snapshot.SectionHashes["users"]
			if masterHash == "" {
				t.Fatal("users 节哈希缺失")
			}
			if got := *snapshot.BasicSettings.SecurityEventsRetentionDays; got != db.DefaultSecurityEventsRetentionDays {
				t.Fatalf("下发保留天数=%d, want 归一为默认 %d（脏值不得进入快照与哈希）", got, db.DefaultSecurityEventsRetentionDays)
			}
			if got := *snapshot.BasicSettings.SecurityEventsRowCap; got != db.DefaultSecurityEventsRowCap {
				t.Fatalf("下发行数上限=%d, want 归一为默认 %d", got, db.DefaultSecurityEventsRowCap)
			}
			if got := *snapshot.BasicSettings.ThreatTrafficSampleN; got != db.DefaultThreatTrafficSampleN {
				t.Fatalf("下发采样口径=%d, want 归一为默认 %d", got, db.DefaultThreatTrafficSampleN)
			}

			// When 从端 apply（落库归一同源）
			tx, err := database.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
				_ = tx.Rollback()
				t.Fatalf("apply snapshot settings: %v", err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}

			// Then 从端重建的 users 节哈希与主端相等，且库值已是默认
			local, err := cluster.driftGuardSectionHashes(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if local["users"] != masterHash {
				t.Fatalf("users 节哈希主从不一致：master=%s local=%s（保留/采样三列归一口径与哈希口径分裂）", masterHash, local["users"])
			}
			var days, rowCap, sample int
			if err := database.QueryRow(`SELECT security_events_retention_days, security_events_row_cap, threat_traffic_sample_n FROM global_config WHERE id=1`).Scan(&days, &rowCap, &sample); err != nil {
				t.Fatal(err)
			}
			if days != db.DefaultSecurityEventsRetentionDays || rowCap != db.DefaultSecurityEventsRowCap || sample != db.DefaultThreatTrafficSampleN {
				t.Fatalf("落库值=(%d,%d,%d), want 默认(%d,%d,%d)", days, rowCap, sample,
					db.DefaultSecurityEventsRetentionDays, db.DefaultSecurityEventsRowCap, db.DefaultThreatTrafficSampleN)
			}
		})
	}
}
