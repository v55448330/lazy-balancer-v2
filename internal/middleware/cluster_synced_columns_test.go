package middleware

// 「触发器列清单 ↔ schema」漂移对账：集群同步表的每一列必须要么进快照触发
// 列清单，要么携理由进 clusterSyncedColumnExclusions（运行态/簿记/节点本地
// 状态/本地去重哈希）。漏登记列时，仅写该列的 UPDATE 不 bump
// cluster_version——从节点经 304 门永久滞留旧值，只能靠无关变更或重启收敛。

import (
	"sort"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// clusterSyncedColumnExclusions 有意不同步的列（逐表登记，每项携理由）。
// 只允许「不同步也无害」的列在此：任何参与跨节点语义的列漏登记都是缺陷。
var clusterSyncedColumnExclusions = map[string]map[string]string{
	"lb_rules": {
		"id": "主键迁移（id→caddy_id）前的历史列，新行恒 NULL，零业务消费",
	},
	"path_rules": {
		"created_at": "时间簿记：业务语义列已全量登记",
		"updated_at": "时间簿记：业务语义列已全量登记",
	},
	"users": {
		"created_at":            "时间簿记：开户时间随首次 INSERT 落库",
		"last_login":            "登录活动运行态：每节点独立记账",
		"login_failed_attempts": "节点本地失败计数：普通失败不得引发版本抖动",
		"mfa_last_timestep":     "MFA 时间步记账：随哈希清零不参与漂移判定",
		"mfa_pending_fails":     "step-up 待定计数：单次会话内状态，不跨节点",
		"mfa_pending_secret":    "step-up 待定密钥：单次会话内状态，不跨节点",
		"is_setup_admin":        "跨节点派生标记：由用户集在启动/导入/快照应用后归一重建，不参与版本漂移判定",
	},
	"api_keys": {
		"created_at": "时间簿记：创建即随 INSERT 落库",
		"last_used":  "密钥使用运行态：每节点独立记账",
	},
	"cert_jobs": {
		"id":                         "节点本地行标识：跨节点以 (rule_id,domain) 关联",
		"message":                    "运行态消息：随 status 流转重写，非业务配置",
		"deployment_attempts":        "部署重试运行态簿记：节点本地推进",
		"deployment_available_after": "部署重试冷却窗口：节点本地运行态",
	},
	"security_crs_version": {
		"consecutive_failures": "连续失败计数：节点本地运行态",
	},
	"security_ip2region_version": {
		"consecutive_failures": "连续失败计数：节点本地运行态",
	},
	"security_threat_sources": {
		"created_at":   "时间簿记：源行播种时间",
		"updated_at":   "时间簿记：源行更新时间",
		"content_hash": "内容指纹：本地去重/缓存判据",
		"raw_hash":     "原始载荷哈希：本地去重判据",
	},
	"security_crawler_sources": {
		"created_at": "时间簿记：源行播种时间",
		"updated_at": "时间簿记：源行更新时间",
	},
}

func syncedSchemaTestDB(t *testing.T) func() {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	return func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	}
}

// pragmaTableColumns 读取真实 schema 列序（迁移后的最终形态）。
func pragmaTableColumns(t *testing.T, table string) []string {
	t.Helper()
	rows, err := db.DB.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan pragma column of %s: %v", table, err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate pragma columns of %s: %v", table, err)
	}
	if len(columns) == 0 {
		t.Fatalf("%s 在 schema 中不存在（同步表清单指向已删除/改名的表）", table)
	}
	return columns
}

func syncedColumnSet(snapshotColumns string) map[string]bool {
	set := map[string]bool{}
	for _, column := range strings.Split(snapshotColumns, ",") {
		if column = strings.TrimSpace(column); column != "" {
			set[column] = true
		}
	}
	return set
}

// 三向对账：schema 列 → 必须登记（或在携理由的白名单）／清单列 → 必须存在
// 于 schema／白名单 → 不得与清单重叠且键必须是已知同步表。
func TestClusterVersionTriggers_syncedColumnsMatchSchema(t *testing.T) {
	cleanup := syncedSchemaTestDB(t)
	defer cleanup()

	for _, table := range clusterSyncedTables {
		t.Run(table.name, func(t *testing.T) {
			listed := syncedColumnSet(table.snapshotColumns)
			exclusions := clusterSyncedColumnExclusions[table.name]
			var unregistered []string
			for _, column := range pragmaTableColumns(t, table.name) {
				if listed[column] {
					continue
				}
				if _, ok := exclusions[column]; ok {
					continue
				}
				unregistered = append(unregistered, column)
			}
			sort.Strings(unregistered)
			if len(unregistered) > 0 {
				t.Fatalf("schema 列未登记：%s —— 既不进快照也不 bump cluster_version（漏同步）",
					strings.Join(unregistered, ","))
			}
			var stale []string
			known := map[string]bool{}
			for _, column := range pragmaTableColumns(t, table.name) {
				known[column] = true
			}
			for column := range listed {
				if !known[column] {
					stale = append(stale, column)
				}
			}
			sort.Strings(stale)
			if len(stale) > 0 {
				t.Fatalf("清单列在 %s 中不存在：%s（陈旧列会让触发器 CREATE 失败）",
					table.name, strings.Join(stale, ","))
			}
			for column, reason := range exclusions {
				if listed[column] {
					t.Fatalf("%s.%s 同时出现在清单与白名单（自相矛盾）", table.name, column)
				}
				if strings.TrimSpace(reason) == "" {
					t.Fatalf("%s.%s 白名单项缺少理由", table.name, column)
				}
			}
		})
	}

	knownTables := map[string]bool{}
	for _, table := range clusterSyncedTables {
		knownTables[table.name] = true
	}
	for table := range clusterSyncedColumnExclusions {
		if !knownTables[table] {
			t.Fatalf("白名单指向未知同步表：%s", table)
		}
	}
}
