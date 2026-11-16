package middleware

// global_config 集群版本触发器 OF 清单的单源漂移护栏。
// 漏列故障形态：新增「仅写漏列」的端点/直改 SQL 时不 bump cluster_version，
// 稳态变更经 304 门滞留主节点（autoban 六列、自动备份组均曾因
// 同类遗漏修过）。故用两条机器断言钉住：①ClusterBasicSettings（同步快照
// 契约）的每个 JSON 字段必须命中清单；②每个补列都能独立触发 bump。

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestGlobalConfigSyncedColumns_coverClusterBasicSettings(t *testing.T) {
	columns := make(map[string]struct{}, len(globalConfigSyncedColumns))
	dupes := map[string]int{}
	for _, column := range globalConfigSyncedColumns {
		if _, exists := columns[column]; exists {
			dupes[column]++
		}
		columns[column] = struct{}{}
	}
	if len(dupes) > 0 {
		t.Fatalf("duplicate columns in globalConfigSyncedColumns: %v", dupes)
	}

	typ := reflect.TypeOf(models.ClusterBasicSettings{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		if _, ok := columns[tag]; !ok {
			t.Errorf("ClusterBasicSettings.%s (json %q) 未列入 globalConfigSyncedColumns——该列变化不会 bump cluster_version，从节点将滞留旧值",
				typ.Field(i).Name, tag)
		}
	}
}

// 三列此前仅靠「同语句 UPDATE 含其他 OF 列」偶然触发 bump；单独 UPDATE 必须
// 也能 bump（trigger 的 OF 成员资格）。值变化守卫落地后，OF 成员资格探测
// 必须用真实值变化形态（col=col 同值写被值守卫有意拦下，不再能探 OF）——
// 逐列全量形态见 TestGlobalConfigSyncedColumns_OFMembershipIndependentOfValueGuard。
func TestClusterVersionTrigger_bumpsForRetentionAndSampleColumns(t *testing.T) {
	for _, column := range []string{"security_events_retention_days", "security_events_row_cap", "threat_traffic_sample_n"} {
		t.Run(column, func(t *testing.T) {
			database := newClusterVersionTestDB(t)
			if err := InstallClusterVersionTriggers(database); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			if got := clusterVersion(t, database); got != 100 {
				t.Fatalf("baseline cluster_version=%d, want 100", got)
			}
			// 真实值变化（+1）：OF 漏列时不 bump；值守卫不得掩盖漏列。
			if _, err := database.Exec("UPDATE global_config SET " + column + " = " + column + " + 1 WHERE id=1"); err != nil {
				t.Fatalf("update %s: %v", column, err)
			}
			if got := clusterVersion(t, database); got != 101 {
				t.Fatalf("cluster_version=%d after updating %s, want 101 (column missing from OF list)", got, column)
			}
		})
	}
}

// TestGlobalConfigSyncedColumns_existInSchema 是单向护栏的补面：清单里的每一列
// 都必须真实存在于 global_config。反向漏检时，列改名/删除而清单未同步会让
// CREATE TRIGGER ... OF <不存在列> 整语句失败——InstallClusterVersionTriggers
// 返回错误，启动门拒绝启动，装配期则让全部分类写 500（且错误文案指向触发器
// 不可用而非缺列）。对照 cluster_synced_columns_test.go 的同款 stale 分支。
func TestGlobalConfigSyncedColumns_existInSchema(t *testing.T) {
	cleanup := syncedSchemaTestDB(t)
	defer cleanup()

	known := map[string]bool{}
	for _, column := range pragmaTableColumns(t, "global_config") {
		known[column] = true
	}
	var stale []string
	for _, column := range globalConfigSyncedColumns {
		if !known[column] {
			stale = append(stale, column)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("清单列在 global_config 中不存在：%s（陈旧列会让触发器 CREATE 失败→全部分类写 500）",
			strings.Join(stale, ","))
	}
}
