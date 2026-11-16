package middleware

// global_config 触发器值变化守卫钉测（与 users 表同构）：
// SQLite UPDATE OF 只要列出现在 SET 即触发（与值是否变化无关）——保存
// 基础设置时 COALESCE(?, col) 会把全部 OF 列写一遍（未提交的字段保值），
// 旧定义无值变化守卫，每次保存都 bump cluster_version，从节点空拉一轮
// 全量快照。改为「任一同步列值真实变化」（OLD.col IS NOT NEW.col 全链
// OR，NULL 安全）：同值写零 bump，真实变更照常 bump。
// OF 成员资格与值守卫正交：OF 漏列时「仅写该列的真实变更」不 bump，
// 由 TestGlobalConfigSyncedColumns_OFMembershipIndependentOfValueGuard
// 逐列钉住（真实值变化形态，不与值守卫冲突）。

import (
	"strings"
	"testing"
)

// 同值写（col=col，模拟保存未提交字段）不得 bump；真实值变化必须 bump。
func TestClusterVersionTrigger_globalConfigSameValueWriteDoesNotBump(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// 同值写：单个 OF 列 col=col。
	if _, err := database.Exec("UPDATE global_config SET timezone=timezone WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 100 {
		t.Fatalf("同值写后 cluster_version=%d, want 100（值变化守卫不得抖动）", got)
	}
	// 同值写：多列保值（保存基础设置形态，全部 OF 列 COALESCE 保值）。
	if _, err := database.Exec("UPDATE global_config SET timezone=timezone, jwt_expire_minutes=jwt_expire_minutes, sync_interval=sync_interval WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 100 {
		t.Fatalf("多列保值写后 cluster_version=%d, want 100", got)
	}
	// 真实值变化：必须 bump。
	if _, err := database.Exec("UPDATE global_config SET jwt_expire_minutes=jwt_expire_minutes+1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 101 {
		t.Fatalf("真实值变化后 cluster_version=%d, want 101", got)
	}
	// NULL 安全比较：NULL→值 与 值→NULL 都算变化（IS NOT 语义）。
	if _, err := database.Exec("UPDATE global_config SET acme_email=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	base := clusterVersion(t, database)
	if _, err := database.Exec("UPDATE global_config SET acme_email='ops@example.com' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != base+1 {
		t.Fatalf("NULL→值后 cluster_version=%d, want %d（IS NOT NULL 安全比较）", got, base+1)
	}
	if _, err := database.Exec("UPDATE global_config SET acme_email=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != base+2 {
		t.Fatalf("值→NULL 后 cluster_version=%d, want %d", got, base+2)
	}
	// NULL→NULL 保值不 bump。
	if _, err := database.Exec("UPDATE global_config SET acme_email=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != base+2 {
		t.Fatalf("NULL→NULL 保值写后 cluster_version=%d, want %d", got, base+2)
	}
}

// OF 成员资格逐列钉测（真实值变化形态）：清单里每一列单独真实变更都必须
// 独立 bump——漏列时稳态变更经 304 门滞留主节点。值变化守卫不得掩盖 OF
// 漏列（旧钉测用 col=col 同值写探 OF 成员资格，与值守卫语义冲突，改为
// 真实值变化探测）。
func TestGlobalConfigSyncedColumns_OFMembershipIndependentOfValueGuard(t *testing.T) {
	for _, column := range globalConfigSyncedColumns {
		t.Run(column, func(t *testing.T) {
			database := newClusterVersionTestDB(t)
			if err := InstallClusterVersionTriggers(database); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			// 构造与现值不同的新值：数值列取域内安全值（0/1 互换，避开
			// CHECK/枚举约束）；文本列置哨兵串（现值恰为哨兵时换另一哨兵）；
			// NULL 现值直接置哨兵即变化。
			var current *string
			if err := database.QueryRow("SELECT CAST(" + column + " AS TEXT) FROM global_config WHERE id=1").Scan(&current); err != nil {
				t.Fatalf("read %s: %v", column, err)
			}
			var newValue string
			switch {
			case current == nil:
				newValue = "'lb-of-probe'"
			case *current == "0":
				newValue = "1"
			case isNumericColumnValue(*current):
				newValue = "0"
			case *current == "lb-of-probe":
				newValue = "'lb-of-probe-2'"
			default:
				newValue = "'lb-of-probe'"
			}
			if _, err := database.Exec("UPDATE global_config SET " + column + " = " + newValue + " WHERE id=1"); err != nil {
				t.Fatalf("update %s: %v", column, err)
			}
			if got := clusterVersion(t, database); got != 101 {
				t.Fatalf("cluster_version=%d after real change of %s, want 101 (column missing from OF list)", got, column)
			}
		})
	}
}

func isNumericColumnValue(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// 触发器定义必须携带全链值变化守卫：OF 清单每一列都要出现在
// OLD.col IS NOT NEW.col 链里（单源 globalConfigSyncedColumns）——
// 漏一列即该列的真实变更不 bump（从节点滞留旧值）。
func TestClusterVersionTrigger_globalConfigValueGuardCoversAllSyncedColumns(t *testing.T) {
	statements := clusterVersionTriggerStatements()
	var definition string
	for _, trigger := range statements {
		if trigger.name == "cluster_version_global_config_update" {
			definition = trigger.createSQL
		}
	}
	if definition == "" {
		t.Fatal("global_config UPDATE 触发器未登记")
	}
	normalized := strings.ToLower(definition)
	for _, column := range globalConfigSyncedColumns {
		predicate := "old." + column + " is not new." + column
		if !strings.Contains(normalized, predicate) {
			t.Errorf("值变化守卫缺列 %s（OLD.%s IS NOT NEW.%s）——该列真实变更不 bump", column, column, column)
		}
	}
}
