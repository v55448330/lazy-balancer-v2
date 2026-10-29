package services

// 角色谓词跨包对账：services 的写语句全部经 masterRoleConditionSQL /
// slaveRoleConditionSQL，而这两个常量必须是 db 单源的别名而不是手抄副本。
// 别名一旦被改回字面量，db/apiKey flusher 与 middleware 触发器会继续用旧口径，
// 三处分裂（写闸放行但触发器不 bump 版本 / 从端仍被允许写从端专有列）无人发现；
// 源码字面量守卫在 db 包，本用例钉住「别名指向同一单源」。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestClusterRoleConditionAliasesMatchDB(t *testing.T) {
	if masterRoleConditionSQL != db.MasterRoleConditionSQL {
		t.Fatalf("services.masterRoleConditionSQL 与 db.MasterRoleConditionSQL 不一致:\n services=%q\n db      =%q",
			masterRoleConditionSQL, db.MasterRoleConditionSQL)
	}
	if slaveRoleConditionSQL != db.SlaveRoleConditionSQL {
		t.Fatalf("services.slaveRoleConditionSQL 与 db.SlaveRoleConditionSQL 不一致:\n services=%q\n db      =%q",
			slaveRoleConditionSQL, db.SlaveRoleConditionSQL)
	}
}
