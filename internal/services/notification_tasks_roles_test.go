package services

// 通知任务的角色注册：notification-apikey-expiry 与
// notification-delivery-retention 必须与同族日报一致声明 RoleMasterOnly。
// 从节点若也跑这两项，同一把临期密钥/同一批过期投递会被多节点各执行一遍
// （去重语义由主节点单点承担）。断言用 TaskMeta.RoleApplicable 派生结论，
// 不读私有 RunsOn 字段。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestNotificationTaskRoles_masterOnlyFamilies(t *testing.T) {
	te := newWireTestEngine(t)
	ids := []string{"notification-apikey-expiry", "notification-delivery-retention", "notification-daily-report"}

	// 从节点：全部不可运行（含既有基线 notification-daily-report 作口径对照）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(false)
	for _, id := range ids {
		meta, ok := te.Lookup(id)
		if !ok {
			t.Fatalf("%s 未注册", id)
		}
		if meta.RoleApplicable {
			t.Fatalf("从节点上 %s 仍被判定可运行（RunsOn 未声明 RoleMasterOnly）", id)
		}
	}

	// 主节点：全部可运行（角色门只拦从节点，不是禁用任务本身）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(true)
	for _, id := range ids {
		meta, ok := te.Lookup(id)
		if !ok {
			t.Fatalf("%s 未注册", id)
		}
		if !meta.RoleApplicable {
			t.Fatalf("主节点上 %s 必须可运行", id)
		}
	}
}
