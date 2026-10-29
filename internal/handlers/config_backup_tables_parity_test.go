package handlers

import "testing"

// 备份表三份清单（导出 configBackupTables / 删除 configBackupDeleteOrder /
// 插入 configBackupInsertOrder）的机械 parity 绊线：新增备份表漏进任一序会让
// live 行残留（漏删）或主键冲突（漏插）→ 事务整体回滚；此前三份各写各的，
// 只有人工比对。引用序约束：security_ip_lists 先于 security_policies
// （refs 是策略行上的 JSON 引用，插入后引用必须即时指向存在行）。
func TestConfigBackupTableOrderParity(t *testing.T) {
	set := func(xs []string) map[string]int {
		m := make(map[string]int, len(xs))
		for i, x := range xs {
			if prev, dup := m[x]; dup {
				t.Fatalf("%q 在序中重复出现（位置 %d 与 %d）", x, prev, i)
			}
			m[x] = i
		}
		return m
	}

	exported := set(configBackupTables)
	for name, order := range map[string][]string{
		"configBackupDeleteOrder": configBackupDeleteOrder,
		"configBackupInsertOrder": configBackupInsertOrder,
	} {
		orderSet := set(order)
		if len(orderSet) != len(exported) {
			t.Fatalf("%s 有 %d 张表, want 与 configBackupTables 相同的 %d 张", name, len(orderSet), len(exported))
		}
		for table := range exported {
			if _, ok := orderSet[table]; !ok {
				t.Fatalf("%s 缺表 %q（导出清单有、导入序无 → live 行残留/主键冲突）", name, table)
			}
		}
	}

	// 引用序：两序均 lists → policies（与集群 apply 侧一致）。
	if indexOfTable(configBackupDeleteOrder, "security_ip_lists") > indexOfTable(configBackupDeleteOrder, "security_policies") {
		t.Fatal("删除序必须 security_ip_lists 先于 security_policies")
	}
	if indexOfTable(configBackupInsertOrder, "security_ip_lists") > indexOfTable(configBackupInsertOrder, "security_policies") {
		t.Fatal("插入序必须 security_ip_lists 先于 security_policies（refs 即时指向存在行）")
	}
}

func indexOfTable(order []string, table string) int {
	for i, x := range order {
		if x == table {
			return i
		}
	}
	return -1
}
