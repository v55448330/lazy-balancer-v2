package handlers

import (
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// trustedProxyTestEntries 生成 count 个互不重叠的 /24 网段条目（JSON 数组
// 文本），offset 平移用于构造「部分重叠」的名单组合。
func trustedProxyTestEntries(count, offset int) string {
	parts := make([]string, 0, count)
	for i := range count {
		n := offset + i
		parts = append(parts, fmt.Sprintf(`{"value":"10.%d.%d.0/24","remark":""}`, n/256, n%256))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// 名单表随备份替换、refs 保持库内存量时，导入后的真实展开规模 =
// 「库内内联网段 ∪ 备份名单行展开」。锁内复核必须按该口径重过总量上限门
// （写侧同口径）：此前该分支只校验引用存在性，备份把被引用名单扩大即可
// 把渲染侧的受信网段数带到远超写侧上限。
func TestRevalidateImportTrustedProxyRefs_listsCarriedEnforcesTotalGate(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	// 引用只在开关开启时参与校验（开关关闭 = 关联字段无意义），锁内总量门同理。
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='[]', trusted_proxy_range_refs='[701,702]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	backupRows := func(entriesA, entriesB string) map[string][]map[string]any {
		return map[string][]map[string]any{
			"security_ip_lists": {
				{"id": 701, "name": "受信-A", "system": 0, "entries": entriesA},
				{"id": 702, "name": "受信-B", "system": 0, "entries": entriesB},
			},
		}
	}
	revalidate := func(t *testing.T, tables map[string][]map[string]any) error {
		t.Helper()
		tx, err := db.DB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return revalidateImportTrustedProxyRefs(t.Context(), tx, &configBackup{Tables: tables})
	}

	// 形状 1：两份名单合计恰好 2000 条（未超限）→ 放行。
	if err := revalidate(t, backupRows(trustedProxyTestEntries(1000, 0), trustedProxyTestEntries(1000, 1000))); err != nil {
		t.Fatalf("合计未超上限必须放行: %v", err)
	}

	// 形状 2：合计 2001 条 → 拒绝并点名 2000 上限。
	if err := revalidate(t, backupRows(trustedProxyTestEntries(1000, 0), trustedProxyTestEntries(1001, 1000))); err == nil || !strings.Contains(err.Error(), "2000") {
		t.Fatalf("合计超上限必须拒绝并点名 2000: %v", err)
	}

	// 形状 3：库内存量内联 1 条 + 名单 2000 条 → 合计 2001 → 拒绝。
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_ranges='["192.0.2.0/24"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := revalidate(t, backupRows(trustedProxyTestEntries(1000, 0), trustedProxyTestEntries(1000, 1000))); err == nil || !strings.Contains(err.Error(), "2000") {
		t.Fatalf("内联 ∪ 引用展开超上限必须拒绝: %v", err)
	}

	// 形状 4：重叠网段只计一次——两份名单内容相同、内联 1 条与名单重叠
	// → 去重后 1000 → 放行。
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_ranges='["10.0.0.0/24"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	same := trustedProxyTestEntries(1000, 0)
	if err := revalidate(t, backupRows(same, same)); err != nil {
		t.Fatalf("重叠网段只计一次，未超上限必须放行: %v", err)
	}
}
