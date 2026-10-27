package db

import (
	"strings"
	"testing"
)

func TestMigrateAutoBackupNodeTopologySection_appendsOnlyOldDefaultOnce(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })

	// 旧默认三分类 + version 0 → 追加节点拓扑。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","rules","security"]', auto_backup_sections_version=0 WHERE id=1`); err != nil {
		t.Fatalf("seed legacy sections: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var sections, version string
	if err := DB.QueryRow(`SELECT auto_backup_sections, auto_backup_sections_version FROM global_config WHERE id=1`).Scan(&sections, &version); err != nil {
		t.Fatalf("read migrated sections: %v", err)
	}
	if sections != `["users","rules","security","cluster"]` || version != "1" {
		t.Fatalf("sections=%s version=%s", sections, version)
	}

	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || entries[0].action != "启动迁移" || entries[0].resource != "系统配置" ||
		!strings.Contains(entries[0].detail, "自动备份") || !strings.Contains(entries[0].detail, "cluster") {
		t.Fatalf("migration audits=%+v, want one node-topology scope change entry", entries)
	}

	// 用户显式取消节点拓扑（version 已为 1）→ 再次启动不得加回。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","rules","security"]' WHERE id=1`); err != nil {
		t.Fatalf("uncheck cluster: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := DB.QueryRow(`SELECT auto_backup_sections FROM global_config WHERE id=1`).Scan(&sections); err != nil {
		t.Fatalf("read unchecked sections: %v", err)
	}
	if sections != `["users","rules","security"]` {
		t.Fatalf("sections=%s, want explicit uncheck preserved", sections)
	}
	if entries = drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("repeated migration audits=%+v, want no new entry", entries)
	}

	// 自定义范围只推进一次性 marker，配置值不变且不得留下虚假修改审计。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","cluster"]', auto_backup_sections_version=0 WHERE id=1`); err != nil {
		t.Fatalf("seed custom sections: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("migrate custom sections: %v", err)
	}
	if err := DB.QueryRow(`SELECT auto_backup_sections, auto_backup_sections_version FROM global_config WHERE id=1`).Scan(&sections, &version); err != nil {
		t.Fatalf("read custom sections: %v", err)
	}
	if sections != `["users","cluster"]` || version != "1" {
		t.Fatalf("custom sections=%s version=%s, want unchanged value with marker", sections, version)
	}
	if entries = drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("custom-scope migration audits=%+v, want none", entries)
	}

	// 畸形值同样只置 marker，不猜测修复、不写配置变更审计。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='{broken', auto_backup_sections_version=0 WHERE id=1`); err != nil {
		t.Fatalf("seed malformed sections: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("migrate malformed sections: %v", err)
	}
	if err := DB.QueryRow(`SELECT auto_backup_sections, auto_backup_sections_version FROM global_config WHERE id=1`).Scan(&sections, &version); err != nil {
		t.Fatalf("read malformed sections: %v", err)
	}
	if sections != "{broken" || version != "1" {
		t.Fatalf("malformed sections=%q version=%s, want preserved value with marker", sections, version)
	}
	if entries = drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("malformed-scope migration audits=%+v, want none", entries)
	}
}
