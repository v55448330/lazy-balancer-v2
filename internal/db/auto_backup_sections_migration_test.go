package db

import (
	"encoding/json"
	"slices"
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

// 迁移写入的默认范围必须按值等于 DefaultAutoBackupSections（单源）：迁移若
// 另抄一份四分类字面量，改常量后带外 NULL 行会下发与 fresh DDL/读侧不一致的
// 范围而无人察觉。空数组则是读侧显式错误形态（未设置=NULL/空串），迁移不得
// 把它「修」成全量默认——那会掩盖损坏值。
func TestMigrateAutoBackupNodeTopologySection_usesDefaultConstantAndKeepsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })

	var want []string
	if err := json.Unmarshal([]byte(DefaultAutoBackupSections), &want); err != nil {
		t.Fatalf("parse DefaultAutoBackupSections: %v", err)
	}
	readStored := func() (string, string) {
		t.Helper()
		var stored, version string
		if err := DB.QueryRow(`SELECT COALESCE(auto_backup_sections,''), auto_backup_sections_version FROM global_config WHERE id=1`).
			Scan(&stored, &version); err != nil {
			t.Fatalf("read auto backup sections: %v", err)
		}
		return stored, version
	}

	// 未设置（NULL）→ 写入默认范围，且按值与单源常量一致。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections=NULL, auto_backup_sections_version=0 WHERE id=1`); err != nil {
		t.Fatalf("seed unset sections: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("migrate unset sections: %v", err)
	}
	stored, version := readStored()
	var got []string
	if err := json.Unmarshal([]byte(stored), &got); err != nil {
		t.Fatalf("parse migrated sections %q: %v", stored, err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("迁移写入的默认范围=%v, want DefaultAutoBackupSections=%v（必须与单源常量同值）", got, want)
	}
	if version != "1" {
		t.Fatalf("sections version=%s, want 1", version)
	}

	// 空数组：保留原值（读侧 fail-visible 500），只推进一次性 marker。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='[]', auto_backup_sections_version=0 WHERE id=1`); err != nil {
		t.Fatalf("seed empty array sections: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("migrate empty array sections: %v", err)
	}
	if stored, version = readStored(); stored != "[]" || version != "1" {
		t.Fatalf("空数组迁移后 sections=%q version=%s, want 原样保留 '[]' 且 marker=1（不得伪装成全量默认）", stored, version)
	}
}
