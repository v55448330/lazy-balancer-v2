package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// R45 F-3: 剥掉 exported_at 的 v2 备份（tables-only 校验和仍匹配）不得借旧格式
// 回退通过完整性门——回退仅限 Version==1 的史前导出，v2 形态一律按不兼容拒绝。
func TestValidateV2Backup_v2StrippedExportedAt_rejected(t *testing.T) {
	// Given v2 备份：tables-only 校验和匹配，但 exported_at 被剥离（Version 仍 =2）
	var b configBackup
	if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 2, "", true)), &b); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}

	// When
	usedLegacy, err := validateV2Backup(b)

	// Then 拒绝且不标记旧格式回退
	if err == nil {
		t.Fatal("剥 exported_at 的 v2 备份不得放行导入")
	}
	if !strings.Contains(err.Error(), "v2.1.2") {
		t.Fatalf("err=%q, want 兼容性拒绝并指引 v2.1.2+ 重新导出", err)
	}
	if usedLegacy {
		t.Fatal("v2 形态不得标记为旧格式校验和回退路径")
	}
}

// R45 F-3: 剥掉 checksum 的 v2 备份整体跳过完整性校验的漏洞闭合——必须拒绝。
func TestValidateV2Backup_v2StrippedChecksum_rejected(t *testing.T) {
	// Given v2 备份：exported_at 保留，但 checksum 被剥离
	var b configBackup
	if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 2, "2026-08-19T00:00:00Z", false)), &b); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}
	b.Meta.Checksum = ""

	// When
	usedLegacy, err := validateV2Backup(b)

	// Then 拒绝
	if err == nil || !strings.Contains(err.Error(), "校验和") {
		t.Fatalf("validateV2Backup err=%v, want 缺少校验和拒绝", err)
	}
	if usedLegacy {
		t.Fatal("剥 checksum 的 v2 备份不得标记为旧格式校验和路径")
	}
}
