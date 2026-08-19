package services

import (
	"context"
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// R41 B1: 从节点侧防御——pre-R40 主节点（或被扩散的快照）可能携带 ≥2 个
// is_default=1 的拦截页，applySecurityBlockPages 必须在写入后降级多余默认页，
// 仅保留 MIN(id)，避免死行在从节点扩散。
func TestApplySnapshot_demotesExtraDefaultBlockPages(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{
		Version:          1,
		SecurityPolicies: json.RawMessage("[]"),
		SecurityBindings: json.RawMessage("[]"),
		SecurityBlockPages: []models.SecurityBlockPage{
			{ID: 1, Name: "默认拦截页面", Description: "sys", Content: "<html>a</html>", IsDefault: true},
			{ID: 5, Name: "旧默认页", Description: "legacy", Content: "<html>b</html>", IsDefault: true},
			{ID: 7, Name: "自定义页", Description: "custom", Content: "<html>c</html>", IsDefault: false},
		},
		SecurityCustomRules:      []models.SecurityCustomRule{},
		SecurityCRSVersion:       []models.ClusterSecurityCRSVersion{},
		SecurityIP2RegionVersion: []models.ClusterSecurityIP2RegionVersion{},
	}

	// When
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then
	var defaultCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaultCount); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if defaultCount != 1 {
		t.Fatalf("default page count=%d, want 1（仅 MIN(id) 保留默认）", defaultCount)
	}
	var defaultID int
	if err := database.QueryRow("SELECT id FROM security_block_pages WHERE is_default=1").Scan(&defaultID); err != nil {
		t.Fatalf("read default page id: %v", err)
	}
	if defaultID != 1 {
		t.Fatalf("default page id=%d, want 1（MIN(id)）", defaultID)
	}
	var legacyDefault bool
	if err := database.QueryRow("SELECT is_default FROM security_block_pages WHERE id=5").Scan(&legacyDefault); err != nil {
		t.Fatalf("read legacy page: %v", err)
	}
	if legacyDefault {
		t.Fatalf("id=5 应被降级为非默认页")
	}
	var customDefault bool
	if err := database.QueryRow("SELECT is_default FROM security_block_pages WHERE id=7").Scan(&customDefault); err != nil {
		t.Fatalf("read custom page: %v", err)
	}
	if customDefault {
		t.Fatalf("id=7 本就不是默认页，不应被误改")
	}
}
