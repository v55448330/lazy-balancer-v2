package handlers

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 策略实体单职化导入侧：旧版本备份（security_policies 行缺 policy_type 键）
// 导入时按内容推断落库（services.InferSnapshotPolicyType → models.
// InferPolicyType），落库后类型不滞留 ”；新备份携带的显式值原样透传。
func TestImportBackup_policyTypeInferredForLegacyRows(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_policies": {
			{"id": 9, "name": "imp-acl", "mode": "off", "ip_acl_enabled": 1, "ip_acl_mode": "deny", "ip_acl_list": `["203.0.113.0/24"]`, "enabled": 1},
			{"id": 10, "name": "imp-typed", "mode": "blocking", "policy_type": "stage3", "enabled": 1},
		},
	})
	rec := postJSONImport(t, g, backup)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}

	var geoType string
	if err := db.DB.QueryRow(`SELECT policy_type FROM security_policies WHERE name='imp-acl'`).Scan(&geoType); err != nil {
		t.Fatal(err)
	}
	if geoType != "stage1" {
		t.Fatalf("legacy row policy_type=%q, want stage1 (inferred)", geoType)
	}
	var typedType string
	if err := db.DB.QueryRow(`SELECT policy_type FROM security_policies WHERE name='imp-typed'`).Scan(&typedType); err != nil {
		t.Fatal(err)
	}
	if typedType != "stage3" {
		t.Fatalf("typed row policy_type=%q, want stage3 (passthrough)", typedType)
	}
}
