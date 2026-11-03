package handlers

import "testing"

// 空白名单导入已放开（2026-11 用户裁定）：空生效集不再是导入拒绝理由
// （运行时渲染层仍恒拒，fail-closed 语义不变）。
func TestValidateV2BackupSecurityPolicies_acceptsEmptyAllow(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "empty-allow", "mode": "blocking", "ip_acl_enabled": true,
			"ip_acl_mode": "allow", "ip_acl_list": "[]", "ip_acl_list_refs": "[]",
		}},
		"security_ip_lists": {},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("empty allow backup must be accepted: %v", err)
	}
}

func TestValidateV2BackupSecurityPolicies_acceptsAllowWithReferencedEntry(t *testing.T) {
	tables := map[string][]map[string]any{
		"security_policies": {{
			"name": "ref-allow", "mode": "blocking", "ip_acl_enabled": true,
			"ip_acl_mode": "allow", "ip_acl_list": "[]", "ip_acl_list_refs": "[1]",
		}},
		"security_ip_lists": {{"id": 1, "name": "ref-list", "category": "custom", "entries": `[{"value":"203.0.113.7","remark":""}]`}},
	}
	if err := validateV2BackupSecurityPolicies(tables, false); err != nil {
		t.Fatalf("allow with referenced entry must pass: %v", err)
	}
}

func TestValidateV2BackupRuntimeSettings_defaultCAPolicy(t *testing.T) {
	tables := map[string][]map[string]any{
		"ca_providers": {{"id": 1}}, // enabled 键缺失 = schema 默认启用
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"default_ca_provider_id": 1}, tables); err != nil {
		t.Fatalf("missing enabled should mean enabled: %v", err)
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"default_ca_provider_id": -1}, tables); err == nil {
		t.Fatal("negative default CA id must be rejected")
	}
}
