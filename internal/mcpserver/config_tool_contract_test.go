package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestPreviewConfigSchemaMatchesUpdateRequest(t *testing.T) {
	properties := decodeRuleSchema(t, "preview_config", previewConfigSchema)
	for _, field := range jsonFieldNames(t, models.UpdateConfigRequest{}) {
		if _, ok := properties[field]; !ok {
			t.Errorf("preview_config schema lacks request field %q", field)
		}
	}
	var source struct {
		Description string `json:"description"`
	}
	rawSource, err := json.Marshal(properties["source"])
	if err != nil {
		t.Fatalf("encode source schema: %v", err)
	}
	if err := json.Unmarshal(rawSource, &source); err != nil {
		t.Fatalf("decode source schema: %v", err)
	}
	for _, want := range []string{"审计归因", "不筛选", "basic", "cluster", "acme", "caddy"} {
		if !strings.Contains(source.Description, want) {
			t.Errorf("source description=%q, missing %q", source.Description, want)
		}
	}
	if strings.Contains(source.Description, "security") || strings.Contains(source.Description, "分区") {
		t.Fatalf("source description=%q, must not claim configuration partitioning", source.Description)
	}
}

func TestConfigSchemasHaveNoRetiredProperties(t *testing.T) {
	for _, tc := range []struct {
		name, schema string
	}{
		{name: "update_config", schema: updateConfigSchema},
		{name: "preview_config", schema: previewConfigSchema},
	} {
		properties := decodeRuleSchema(t, tc.name, tc.schema)
		if _, exists := properties["dns_credentials"]; exists {
			t.Errorf("%s schema contains retired dns_credentials", tc.name)
		}
		expected := map[string]bool{}
		for _, field := range jsonFieldNames(t, models.UpdateConfigRequest{}) {
			expected[field] = true
		}
		for field := range properties {
			if !expected[field] {
				t.Errorf("%s schema property %q has no UpdateConfigRequest binding", tc.name, field)
			}
		}
	}
}

func TestCertificateTestSchemaMatchesStoredConfigEndpoint(t *testing.T) {
	spec := toolSpecsByName["test_certificate_config"]
	properties := decodeRuleSchema(t, spec.name, spec.schema)
	for _, field := range []string{"id", "domain"} {
		if _, ok := properties[field]; !ok {
			t.Errorf("test_certificate_config schema lacks %q", field)
		}
	}
	// /certificate-configs/{id}/test 从数据库读取 provider/credentials；
	// 同名请求字段仅由无 ID 的面板保存前测试消费，不得在此虚假宣传。
	for _, field := range []string{"dns_provider", "dns_credentials"} {
		if _, ok := properties[field]; ok {
			t.Errorf("test_certificate_config schema advertises ignored override %q", field)
		}
	}
}
