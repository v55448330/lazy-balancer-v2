package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// U11-8（第 78 轮）：通用绊线——pathArgs/queryArgs 是转发器实际取值依据，
// 必须全部出现在该工具的 input_schema.properties 中（bodySchema 宽松形态
// 豁免）。R68 B-F2/APIMCP45-1/R72 F2 三次同类缺陷此前只靠单工具测试兜底。
func TestEveryToolSchemaCoversPathAndQueryArgs(t *testing.T) {
	checked := 0
	for _, spec := range tools {
		if spec.schema == bodySchema {
			continue
		}
		var shape struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal([]byte(spec.schema), &shape); err != nil {
			t.Errorf("tool %s schema is not valid JSON: %v", spec.name, err)
			continue
		}
		args := make([]string, 0, len(spec.pathArgs)+len(spec.queryArgs))
		args = append(args, spec.pathArgs...)
		args = append(args, spec.queryArgs...)
		for _, arg := range args {
			if _, ok := shape.Properties[arg]; !ok {
				t.Errorf("tool %s (%s %s) declares %q as path/query arg but input_schema lacks it: %s", spec.name, spec.method, spec.path, arg, spec.schema)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no path/query args checked——schema 解析形态失效")
	}
}

// U11-4（第 78 轮）：单/少字段写工具的 schema 必须声明 properties/required
// （保留 additionalProperties 兼容性），否则 Agent 只能凭描述猜字段名，错名
// 由 REST 侧返回 400。
func TestSmallWriteToolSchemasDeclareFields(t *testing.T) {
	cases := []struct {
		name       string
		required   []string
		properties []string
	}{
		{"toggle_crs_auto_update", []string{"auto_update"}, []string{"auto_update"}},
		{"toggle_ip2region_auto_update", []string{"auto_update"}, []string{"auto_update"}},
		{"toggle_user_status", []string{"id", "is_enabled"}, []string{"id", "is_enabled"}},
		{"set_cluster_mode", []string{"mode", "master_url", "register_token"}, []string{"mode", "master_url", "register_token", "node_name"}},
		{"update_cluster_settings", nil, []string{"sync_interval", "sync_users", "sync_rules", "sync_security"}},
		{"parse_certificate", []string{"cert_pem", "key_pem"}, []string{"cert_pem", "key_pem"}},
		{"update_node_access_url", []string{"id", "access_url"}, []string{"id", "access_url"}},
		{"update_ca_provider", []string{"id"}, []string{"id", "name", "provider", "credentials", "max_concurrent", "min_interval_ms", "enabled"}},
		{"update_admin_tls", nil, []string{"enabled", "mode", "cert_file", "key_file"}},
		{"inspect_admin_tls", []string{"cert_file", "key_file"}, []string{"cert_file", "key_file"}},
	}
	byName := make(map[string]toolSpec, len(tools))
	for _, spec := range tools {
		byName[spec.name] = spec
	}
	for _, testCase := range cases {
		spec, ok := byName[testCase.name]
		if !ok {
			t.Errorf("tool %s not registered", testCase.name)
			continue
		}
		var shape struct {
			Required             []string                   `json:"required"`
			Properties           map[string]json.RawMessage `json:"properties"`
			AdditionalProperties *bool                      `json:"additionalProperties"`
		}
		if err := json.Unmarshal([]byte(spec.schema), &shape); err != nil {
			t.Errorf("tool %s schema is not valid JSON: %v", testCase.name, err)
			continue
		}
		for _, property := range testCase.properties {
			if _, ok := shape.Properties[property]; !ok {
				t.Errorf("tool %s schema lacks property %q: %s", testCase.name, property, spec.schema)
			}
		}
		for _, required := range testCase.required {
			if !containsString(shape.Required, required) {
				t.Errorf("tool %s schema required=%v, want %q", testCase.name, shape.Required, required)
			}
		}
		if shape.AdditionalProperties == nil || !*shape.AdditionalProperties {
			t.Errorf("tool %s schema additionalProperties=%v, want true（向前兼容）", testCase.name, shape.AdditionalProperties)
		}
	}
}

// U11-9（第 78 轮）：control_system_task 的 schema enum、handler 接受集
// （taskmonitor.go ControlSystemTask：start/stop/restart）与描述必须一致，
// 并说明与 toggle_system_task 的分工。
func TestControlSystemTaskSchemaMatchesHandlerActionSet(t *testing.T) {
	var shape struct {
		Properties struct {
			Action struct {
				Enum []string `json:"enum"`
			} `json:"action"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(controlTaskSchema), &shape); err != nil {
		t.Fatalf("parse controlTaskSchema: %v", err)
	}
	want := []string{"start", "stop", "restart"}
	if len(shape.Properties.Action.Enum) != len(want) {
		t.Fatalf("controlTaskSchema enum=%v, want %v", shape.Properties.Action.Enum, want)
	}
	for _, action := range want {
		if !containsString(shape.Properties.Action.Enum, action) {
			t.Errorf("controlTaskSchema enum=%v, want %q", shape.Properties.Action.Enum, action)
		}
	}
	var spec *toolSpec
	for index := range tools {
		if tools[index].name == "control_system_task" {
			spec = &tools[index]
			break
		}
	}
	if spec == nil {
		t.Fatal("control_system_task not registered")
	}
	for _, action := range want {
		if !strings.Contains(spec.description, action) {
			t.Errorf("control_system_task description=%q lacks action %q", spec.description, action)
		}
	}
	if !strings.Contains(spec.description, "toggle_system_task") {
		t.Errorf("control_system_task description=%q lacks toggle_system_task division note", spec.description)
	}
	if strings.Contains(spec.description, "仅 restart") || strings.Contains(spec.description, "action=restart——启停已由调度开关承担") {
		t.Errorf("control_system_task description=%q retains stale restart-only wording", spec.description)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestListToolSpecs_returns_sanitized_independent_copy(t *testing.T) {
	// Given
	first := ListToolSpecs()

	// When
	first[0].Name = "changed_by_caller"
	second := ListToolSpecs()
	encoded, err := json.Marshal(second)

	// Then
	if err != nil {
		t.Fatalf("marshal public tool specs: %v", err)
	}
	if len(second) != len(tools) {
		t.Fatalf("tool count=%d, want %d", len(second), len(tools))
	}
	if second[0].Name == "changed_by_caller" {
		t.Fatal("ListToolSpecs returned caller-mutable registry state")
	}
	if strings.Contains(string(encoded), "path_args") || strings.Contains(string(encoded), "query_args") {
		t.Fatalf("public registry leaks internal fields: %s", encoded)
	}
	for index, spec := range second {
		if spec.Name == "" || spec.Description == "" || spec.Method == "" || !strings.HasPrefix(spec.Path, "/api/v1/") {
			t.Fatalf("tool %d has incomplete public metadata: %+v", index, spec)
		}
		_, probe := ReadOnlyProbeTools[spec.Name]
		_, hidden := readOnlyHiddenTools[spec.Name]
		if wantReadOnly := (spec.Method == http.MethodGet && !hidden) || probe; spec.ReadOnly != wantReadOnly {
			t.Fatalf("tool %s read_only=%v method=%s probe=%v hidden=%v, want %v", spec.Name, spec.ReadOnly, spec.Method, probe, hidden, wantReadOnly)
		}
		if len(spec.InputSchema) > 0 {
			var shape map[string]any
			if err := json.Unmarshal(spec.InputSchema, &shape); err != nil || shape["type"] != "object" {
				t.Fatalf("tool %s input_schema is not a valid JSON schema object: %s", spec.Name, spec.InputSchema)
			}
		}
	}
}
