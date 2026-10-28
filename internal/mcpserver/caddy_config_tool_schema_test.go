package mcpserver

// update_caddy_config 的 REST 契约是
// {"content":"<完整 Caddy 配置 JSON 文本>"}（handlers.PutCaddyConfig 只解
// content 字段，再对该字符串二次 Unmarshal）；schema 却声明「整份 JSON 直传」，
// Agent 按 schema 构参必然被 REST 400（缺少 content / 无效的 JSON 配置）。
// validate_config 走 handlers.ValidateConfig 直接绑定请求体，继续保留直传语义。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateCaddyConfigSchemaMatchesRESTContentBinding(t *testing.T) {
	// Given：schema 文本
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(updateCaddyConfigSchema), &schema); err != nil {
		t.Fatalf("updateCaddyConfigSchema 不是合法 JSON: %v", err)
	}

	// Then：content 必须必填且为字符串（REST 绑定 Content string）
	required := make(map[string]struct{}, len(schema.Required))
	for _, name := range schema.Required {
		required[name] = struct{}{}
	}
	if _, ok := required["content"]; !ok {
		t.Fatalf("required=%v, want 含 content——REST 只解 {\"content\":...}，缺 content 恒 400", schema.Required)
	}
	raw, ok := schema.Properties["content"]
	if !ok {
		t.Fatalf("properties 缺 content：%s", updateCaddyConfigSchema)
	}
	var contentProp struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &contentProp); err != nil {
		t.Fatalf("content property 不是合法 JSON: %v", err)
	}
	if contentProp.Type != "string" {
		t.Fatalf("content.type=%q, want string（REST 侧 Content string，配置本体是 JSON 文本）", contentProp.Type)
	}

	// Then：validate_config 的直传语义不得被牵连（整份 JSON 本体作请求体）
	var validateSchema struct {
		Required             []string       `json:"required"`
		Properties           map[string]any `json:"properties"`
		AdditionalProperties bool           `json:"additionalProperties"`
	}
	if err := json.Unmarshal([]byte(validateConfigSchema), &validateSchema); err != nil {
		t.Fatalf("validateConfigSchema 不是合法 JSON: %v", err)
	}
	if len(validateSchema.Required) != 0 || len(validateSchema.Properties) != 0 || !validateSchema.AdditionalProperties {
		t.Fatalf("validate_config schema=%s, want 无固定字段的直传形态（REST 直接绑定请求体）", validateConfigSchema)
	}
}

// 转发行为：content 必须原样作为 JSON 字段进入请求体（不是被展开成顶层字段）。
func TestUpdateCaddyConfigToolForwardsContentField(t *testing.T) {
	const configBody = `{"apps":{"http":{"servers":{}}}}`
	var got map[string]any
	var method, path string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer rest.Close()

	handler := NewForTest(rest.URL+"/api/v1", rest.Client())
	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"update_caddy_config","arguments":{"content":` + mustJSONString(t, configBody) + `}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_forward-test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("mcp status=%d body=%q", response.Code, response.Body.String())
	}
	if method != http.MethodPut || path != "/api/v1/caddy/config" {
		t.Fatalf("REST 收到 %s %s, want PUT /api/v1/caddy/config", method, path)
	}
	if len(got) != 1 {
		t.Fatalf("body=%v, want 只有 content 一个字段（顶层展开会让 REST 400）", got)
	}
	if got["content"] != configBody {
		t.Fatalf("content=%v, want 原样配置 JSON 文本 %q", got["content"], configBody)
	}
}

func mustJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %q: %v", value, err)
	}
	return string(encoded)
}
