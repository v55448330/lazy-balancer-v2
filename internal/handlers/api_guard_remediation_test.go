package handlers

// 规则版本前置条件（乐观并发）的机器契约门：面板编辑规则时会回传打开表单时的
// updated_at，别人先提交则 409 而不是静默覆盖——但这条护栏此前只在面板代码里，
// OpenAPI 生成的 SDK 与 MCP Agent 都看不到（缺席的字段=不可发现的保护）。
// 本文件同时钉两侧：
//   - OpenAPI：PUT /rules/{caddy_id} 必须登记 expected_updated_at 的两个错误码
//     与说明，GET /rules/{caddy_id} 示例必须携带 updated_at 基线；
//   - 导入面：api_keys.mcp_ip_whitelist 的带外数据校验（畸形白名单此前落库后
//     该 Key 每个请求恒 500）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestAPIDocs_UpdateRuleDocumentsVersionPrecondition(t *testing.T) {
	route := routesEntry(t, "PUT /rules/:caddy_id")
	errorsJoined := strings.Join(route.Errors, "\n")
	for _, want := range []string{"409 rule_version_conflict", "400 invalid_expected_updated_at"} {
		if !strings.Contains(errorsJoined, want) {
			t.Errorf("PUT /rules/:caddy_id 未登记错误码 %q（并发护栏的失败形态对机器客户端不可见）：%v", want, route.Errors)
		}
	}
	if !strings.Contains(route.Description, "expected_updated_at") {
		t.Errorf("PUT /rules/:caddy_id 描述未说明 expected_updated_at 版本前置条件：%s", route.Description)
	}

	// 生成后的 YAML 必须同样携带（路由表 → 规格是单向派生，此处防派生丢键）。
	yaml := buildOpenAPIYAML()
	for _, want := range []string{"rule_version_conflict", "invalid_expected_updated_at"} {
		if !strings.Contains(yaml, want) {
			t.Errorf("openapi.yaml 未包含 %q", want)
		}
	}
}

func TestAPIDocs_RuleDetailExampleCarriesVersionBaseline(t *testing.T) {
	route := routesEntry(t, "GET /rules/:caddy_id")
	var example map[string]any
	if err := json.Unmarshal([]byte(route.Response), &example); err != nil {
		t.Fatalf("GET /rules/:caddy_id 示例不是 JSON: %v", err)
	}
	for _, key := range []string{"updated_at", "created_at", "created_by", "updated_by"} {
		if _, ok := example[key]; !ok {
			t.Errorf("GET /rules/:caddy_id 示例缺 %q：PUT 的版本前置条件以 updated_at 为基线，示例不给基线等于让 SDK 无从取用", key)
		}
	}
}

// 校验门单测：畸形白名单必须在导入校验阶段被点名拒绝（不是落库后每请求 500）。
func TestValidateV2BackupMCPIPWhitelist(t *testing.T) {
	cases := []struct {
		name      string
		rows      []map[string]any
		wantErr   bool
		wantInMsg string
	}{
		{
			name: "合法 JSON 数组",
			rows: []map[string]any{{"mcp_ip_whitelist": `["10.0.0.0/8","192.168.1.5"]`}},
		},
		{
			name: "空串与字面量 null（旧从节点导出形态）",
			rows: []map[string]any{{"mcp_ip_whitelist": ""}, {"mcp_ip_whitelist": "null"}},
		},
		{
			name: "列缺失",
			rows: []map[string]any{{"name": "key-without-column"}},
		},
		{
			name:      "JSON 形态损坏",
			rows:      []map[string]any{{"mcp_ip_whitelist": `["10.0.0.0/8"`}},
			wantErr:   true,
			wantInMsg: "api_keys 第 1 行",
		},
		{
			name:      "含非 CIDR 条目",
			rows:      []map[string]any{{"mcp_ip_whitelist": `["10.0.0.0/8","not-a-cidr"]`}},
			wantErr:   true,
			wantInMsg: "not-a-cidr",
		},
		{
			name:      "数组元素不是字符串",
			rows:      []map[string]any{{"mcp_ip_whitelist": `[10]`}},
			wantErr:   true,
			wantInMsg: "api_keys 第 1 行",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateV2BackupMCPIPWhitelist(tc.rows)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("不应拒绝：%v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("畸形白名单必须被拒绝")
			}
			if !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Fatalf("错误文案未点名（want 含 %q）：%v", tc.wantInMsg, err)
			}
		})
	}
}

// 写入侧归一：裸 IP → /32、重复条目去重、字面量 null/空串 → ”（与写侧
// encodeMCPIPWhitelist 同形态），保证落库值可被认证中间件直接解析。
func TestRestoreRowStatementNormalizesMCPIPWhitelist(t *testing.T) {
	valid := map[string]bool{"mcp_ip_whitelist": true, "name": true}
	cases := []struct {
		name string
		raw  any
		want string
	}{
		{name: "裸 IPv4 补 /32", raw: `["192.168.1.5"]`, want: `["192.168.1.5/32"]`},
		{name: "重复条目去重", raw: `["10.0.0.0/8","10.0.0.1/8"]`, want: `["10.0.0.0/8"]`},
		{name: "字面量 null", raw: "null", want: ""},
		{name: "空串", raw: "", want: ""},
		{name: "IPv6 裸地址", raw: `["::1"]`, want: `["::1/128"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statement, values, ok := restoreRowStatement("api_keys", map[string]any{
				"name":             "key",
				"mcp_ip_whitelist": tc.raw,
			}, valid)
			if !ok {
				t.Fatal("行内至少一列有效，ok 必须为 true")
			}
			// values 与列名同序（restoreRowStatement 按列名排序拼 SQL），
			// "mcp_ip_whitelist" < "name"，故白名单值在首位。
			if len(values) != 2 || values[0] != tc.want {
				t.Fatalf("归一值=%v（sql=%s），want %q", values, statement, tc.want)
			}
		})
	}
}

// 端到端：畸形白名单的备份整包 400（不落库、不再出现「导入成功但 Key 恒 500」）。
func TestImportConfigBackupRejectsMalformedMCPIPWhitelist(t *testing.T) {
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"api_keys": {{
			"id": 1, "name": "mcp-agent", "key_hash": "hash", "key_prefix": "lb_sk_test",
			"created_by": 1, "is_enabled": 1, "mcp_enabled": 1, "read_only": 0,
			"mcp_ip_whitelist": `["10.0.0.0/8","definitely-not-a-cidr"]`,
		}},
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "白名单") {
		t.Fatalf("错误文案未点名 IP 白名单：%s", response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE name='mcp-agent'`).Scan(&count); err != nil {
		t.Fatalf("计数 api_keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("被拒绝的导入不得落库，count=%d", count)
	}
}
