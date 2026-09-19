package mcpserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// APIMCP44-1(P3):filterReadOnlyTools 对错误形态(含 error 成员)或缺
// result/result.tools 的响应必须原样透传输入字节——固定结构体重建会把
// error 形态改写为「result.tools:null」假成功,吞掉上游错误信号。
func TestAPIMCP44_1_filterReadOnlyTools_passthrough_non_tools_list_shapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "JSON-RPC error 形态", input: `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}`},
		{name: "缺 result 成员", input: `{"jsonrpc":"2.0","id":1}`},
		{name: "result 缺 tools 成员", input: `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{name: "result 非对象", input: `{"jsonrpc":"2.0","id":1,"result":42}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// When
			filtered, err := filterReadOnlyTools([]byte(tt.input))

			// Then 原样透传:无错误、输出与输入逐字节相等
			if err != nil {
				t.Fatalf("filterReadOnlyTools err=%v, want nil(透传不得报错)", err)
			}
			if !bytes.Equal(filtered, []byte(tt.input)) {
				t.Fatalf("非 tools 列表形态被重建:\n输入: %s\n输出: %s\nwant 逐字节透传", tt.input, string(filtered))
			}
		})
	}
}

// APIMCP44-1 回归形状:正常 tools/list 响应仍按只读白名单过滤——GET 工具
// (list_rules)保留,写工具(create_rule)剔除,jsonrpc/id 原样保留。
func TestAPIMCP44_1_filterReadOnlyTools_still_filters_tools_list(t *testing.T) {
	// Given 正常 tools/list 响应(一只读一写工具)
	input := `{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"list_rules","description":"列出"},{"name":"create_rule","description":"创建"}]}}`

	// When
	filtered, err := filterReadOnlyTools([]byte(input))

	// Then
	if err != nil {
		t.Fatalf("filterReadOnlyTools err=%v", err)
	}
	out := string(filtered)
	if !strings.Contains(out, `"list_rules"`) {
		t.Fatalf("只读工具 list_rules 必须保留,输出: %s", out)
	}
	if strings.Contains(out, `"create_rule"`) {
		t.Fatalf("写工具 create_rule 必须剔除,输出: %s", out)
	}
	if !strings.Contains(out, `"id":7`) || !strings.Contains(out, `"jsonrpc":"2.0"`) {
		t.Fatalf("jsonrpc/id 成员必须保留,输出: %s", out)
	}
}

// APIMCP44-3(P5,文案):MCP 回环客户端超时错误提示必须补「操作可能已在服务端
// 生效,请先用查询类工具核对状态再重试」——纯传输层失败文案会让 Agent 直接
// 重试非幂等操作(备份/导入/重启等),造成重复执行。
func TestAPIMCP44_3_forward_timeout_error_carries_state_check_hint(t *testing.T) {
	// Given 上游响应慢于客户端超时
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	t.Cleanup(slow.Close)
	client := &http.Client{Timeout: 50 * time.Millisecond}
	spec := toolSpec{name: "list_rules", method: http.MethodGet, path: "/rules"}
	call := mcp.CallToolRequest{}
	call.Header = http.Header{}
	call.Header.Set("X-API-Key", "lb_sk_test")

	// When
	_, err := forward(context.Background(), client, slow.URL, "", spec, call)

	// Then 超时错误必须含状态核对提示
	if err == nil {
		t.Fatal("慢上游+短超时必须产生错误")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("超时错误须点名超时语义,实际: %v", err)
	}
	if !strings.Contains(err.Error(), "操作可能已在服务端生效") {
		t.Fatalf("超时错误须附「先核对状态再重试」提示,实际: %v", err)
	}
}

// APIMCP44-3 回归形状:非超时失败(连接拒绝)保持原「内部 API 请求失败」
// 文案,不带超时提示。
func TestAPIMCP44_3_forward_non_timeout_error_keeps_original_message(t *testing.T) {
	// Given 不可达地址(连接拒绝,非超时)
	client := &http.Client{Timeout: time.Second}
	spec := toolSpec{name: "list_rules", method: http.MethodGet, path: "/rules"}
	call := mcp.CallToolRequest{}
	call.Header = http.Header{}
	call.Header.Set("X-API-Key", "lb_sk_test")

	// When
	_, err := forward(context.Background(), client, "http://127.0.0.1:1", "", spec, call)

	// Then
	if err == nil {
		t.Fatal("不可达地址必须产生错误")
	}
	if !strings.Contains(err.Error(), "内部 API 请求失败") {
		t.Fatalf("非超时失败须保持原文案,实际: %v", err)
	}
	if strings.Contains(err.Error(), "操作可能已在服务端生效") {
		t.Fatalf("非超时失败不得带超时提示,实际: %v", err)
	}
}

// W3-R44-4(第 44 轮 W3 评审,健壮性):显式 "error":null 形态(RawMessage 取到
// 4 字节 "null")不得误判为错误形态而跳过过滤——正常 result.tools 仍须过滤。
func TestW3R44_4_filterReadOnlyTools_error_null_still_filters(t *testing.T) {
	// Given error:null + 正常 result.tools(一写工具)
	input := `{"jsonrpc":"2.0","id":9,"error":null,"result":{"tools":[{"name":"create_rule","description":"创建"}]}}`

	// When
	filtered, err := filterReadOnlyTools([]byte(input))

	// Then 过滤仍生效:写工具被剔除(修复前 error:null 被当错误形态整体透传)
	if err != nil {
		t.Fatalf("filterReadOnlyTools err=%v", err)
	}
	if strings.Contains(string(filtered), `"create_rule"`) {
		t.Fatalf("error:null 不得跳过滤,写工具必须剔除,输出: %s", filtered)
	}
}
