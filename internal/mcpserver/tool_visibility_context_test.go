package mcpserver

// 网关与 MCP 传输层的一次性元数据通道：请求体已由网关限长读取并解析出
// JSON-RPC 定位字段、Key 属主属性已由 apiKeyAuth 解析（同一次
// db.ResolveAPIKeyIdentity）——tools/list 可见性过滤必须复用，不得重复读取
// 同一 1 MiB 请求体、也不得重复点查 Key。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// countingReadCloser 记录请求体被读取的次数。
type countingReadCloser struct {
	reader io.Reader
	reads  int
}

func (b *countingReadCloser) Read(p []byte) (int, error) {
	b.reads++
	return b.reader.Read(p)
}

func (b *countingReadCloser) Close() error { return nil }

// toolsListHandler 返回含一个只读工具（list_rules）与一个写工具（create_rule）
// 的 tools/list 响应，供可见性过滤断言。
func toolsListHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_rules"},{"name":"create_rule"}]}}`))
	})
}

func toolNamesFromResponse(t *testing.T, body []byte) []string {
	t.Helper()
	var payload struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("parse tools/list response %q: %v", body, err)
	}
	names := make([]string, 0, len(payload.Result.Tools))
	for _, tool := range payload.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// 网关已注入 method/id 与 Key 属主属性时：请求体不再被读取，resolver 不再被
// 调用，过滤仍按 context 的只读轴执行。
func TestServeWithToolVisibility_reusesGatewayRequestMetaAndKeyVisibility(t *testing.T) {
	resolver := func(string) (apiKeyVisibility, error) {
		t.Fatal("resolver 不应被调用：Key 属主属性已由网关注入 context")
		return apiKeyVisibility{}, nil
	}
	body := &countingReadCloser{reader: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", body)
	request = request.WithContext(WithAPIKeyVisibility(
		WithRequestMeta(request.Context(), RequestMeta{Method: "tools/list", ID: json.RawMessage(`1`)}),
		true, false,
	))
	response := httptest.NewRecorder()

	serveWithToolVisibility(response, request, toolsListHandler(), resolver)

	if body.reads != 0 {
		t.Fatalf("可见性层读取请求体 %d 次，want 0（网关已读取并解析）", body.reads)
	}
	names := toolNamesFromResponse(t, response.Body.Bytes())
	if len(names) != 1 || names[0] != "list_rules" {
		t.Fatalf("只读 Key tools/list=%v, want [list_rules]", names)
	}
}

// 网关注入的 method 不是 tools/list 时零过滤透传（且同样不读体）。
func TestServeWithToolVisibility_gatewayMetaNonToolsListSkipsFiltering(t *testing.T) {
	resolver := func(string) (apiKeyVisibility, error) {
		t.Fatal("非 tools/list 请求不得触发可见性解析")
		return apiKeyVisibility{}, nil
	}
	body := &countingReadCloser{reader: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", body)
	request = request.WithContext(WithRequestMeta(request.Context(), RequestMeta{Method: "ping", ID: json.RawMessage(`1`)}))
	response := httptest.NewRecorder()

	serveWithToolVisibility(response, request, toolsListHandler(), resolver)

	if body.reads != 0 {
		t.Fatalf("可见性层读取请求体 %d 次，want 0", body.reads)
	}
	if names := toolNamesFromResponse(t, response.Body.Bytes()); len(names) != 2 {
		t.Fatalf("非 tools/list 响应被过滤: %v", names)
	}
}

// tools/list 过滤重写响应体后，上游声明的表示元数据必须一并失效：过滤结果
// 更短且内容不同，沿用上游 Content-Length 会让客户端按旧长度截读（unexpected
// EOF / JSON 解析失败），沿用 ETag 会让缓存把改写的工具列表当成同一实体。
// 上游显式声明这两个头由注入的上游 handler 复现——传输层当前不声明它们，
// 契约防的是「头随体重写后漂移」这类加固缺口。
func TestServeWithToolVisibility_dropsUpstreamRepresentationHeadersOnRewrite(t *testing.T) {
	resolver := func(string) (apiKeyVisibility, error) { return apiKeyVisibility{readOnly: true}, nil }
	upstreamBody := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_rules"},{"name":"create_rule"}]}}`)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamBody)))
		w.Header().Set("ETag", `"upstream-unfiltered-body"`)
		_, _ = w.Write(upstreamBody)
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	request = request.WithContext(WithRequestMeta(request.Context(), RequestMeta{Method: "tools/list", ID: json.RawMessage(`1`)}))
	response := httptest.NewRecorder()

	serveWithToolVisibility(response, request, next, resolver)

	filtered := response.Body.Bytes()
	if len(filtered) >= len(upstreamBody) {
		t.Fatalf("前置条件不成立：过滤后体未变短（%d vs 上游 %d）", len(filtered), len(upstreamBody))
	}
	if got := response.Header().Get("Content-Length"); got != "" && got != strconv.Itoa(len(filtered)) {
		t.Fatalf("Content-Length=%q 与重写后体长 %d 不一致（客户端会按旧长度截读）", got, len(filtered))
	}
	if got := response.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag=%q 未随重写的响应体失效（缓存会把不同工具列表当同一实体）", got)
	}
	if names := toolNamesFromResponse(t, filtered); len(names) != 1 || names[0] != "list_rules" {
		t.Fatalf("过滤结果=%v, want [list_rules]", names)
	}
}

// tools/list 的通知形态（JSON-RPC 无 id）不是请求：MCP Streamable HTTP 对通知
// 回 202 空体，客户端不会也不该把任何响应体配对给它。旧实现只判 method，
// 把通知当请求处理：recorder 收到空体 → 过滤失败 → fail-closed 写出
// 200 + id:null，凭空构造一个客户端无从配对的响应（协议形态偏差）。
func TestServeWithToolVisibility_notificationToolsListKeepsProtocolNoContent(t *testing.T) {
	resolver := func(string) (apiKeyVisibility, error) {
		t.Fatal("通知形态无响应可配对，不得触发可见性解析")
		return apiKeyVisibility{}, nil
	}
	// mcp-go 对无 id 的 tools/list 回 202 空体（response == nil 分支）。
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	note := `{"jsonrpc":"2.0","method":"tools/list","params":{}}`
	body := &countingReadCloser{reader: strings.NewReader(note)}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", body)
	request = request.WithContext(WithRequestMeta(request.Context(), RequestMeta{Method: "tools/list"}))
	response := httptest.NewRecorder()

	serveWithToolVisibility(response, request, next, resolver)

	if response.Code != http.StatusAccepted {
		t.Fatalf("通知 status=%d, want 202（不得被改写成 200 应答）", response.Code)
	}
	if got := strings.TrimSpace(response.Body.String()); got != "" {
		t.Fatalf("通知响应体=%q, want 空（客户端无从配对该响应）", got)
	}
}
