package mcpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestCreateRuleToolForwardsBodyAndAPIKey(t *testing.T) {
	var received bool
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/rules" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "lb_sk_forward-test" {
			t.Errorf("X-API-Key=%q", r.Header.Get("X-API-Key"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["name"] != "MCP rule" || body["protocol"] != "http" {
			t.Errorf("body=%v", body)
		}
		upstreams := body["upstreams"].([]any)
		if enabled, ok := upstreams[0].(map[string]any)["enabled"].(bool); !ok || !enabled {
			t.Errorf("upstreams=%v", upstreams)
		}
		received = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"caddy_id":"lb_created"}}`))
	}))
	defer rest.Close()

	handler := New(rest.URL+"/api/v1", rest.Client())
	body := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_rule","arguments":{"name":"MCP rule","protocol":"http","listen_port":8080,"upstreams":[{"host":"127.0.0.1","port":9000}]}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_forward-test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || !received || !strings.Contains(response.Body.String(), "lb_created") {
		t.Fatalf("status=%d received=%v body=%q", response.Code, received, response.Body.String())
	}
}

func TestIssueCertificateSchemaRequiresExplicitAllOrCaddyID(t *testing.T) {
	// Given：C-19 确认门——空 body（全量重签）不再放行，批量必须显式
	// {"all":true}（enum 锁死 true，防 all:false 静默变成空批量）；定向
	// 签发仍走 caddy_id（domain 可选）。
	var schema struct {
		Properties struct {
			All struct {
				Enum []bool `json:"enum"`
			} `json:"all"`
		} `json:"properties"`
		OneOf []struct {
			Required []string `json:"required"`
		} `json:"oneOf"`
	}

	// When
	if err := json.Unmarshal([]byte(issueCertificateSchema), &schema); err != nil {
		t.Fatal(err)
	}

	// Then
	if len(schema.OneOf) != 2 || strings.Join(schema.OneOf[0].Required, ",") != "all" || strings.Join(schema.OneOf[1].Required, ",") != "caddy_id" {
		t.Fatalf("oneOf=%+v", schema.OneOf)
	}
	if len(schema.Properties.All.Enum) != 1 || !schema.Properties.All.Enum[0] {
		t.Fatalf("all enum=%v, want [true]", schema.Properties.All.Enum)
	}
}

func TestUpdateConfigSchemaExcludesCaddyLogPath(t *testing.T) {
	// Given：caddy_log_path 死配置已全链路摘除（db 列已 drop），schema 不得再收该字段
	var schema struct {
		Properties map[string]any `json:"properties"`
	}

	// When
	err := json.Unmarshal([]byte(updateConfigSchema), &schema)

	// Then
	if err != nil {
		t.Fatalf("parse update config schema: %v", err)
	}
	if _, exists := schema.Properties["caddy_log_path"]; exists {
		t.Fatal("update_config schema must not contain removed caddy_log_path")
	}
	if _, exists := schema.Properties["caddy_log_level"]; !exists {
		t.Fatal("update_config schema missing caddy_log_level")
	}
	if _, exists := schema.Properties["caddy_log_size_mb"]; !exists {
		t.Fatal("update_config schema missing caddy_log_size_mb")
	}
}

func TestToolsListHidesWriteTools_forReadOnlyAPIKey(t *testing.T) {
	// Given
	resolver := func(apiKey string) (bool, error) {
		return apiKey == "lb_sk_read-only", nil
	}
	handler := newWithReadOnlyResolver("http://127.0.0.1/api/v1", http.DefaultClient, "", resolver)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_read-only")
	response := httptest.NewRecorder()

	// When
	handler.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var payload struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse tools/list response: %v", err)
	}
	// 54 = 对只读 Key 可见的 GET 工具数（export_config 属 GET 但被 readOnlyHiddenTools 隐藏——HTTP 层只读 Key 403），写工具被只读可见性收敛隐藏
	if len(payload.Result.Tools) != 54 {
		t.Fatalf("read-only tool count=%d, want 54", len(payload.Result.Tools))
	}
	dashboardVisible := false
	for _, tool := range payload.Result.Tools {
		if tool.Name == "get_metrics_dashboard" {
			dashboardVisible = true
		}
		for _, spec := range tools {
			if spec.name == tool.Name && spec.method != http.MethodGet {
				t.Errorf("read-only tools/list exposes write tool %s", tool.Name)
			}
		}
	}
	if !dashboardVisible {
		t.Fatal("read-only tools/list hides get_metrics_dashboard")
	}
}

func TestResolveAPIKeyReadOnly_returnsPersistedPermission(t *testing.T) {
	// Given
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	apiKey := "lb_sk_persisted-read-only"
	hash := sha256.Sum256([]byte(apiKey))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (91,'mcp-read-only','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,read_only) VALUES ('mcp-read-only',?,?,91,1,1,1)`, fmt.Sprintf("%x", hash[:]), apiKey[:12]); err != nil {
		t.Fatal(err)
	}

	// When
	readOnly, err := resolveAPIKeyReadOnly(apiKey)

	// Then
	if err != nil || !readOnly {
		t.Fatalf("readOnly=%v err=%v", readOnly, err)
	}
}

func TestResolveAPIKeyReadOnly_treatsDisabledOwnerAsNotReadOnly(t *testing.T) {
	// Given
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	apiKey := "lb_sk_disabled-owner"
	hash := sha256.Sum256([]byte(apiKey))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (92,'disabled-owner','x','admin',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,read_only) VALUES ('disabled-owner',?,?,92,1,1,1)`, fmt.Sprintf("%x", hash[:]), apiKey[:12]); err != nil {
		t.Fatal(err)
	}

	// When
	readOnly, err := resolveAPIKeyReadOnly(apiKey)

	// Then：所有者被禁用时按 key-not-found 处理，不视为只读
	if err == nil {
		t.Fatalf("want key-not-found err for disabled owner, got nil")
	}
	if readOnly {
		t.Fatalf("disabled owner key treated as read-only")
	}
}

func TestResolveAPIKeyReadOnly_rejectsExpiredKey(t *testing.T) {
	// Given
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	apiKey := "lb_sk_expired-key"
	hash := sha256.Sum256([]byte(apiKey))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (93,'expired-owner','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,read_only,expires_at) VALUES ('expired-owner',?,?,93,1,1,1,datetime('now','-1 hour'))`, fmt.Sprintf("%x", hash[:]), apiKey[:12]); err != nil {
		t.Fatal(err)
	}

	// When
	readOnly, err := resolveAPIKeyReadOnly(apiKey)

	// Then：key 已过期时按 key-not-found 处理，不视为只读
	if err == nil {
		t.Fatalf("want key-not-found err for expired key, got nil")
	}
	if readOnly {
		t.Fatalf("expired key treated as read-only")
	}
}

// 第 15 轮审计 K-1：forward 必须把网关注入 context 的真实客户端 IP 转写为内部
// 头（回环自调用下接收端 RemoteAddr 恒为 127.0.0.1，审计源 IP 依赖此头）。
func TestForwardPropagatesClientIPFromContext(t *testing.T) {
	var receivedIP string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedIP = r.Header.Get(InternalClientIPHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer rest.Close()

	handler := New(rest.URL+"/api/v1", rest.Client())
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_rules","arguments":{}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_ip-propagation-test")
	request = request.WithContext(WithClientIP(request.Context(), "192.0.2.7"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if receivedIP != "192.0.2.7" {
		t.Fatalf("internal API did not receive the real client IP header, got %q", receivedIP)
	}
}

// 无网关注入（直连/旧网关）时不得设置内部头——接收端按 ClientIP 兜底。
func TestForwardOmitsClientIPHeaderWithoutContextInjection(t *testing.T) {
	var receivedIP string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedIP = r.Header.Get(InternalClientIPHeader)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer rest.Close()

	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "list_rules", `{}`)
	// MCP 信封内层 JSON 文本被转义（\"code\":0），按转义形态匹配
	if !strings.Contains(result, `\"code\":0`) {
		t.Fatalf("result=%q", result)
	}
	if receivedIP != "" {
		t.Fatalf("internal client IP header must be absent without gateway injection, got %q", receivedIP)
	}
}

func TestIsLoopbackHTTPURLAllowsIPv6Loopback(t *testing.T) {
	target, err := url.Parse("http://[::1]:8000/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	if !isLoopbackHTTPURL(target) {
		t.Fatal("IPv6 loopback URL was rejected")
	}
}

func TestRedirectedPOSTPreservesMethodAndBody(t *testing.T) {
	wantBody := `{"caddy_id":"rule-1","domain":"example.com"}`
	requests := 0
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Location", "/api/v1/redirected")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/redirected" || string(body) != wantBody {
			t.Errorf("request=%s %s body=%q", r.Method, r.URL.Path, body)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer rest.Close()

	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "issue_certificate", wantBody)
	if requests != 2 || !strings.Contains(result, "ok") {
		t.Fatalf("requests=%d result=%q", requests, result)
	}
}

func TestSecondRedirectReturnsError(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/again")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer rest.Close()

	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "issue_certificate", `{}`)
	if !strings.Contains(result, "重定向次数超过限制") {
		t.Fatalf("result=%q", result)
	}
}

func TestExternalRedirectDoesNotSendAPIKey(t *testing.T) {
	externalRequests := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "localhost:8000" {
			return redirectResponse(r, "https://example.com/api/v1/rules"), nil
		}
		externalRequests++
		return nil, nil
	})}

	result := callTool(t, New("http://localhost:8000/api/v1", client), "issue_certificate", `{}`)
	if externalRequests != 0 || !strings.Contains(result, "拒绝非回环") {
		t.Fatalf("externalRequests=%d result=%q", externalRequests, result)
	}
}

func TestRelativeRedirectIsResolved(t *testing.T) {
	var redirectedPath string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if redirectedPath == "" {
			redirectedPath = "pending"
			return redirectResponse(r, "next"), nil
		}
		redirectedPath = r.URL.Path
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: make(http.Header), Request: r}, nil
	})}

	result := callTool(t, New("http://localhost:8000/api/v1", client), "issue_certificate", `{}`)
	if redirectedPath != "/api/v1/certificates/next" || !strings.Contains(result, "ok") {
		t.Fatalf("path=%q result=%q", redirectedPath, result)
	}
}

func TestOversizedResponseReturnsToolError(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseSize+1))
	}))
	defer rest.Close()

	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "issue_certificate", `{}`)
	if !strings.Contains(result, "超过 4 MiB 上限") || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("result=%q", result)
	}
}

func TestResetUserPasswordToolInjectsRandomPassword(t *testing.T) {
	// Given：后端要求 new_password，工具层应注入 16 位随机字母数字密码并在成功结果中回显
	var receivedPassword string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/users/7/reset-password" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		password, _ := body["new_password"].(string)
		if len(password) != 16 {
			t.Errorf("new_password=%q, want 16 chars", password)
		}
		for _, ch := range password {
			if !strings.ContainsRune(randomPasswordCharset, ch) {
				t.Errorf("new_password=%q contains non-alphanumeric rune %q", password, ch)
			}
		}
		receivedPassword = password
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"密码重置成功"}`))
	}))
	defer rest.Close()

	// When
	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "reset_user_password", `{"id":7}`)

	// Then
	if !strings.Contains(result, "密码重置成功") {
		t.Fatalf("result=%q", result)
	}
	if !strings.Contains(result, "本次密码为系统生成："+receivedPassword) {
		t.Fatalf("result must echo generated password %q, got %q", receivedPassword, result)
	}
}

func TestResetUserPasswordToolDoesNotEchoPasswordOnFailure(t *testing.T) {
	// Given：后端返回非 2xx 时不回显密码，避免重置失败却泄露已生成口令
	var receivedPassword string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		receivedPassword, _ = body["new_password"].(string)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":404,"message":"用户不存在"}`))
	}))
	defer rest.Close()

	// When
	result := callTool(t, New(rest.URL+"/api/v1", rest.Client()), "reset_user_password", `{"id":404}`)

	// Then
	if !strings.Contains(result, "用户不存在") || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("result=%q", result)
	}
	if strings.Contains(result, receivedPassword) {
		t.Fatalf("result must not echo password on failure, got %q", result)
	}
}

func callTool(t *testing.T, handler http.Handler, name, arguments string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_redirect-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Body.String()
}

func redirectResponse(request *http.Request, location string) *http.Response {
	header := make(http.Header)
	header.Set("Location", location)
	return &http.Response{StatusCode: http.StatusMovedPermanently, Body: http.NoBody, Header: header, Request: request}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestUpdateRuleToolInjectsDefaultUpstreamEnabled(t *testing.T) {
	// Given：update_rule 与 create_rule 同为 upstreams 全量替换入口——载荷缺省
	// enabled 时 MCP 层须注入默认 true（对齐 create_rule），显式 false 保留。
	var forwardedUpstreams []any
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/rules/lb_upsert" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		forwardedUpstreams = body["upstreams"].([]any)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"Rule updated"}`))
	}))
	defer rest.Close()

	handler := New(rest.URL+"/api/v1", rest.Client())

	// When
	response := callTool(t, handler, "update_rule", `{"caddy_id":"lb_upsert","upstreams":[{"host":"127.0.0.1","port":9000},{"host":"127.0.0.2","port":9001,"enabled":false}]}`)

	// Then
	if !strings.Contains(response, "Rule updated") {
		t.Fatalf("response=%s", response)
	}
	if len(forwardedUpstreams) != 2 {
		t.Fatalf("forwarded upstreams=%v", forwardedUpstreams)
	}
	defaulted, ok := forwardedUpstreams[0].(map[string]any)
	if !ok {
		t.Fatalf("forwarded upstreams[0]=%v", forwardedUpstreams[0])
	}
	if enabled, ok := defaulted["enabled"].(bool); !ok || !enabled {
		t.Fatalf("upstreams[0].enabled=%v, want injected true", defaulted["enabled"])
	}
	explicit, ok := forwardedUpstreams[1].(map[string]any)
	if !ok {
		t.Fatalf("forwarded upstreams[1]=%v", forwardedUpstreams[1])
	}
	if enabled, ok := explicit["enabled"].(bool); !ok || enabled {
		t.Fatalf("upstreams[1].enabled=%v, want preserved false", explicit["enabled"])
	}
}

func TestForwardFormatsLargeIntegerPathArgumentsWithoutExponent(t *testing.T) {
	// Given：JSON 数值参数反序列化为 float64，路径替换若用 fmt.Sprint 则
	// 1000000 输出 "1e+06"（科学计数法），REST 端 Atoi 失败 400——路径参数
	// 必须与 query 参数同样经 scalarString 归一为十进制整数串。
	var forwardedPath string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer rest.Close()

	// When：以数值 1000000 作路径参数调用 retry_cert_job
	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "retry_cert_job", `{"id":1000000}`)

	// Then：转发 URL 含 /1000000/ 而非 /1e+06/
	if forwardedPath != "/api/v1/certificates/jobs/1000000/retry" {
		t.Fatalf("forwarded path=%q, want /api/v1/certificates/jobs/1000000/retry", forwardedPath)
	}
}

func TestGetRuleMetricsHistoryForwardsRangeQuery(t *testing.T) {
	// Given：REST 侧 metricsHistoryRange 支持 1h/6h/24h/7d（默认 24h）——工具
	// 须把 range 透传为 query 参数；未传时不得携带（由 REST 侧默认）。
	var forwardedQueries []string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedQueries = append(forwardedQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()
	handler := New(rest.URL+"/api/v1", rest.Client())

	// When：带 range=7d 与不带 range 各调用一次
	callTool(t, handler, "get_rule_metrics_history", `{"caddy_id":"lb_metrics","range":"7d"}`)
	callTool(t, handler, "get_rule_metrics_history", `{"caddy_id":"lb_metrics"}`)

	// Then
	if len(forwardedQueries) != 2 {
		t.Fatalf("forwarded requests=%d, want 2 (schema must accept range)", len(forwardedQueries))
	}
	if forwardedQueries[0] != "range=7d" {
		t.Fatalf("forwarded query=%q, want range=7d", forwardedQueries[0])
	}
	if forwardedQueries[1] != "" {
		t.Fatalf("forwarded query=%q, want empty (no range key when omitted)", forwardedQueries[1])
	}
}

func TestOversizedResponseMessageDistinguishesExportConfig(t *testing.T) {
	// Given：内部 API 返回超过 4 MiB——export_config 无分页参数也无专用导出
	// 工具，通用文案「改用分页或专用导出工具」对它是死路指引，须给专用文案。
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseSize+1))
	}))
	defer rest.Close()
	handler := New(rest.URL+"/api/v1", rest.Client())

	// When
	exportResult := callTool(t, handler, "export_config", `{}`)
	otherResult := callTool(t, handler, "issue_certificate", `{}`)

	// Then：export_config 得面板/REST 指引，其余工具维持通用分页指引
	if !strings.Contains(exportResult, "配置过大") || !strings.Contains(exportResult, "/config/export") {
		t.Fatalf("export_config result=%s, want dedicated oversized-backup message", exportResult)
	}
	if strings.Contains(exportResult, "请改用分页或专用导出工具") {
		t.Fatalf("export_config result must not carry generic pagination hint: %s", exportResult)
	}
	if !strings.Contains(otherResult, "请改用分页或专用导出工具") {
		t.Fatalf("other tool result=%s, want generic oversized message retained", otherResult)
	}
}

func TestAddIPToListToolForwardsValue(t *testing.T) {
	// Given：安全事件处置用单条追加（幂等）——id 进路径、value 进 body
	var receivedMethod, receivedPath, receivedBody string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"added":true}}`))
	}))
	defer rest.Close()

	// When
	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "add_ip_to_list", `{"id":9,"value":"203.0.113.7"}`)

	// Then
	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/security/ip-lists/9/ips" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
	if receivedBody != `{"value":"203.0.113.7"}` {
		t.Fatalf("body=%s, want value only (id belongs to path)", receivedBody)
	}
}

func TestForgetClusterPinsToolForwardsEmptyBody(t *testing.T) {
	// Given/When/Then：从节点 PinMismatch 自救，POST 空体
	var receivedMethod, receivedPath string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer rest.Close()

	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "forget_cluster_pins", `{}`)

	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/cluster/forget-pins" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
}

func TestForgetClusterNodePinToolForwardsPathID(t *testing.T) {
	// Given/When/Then：主节点侧单节点重钉，id 整型进路径
	var receivedMethod, receivedPath string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer rest.Close()

	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "forget_cluster_node_pin", `{"id":7}`)

	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/cluster/nodes/7/forget-pin" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
}

func TestControlClusterNodeServiceToolForwardsAction(t *testing.T) {
	// Given：主节点遥控从节点服务，action 进 body（enum 与后端
	// IsValidClusterServiceAction 支持集一致）
	var receivedMethod, receivedPath, receivedBody string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"Caddy 已重启"}`))
	}))
	defer rest.Close()

	// When
	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "control_cluster_node_service", `{"id":7,"action":"restart_caddy"}`)

	// Then
	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/cluster/nodes/7/service" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
	if receivedBody != `{"action":"restart_caddy"}` {
		t.Fatalf("body=%s, want action only", receivedBody)
	}
}

func TestResetUserMFAToolForwardsCode(t *testing.T) {
	// Given：管理员重置用户 MFA——后端 ShouldBindJSON 必须收到 body，
	// code 为操作者自己的动态验证码（操作者未启用 MFA 时传空串）
	var receivedMethod, receivedPath, receivedBody string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"已重置用户 MFA"}`))
	}))
	defer rest.Close()

	// When
	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "reset_user_mfa", `{"id":7,"code":"123456"}`)

	// Then
	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/users/7/mfa/reset" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
	if receivedBody != `{"code":"123456"}` {
		t.Fatalf("body=%s, want code only", receivedBody)
	}
}

func TestGetCRSRuleIndexToolForwardsReadOnly(t *testing.T) {
	// Given/When/Then：CRS 结构化规则索引，GET 无 query 参数
	var receivedMethod, receivedPath, receivedQuery string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath, receivedQuery = r.Method, r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"version":"v4.28.0","rules":[]}}`))
	}))
	defer rest.Close()

	callTool(t, New(rest.URL+"/api/v1", rest.Client()), "get_crs_rule_index", `{}`)

	if receivedMethod != http.MethodGet || receivedPath != "/api/v1/security/crs/rule-index" || receivedQuery != "" {
		t.Fatalf("request=%s %s query=%q", receivedMethod, receivedPath, receivedQuery)
	}
}
