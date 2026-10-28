package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

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

	handler := NewForTest(rest.URL+"/api/v1", rest.Client())
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
	// Given：确认门——空 body（全量重签）不再放行，批量必须显式
	// {"all":true}（enum 锁死 true，防 all:false 静默变成空批量）；定向
	// 签发仍走 caddy_id（domain 可选）。
	var schema struct {
		Properties struct {
			All struct {
				Enum []bool `json:"enum"`
			} `json:"all"`
		} `json:"properties"`
		// anyOf 而非 oneOf：REST 接受 all 与 caddy_id 同传并以 caddy_id 为准，
		// oneOf 会禁止该合法形态（同时命中两个分支即失败）。
		AnyOf []struct {
			Required []string `json:"required"`
		} `json:"anyOf"`
		OneOf []struct {
			Required []string `json:"required"`
		} `json:"oneOf"`
	}

	// When
	if err := json.Unmarshal([]byte(issueCertificateSchema), &schema); err != nil {
		t.Fatal(err)
	}

	// Then
	if len(schema.AnyOf) != 2 || strings.Join(schema.AnyOf[0].Required, ",") != "all" || strings.Join(schema.AnyOf[1].Required, ",") != "caddy_id" {
		t.Fatalf("anyOf=%+v", schema.AnyOf)
	}
	if len(schema.OneOf) != 0 {
		t.Fatalf("oneOf=%+v：oneOf 会禁止 all 与 caddy_id 同传（REST 接受同传并以 caddy_id 为准）", schema.OneOf)
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

func TestUpdateConfigSchemaCurrentWritableFields(t *testing.T) {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(updateConfigSchema), &schema); err != nil {
		t.Fatalf("parse update config schema: %v", err)
	}
	for _, field := range []string{"threat_screen_mode", "threat_traffic_sample_n", "security_events_retention_days", "security_events_row_cap"} {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("update_config schema lacks writable field %q", field)
		}
	}

	var mode struct {
		Enum []string `json:"enum"`
	}
	if raw := schema.Properties["threat_screen_mode"]; json.Unmarshal(raw, &mode) != nil || strings.Join(mode.Enum, ",") != "map,globe" {
		t.Errorf("threat_screen_mode enum=%v, want map/globe", mode.Enum)
	}
	var sample struct {
		Enum []int `json:"enum"`
	}
	if raw := schema.Properties["threat_traffic_sample_n"]; json.Unmarshal(raw, &sample) != nil || len(sample.Enum) != 2 || sample.Enum[0] != -1 || sample.Enum[1] != 0 {
		t.Errorf("threat_traffic_sample_n enum=%v, want [-1,0]", sample.Enum)
	}
	// 上限期望值直接取 db.Max*（禁止在测试里复制同一份数字）：schema 由模板
	// 占位生成，写侧校验也从同一常量取值——复制常量会让「模板占位失效」与
	// 「常量上调」互相掩盖。另断更新前后文本不同，钉住替换不是 no-op。
	for field, wantMax := range map[string]int{
		"security_events_retention_days": db.MaxSecurityEventsRetentionDays,
		"security_events_row_cap":        db.MaxSecurityEventsRowCap,
	} {
		var property struct {
			Maximum int `json:"maximum"`
		}
		if err := json.Unmarshal(schema.Properties[field], &property); err != nil || property.Maximum != wantMax {
			t.Errorf("%s maximum=%d err=%v, want %d（db.Max* 单源）", field, property.Maximum, err, wantMax)
		}
	}
	if updateConfigSchema == updateConfigSchemaTemplate {
		t.Fatal("update_config schema 未替换保留上限占位——上限会与 db.Max* 静默漂移")
	}
	if strings.Contains(updateConfigSchema, "%!") || strings.Contains(updateConfigSchema, "%[1]d") {
		t.Fatalf("update_config schema 保留未展开的格式占位：见 %q", updateConfigSchema)
	}

	for _, field := range []string{"trusted_proxy_ranges", "trusted_proxy_headers"} {
		var property struct {
			Description string `json:"description"`
		}
		if err := json.Unmarshal(schema.Properties[field], &property); err != nil {
			t.Fatalf("decode %s: %v", field, err)
		}
		if strings.Contains(property.Description, "逗号分隔") || !strings.Contains(property.Description, "JSON 字符串数组文本") || !strings.Contains(property.Description, "[\"") {
			t.Errorf("%s description=%q, want JSON string-array text with example", field, property.Description)
		}
	}
}

func TestToolsListHidesWriteTools_forReadOnlyAPIKey(t *testing.T) {
	// Given：只读可见数按 isReadOnlyTool 的全量口径推导（含 admin 组 GET 工具），
	// 断言成立的前提是 admin 组路由集合未注入。该集合是包级装配态，另一测试
	// （SetupRouter 路径）会写入且不复位——必须在本用例内隔离，否则断言随
	// 执行顺序变化（-shuffle 下同包/外部测试先后不定）。
	previous := nonAdminForbiddenRoutePaths.Load()
	SetNonAdminForbiddenRoutes(nil)
	t.Cleanup(func() { nonAdminForbiddenRoutePaths.Store(previous) })
	resolver := func(apiKey string) (apiKeyVisibility, error) {
		return apiKeyVisibility{readOnly: apiKey == "lb_sk_read-only"}, nil
	}
	handler := newWithVisibilityResolver("http://127.0.0.1/api/v1", http.DefaultClient, "", resolver)
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
	// 只读可见数按 isReadOnlyTool 动态计算（此前硬编码
	// 64，每新增 GET 工具都要手工改并只报数字）。只读筛选口径 = GET 且非
	// 隐藏工具 + 读探测 POST 白名单（与 ListToolSpecs.read_only 同源）。
	wantReadOnly := 0
	for _, spec := range tools {
		if isReadOnlyTool(spec) {
			wantReadOnly++
		}
	}
	if wantReadOnly == 0 || wantReadOnly == len(tools) {
		t.Fatalf("read-only tool count=%d/%d——判据退化", wantReadOnly, len(tools))
	}
	if len(payload.Result.Tools) != wantReadOnly {
		t.Fatalf("read-only tool count=%d, want %d (isReadOnlyTool)", len(payload.Result.Tools), wantReadOnly)
	}
	dashboardVisible := false
	for _, tool := range payload.Result.Tools {
		if tool.Name == "get_metrics_dashboard" {
			dashboardVisible = true
		}
		// ApiMcp-新1:读探测 POST 工具对只读 Key 合法可见(单一事实源
		// ReadOnlyProbeTools，收敛； 后 3 项)
		for _, spec := range tools {
			if spec.name == tool.Name && spec.method != http.MethodGet {
				if _, probe := ReadOnlyProbeTools[tool.Name]; !probe {
					t.Errorf("read-only tools/list exposes write tool %s", tool.Name)
				}
			}
		}
	}
	if !dashboardVisible {
		t.Fatal("read-only tools/list hides get_metrics_dashboard")
	}
}

// 工具可见性过滤只认「顶层单体 JSON-RPC 对象」——mcp-go v0.58.0 的 Streamable
// HTTP 传输按单体对象解析请求体，批处理数组返回 PARSE_ERROR（HTTP 400），因此
// 批处理无法绕过过滤拿到全量工具列表。本用例把该上游假设钉成回归：升级 mcp-go
// 后若开始接受批处理，这里先红（届时过滤需改为响应侧重建）。
func TestToolsListBatchRequestRejectedByProtocol(t *testing.T) {
	previous := nonAdminForbiddenRoutePaths.Load()
	SetNonAdminForbiddenRoutes(nil)
	t.Cleanup(func() { nonAdminForbiddenRoutePaths.Store(previous) })
	resolver := func(apiKey string) (apiKeyVisibility, error) {
		return apiKeyVisibility{readOnly: true}, nil
	}
	handler := newWithVisibilityResolver("http://127.0.0.1/api/v1", http.DefaultClient, "", resolver)

	// Given：JSON-RPC 批处理数组（两条 tools/list）。
	body := `[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}]`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_read-only")
	response := httptest.NewRecorder()

	// When
	handler.ServeHTTP(response, request)

	// Then：协议层拒绝（400 + PARSE_ERROR），不得回退成未过滤的工具列表。
	if response.Code != http.StatusBadRequest {
		t.Fatalf("batch status=%d body=%q, want 400（mcp-go 不接受批处理）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "-32700") {
		t.Fatalf("batch body=%q, want PARSE_ERROR(-32700)", response.Body.String())
	}
	for _, name := range []string{"create_rule", "export_config", "get_caddy_config"} {
		if strings.Contains(response.Body.String(), name) {
			t.Fatalf("batch response leaks tool %s: %s", name, response.Body.String())
		}
	}
}

func TestResolveAPIKeyReadOnly_returnsPersistedPermission(t *testing.T) {
	// Given
	withIsolatedMCPDatabase(t)
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

func TestResolveAPIKeyReadOnly_requiresMatchingIndexedPrefix(t *testing.T) {
	// Given：正确 hash 但错误 prefix 的带外脏行；修复前单列 hash 查询会误命中。
	withIsolatedMCPDatabase(t)
	apiKey := "lb_sk_indexed-read-only"
	hash := sha256.Sum256([]byte(apiKey))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (94,'mcp-indexed','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,read_only) VALUES ('mcp-indexed',?,?,94,1,1,1)`, fmt.Sprintf("%x", hash[:]), "lb_sk_wrong!"); err != nil {
		t.Fatal(err)
	}

	// When / Then：prefix 必须与 hash 同时匹配（命中复合索引左前缀）。
	readOnly, err := resolveAPIKeyReadOnly(apiKey)
	if err == nil || readOnly {
		t.Fatalf("wrong-prefix row resolved readOnly=%v err=%v, want key not found", readOnly, err)
	}
	// 回归形状：纠正 prefix 后同一行正常可见。
	if _, err := db.DB.Exec(`UPDATE api_keys SET key_prefix=?`, apiKey[:12]); err != nil {
		t.Fatal(err)
	}
	readOnly, err = resolveAPIKeyReadOnly(apiKey)
	if err != nil || !readOnly {
		t.Fatalf("valid indexed key readOnly=%v err=%v, want true/nil", readOnly, err)
	}
	// 边界形状：短 key 不得因取 12 字节前缀而 panic。
	if readOnly, err = resolveAPIKeyReadOnly("short"); err == nil || readOnly {
		t.Fatalf("short key readOnly=%v err=%v, want not found", readOnly, err)
	}
}

func TestResolveAPIKeyReadOnly_treatsDisabledOwnerAsNotReadOnly(t *testing.T) {
	// Given
	withIsolatedMCPDatabase(t)
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
	withIsolatedMCPDatabase(t)
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

// 历史 forward 必须把网关注入 context 的真实客户端 IP 转写为内部
// 头（回环自调用下接收端 RemoteAddr 恒为 127.0.0.1，审计源 IP 依赖此头）。
func TestForwardPropagatesClientIPFromContext(t *testing.T) {
	var receivedIP string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedIP = r.Header.Get(InternalClientIPHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer rest.Close()

	handler := NewForTest(rest.URL+"/api/v1", rest.Client())
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

	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "list_rules", `{}`)
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

	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "issue_certificate", wantBody)
	if requests != 2 || !strings.Contains(result, "ok") {
		t.Fatalf("requests=%d result=%q", requests, result)
	}
}

// 面板 TLS 嗅探层对明文请求实际返回 302（cmd/server
// http_redirect_mux.go），转发重放集合必须含 302——否则面板启用 HTTPS 后
// 全部 tools/call 收到 302 空 body 走 {} 错误。本测试钉「302 同样按原方法/
// 原请求体重放一次」。
func TestRedirect302PreservesMethodAndBody(t *testing.T) {
	wantBody := `{"caddy_id":"rule-1","domain":"example.com"}`
	requests := 0
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Location", "/api/v1/redirected")
			w.WriteHeader(http.StatusFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/redirected" || string(body) != wantBody {
			t.Errorf("request=%s %s body=%q", r.Method, r.URL.Path, body)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer rest.Close()

	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "issue_certificate", wantBody)
	if requests != 2 || !strings.Contains(result, "ok") {
		t.Fatalf("requests=%d result=%q（302 须与 301 同口径重放）", requests, result)
	}
}

// 畸形形状：第二次仍是 302 时必须报「重定向次数超过限制」（重放只一次）。
func TestSecond302RedirectReturnsError(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/again")
		w.WriteHeader(http.StatusFound)
	}))
	defer rest.Close()

	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "issue_certificate", `{}`)
	if !strings.Contains(result, "重定向次数超过限制") {
		t.Fatalf("result=%q", result)
	}
}

func TestSecondRedirectReturnsError(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/again")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer rest.Close()

	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "issue_certificate", `{}`)
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

	result := callTool(t, NewForTest("http://localhost:8000/api/v1", client), "issue_certificate", `{}`)
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

	result := callTool(t, NewForTest("http://localhost:8000/api/v1", client), "issue_certificate", `{}`)
	if redirectedPath != "/api/v1/certificates/next" || !strings.Contains(result, "ok") {
		t.Fatalf("path=%q result=%q", redirectedPath, result)
	}
}

func TestOversizedResponseReturnsToolError(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseSize+1))
	}))
	defer rest.Close()

	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "issue_certificate", `{}`)
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
	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "reset_user_password", `{"id":7}`)

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
	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "reset_user_password", `{"id":404}`)

	// Then
	if !strings.Contains(result, "用户不存在") || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("result=%q", result)
	}
	if strings.Contains(result, receivedPassword) {
		t.Fatalf("result must not echo password on failure, got %q", result)
	}
}

func TestCertificateToolsForwardForceAsQuery(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		arguments []string
		wantPath  string
	}{
		{name: "retry", tool: "retry_cert_job", arguments: []string{`{"id":7}`, `{"id":7,"force":true}`, `{"id":7,"force":false}`}, wantPath: "/api/v1/certificates/jobs/7/retry"},
		{name: "targeted issue", tool: "issue_certificate", arguments: []string{`{"caddy_id":"lb_1"}`, `{"caddy_id":"lb_1","force":true}`, `{"caddy_id":"lb_1","force":false}`}, wantPath: "/api/v1/certificates/issue"},
		{name: "all issue", tool: "issue_certificate", arguments: []string{`{"all":true,"force":true}`}, wantPath: "/api/v1/certificates/issue"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var queries []url.Values
			var bodies []map[string]any
			rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.wantPath {
					t.Errorf("path=%q, want %q", r.URL.Path, test.wantPath)
				}
				queries = append(queries, r.URL.Query())
				body := map[string]any{}
				if r.Body != nil {
					_ = json.NewDecoder(r.Body).Decode(&body)
				}
				bodies = append(bodies, body)
				_, _ = w.Write([]byte(`{"code":0}`))
			}))
			defer rest.Close()

			for _, arguments := range test.arguments {
				callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), test.tool, arguments)
			}

			if len(queries) != len(test.arguments) {
				t.Fatalf("requests=%d, want %d", len(queries), len(test.arguments))
			}
			for index, query := range queries {
				wantForce := ""
				if strings.Contains(test.arguments[index], `"force":true`) {
					wantForce = "true"
				} else if strings.Contains(test.arguments[index], `"force":false`) {
					wantForce = "false"
				}
				if got := query.Get("force"); got != wantForce {
					t.Errorf("arguments=%s force query=%q, want %q", test.arguments[index], got, wantForce)
				}
				if _, exists := bodies[index]["force"]; exists {
					t.Errorf("arguments=%s leaked force into request body: %v", test.arguments[index], bodies[index])
				}
			}
		})
	}
}

func TestResetUserPasswordTimeoutReturnsCandidateForRecovery(t *testing.T) {
	for _, secondHop := range []bool{false, true} {
		name := "first hop"
		if secondHop {
			name = "TLS replay"
		}
		t.Run(name, func(t *testing.T) {
			var candidate string
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if candidate == "" {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode reset body: %v", err)
					}
					candidate, _ = body["new_password"].(string)
					if secondHop {
						response := redirectResponse(r, "https://localhost:8000/api/v1/users/7/reset-password")
						response.StatusCode = http.StatusFound
						return response, nil
					}
				}
				return nil, context.DeadlineExceeded
			})}

			result := callTool(t, NewForTest("http://localhost:8000/api/v1", client), "reset_user_password", `{"id":7}`)

			if len(candidate) != 16 {
				t.Fatalf("candidate=%q, want generated 16-character password", candidate)
			}
			for _, want := range []string{`"isError":true`, "操作可能已在服务端生效", candidate, "若未生效请继续使用旧密码"} {
				if !strings.Contains(result, want) {
					t.Errorf("result=%q, want recovery detail %q", result, want)
				}
			}
		})
	}
}

func TestResetUserPasswordConnectionFailureDoesNotClaimUncertainty(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})}

	result := callTool(t, NewForTest("http://localhost:8000/api/v1", client), "reset_user_password", `{"id":7}`)

	if !strings.Contains(result, "内部 API 请求失败") || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("result=%q", result)
	}
	for _, unwanted := range []string{"操作可能已在服务端生效", "候选密码", "若未生效请继续使用旧密码"} {
		if strings.Contains(result, unwanted) {
			t.Errorf("result=%q must not contain %q", result, unwanted)
		}
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

	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

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
	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "retry_cert_job", `{"id":1000000}`)

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
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

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

func TestForwardQueryNullTreatedAsOmitted(t *testing.T) {
	// Given：显式 JSON null 是 Agent 表达「可选筛选不填」的常见形态——若按
	// fmt.Sprint 串化会变成 "<nil>" 被当真实过滤值转发（分页 400 / 按字面
	// 过滤后静默空结果）。
	var forwardedQueries []string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedQueries = append(forwardedQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

	// When：可选 query 参数显式传 null（range 与分页/过滤参数同属可选面）
	callTool(t, handler, "get_rule_metrics_history", `{"caddy_id":"lb_metrics","range":null}`)
	callTool(t, handler, "list_security_events", `{"page":null,"ip":null,"start_time":null}`)

	// Then：null 等同未提供，转发 URL 不带该参数
	if len(forwardedQueries) != 2 {
		t.Fatalf("forwarded requests=%d, want 2", len(forwardedQueries))
	}
	if forwardedQueries[0] != "" {
		t.Fatalf("forwarded query=%q, want empty (null range treated as omitted)", forwardedQueries[0])
	}
	if forwardedQueries[1] != "" {
		t.Fatalf("forwarded query=%q, want empty (null page/ip/start_time treated as omitted)", forwardedQueries[1])
	}
}

func TestForwardPathArgNullReturnsMissingParam(t *testing.T) {
	// Given：路径参数显式 null 时不得拼出 /rules/%3Cnil%3E（REST 侧 404，
	// 错误指向不存在的规则而非缺少参数）。
	restCalls := 0
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		restCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

	// When
	result := callTool(t, handler, "get_rule", `{"caddy_id":null}`)

	// Then：按「缺少参数」返回工具错误，且不发出请求
	if !strings.Contains(result, `"isError":true`) || !strings.Contains(result, "缺少参数 caddy_id") {
		t.Fatalf("result=%q, want isError + 缺少参数 caddy_id", result)
	}
	if restCalls != 0 {
		t.Fatalf("upstream calls=%d, want 0 (null path arg must not be forwarded)", restCalls)
	}
}

func TestOversizedResponseMessageDistinguishesExportConfig(t *testing.T) {
	// Given：内部 API 返回超过 4 MiB——export_config 无分页参数也无专用导出
	// 工具，通用文案「改用分页或专用导出工具」对它是死路指引，须给专用文案。
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseSize+1))
	}))
	defer rest.Close()
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

	// When
	exportResult := callTool(t, handler, "export_config", `{}`)
	caddyConfigResult := callTool(t, handler, "get_caddy_config", `{}`)
	postNoPaginationResult := callTool(t, handler, "issue_certificate", `{}`)
	previewResult := callTool(t, handler, "preview_config", `{}`)
	ruleLogsResult := callTool(t, handler, "get_rule_logs", `{"caddy_id":"lb_x"}`)

	// Then：export_config 得面板/REST 指引，get_caddy_config 得按规则查询指引，
	// 其余无分页工具（含 POST）得「无分页参数」指引，不得落进通用分页文案。
	if !strings.Contains(exportResult, "配置过大") || !strings.Contains(exportResult, "/config/export") {
		t.Fatalf("export_config result=%s, want dedicated oversized-backup message", exportResult)
	}
	if strings.Contains(exportResult, "请改用分页或专用导出工具") {
		t.Fatalf("export_config result must not carry generic pagination hint: %s", exportResult)
	}
	if strings.Contains(caddyConfigResult, "请改用分页或专用导出工具") {
		t.Fatalf("get_caddy_config result must not carry generic pagination hint: %s", caddyConfigResult)
	}
	for _, fragment := range []string{"4 MiB", "get_rule_caddy_config", "管理面板"} {
		if !strings.Contains(caddyConfigResult, fragment) {
			t.Fatalf("get_caddy_config result=%s, want actionable guidance containing %q", caddyConfigResult, fragment)
		}
	}
	if !strings.Contains(postNoPaginationResult, "无分页参数") || strings.Contains(postNoPaginationResult, "请改用分页或专用导出工具") {
		t.Fatalf("POST 无分页工具 result=%s, want 「无分页参数」指引而非通用分页文案", postNoPaginationResult)
	}
	if !strings.Contains(previewResult, "source") || strings.Contains(previewResult, "请改用分页或专用导出工具") {
		t.Fatalf("preview_config result=%s, want 拆小 source 的可执行指引", previewResult)
	}
	if !strings.Contains(ruleLogsResult, "log-stream") || strings.Contains(ruleLogsResult, "请改用对应的单条查询工具") {
		t.Fatalf("get_rule_logs result=%s, want REST log-stream 增益续读指引（不得指向自身）", ruleLogsResult)
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
	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "add_ip_to_list", `{"id":9,"value":"203.0.113.7"}`)

	// Then
	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/security/ip-lists/9/ips" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
	if receivedBody != `{"value":"203.0.113.7"}` {
		t.Fatalf("body=%s, want value only (id belongs to path)", receivedBody)
	}
}

func TestGetIPListToolForwardsID(t *testing.T) {
	// Given：v2.3.2 名单瘦身后 list_ip_lists 仅含 entry_count，读条目唯一通道
	// 是 GET /security/ip-lists/:id——补 get_ip_list 工具
	// 覆盖该端点（GET 只读，id 进路径）。
	var receivedMethod, receivedPath string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"id":9,"name":"办公网","entries":[{"value":"10.0.0.0/8","remark":"内网段"}],"entry_count":1,"system":false}}`))
	}))
	defer rest.Close()

	// When/Then：tools/list 含 get_ip_list（GET，路径参数契约形态）
	found := false
	for _, spec := range ListToolSpecs() {
		if spec.Name == "get_ip_list" {
			found = true
			if spec.Method != http.MethodGet || spec.Path != "/api/v1/security/ip-lists/{id}" {
				t.Errorf("spec=%s %s", spec.Method, spec.Path)
			}
		}
	}
	if !found {
		t.Fatal("tools/list 缺 get_ip_list")
	}

	// When
	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "get_ip_list", `{"id":9}`)

	// Then：转发到 GET /api/v1/security/ip-lists/9，响应原文含 entries
	if receivedMethod != http.MethodGet || receivedPath != "/api/v1/security/ip-lists/9" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
	if !strings.Contains(result, "entries") {
		t.Fatalf("result=%q, want forwarded entries payload", result)
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

	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "forget_cluster_pins", `{}`)

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

	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "forget_cluster_node_pin", `{"id":7}`)

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
	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "control_cluster_node_service", `{"id":7,"action":"restart_caddy"}`)

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
	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "reset_user_mfa", `{"id":7,"code":"123456"}`)

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

	callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "get_crs_rule_index", `{}`)

	if receivedMethod != http.MethodGet || receivedPath != "/api/v1/security/crs/rule-index" || receivedQuery != "" {
		t.Fatalf("request=%s %s query=%q", receivedMethod, receivedPath, receivedQuery)
	}
}

// v2.3.0 起 /config/export 恒返回 lbbak 二进制(tar.gz,
// application/gzip)——forward 把响应体喂 NewToolResultText 会把 gzip 字节
// 静默损坏成不可读文本。非 JSON 必须以 IsError 文本指引改走
// 面板/REST,不得让二进制字节进文本结果。
func TestExportConfigToolRejectsNonJSONContentType(t *testing.T) {
	// Given:内部 API 对 export_config 返回非 JSON(如 lbbak application/gzip)
	// 小载荷(≤4MiB,排除体积分支干扰)。
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 'b', 'i', 'n', 0x03})
	}))
	defer rest.Close()
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

	// When
	result := callTool(t, handler, "export_config", `{}`)

	// Then:IsError 文本含面板/REST 下载指引,且不含原始二进制字节。
	if !strings.Contains(result, `"isError":true`) {
		t.Fatalf("export_config result=%s, want IsError", result)
	}
	for _, fragment := range []string{"lbbak", "MCP 通道", "/config/export"} {
		if !strings.Contains(result, fragment) {
			t.Fatalf("export_config result=%s, want guidance containing %q", result, fragment)
		}
	}
	if strings.Contains(result, "\\u001f") || strings.Contains(result, "x1f") {
		t.Fatalf("export_config result leaked binary payload: %s", result)
	}
}

// get_rule_stage_stats 带必填路径参数却声明 emptySchema——运行时未
// 启用 WithInputSchemaValidation，input_schema 是 Agent 侧唯一的参数契约文档，
// 缺 caddy_id 声明会让 Agent 无从得知该 GET 需要路径参数。与同族
// get_rule_security_policy 的 idSchema 形态对齐。
func TestToolSpecs_stageStatsSchemaDeclaresCaddyID(t *testing.T) {
	// Given
	found := false
	var schemaJSON json.RawMessage
	for _, item := range ListToolSpecs() {
		if item.Name == "get_rule_stage_stats" {
			found = true
			schemaJSON = item.InputSchema
			break
		}
	}
	if !found {
		t.Fatal("get_rule_stage_stats missing from ListToolSpecs")
	}

	// When
	var schema struct {
		Required   []string       `json:"required"`
		Properties map[string]any `json:"properties"`
	}
	err := json.Unmarshal([]byte(schemaJSON), &schema)

	// Then
	if err != nil {
		t.Fatalf("parse stage-stats input schema: %v (%s)", err, schemaJSON)
	}
	if _, exists := schema.Properties["caddy_id"]; !exists {
		t.Fatalf("stage-stats input_schema missing caddy_id property: %s", schemaJSON)
	}
	required := false
	for _, name := range schema.Required {
		if name == "caddy_id" {
			required = true
		}
	}
	if !required {
		t.Fatalf("stage-stats input_schema required=%v, want caddy_id declared required", schema.Required)
	}
}

// resolveAPIKeyReadOnly 是只读判定的测试便利包装（生产只用
// resolveAPIKeyVisibility——避免生产侧保留零消费函数）。
func resolveAPIKeyReadOnly(apiKey string) (bool, error) {
	visibility, err := resolveAPIKeyVisibility(apiKey)
	return visibility.readOnly, err
}

// requestToolNames 发起 tools/list 并返回工具名集合。
func requestToolNames(t *testing.T, handler http.Handler, apiKey string) map[string]bool {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", apiKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%q", response.Code, response.Body.String())
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
	names := make(map[string]bool, len(payload.Result.Tools))
	for _, tool := range payload.Result.Tools {
		names[tool.Name] = true
	}
	return names
}

// 「非管理员恒 403」路由（admin 组全部 + business 组未豁免只读白名单的写路由）
// 必须从非管理员 tools/list 中隐藏——否则属主反复试错恒 403 工具。管理员全权
// Key 不受影响；business 组的只读探测 POST（preview_config/validate_import/
// parse_certificate）在 REST 白名单内，非管理员可用，必须保留。
func TestToolsListHidesForbiddenToolsForNonAdminKey(t *testing.T) {
	// Given：与 middleware.SetupRouter 同源形态的集合（生产由注册记录派生）
	previous := nonAdminForbiddenRoutePaths.Load()
	t.Cleanup(func() { nonAdminForbiddenRoutePaths.Store(previous) })
	SetNonAdminForbiddenRoutes(map[string]struct{}{
		// admin 组（全部方法）——只读探测 POST 也在该组（adminOnly 对非管理员 403）
		"GET /api/v1/caddy/config":            {},
		"POST /api/v1/config/preview":         {},
		"POST /api/v1/config/import/validate": {},
		"PUT /api/v1/users/:id":               {},
		"POST /api/v1/users":                  {},
		// business 组写路由（readOnlyGuard 对非管理员 403）
		"POST /api/v1/rules":                       {},
		"PUT /api/v1/rules/:caddy_id":              {},
		"DELETE /api/v1/rules/:caddy_id":           {},
		"POST /api/v1/rules/:caddy_id/enable":      {},
		"POST /api/v1/certificates/jobs/:id/retry": {},
		"DELETE /api/v1/certificates/jobs/:id":     {},
		"POST /api/v1/admin-tls/inspect":           {},
	})

	// When：非管理员全权 Key
	nonAdmin := newWithVisibilityResolver("http://127.0.0.1/api/v1", http.DefaultClient, "",
		func(string) (apiKeyVisibility, error) { return apiKeyVisibility{}, nil })
	names := requestToolNames(t, nonAdmin, "lb_sk_non-admin")

	// Then：恒 403 工具不可见
	for _, hidden := range []string{
		"get_caddy_config", "preview_config", "validate_import",
		"update_user", "create_user",
		"create_rule", "update_rule", "delete_rule", "enable_rule",
		"retry_cert_job", "delete_cert_job", "inspect_admin_tls",
	} {
		if names[hidden] {
			t.Errorf("non-admin tools/list exposes tool %s (调用恒 403)", hidden)
		}
	}
	// business 组只读查询与读探测 POST（parse_certificate 在白名单内）保留
	for _, visible := range []string{"list_rules", "get_config", "parse_certificate"} {
		if !names[visible] {
			t.Errorf("non-admin tools/list hides callable tool %s", visible)
		}
	}

	// When：管理员全权 Key
	admin := newWithVisibilityResolver("http://127.0.0.1/api/v1", http.DefaultClient, "",
		func(string) (apiKeyVisibility, error) { return apiKeyVisibility{admin: true}, nil })
	adminNames := requestToolNames(t, admin, "lb_sk_admin")

	// Then：管理员全量可见
	for _, visible := range []string{"get_caddy_config", "update_user", "create_rule", "retry_cert_job", "inspect_admin_tls"} {
		if !adminNames[visible] {
			t.Errorf("admin tools/list hides tool %s", visible)
		}
	}
}

// 只读 Key 的 tools/list 不得呈现「handler 对只读 Key 恒 403」的 GET 工具——
// get_caddy_config 与 export_config 同格（原始运行配置/备份含敏感材料，handler
// 首行拒绝只读 Key）。read_only 元数据同步为 false，避免「列表可见即只读可用」
// 的语义失真。
func TestToolsListHidesReadOnlyForbiddenGets(t *testing.T) {
	previous := nonAdminForbiddenRoutePaths.Load()
	t.Cleanup(func() { nonAdminForbiddenRoutePaths.Store(previous) })
	SetNonAdminForbiddenRoutes(nil)

	// admin 属主的只读 Key（read_only）——export_config/get_caddy_config 都必须消失
	adminReadOnly := newWithVisibilityResolver("http://127.0.0.1/api/v1", http.DefaultClient, "",
		func(string) (apiKeyVisibility, error) { return apiKeyVisibility{admin: true, readOnly: true}, nil })
	names := requestToolNames(t, adminReadOnly, "lb_sk_admin-read-only")
	for _, hidden := range ReadOnlyHiddenToolNamesForTest() {
		if names[hidden] {
			t.Errorf("read-only key tools/list exposes always-403 tool %s", hidden)
		}
	}
	if !names["list_rules"] || !names["parse_certificate"] {
		t.Fatalf("read-only key tools/list must keep read tools: %v", names)
	}

	// 元数据同源：隐藏集合内工具不得标 read_only
	hiddenNames := make(map[string]bool)
	for _, name := range ReadOnlyHiddenToolNamesForTest() {
		hiddenNames[name] = true
	}
	for _, spec := range ListToolSpecs() {
		if !hiddenNames[spec.Name] {
			continue
		}
		if spec.ReadOnly {
			t.Errorf("%s read_only=%v, want false（只读 Key 调用恒 403）", spec.Name, spec.ReadOnly)
		}
	}
}

// tools/list 可见性过滤 fail-closed：Key 属主属性解析失败时不得原样透传
// 全量工具（旧实现 err → next 直出），改为下发空 tools 列表并保留 JSON-RPC
// id——调用方仍能配对响应，但不会看到任何未经身份判定的工具。
func TestToolsListFailsClosedWhenVisibilityResolutionFails(t *testing.T) {
	handler := newWithVisibilityResolver("http://127.0.0.1/api/v1", http.DefaultClient, "",
		func(string) (apiKeyVisibility, error) {
			return apiKeyVisibility{}, fmt.Errorf("解析 Key 属主失败")
		})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"tools/list","params":{}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_visibility-broken")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("fail-closed tools/list status=%d body=%q", response.Code, response.Body.String())
	}
	var payload struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse fail-closed response %q: %v", response.Body.String(), err)
	}
	if len(payload.Result.Tools) != 0 {
		t.Fatalf("visibility resolution failure leaked %d tools (fail-open)", len(payload.Result.Tools))
	}
	if string(payload.ID) != "42" {
		t.Fatalf("fail-closed response lost JSON-RPC id: %s", response.Body.String())
	}
}

// 过滤阶段失败同样 fail-closed：上游响应无法解析时不得回退为未过滤原文。
// 过滤在 recorder 上完成后若出错，旧实现 `filtered = recorder.body.Bytes()`
// 把全量工具透传——与解析失败同属 fail-open。
func TestServeWithToolVisibilityFailsClosedOnFilterError(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	})
	resolver := func(string) (apiKeyVisibility, error) { return apiKeyVisibility{}, nil }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{}}`))
	response := httptest.NewRecorder()

	serveWithToolVisibility(response, request, next, resolver)

	var payload struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse fail-closed response %q: %v", response.Body.String(), err)
	}
	if len(payload.Result.Tools) != 0 {
		t.Fatalf("filter failure leaked %d tools (fail-open)", len(payload.Result.Tools))
	}
	if string(payload.ID) != `"abc"` {
		t.Fatalf("fail-closed response lost JSON-RPC id: %s", response.Body.String())
	}
}

func TestRemoveIPFromListToolForwardsIDAndValue(t *testing.T) {
	// Given：封禁处置闭环的解封原语——幂等单条移除（与 add_ip_to_list 对称），
	// 免去读全表-改-全量写回与自动封禁并发写入的竞态路径。
	var receivedMethod, receivedPath, receivedBody string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod, receivedPath = r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"removed":true}}`))
	}))
	defer rest.Close()

	// When
	result := callTool(t, NewForTest(rest.URL+"/api/v1", rest.Client()), "remove_ip_from_list", `{"id":9,"value":"203.0.113.7"}`)

	// Then
	if receivedMethod != http.MethodPost || receivedPath != "/api/v1/security/ip-lists/9/remove-ip" {
		t.Fatalf("request=%s %s", receivedMethod, receivedPath)
	}
	if receivedBody != `{"value":"203.0.113.7"}` {
		t.Fatalf("body=%s, want value only (id belongs to path)", receivedBody)
	}
	if strings.Contains(result, `"isError":true`) {
		t.Fatalf("result=%s, want success", result)
	}
}

// 缺路径参数/缺 API Key/传输失败是调用方可恢复的调用层错误——按文档承诺以
// IsError+文本返回，而非 JSON-RPC -32603（Agent 只处理 IsError 分支时会漏掉）。
func TestForward_callLayerErrorsReturnIsErrorResults(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer rest.Close()
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

	// 缺路径参数
	result := callTool(t, handler, "get_rule", `{}`)
	if !strings.Contains(result, "缺少参数") || !strings.Contains(result, `"isError":true`) {
		t.Fatalf("missing path arg result=%s, want IsError tool result", result)
	}
	if strings.Contains(result, "-32603") {
		t.Fatalf("missing path arg surfaced as JSON-RPC internal error: %s", result)
	}

	// 缺 API Key
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_rules","arguments":{}}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), "缺少 API 密钥") || !strings.Contains(response.Body.String(), `"isError":true`) {
		t.Fatalf("missing API key body=%s, want IsError tool result", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "-32603") {
		t.Fatalf("missing API key surfaced as JSON-RPC internal error: %s", response.Body.String())
	}

	// 传输失败（连接拒绝）
	down := NewForTest("http://127.0.0.1:1/api/v1", &http.Client{Timeout: 2 * time.Second})
	result = callTool(t, down, "list_rules", `{}`)
	if !strings.Contains(result, `"isError":true`) || strings.Contains(result, "-32603") {
		t.Fatalf("transport failure result=%s, want IsError tool result", result)
	}
}

// 无分页参数的整份返回工具（list_rules/list_ip_lists/get_config 等）超限时
// 通用「改用分页」指引是死路——必须给单条查询/管理面板的可执行路径；
// 有分页参数的工具维持通用分页指引。判据= schema 是否声明 page/page_size，
// 不是 queryArgs 是否为空、也不是 HTTP 方法：get_metrics_history/get_caddy_logs
// 有过滤维度但无分页；POST 整份返回工具同样无分页。
func TestOversizedResponseMessageGuidesNonPaginatedGetTools(t *testing.T) {
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseSize+1))
	}))
	defer rest.Close()
	handler := NewForTest(rest.URL+"/api/v1", rest.Client())

	noPagination := callTool(t, handler, "list_ip_lists", `{}`)
	if !strings.Contains(noPagination, "无分页参数") || strings.Contains(noPagination, "请改用分页或专用导出工具") {
		t.Fatalf("list_ip_lists result=%s, want 单条查询/面板指引而非死路分页文案", noPagination)
	}
	paginated := callTool(t, handler, "list_security_events", `{}`)
	if !strings.Contains(paginated, "请改用分页或专用导出工具") {
		t.Fatalf("list_security_events result=%s, want 通用分页指引保留", paginated)
	}
	// 有 queryArgs 但无分页参数的三个工具：必须给各自可执行路径，不得退回
	// 「改用分页」（对它们无可传参数，是死路）。
	for tool, want := range map[string]string{
		"get_metrics_history":      "rule_id",
		"get_rule_metrics_history": "range",
		"get_caddy_logs":           "get_rule_logs",
	} {
		result := callTool(t, handler, tool, `{"caddy_id":"lb_x"}`)
		if strings.Contains(result, "请改用分页或专用导出工具") {
			t.Errorf("%s result=%s, want 专用指引而非通用分页文案", tool, result)
		}
		if !strings.Contains(result, want) {
			t.Errorf("%s result=%s, want 含可执行收敛路径 %q", tool, result, want)
		}
	}
}

// withIsolatedMCPDatabase 替换三句柄并在清理时经保存值恢复：只还原 db.DB 会把
// 已关闭/已删临时目录的 MetricsDB/AuditDB 留给后续用例（-shuffle 下出现
// 「database is closed」类顺序依赖假红）。
func withIsolatedMCPDatabase(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
		RestoreDBForTest(oldDB, oldMetricsDB, oldAuditDB)
	})
}

// list_certificates 的 rule_id 必须真正转发到 REST 查询串：转发层只遍历
// toolSpec.queryArgs，漏登记时 Agent 的过滤参数会被静默丢弃（返回全局首页，
// 目标规则不在首页即被误判为无证书），而 schema 声明了却没有转发同样难察觉。
func TestListCertificatesForwardsRuleIDFilter(t *testing.T) {
	var gotQuery url.Values
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/certificates" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"certificates":[],"total":0,"page":1,"page_size":1000}}`))
	}))
	defer rest.Close()

	handler := NewForTest(rest.URL+"/api/v1", rest.Client())
	result := callTool(t, handler, "list_certificates", `{"rule_id":"lb_cert-rule","page":2,"page_size":50}`)
	if !strings.Contains(result, `\"total\":0`) {
		t.Fatalf("result=%q", result)
	}
	if got := gotQuery.Get("rule_id"); got != "lb_cert-rule" {
		t.Fatalf("内部请求 rule_id=%q, want lb_cert-rule（过滤参数不得静默丢弃）", got)
	}
	// 分页参数回归：与 rule_id 同一条查询串。
	if got := gotQuery.Get("page"); got != "2" {
		t.Fatalf("内部请求 page=%q, want 2", got)
	}
	if got := gotQuery.Get("page_size"); got != "50" {
		t.Fatalf("内部请求 page_size=%q, want 50", got)
	}
}

// schema 声明的 query 参数集合必须与注册表的 queryArgs 完全一致——两个方向
// 都要查：漏声明（Agent 看不见）与漏转发（参数被静默丢弃）同样是契约缺口。
func TestCertificateToolsQueryArgsMatchSchema(t *testing.T) {
	for tool, want := range map[string][]string{
		"list_certificates": {"rule_id", "page", "page_size"},
		"list_cert_jobs":    {"rule_id", "page", "page_size"},
	} {
		spec, ok := toolSpecsByName[tool]
		if !ok {
			t.Fatalf("%s 未在工具注册表中", tool)
		}
		var properties map[string]json.RawMessage
		if err := json.Unmarshal([]byte(toolSpecPropertyBlock(t, spec)), &properties); err != nil {
			t.Fatalf("%s schema 解析失败: %v", tool, err)
		}
		for _, name := range want {
			if _, ok := properties[name]; !ok {
				t.Errorf("%s schema 缺少 query 参数 %q", tool, name)
			}
			if !containsString(spec.queryArgs, name) {
				t.Errorf("%s queryArgs 缺少 %q（schema 声明了却不转发）", tool, name)
			}
		}
		if len(properties) != len(spec.queryArgs) {
			t.Errorf("%s schema 参数数=%d, queryArgs 数=%d（两处必须同集）", tool, len(properties), len(spec.queryArgs))
		}
	}
}

func toolSpecPropertyBlock(t *testing.T, spec toolSpec) string {
	t.Helper()
	var schema struct {
		Properties json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal([]byte(spec.schema), &schema); err != nil {
		t.Fatalf("%s schema 解析失败: %v", spec.name, err)
	}
	return string(schema.Properties)
}

// 权限说明里的写方法集合必须覆盖工具注册表实际使用的全部非 GET 方法：
// 漏掉 PATCH 会让 Agent 误判 update_api_key_status 这类工具的读写属性，
// 也说明新增方法（如未来的 PATCH 工具）没有同步到 initialize 说明与手册。
func TestPermissionTextsCoverRegisteredWriteMethods(t *testing.T) {
	writeMethods := map[string]struct{}{}
	for _, spec := range tools {
		if spec.method == http.MethodGet {
			continue
		}
		writeMethods[spec.method] = struct{}{}
	}
	if len(writeMethods) == 0 {
		t.Fatal("工具清单没有任何非 GET 工具——派生基线失效")
	}
	texts := map[string]string{
		"initialize instructions": serverInstructions,
		"ops playbook":            opsPlaybook,
	}
	for label, text := range texts {
		for method := range writeMethods {
			if !strings.Contains(text, method) {
				t.Errorf("%s 未把注册表实际使用的写方法 %s 计入权限说明", label, method)
			}
		}
	}
	// 有 PATCH 工具时必须明确点名（上面的集合断言在 PATCH 消失后不再覆盖）。
	hasPatchTool := false
	for _, spec := range tools {
		if spec.method == http.MethodPatch {
			hasPatchTool = true
			break
		}
	}
	if hasPatchTool && (!strings.Contains(serverInstructions, "POST/PUT/PATCH/DELETE") || !strings.Contains(opsPlaybook, "POST/PUT/PATCH/DELETE")) {
		t.Fatal("存在 PATCH 工具时，两处权限说明都必须写全 POST/PUT/PATCH/DELETE")
	}
}

// import_config / validate_import 的分类子集必须走 query（等价 REST ?sections=），
// 不能落在 body：REST 侧体内 sections 是备份打包时的分类记录，参与 v3 校验和
// 摘要，被改写后 verifyBackupIntegrity 会把健康备份判成「已篡改」硬拒
// （config_backup.go 的 configBackupChecksumPayload）。转发层只按 queryArgs 拼
// 查询串，schema 声明却漏登记即「按分类导入」能力整体失效且错误文案误导。
func TestImportToolsForwardSectionsAsQueryNotBody(t *testing.T) {
	for _, tool := range []string{"import_config", "validate_import"} {
		t.Run(tool, func(t *testing.T) {
			var gotQuery url.Values
			var gotBody map[string]any
			rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.Query()
				gotBody = nil
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":0,"message":"配置导入成功"}`))
			}))
			defer rest.Close()

			handler := NewForTest(rest.URL+"/api/v1", rest.Client())
			payload := `{"meta":{"app":"lazy-balancer-v2","version":3,"checksum":"abc"},"tables":{"users":[]},"sections":"users,security"}`
			_ = callTool(t, handler, tool, payload)

			if got := gotQuery.Get("sections"); got != "users,security" {
				t.Fatalf("%s 内部请求 sections=%q, want users,security（分类子集必须走 query）", tool, got)
			}
			if _, ok := gotBody["sections"]; ok {
				t.Fatalf("%s 把 sections 写进了请求体：体内 sections 参与备份校验和，改写会被 REST 判成「已篡改」", tool)
			}
			if _, ok := gotBody["tables"]; !ok {
				t.Fatalf("%s 请求体丢失备份正文（tables），body=%v", tool, gotBody)
			}
		})
	}
}

// 空字符串（含纯空白）路径参数与「未提供」同义：空串拼出的 `/rules/` 等
// 尾斜杠路径会命中 Gin 默认 RedirectTrailingSlash 的 301，转发器按原方法
// 重放到集合端点，于是详情工具以 isError=false 返回整表（与「缺少参数」
// 契约相反，Agent 会把列表首项当成目标对象）。query 侧早已丢弃空串，
// path 侧口径必须一致。
func TestForwardPathArgEmptyStringReturnsMissingParam(t *testing.T) {
	cases := []struct{ tool, arg string }{
		{"get_rule", "caddy_id"},
		{"get_cert_job", "id"},
		{"get_security_policy", "id"},
		{"get_ip_list", "id"},
		{"get_ca_provider", "id"},
		{"get_crs_rule", "filename"},
	}
	for _, tc := range cases {
		for _, value := range []string{"", "   "} {
			t.Run(tc.tool+"/"+value, func(t *testing.T) {
				restCalls := 0
				rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					restCalls++
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"code":0,"data":[]}`))
				}))
				defer rest.Close()
				handler := NewForTest(rest.URL+"/api/v1", rest.Client())

				result := callTool(t, handler, tc.tool, `{"`+tc.arg+`":"`+value+`"}`)

				if !strings.Contains(result, `"isError":true`) || !strings.Contains(result, "缺少参数 "+tc.arg) {
					t.Fatalf("result=%q, want isError + 缺少参数 %s", result, tc.arg)
				}
				if restCalls != 0 {
					t.Fatalf("upstream calls=%d, want 0（空串路径参数不得转发到集合端点）", restCalls)
				}
			})
		}
	}
}

// 请求已写出后连接被对端关闭（EOF/reset/broken pipe）与超时同属「结果未知」：
// 服务端可能已执行。非幂等工具必须提示先核对状态再重试；reset_user_password
// 还要交付候选密码（否则密码已改而口令未回传，用户被锁在门外）。
// 连接被拒绝仍是「确定未发送」，不得带任何不确定措辞。
func TestTransportFailureAfterRequestSentClaimsUncertainty(t *testing.T) {
	uncertainErrors := []struct {
		name string
		err  error
	}{
		{"unexpected EOF", io.ErrUnexpectedEOF},
		{"connection reset", fmt.Errorf("read tcp: %w", syscall.ECONNRESET)},
		{"broken pipe", fmt.Errorf("write tcp: %w", syscall.EPIPE)},
	}
	for _, tc := range uncertainErrors {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, tc.err
			})}
			handler := NewForTest("http://localhost:8000/api/v1", client)

			result := callTool(t, handler, "restart_system", `{}`)

			if !strings.Contains(result, `"isError":true`) || !strings.Contains(result, "操作可能已在服务端生效") {
				t.Fatalf("result=%q, want 不确定态提示（请求可能已送达并生效）", result)
			}
			if strings.Contains(result, "候选密码") {
				t.Fatalf("result=%q, 非密码工具不得出现候选密码", result)
			}
		})
	}

	t.Run("reset_user_password delivers candidate", func(t *testing.T) {
		var candidate string
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode reset body: %v", err)
			}
			candidate, _ = body["new_password"].(string)
			return nil, io.ErrUnexpectedEOF
		})}
		handler := NewForTest("http://localhost:8000/api/v1", client)

		result := callTool(t, handler, "reset_user_password", `{"id":7}`)

		if candidate == "" {
			t.Fatal("reset body 未携带系统生成密码（无法交付候选值）")
		}
		for _, want := range []string{"操作可能已在服务端生效", candidate, "若未生效请继续使用旧密码"} {
			if !strings.Contains(result, want) {
				t.Fatalf("result=%q, want %q", result, want)
			}
		}
	})

	t.Run("connection refused stays definite", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial tcp: %w", syscall.ECONNREFUSED)
		})}
		handler := NewForTest("http://localhost:8000/api/v1", client)

		result := callTool(t, handler, "reset_user_password", `{"id":7}`)

		if !strings.Contains(result, "内部 API 请求失败") {
			t.Fatalf("result=%q, want 通用失败文案", result)
		}
		for _, unwanted := range []string{"操作可能已在服务端生效", "候选密码"} {
			if strings.Contains(result, unwanted) {
				t.Fatalf("result=%q must not contain %q（连接被拒绝=确定未发送）", result, unwanted)
			}
		}
	})
}
