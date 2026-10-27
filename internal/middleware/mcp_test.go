package middleware

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/mcpserver"
)

func TestAPIKeyReadOnlyGuardBlocksWritesAndAllowsReadOnlyPOST(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", true)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.POST("/api/v1/rules", noContent)
	router.POST("/api/v1/rules/cert-info", noContent)
	router.POST("/api/v1/certificates/parse", noContent)
	router.POST("/api/v1/certificate-configs/test", noContent)

	blocked := httptest.NewRecorder()
	router.ServeHTTP(blocked, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))
	if blocked.Code != http.StatusForbidden || !strings.Contains(blocked.Body.String(), "只读 API 密钥禁止写操作") {
		t.Fatalf("write status=%d body=%q", blocked.Code, blocked.Body.String())
	}
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, httptest.NewRequest(http.MethodPost, "/api/v1/rules/cert-info", nil))
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("read-only POST status=%d, want 204", allowed.Code)
	}
	parseAllowed := httptest.NewRecorder()
	router.ServeHTTP(parseAllowed, httptest.NewRequest(http.MethodPost, "/api/v1/certificates/parse", nil))
	if parseAllowed.Code != http.StatusNoContent {
		t.Fatalf("parse POST status=%d, want 204", parseAllowed.Code)
	}
	// DNS 凭证测试端点会真实 Present+CleanUp DNS TXT——已移出
	// 只读白名单，只读 API Key 必须 403。
	testBlocked := httptest.NewRecorder()
	router.ServeHTTP(testBlocked, httptest.NewRequest(http.MethodPost, "/api/v1/certificate-configs/test", nil))
	if testBlocked.Code != http.StatusForbidden {
		t.Fatalf("cert-config test POST status=%d, want 403（真实 DNS 写副作用）", testBlocked.Code)
	}
}

func TestMCPEndpointAuthenticationGatesAndProtocol(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_mcp-test-secret"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (30,'mcp-admin','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,mcp_ip_whitelist)
		VALUES ('mcp',?,?,30,1,0,'')`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}

	initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	request := func(body []byte) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("X-API-Key", key)
		router.ServeHTTP(recorder, req)
		return recorder
	}

	if response := request(initialize); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "MCP 功能未开启") {
		t.Fatalf("disabled status=%d body=%q", response.Code, response.Body.String())
	}
	if _, err := db.DB.Exec(`UPDATE api_keys SET mcp_enabled=1,mcp_ip_whitelist='["10.0.0.0/8"]' WHERE name='mcp'`); err != nil {
		t.Fatal(err)
	}
	if response := request(initialize); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "来源 IP 不在白名单") {
		t.Fatalf("whitelist status=%d body=%q", response.Code, response.Body.String())
	}
	if _, err := db.DB.Exec(`UPDATE api_keys SET mcp_ip_whitelist='' WHERE name='mcp'`); err != nil {
		t.Fatal(err)
	}
	if response := request(initialize); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"serverInfo"`) {
		t.Fatalf("initialize status=%d body=%q", response.Code, response.Body.String())
	}
	response := request([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%q", response.Code, response.Body.String())
	}
	var payload struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	// 不钉工具总数——硬编码 136 在每次增删工具时都红，且不表达任何
	// 可观察契约。改为断言 tools/list 与 ListToolSpecs 全量一致（无遗漏/无重复/
	// 无多余），新增工具无需改测试。
	specs := mcpserver.ListToolSpecs()
	expected := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		expected[spec.Name] = struct{}{}
	}
	if len(payload.Result.Tools) != len(expected) {
		t.Fatalf("tools/list count=%d, want %d (= ListToolSpecs)", len(payload.Result.Tools), len(expected))
	}
	seen := make(map[string]struct{}, len(payload.Result.Tools))
	for _, raw := range payload.Result.Tools {
		var tool struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &tool); err != nil {
			t.Fatalf("tool entry unmarshal: %v", err)
		}
		if _, ok := expected[tool.Name]; !ok {
			t.Fatalf("tools/list exposes unregistered tool %q", tool.Name)
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			t.Fatalf("tools/list repeats tool %q", tool.Name)
		}
		seen[tool.Name] = struct{}{}
	}
}

// 装配钉：SetupRouter 把 admin 组路由集合注入 MCP 可见性后，非管理员
// 属主的 MCP Key 的 tools/list 不再暴露恒 403 的管理工具（真实守卫链 + 真实
// 注入），business 组工具照常可见。
func TestMCPToolsListForNonAdminKeyHidesAdminGroupTools(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_mcp-nonadmin"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (31,'mcp-nonadmin','x','user',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,mcp_ip_whitelist)
		VALUES ('mcp-nonadmin',?,?,31,1,1,'')`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}
	request := func(body []byte) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("X-API-Key", key)
		router.ServeHTTP(recorder, req)
		return recorder
	}
	initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if response := request(initialize); response.Code != http.StatusOK {
		t.Fatalf("initialize status=%d body=%q", response.Code, response.Body.String())
	}

	// When
	response := request([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))

	// Then
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
		t.Fatal(err)
	}
	visible := make(map[string]bool, len(payload.Result.Tools))
	for _, tool := range payload.Result.Tools {
		visible[tool.Name] = true
	}
	// admin 组路由与 business 组未豁免只读白名单的写路由对非管理员恒 403，
	// tools/list 必须同口径隐藏；business 组只读查询与读探测 POST 保留。
	// preview_config/validate_import 虽为只读探测语义，但注册在 admin 组
	// （adminOnly 对非管理员一律 403），故仍不可见。
	known := map[string]bool{}
	for _, spec := range mcpserver.ListToolSpecs() {
		known[spec.Name] = true
	}
	hiddenNames := []string{"get_caddy_config", "preview_config", "validate_import", "update_user", "create_user", "create_rule", "update_rule", "retry_cert_job", "inspect_admin_tls"}
	// 反向对账：隐藏名单必须先落在真实工具目录内——工具改名/删除后旧名恒
	// false，`visible[hidden]` 断言会静默通过（假绿）。
	for _, hidden := range hiddenNames {
		if !known[hidden] {
			t.Fatalf("隐藏名单中的 %s 不在 ListToolSpecs（改名/删除后的陈旧键）", hidden)
		}
	}
	for _, hidden := range hiddenNames {
		if visible[hidden] {
			t.Errorf("non-admin tools/list exposes tool %s（调用恒 403）", hidden)
		}
	}
	for _, callable := range []string{"list_rules", "get_config", "parse_certificate"} {
		if !visible[callable] {
			t.Errorf("non-admin tools/list hides callable tool %s: %v", callable, visible)
		}
	}
}

func TestMCPEndpointToolCallAllowsOriginalClientIPWhitelist(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	router := newMiddlewareTestRouterAtPort(t, port)
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: router}}
	server.Start()
	t.Cleanup(server.Close)
	key := "lb_sk_mcp-whitelist"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (32,'mcp-whitelist','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,mcp_ip_whitelist)
		VALUES ('mcp-whitelist',?,?,32,1,1,'["192.0.2.0/24"]')`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_rules","arguments":{}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", key)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "来源 IP 不在白名单") || !strings.Contains(response.Body.String(), `\"code\":0`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

// MCP 工具调用经回环转发后，操作审计的源 IP 必须是发起
// MCP 请求的真实客户端 IP，而非回环地址 127.0.0.1（此前 RemoteAddr 恒为
// 回环，MCP 操作在审计日志里无法定位真实来源）。stop_caddy 走 Generic
// 中间件审计（Caddy 测试环境不可达 → 500，中间件仍记录）。
func TestMCPEndpointAuditRecordsOriginalClientIP(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	router := newMiddlewareTestRouterAtPort(t, port)
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: router}}
	server.Start()
	t.Cleanup(server.Close)
	key := "lb_sk_mcp-audit-ip"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (33,'mcp-audit-ip','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled)
		VALUES ('mcp-audit-ip',?,?,33,1,1)`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}

	// When：真实客户端 IP 192.0.2.99 发起 MCP 工具调用
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stop_caddy","arguments":{}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	request.RemoteAddr = "192.0.2.99:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", key)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("mcp status=%d body=%q", response.Code, response.Body.String())
	}

	// Then：中间件审计记录的源 IP 为真实客户端 IP 而非回环
	var recordedIP string
	if err := db.AuditDB.QueryRow(`SELECT ip_address FROM audit_log WHERE resource='Caddy服务' ORDER BY id DESC LIMIT 1`).Scan(&recordedIP); err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if recordedIP != "192.0.2.99" {
		t.Fatalf("audit ip_address=%q, want 192.0.2.99 (original client IP, not loopback)", recordedIP)
	}
}

// 外部请求伪造内部客户端 IP 头不得影响审计源 IP（仅内部认证密钥匹配时采信）。
func TestMCPEndpointAuditIgnoresForgedInternalClientIPHeader(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_mcp-forged-ip"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (34,'mcp-forged','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled)
		VALUES ('mcp-forged',?,?,34,1,1)`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}

	// 直接以普通 REST 写请求伪造内部头：内部认证密钥不匹配 → 审计按真实
	// RemoteAddr（httptest 默认 192.0.2.1）记录，伪造值 8.8.8.8 不得出现
	request := httptest.NewRequest(http.MethodPost, "/api/v1/caddy/stop", nil)
	request.Header.Set("X-API-Key", key)
	request.Header.Set("X-Lazy-Balancer-Internal-MCP-Auth", "forged-secret")
	request.Header.Set("X-Lazy-Balancer-Internal-MCP-Client-IP", "8.8.8.8")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	// 测试环境无 Caddy：stopCaddy 按事实分类为「已停止」（admin 不可达且无
	// caddy 进程）→ 200 且保留 pause。本用例的断言面是审计源 IP，不是停止结果；
	// 请求必须真正进入 handler 并落审计，故只要求非鉴权失败（非 401/403）。
	if response.Code != http.StatusOK {
		t.Fatalf("caddy/stop status=%d body=%q, want 200（已停止判定；鉴权必须通过）", response.Code, response.Body.String())
	}
	var recordedIP string
	if err := db.AuditDB.QueryRow(`SELECT ip_address FROM audit_log WHERE resource='Caddy服务' ORDER BY id DESC LIMIT 1`).Scan(&recordedIP); err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if recordedIP == "8.8.8.8" {
		t.Fatalf("forged internal client IP header was trusted, audit ip_address=8.8.8.8")
	}
	if recordedIP != "192.0.2.1" {
		t.Fatalf("audit ip_address=%q, want 192.0.2.1 (real RemoteAddr)", recordedIP)
	}
}

func TestMCPEndpointRejectsRequestBodyLargerThanOneMiB(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_mcp-oversize"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (31,'mcp-large','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled) VALUES ('mcp-large',?,?,31,1,1)`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<20)+1)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", key)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q, want 413", response.Code, response.Body.String())
	}
}

// mcpAccessGuard 两拒绝分支此前不留任何审计——无凭证探测 /mcp 与
// 未开启 MCP 的 Key 使用在认证拒绝台账零痕迹（同链 adminOnly/apiKeyReadOnly/
// readOnly 守卫均已留痕）。镜像既有形态：recordAuthenticationRejection +
// securityAuditLimiter 去重（同 reason+path+ip 一分钟窗记 1 条）。
func TestMCPAccessGuard_rejectionsAreAudited(t *testing.T) {
	// Given：桩 apiKeyAuth 产物（auth_type/api_key_mcp_enabled 即守卫的全部输入）
	recorded := captureAuthenticationSecurityAudits(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if key := c.GetHeader("X-API-Key"); key != "" {
			c.Set("auth_type", "api_key")
			c.Set("api_key_mcp_enabled", key == "lb_sk_mcp-on")
		}
		c.Next()
	}, mcpAccessGuard())
	router.POST("/api/v1/mcp", noContent)

	// When：无凭证（JWT/匿名同形——auth_type 非 api_key），窗口内双发
	serveRepeatedDeniedRequests(router, http.MethodPost, "/api/v1/mcp", "Authorization", "Bearer jwt-plaintext")

	// Then：401 且落 mcp_auth_rejected 审计（限重窗去重为 1 条，不泄漏凭证）
	assertSingleSecurityAudit(t, *recorded, "mcp_auth_rejected", "jwt-plaintext")

	// When：Key 有效但未开启 MCP
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	request.RemoteAddr = "198.51.100.77:1234"
	request.Header.Set("X-API-Key", "lb_sk_mcp-off")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：403 且落 mcp_disabled 审计（独立原因类别，不与上一窗合并）
	if response.Code != http.StatusForbidden {
		t.Fatalf("mcp disabled status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if len(*recorded) != 2 {
		t.Fatalf("security audit events=%d, want 2: %q", len(*recorded), *recorded)
	}
	if !strings.Contains((*recorded)[1], "原因类别：mcp_disabled") {
		t.Fatalf("security audit=%q, want reason mcp_disabled", (*recorded)[1])
	}
	if strings.Contains((*recorded)[1], "lb_sk_mcp-off") {
		t.Fatalf("security audit leaked credential: %q", (*recorded)[1])
	}

	// When：已开启 MCP 的有效 Key 正常透传
	passage := httptest.NewRecorder()
	passageRequest := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
	passageRequest.Header.Set("X-API-Key", "lb_sk_mcp-on")
	router.ServeHTTP(passage, passageRequest)

	// Then：透传至业务 handler，且不新增拒绝审计
	if passage.Code != http.StatusNoContent {
		t.Fatalf("valid key status=%d, want pass-through 204", passage.Code)
	}
	if len(*recorded) != 2 {
		t.Fatalf("pass-through must not add rejection audits, got %d: %q", len(*recorded), *recorded)
	}
}

// 从节点 MCP 写工具的端到端契约：真实 listener + 完整 router + 管理员 Key
// （mcp_enabled=1）。MCP 层不做从节点判定，写请求经回环转发后被 REST 侧
// readOnlyGuard 拦截——工具结果必须是内层 403「从节点只读」，且规则零落库
// （此前只有转发目标路由的中间件级钉测，没有「转发确实发生且被拦」的证明）。
func TestMCPEndpoint_slaveWriteToolRejectedByInnerReadOnlyGuard(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	router := newMiddlewareTestRouterAtPort(t, port)
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: router}}
	server.Start()
	t.Cleanup(server.Close)

	key := "lb_sk_mcp-slave-write"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (34,'mcp-slave','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled)
		VALUES ('mcp-slave',?,?,34,1,1)`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}
	// Given 本节点为从节点
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_rule","arguments":{}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", key)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then ① JSON-RPC 层成功返回（错误经工具结果表达，不劫持协议层）
	if response.Code != http.StatusOK {
		t.Fatalf("mcp status=%d body=%q", response.Code, response.Body.String())
	}
	// ② 工具结果标记 isError 且携带内层 403 真因
	if !strings.Contains(response.Body.String(), `"isError":true`) {
		t.Fatalf("body=%q, want 工具结果 isError=true", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "从节点只读") {
		t.Fatalf("body=%q, want 内层 403「从节点只读」", response.Body.String())
	}
	// ③ 规则零落库
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules`).Scan(&count); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("lb_rules 行数=%d, want 0（从节点写入必须被拦截且不落库）", count)
	}
}

// 自签回环豁免只属于 MCP 内部转发专用客户端：通用默认传输一旦被改成跳过
// 校验，面板全部出站请求（集群同步、CA/DNS 调用）都会静默失去证书校验。
// 每次装配返回独立 transport，避免调用方改 CheckRedirect 等字段互相污染。
func TestLoopbackAPIClient_TLSExemptionIsScoped(t *testing.T) {
	client := LoopbackAPIClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("LoopbackAPIClient().Transport=%T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("回环专用客户端必须显式豁免自签证书校验（面板 selfsigned 形态下 TLS 重放依赖它）")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("回环 TLS MinVersion=%x, want TLS1.2", transport.TLSClientConfig.MinVersion)
	}
	if client.Timeout != 60*time.Second {
		t.Fatalf("回环客户端 Timeout=%s, want 60s（长操作单次等待上限）", client.Timeout)
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport=%T, want *http.Transport", http.DefaultTransport)
	}
	if defaultTransport.TLSClientConfig != nil && defaultTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("默认传输被改成跳过证书校验——豁免不得扩散到通用客户端")
	}
	if LoopbackAPIClient().Transport == client.Transport {
		t.Fatal("每次装配必须返回独立 transport（客户端副本改字段不得污染共享实例）")
	}
}
