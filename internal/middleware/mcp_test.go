package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
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
	testAllowed := httptest.NewRecorder()
	router.ServeHTTP(testAllowed, httptest.NewRequest(http.MethodPost, "/api/v1/certificate-configs/test", nil))
	if testAllowed.Code != http.StatusNoContent {
		t.Fatalf("test POST status=%d, want 204", testAllowed.Code)
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
	if len(payload.Result.Tools) != 117 {
		t.Fatalf("tool count=%d, want 117", len(payload.Result.Tools))
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

// 第 15 轮审计 K-1：MCP 工具调用经回环转发后，操作审计的源 IP 必须是发起
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
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("caddy/stop status=%d body=%q, want 500 (caddy unreachable in test)", response.Code, response.Body.String())
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
