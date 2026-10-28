package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// MCP 端点与其他公开写端点同族：请求体上限 1 MiB 并逐条转发到内部 API。
// 不挂限流时单个 API Key 可以线速灌满内部 API/审计库，且限流必须发生在
// 请求体读取与认证之前（未认证流量不得先花掉 1 MiB 读与一次密钥点查）。
func TestMCPEndpointRateLimited(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)

	key := "lb_sk_mcp-ratelimit-secret"
	hash := sha256.Sum256([]byte(key))
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (31,'mcp-ratelimit','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,mcp_ip_whitelist)
		VALUES ('mcp-ratelimit',?,?,31,1,1,'')`, hex.EncodeToString(hash[:]), key[:12]); err != nil {
		t.Fatal(err)
	}

	initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ratelimit","version":"1"}}}`)
	send := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(initialize))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("X-API-Key", key)
		router.ServeHTTP(recorder, request)
		return recorder
	}

	for i := range mcpRateLimitPerMinute {
		response := send()
		if response.Code == http.StatusTooManyRequests {
			t.Fatalf("第 %d 次请求（限额 %d 内）被限流: %s", i+1, mcpRateLimitPerMinute, response.Body.String())
		}
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"serverInfo"`) {
			t.Fatalf("第 %d 次请求未到达 MCP handler: status=%d body=%q", i+1, response.Code, response.Body.String())
		}
	}

	overLimit := send()
	if overLimit.Code != http.StatusTooManyRequests {
		t.Fatalf("超过限额的请求 status=%d body=%q, want 429", overLimit.Code, overLimit.Body.String())
	}
	var payload struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(overLimit.Body.Bytes(), &payload); err != nil {
		t.Fatalf("429 响应不是标准形态: %v body=%q", err, overLimit.Body.String())
	}
	if payload.Code != http.StatusTooManyRequests || payload.Message == "" {
		t.Fatalf("429 形态不合规: %+v", payload)
	}
}
