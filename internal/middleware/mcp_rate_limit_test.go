package middleware

import (
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
	seedMCPRateLimitKeys(t, key)
	send := func() *httptest.ResponseRecorder {
		return sendMCPInitialize(router, key)
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
	retryAfter := overLimit.Header().Get("Retry-After")
	retrySeconds, err := json.Number(retryAfter).Int64()
	if err != nil || retrySeconds < 1 || retrySeconds > 60 {
		t.Fatalf("429 Retry-After=%q, want integer seconds in [1,60]", retryAfter)
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

func TestMCPRateLimitSeparatesKeysAtSameSourceIP(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)
	firstKey := "lb_sk_mcp-ratelimit-first"
	secondKey := "lb_sk_mcp-ratelimit-second"
	seedMCPRateLimitKeys(t, firstKey, secondKey)

	for attempt := 1; attempt <= mcpRateLimitPerMinute; attempt++ {
		if response := sendMCPInitialize(router, firstKey); response.Code != http.StatusOK {
			t.Fatalf("first key attempt %d status=%d body=%q, want 200", attempt, response.Code, response.Body.String())
		}
	}
	if response := sendMCPInitialize(router, secondKey); response.Code != http.StatusOK {
		t.Fatalf("second key at same IP status=%d body=%q, want independent budget", response.Code, response.Body.String())
	}
}

func TestMCPAuthenticatedRequestsDoNotConsumeAnonymousFailureBudget(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)
	key := "lb_sk_mcp-ratelimit-authenticated"
	seedMCPRateLimitKeys(t, key)

	for attempt := 1; attempt < mcpRateLimitPerMinute; attempt++ {
		if response := sendMCPInitialize(router, ""); response.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous attempt %d status=%d body=%q, want 401", attempt, response.Code, response.Body.String())
		}
	}
	if response := sendMCPInitialize(router, key); response.Code != http.StatusOK {
		t.Fatalf("authenticated request status=%d body=%q, want 200", response.Code, response.Body.String())
	}
	if response := sendMCPInitialize(router, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous request after authenticated success status=%d body=%q, want 401 with reservation rolled back", response.Code, response.Body.String())
	}
	if response := sendMCPInitialize(router, ""); response.Code != http.StatusTooManyRequests {
		t.Fatalf("anonymous request beyond failure budget status=%d body=%q, want 429", response.Code, response.Body.String())
	}
}

const mcpRateLimitInitialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ratelimit","version":"1"}}}`

func seedMCPRateLimitKeys(t *testing.T, keys ...string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (31,'mcp-ratelimit','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		hash := sha256.Sum256([]byte(key))
		if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,mcp_ip_whitelist)
			VALUES (?,?,?,31,1,1,'')`, key, hex.EncodeToString(hash[:]), key[:12]); err != nil {
			t.Fatal(err)
		}
	}
}

func sendMCPInitialize(router http.Handler, key string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(mcpRateLimitInitialize))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if key != "" {
		request.Header.Set("X-API-Key", key)
	}
	router.ServeHTTP(recorder, request)
	return recorder
}
