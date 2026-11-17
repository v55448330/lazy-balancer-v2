package mcpserver

// 会话注册表钉测：initialize 落行（属主来自网关注入）、每请求活性刷新、
// 强制断开三处生效（管理器终止→404/注销推送/删行）、实时推送经会话下一
// POST 以 SSE 冲刷、全局开关停推、工具调用统计按日×工具×Key upsert。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// sessionRegistryTestHandler 装配真实传输层 handler，并模拟网关把属主随
// context 注入（生产由 middleware /mcp 闭包完成）。
func sessionRegistryTestHandler(t *testing.T, restURL string, client *http.Client, userID, keyID int64) http.Handler {
	t.Helper()
	inner := NewForTest(restURL+"/api/v1", client)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithSessionOwner(r.Context(), userID, keyID, "10.1.2.3", "session-registry-test"))
		inner.ServeHTTP(w, r)
	})
}

// postMCPJSON 单发 JSON-RPC 请求（可带会话头），返回 recorder 供断言。
func postMCPJSON(t *testing.T, handler http.Handler, sessionID, payload string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	// 工具转发链要求 Key 在头（服务端测试同形）；本套件不做 Key 级可见性断言，
	// 只需非空即可放行转发。
	request.Header.Set("X-API-Key", "lb_sk_session-registry-test")
	if sessionID != "" {
		request.Header.Set(mcpSessionIDHeader, sessionID)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

const initializePayload = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"session-registry-test","version":"0"}}}`

// initializeMCPSession 完成 initialize 握手并返回回传的会话 ID。
func initializeMCPSession(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := postMCPJSON(t, handler, "", initializePayload)
	if response.Code != http.StatusOK {
		t.Fatalf("initialize status=%d body=%s", response.Code, response.Body.String())
	}
	sessionID := response.Header().Get(mcpSessionIDHeader)
	if sessionID == "" {
		t.Fatalf("initialize 响应未回传会话头（有状态化失败）")
	}
	return sessionID
}

func TestSessionRegistryInitializeRegistersOwnerRow(t *testing.T) {
	withIsolatedMCPDatabase(t)
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()

	handler := sessionRegistryTestHandler(t, rest.URL, rest.Client(), 7, 42)
	sessionID := initializeMCPSession(t, handler)
	var userID, keyID int64
	var ip, userAgent string
	if err := db.DB.QueryRow(`SELECT user_id, api_key_id, ip, user_agent FROM mcp_sessions WHERE session_id=?`, sessionID).
		Scan(&userID, &keyID, &ip, &userAgent); err != nil {
		t.Fatalf("会话行未落库: %v", err)
	}
	if userID != 7 || keyID != 42 {
		t.Errorf("属主=%d/%d, want 7/42（网关注入断链）", userID, keyID)
	}
	if ip != "10.1.2.3" || userAgent != "session-registry-test" {
		t.Errorf("来源=%q/%q, want 注入值", ip, userAgent)
	}
}

func TestSessionRegistryTouchesLastSeenPerRequest(t *testing.T) {
	withIsolatedMCPDatabase(t)
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()

	handler := sessionRegistryTestHandler(t, rest.URL, rest.Client(), 7, 42)
	sessionID := initializeMCPSession(t, handler)
	if _, err := db.DB.Exec(`UPDATE mcp_sessions SET last_seen='2020-01-01 00:00:00' WHERE session_id=?`, sessionID); err != nil {
		t.Fatalf("age last_seen: %v", err)
	}

	payload := `{"jsonrpc":"2.0","id":2,"method":"ping"}`
	response := postMCPJSON(t, handler, sessionID, payload)
	if response.Code != http.StatusOK {
		t.Fatalf("ping status=%d body=%s", response.Code, response.Body.String())
	}
	var lastSeen string
	if err := db.DB.QueryRow(`SELECT last_seen FROM mcp_sessions WHERE session_id=?`, sessionID).Scan(&lastSeen); err != nil {
		t.Fatalf("会话行丢失: %v", err)
	}
	if strings.HasPrefix(lastSeen, "2020-01-01") {
		t.Errorf("last_seen=%s 未随请求刷新", lastSeen)
	}
}

func TestSessionRegistryDisconnectRejectsTerminatedSession(t *testing.T) {
	withIsolatedMCPDatabase(t)
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()

	handler := sessionRegistryTestHandler(t, rest.URL, rest.Client(), 7, 42)
	sessionID := initializeMCPSession(t, handler)

	deleted, err := DisconnectSession(sessionID)
	if err != nil || !deleted {
		t.Fatalf("DisconnectSession deleted=%v err=%v, want true/nil", deleted, err)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM mcp_sessions WHERE session_id=?`, sessionID).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Errorf("会话行未删（rows=%d）", rows)
	}
	// 重复断开：行已删，幂等清理返回 false/nil。
	deleted, err = DisconnectSession(sessionID)
	if err != nil || deleted {
		t.Errorf("重复断开 deleted=%v err=%v, want false/nil", deleted, err)
	}

	response := postMCPJSON(t, handler, sessionID, `{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	if response.Code != http.StatusNotFound {
		t.Errorf("终止后请求 status=%d, want 404 Session terminated", response.Code)
	}
}

func TestSessionRegistryPushDeliveredOnNextRequest(t *testing.T) {
	withIsolatedMCPDatabase(t)
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()

	handler := sessionRegistryTestHandler(t, rest.URL, rest.Client(), 7, 42)
	sessionID := initializeMCPSession(t, handler)

	// 推送 hook 已在装配时注册；会话行属主=7，推送应命中本会话（注册成功，
	// 通知入会话缓冲），下一 POST 响应以 SSE 冲刷。
	target := pushTargetServer.Load()
	if target == nil {
		t.Fatalf("推送目标未注册")
	}
	pushToUserSessions(target, 7, notify.Message{
		EventType: "cert_failed", Level: "critical",
		Title: "证书续签失败", Body: "规则 lb_x 证书申请失败",
	})

	response := postMCPJSON(t, handler, sessionID, `{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("push 后请求 status=%d body=%s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("push 后响应未升级 SSE（Content-Type=%s）", contentType)
	}
	body := response.Body.String()
	if !strings.Contains(body, "notifications/message") || !strings.Contains(body, "证书续签失败") {
		t.Errorf("SSE 冲刷缺通知载荷: %s", body)
	}
}

func TestSessionRegistryGlobalSwitchBlocksPush(t *testing.T) {
	withIsolatedMCPDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO notify_settings(key, value) VALUES ('notify.mcp_enabled', '0')`); err != nil {
		t.Fatalf("seed switch: %v", err)
	}
	if MCPSwitchEnabled() {
		t.Fatalf("开关 '0' 仍判启用")
	}
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer rest.Close()

	handler := sessionRegistryTestHandler(t, rest.URL, rest.Client(), 7, 42)
	sessionID := initializeMCPSession(t, handler)
	pushToUserSessions(pushTargetServer.Load(), 7, notify.Message{
		EventType: "cert_failed", Level: "critical", Title: "不应送达",
	})

	response := postMCPJSON(t, handler, sessionID, `{"jsonrpc":"2.0","id":5,"method":"ping"}`)
	if strings.Contains(response.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("停用后推送仍升级 SSE")
	}
	var parsed struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil || len(parsed.Result) == 0 {
		t.Errorf("停用开关不应改变正常 RPC 响应: body=%s err=%v", response.Body.String(), err)
	}
}

func TestToolStatUpsertsPerDayToolKey(t *testing.T) {
	withIsolatedMCPDatabase(t)
	var gotPath string
	rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"rules":[]}}`))
	}))
	defer rest.Close()

	handler := sessionRegistryTestHandler(t, rest.URL, rest.Client(), 7, 42)
	// 成功调用一次。
	if result := callToolWithHandler(t, handler, "list_rules", `{}`); strings.Contains(result, "error") || strings.Contains(result, `"isError":true`) {
		t.Fatalf("list_rules result=%s", result)
	}
	if gotPath == "" {
		t.Fatalf("工具未转发")
	}
	var calls, errs int
	if err := db.DB.QueryRow(`SELECT calls, errors FROM mcp_tool_stats WHERE tool='list_rules'`).Scan(&calls, &errs); err != nil {
		t.Fatalf("统计行未落库: %v", err)
	}
	if calls != 1 || errs != 0 {
		t.Errorf("成功调用统计 calls=%d errors=%d, want 1/0", calls, errs)
	}
	// 失败调用两次（缺参 toolCallError）：同 PK upsert 累加。
	_ = callToolWithHandler(t, handler, "list_rules", `{}`)
	_ = callToolWithHandler(t, handler, "get_rule", `{}`)
	if err := db.DB.QueryRow(`SELECT calls, errors FROM mcp_tool_stats WHERE tool='list_rules'`).Scan(&calls, &errs); err != nil {
		t.Fatalf("统计行丢失: %v", err)
	}
	if calls != 2 {
		t.Errorf("list_rules 累加 calls=%d, want 2", calls)
	}
	var badCalls, badErrs int
	if err := db.DB.QueryRow(`SELECT calls, errors FROM mcp_tool_stats WHERE tool='get_rule'`).Scan(&badCalls, &badErrs); err != nil {
		t.Fatalf("失败统计行未落库: %v", err)
	}
	if badCalls != 1 || badErrs != 1 {
		t.Errorf("失败调用统计 calls=%d errors=%d, want 1/1", badCalls, badErrs)
	}
	var keyID int64
	if err := db.DB.QueryRow(`SELECT DISTINCT key_id FROM mcp_tool_stats`).Scan(&keyID); err != nil {
		t.Fatalf("key_id 读取: %v", err)
	}
	if keyID != 42 {
		t.Errorf("key_id=%d, want 42（网关注入）", keyID)
	}
}

// callToolWithHandler 与 server_test.go callTool 同形，但接受外部 handler
// （会话属主注入形态）。
func callToolWithHandler(t *testing.T, handler http.Handler, name, arguments string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	response := postMCPJSON(t, handler, "", body)
	return response.Body.String()
}
