package mcpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
