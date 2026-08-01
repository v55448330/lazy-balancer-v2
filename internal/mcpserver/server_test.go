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

func TestIssueCertificateSchemaAllowsEmptyOrCaddyIDWithOptionalDomain(t *testing.T) {
	// Given
	var schema struct {
		OneOf []struct {
			Required      []string `json:"required"`
			MaxProperties *int     `json:"maxProperties"`
		} `json:"oneOf"`
	}

	// When
	if err := json.Unmarshal([]byte(issueCertificateSchema), &schema); err != nil {
		t.Fatal(err)
	}

	// Then
	if len(schema.OneOf) != 2 || schema.OneOf[0].MaxProperties == nil || *schema.OneOf[0].MaxProperties != 0 || strings.Join(schema.OneOf[1].Required, ",") != "caddy_id" {
		t.Fatalf("oneOf=%+v", schema.OneOf)
	}
}

func TestUpdateConfigSchemaIncludesCaddyLogPath(t *testing.T) {
	// Given
	var schema struct {
		Properties map[string]any `json:"properties"`
	}

	// When
	err := json.Unmarshal([]byte(updateConfigSchema), &schema)

	// Then
	if err != nil {
		t.Fatalf("parse update config schema: %v", err)
	}
	if _, exists := schema.Properties["caddy_log_path"]; !exists {
		t.Fatal("update_config schema missing caddy_log_path")
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
	if len(payload.Result.Tools) != 15 {
		t.Fatalf("read-only tool count=%d, want 15", len(payload.Result.Tools))
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
