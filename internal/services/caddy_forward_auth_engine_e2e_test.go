package services

// 认证网关引擎级 E2E：真实 Caddy 二进制（项目定制镜像二进制，PATH 提供；
// 缺席则跳过——与 caddy_engine_acceptance_test 同契约）加载本渲染器产出的
// forward_auth 配置，httptest 假网关/假后端实测两条主路径：
// ①网关 200 + Remote-User → 后端收到注入的身份头；
// ②网关 401 → 客户端原样收到网关响应（状态码/响应体），后端零请求。

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestForwardAuthEngineEndToEnd(t *testing.T) {
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Skipf("真实 Caddy 引擎不可用：PATH 中未找到 caddy（需含 forward_auth 所需标准模块）: %v", err)
	}

	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.Header().Set("X-Backend-Seen-User", r.Header.Get("Remote-User"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	gatewayMode := "allow"
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("gateway got method %s, want GET", r.Method)
		}
		if r.Header.Get("X-Forwarded-Method") == "" || r.Header.Get("X-Forwarded-Uri") == "" {
			t.Errorf("gateway missing X-Forwarded-Method/Uri headers")
		}
		if gatewayMode == "deny" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("gateway-401-body"))
			return
		}
		w.Header().Set("Remote-User", "alice@example.test")
		w.WriteHeader(http.StatusOK)
	}))
	defer gateway.Close()

	gatewayURL := gateway.URL
	rule := baseHTTPRule()
	rule.ForwardAuthEnabled = 1
	rule.ForwardAuthUpstream = gatewayURL
	rule.ForwardAuthURI = "/api/authz/forward-auth"
	rule.ForwardAuthCopyHeaders = "Remote-User"
	handler, err := buildForwardAuthHandler(rule)
	if err != nil {
		t.Fatalf("buildForwardAuthHandler: %v", err)
	}
	backendUpstreams := []interface{}{map[string]interface{}{"dial": trimSchemeHostPort(backend.URL)}}
	proxyHandler := map[string]interface{}{"handler": "reverse_proxy", "upstreams": backendUpstreams}

	// 独立监听端口承载被测路由（host matcher 省略——listener 全量匹配）。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	config := map[string]interface{}{
		"admin": map[string]interface{}{"disabled": true},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{"127.0.0.1:" + strconv.Itoa(port)},
						"routes": []interface{}{map[string]interface{}{
							"handle": []interface{}{handler, proxyHandler},
						}},
					},
				},
			},
		},
	}
	configPath := filepath.Join(t.TempDir(), "fa-e2e.json")
	rendered, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, rendered, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("validate", func(t *testing.T) {
		// 裸 JSON 配置不携带 adapter（caddy validate 默认按 JSON 读取；
		// --adapter json 未注册于标准构建）。
		out, err := exec.CommandContext(t.Context(), binary, "validate", "--config", configPath).CombinedOutput()
		if err != nil {
			t.Fatalf("caddy validate rejected forward_auth config: %v\n%s", err, out)
		}
	})

	cmd := exec.CommandContext(t.Context(), binary, "run", "--config", configPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	waitForListener(t, base)

	t.Run("2xx 注入身份头", func(t *testing.T) {
		resp, err := client.Get(base + "/app/path?q=1")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("X-Backend-Seen-User") != "alice@example.test" {
			t.Fatalf("status=%d seen-user=%q, want 200/alice@example.test", resp.StatusCode, resp.Header.Get("X-Backend-Seen-User"))
		}
	})

	t.Run("401 原样透传", func(t *testing.T) {
		gatewayMode = "deny"
		hitsBefore := backendHits
		resp, err := client.Get(base + "/denied")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		if resp.StatusCode != 401 || string(buf[:n]) != "gateway-401-body" {
			t.Fatalf("status=%d body=%q, want 401/gateway-401-body", resp.StatusCode, string(buf[:n]))
		}
		if backendHits != hitsBefore {
			t.Fatalf("backend received %d requests on unauthenticated path, want 0", backendHits-hitsBefore)
		}
	})
}

func trimSchemeHostPort(rawURL string) string {
	// httptest.Server URL → host:port。
	for _, prefix := range []string{"http://", "https://"} {
		if len(rawURL) > len(prefix) && rawURL[:len(prefix)] == prefix {
			return rawURL[len(prefix):]
		}
	}
	return rawURL
}

func waitForListener(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/e2e-warmup")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("caddy listener did not come up")
}
