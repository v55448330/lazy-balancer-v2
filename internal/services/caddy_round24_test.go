package services

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Round 24 C-N4：Caddy 管理接口不可达（传输层错误）时必须显式报错，
// 不能把 GetConfig 的失败当成“校验通过”静默放行。
func TestValidateRouteMergedConfig_adminUnreachable_returnsError(t *testing.T) {
	// Given：占用后立即释放的端口，模拟 Caddy 管理接口未监听
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	unreachableURL := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	service := NewCaddyService(unreachableURL)

	// When
	err = service.ValidateRouteMergedConfig("http_80", map[string]interface{}{"@id": "rule-new"})

	// Then
	if err == nil || !strings.Contains(err.Error(), "无法连接 Caddy 管理接口") {
		t.Fatalf("ValidateRouteMergedConfig() error = %v, want admin unreachable error", err)
	}
}

// Round 24 C-N4：Caddy 已运行但尚无任何已加载配置（空配置）时，仍按原语义放行
// （首条规则创建场景，实际校验发生在配置应用阶段）。
func TestValidateRouteMergedConfig_emptyConfig_passes(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/config/" {
			_, _ = writer.Write([]byte(`{}`))
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// When
	err := NewCaddyService(server.URL).ValidateRouteMergedConfig("http_80", map[string]interface{}{"@id": "rule-new"})

	// Then
	if err != nil {
		t.Fatalf("ValidateRouteMergedConfig() error = %v, want nil for empty config", err)
	}
}
