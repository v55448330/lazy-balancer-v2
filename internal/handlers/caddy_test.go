package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

func TestCaddyLifecycleHandlers_wait_for_rule_operation_lock(t *testing.T) {
	tests := []struct {
		name  string
		mount func(*gin.Engine, *Handlers)
	}{
		{name: "start", mount: func(r *gin.Engine, h *Handlers) { r.POST("/lifecycle", h.StartCaddy) }},
		{name: "stop", mount: func(r *gin.Engine, h *Handlers) { r.POST("/lifecycle", h.StopCaddy) }},
		{name: "restart", mount: func(r *gin.Engine, h *Handlers) { r.POST("/lifecycle", h.RestartCaddy) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{cfg: &config.Config{CaddyAdminURL: "http://127.0.0.1:1"}}
			router := gin.New()
			tt.mount(router, h)
			h.caddyOpMu.Lock()
			started := make(chan struct{})
			done := make(chan struct{})
			go func() {
				close(started)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/lifecycle", nil))
				close(done)
			}()
			<-started
			select {
			case <-done:
				h.caddyOpMu.Unlock()
				t.Fatal("lifecycle handler ran while rule operation lock was held")
			case <-time.After(50 * time.Millisecond):
			}
			h.caddyOpMu.Unlock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("lifecycle handler did not resume after rule operation lock release")
			}
		})
	}
}

func TestStartCaddy_does_not_overlap_UpdateRule(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_lifecycle", 0, true)
	seedAuditRule(t, "lb_lifecycle", "original", "lifecycle.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_lifecycle")
	original := caddyRunCommand
	startInvoked := make(chan struct{})
	caddyRunCommand = func() *exec.Cmd {
		close(startInvoked)
		return exec.Command("sh", "-c", "exit 7")
	}
	t.Cleanup(func() { caddyRunCommand = original })
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	router.POST("/caddy/start", harness.handler.StartCaddy)
	updateDone := make(chan struct{})
	go func() {
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_lifecycle", strings.NewReader(`{"name":"updated"}`))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), request)
		close(updateDone)
	}()
	<-harness.firstRouteEntered
	startDone := make(chan struct{})
	go func() {
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/caddy/start", nil))
		close(startDone)
	}()
	select {
	case <-startInvoked:
		t.Fatal("StartCaddy entered process mutation while UpdateRule held the operation lock")
	case <-time.After(50 * time.Millisecond):
	}
	harness.release()
	select {
	case <-updateDone:
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateRule did not finish after barrier release")
	}
	select {
	case <-startDone:
	case <-time.After(5 * time.Second):
		t.Fatal("StartCaddy did not run after UpdateRule finished")
	}
}

func TestStartCaddy_returns_500_when_process_exits_before_ready(t *testing.T) {
	original := caddyRunCommand
	caddyRunCommand = func() *exec.Cmd { return exec.Command("sh", "-c", "exit 7") }
	t.Cleanup(func() { caddyRunCommand = original })
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: "http://127.0.0.1:1"}}
	router := gin.New()
	router.POST("/start", h.StartCaddy)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/start", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
}

func TestStopCaddy_returns_500_when_stop_command_fails(t *testing.T) {
	original := caddyStopCommand
	caddyStopCommand = func(string) *exec.Cmd { return exec.Command("sh", "-c", "exit 8") }
	t.Cleanup(func() { caddyStopCommand = original })
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: "http://127.0.0.1:1"}}
	router := gin.New()
	router.POST("/stop", h.StopCaddy)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/stop", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
}

func TestValidateConfig_validates_submitted_config(t *testing.T) {
	// Given
	requests := 0
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/load" || request.URL.Query().Get("validate") != "true" {
			t.Fatalf("validation request path=%q query=%q", request.URL.Path, request.URL.RawQuery)
		}
		var config map[string]any
		if err := json.NewDecoder(request.Body).Decode(&config); err != nil {
			t.Fatalf("decode submitted config: %v", err)
		}
		if invalid, _ := config["invalid"].(bool); invalid {
			response.WriteHeader(http.StatusBadRequest)
			_, _ = response.Write([]byte("invalid config"))
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{
		cfg:          &config.Config{CaddyAdminURL: fakeCaddy.URL},
		caddyService: services.NewCaddyService(fakeCaddy.URL),
	}
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfig)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "valid", body: `{"apps":{"http":{}}}`, wantStatus: http.StatusOK},
		{name: "invalid", body: `{"invalid":true}`, wantStatus: http.StatusBadRequest},
		{name: "malformed", body: `{"apps":`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, request)

			// Then
			if response.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantStatus)
			}
		})
	}
	if requests != 2 {
		t.Fatalf("Caddy validation requests=%d, want 2 (malformed JSON must stop at the handler)", requests)
	}
}

func TestGetUpstreamHealth_returnsBadGatewayWithoutLeakingCollectorError(t *testing.T) {
	h := &Handlers{caddyService: services.NewCaddyService("http://127.0.0.1:1/private-admin")}
	router := gin.New()
	router.GET("/health", h.GetUpstreamHealth)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "127.0.0.1") || strings.Contains(response.Body.String(), "private-admin") {
		t.Fatalf("response leaked collector details: %s", response.Body.String())
	}
}
