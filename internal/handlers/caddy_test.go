package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

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
