package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
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
	// R69 C-N3-c：validate 成功后 handler 回弹 DB 生成的权威配置（/load 无
	// validate-only 语义，成功即已加载）——契约更新为 valid 用例两次 /load
	// POST（校验 + 回弹）。
	newBackupTestHandlers(t)
	requests := 0
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/load" {
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
	// valid（校验+回弹）+ invalid（仅校验）= 3；malformed 停在 handler。
	if requests != 3 {
		t.Fatalf("Caddy validation requests=%d, want 3 (malformed JSON must stop at the handler)", requests)
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

// R40 F-2: PutCaddyConfig 对 chunked/未知 ContentLength 的超大请求体（绕过预检、
// 经 MaxBytesReader 拦截）须映射 413，与导入路径口径一致，而非统一 400。
func TestPutCaddyConfig_oversized_unknown_length_body_returns_413(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.PUT("/caddy", h.PutCaddyConfig)

	body := `{"content":"` + strings.Repeat("x", 1<<20) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/caddy", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = -1 // 模拟 chunked/未知长度，绕过预检走 MaxBytesReader
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413", response.Code, response.Body.String())
	}
}

// R41 D-F2: 键集合一致性——planConfigChanges 中归属「Caddy配置」分组的 add() 键
// 必须与 UpdateConfig PUT SQL 实际更新的同分组列集合相等（防止变更提示与实际写入漂移）。
func TestCaddySectionKeys_matchUpdateSQL(t *testing.T) {
	changesSrc, err := os.ReadFile("config_changes.go")
	if err != nil {
		t.Fatalf("read config_changes.go: %v", err)
	}
	caddySrc, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}

	addKeyRe := regexp.MustCompile(`\badd\("([a-z0-9_]+)"`)
	changesKeys := map[string]bool{}
	for _, m := range addKeyRe.FindAllStringSubmatch(string(changesSrc), -1) {
		if services.GetConfigSection(m[1]) == "Caddy配置" {
			changesKeys[m[1]] = true
		}
	}

	updateStart := strings.Index(string(caddySrc), "UPDATE global_config SET")
	updateEnd := strings.Index(string(caddySrc[updateStart:]), "WHERE id = 1")
	if updateStart < 0 || updateEnd < 0 {
		t.Fatalf("cannot locate UPDATE global_config block in caddy.go")
	}
	updateBlock := string(caddySrc[updateStart : updateStart+updateEnd])
	colRe := regexp.MustCompile(`(?m)^\s*([a-z0-9_]+)\s*=\s*(?:COALESCE|CASE WHEN)`)
	sqlKeys := map[string]bool{}
	for _, m := range colRe.FindAllStringSubmatch(updateBlock, -1) {
		if services.GetConfigSection(m[1]) == "Caddy配置" {
			sqlKeys[m[1]] = true
		}
	}

	if len(changesKeys) == 0 || len(sqlKeys) == 0 {
		t.Fatalf("extracted empty key set: changes=%v sql=%v", changesKeys, sqlKeys)
	}
	for k := range changesKeys {
		if !sqlKeys[k] {
			t.Fatalf("key %q in planConfigChanges but not in UpdateConfig SQL", k)
		}
	}
	for k := range sqlKeys {
		if !changesKeys[k] {
			t.Fatalf("key %q in UpdateConfig SQL but not in planConfigChanges", k)
		}
	}
}
