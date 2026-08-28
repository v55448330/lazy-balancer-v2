package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
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

// seedProcStat 在伪 /proc 根下写一个进程的 stat 文件（格式：pid (comm) state ...）。
func seedProcStat(t *testing.T, root, pid, comm string, state byte) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fake proc: %v", err)
	}
	stat := fmt.Sprintf("%s (%s) %c S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0", pid, comm, state)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatalf("write fake stat: %v", err)
	}
}

func TestCaddyProcessRunning_excludesZombieProcesses(t *testing.T) {
	// Given 伪 /proc 中只有僵尸 caddy（entrypoint 孵化、父进程未回收的子进程——
	// comm 仍为 caddy 且进程存在，但已 dead 不能再服务）
	root := t.TempDir()
	seedProcStat(t, root, "10", "caddy", 'Z')
	original := caddyProcRoot
	caddyProcRoot = root
	t.Cleanup(func() { caddyProcRoot = original })

	// When/Then 僵尸不得计为运行中（否则 stop/restart 的完成判定永远失败）
	if caddyProcessRunning() {
		t.Fatal("zombie-only view must not count as running（僵尸进程≠运行中）")
	}
}

func TestCaddyProcessRunning_detectsLiveProcess(t *testing.T) {
	// Given 伪 /proc 中一个僵尸 + 一个存活 caddy
	root := t.TempDir()
	seedProcStat(t, root, "10", "caddy", 'Z')
	seedProcStat(t, root, "686", "caddy", 'S')
	original := caddyProcRoot
	caddyProcRoot = root
	t.Cleanup(func() { caddyProcRoot = original })

	// When/Then 任一非 Z 状态即视为运行中
	if !caddyProcessRunning() {
		t.Fatal("live process view must count as running")
	}
}

func TestCaddyProcessRunning_ignoresNonCaddyAndEmpty(t *testing.T) {
	// Given 伪 /proc 只有其他进程与无 caddy 的空目录两种情况
	root := t.TempDir()
	seedProcStat(t, root, "1", "lazy-balancer", 'S')
	original := caddyProcRoot
	caddyProcRoot = root
	t.Cleanup(func() { caddyProcRoot = original })

	// When/Then 非 caddy 进程不计入
	if caddyProcessRunning() {
		t.Fatal("non-caddy process must not count as running")
	}
	// When/Then 空 /proc（无进程）同样未运行
	empty := t.TempDir()
	caddyProcRoot = empty
	if caddyProcessRunning() {
		t.Fatal("empty proc view must not count as running")
	}
}

func TestGetCaddyStatus_reportsPidAndState(t *testing.T) {
	// Given /config/ 可达（admin 200）且 /proc 中存在存活 caddy（pid 686）+ 僵尸（pid 10）
	root := t.TempDir()
	seedProcStat(t, root, "10", "caddy", 'Z')
	seedProcStat(t, root, "686", "caddy", 'S')
	original := caddyProcRoot
	caddyProcRoot = root
	t.Cleanup(func() { caddyProcRoot = original })
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: fakeCaddy.URL}}
	router := gin.New()
	router.GET("/status", h.GetCaddyStatus)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))

	// Then status=running 且 pid=首个存活进程（僵尸 10 被排除）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data["status"] != "running" {
		t.Fatalf("status=%q, want running", body.Data["status"])
	}
	if body.Data["pid"] != "686" {
		t.Fatalf("pid=%q, want 686（首个非 Z 进程）", body.Data["pid"])
	}
}

func TestGetCaddyStatus_fallsBackToProcWhenAdminUnreachable(t *testing.T) {
	// Given /config/ 不可达且 /proc 中存活 caddy（pid 686）与仅僵尸（pid 10）两种视图
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: "http://127.0.0.1:1"}}
	router := gin.New()
	router.GET("/status", h.GetCaddyStatus)
	original := caddyProcRoot
	t.Cleanup(func() { caddyProcRoot = original })

	// When 存活视图
	root := t.TempDir()
	seedProcStat(t, root, "686", "caddy", 'S')
	caddyProcRoot = root
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	// Then /proc 回报 running（替换 busybox 不兼容的 GNU ps 管线）且带 pid
	var body struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data["status"] != "running" || body.Data["pid"] != "686" {
		t.Fatalf("live view: status=%q pid=%q, want running/686", body.Data["status"], body.Data["pid"])
	}

	// When 仅僵尸视图
	zroot := t.TempDir()
	seedProcStat(t, zroot, "10", "caddy", 'Z')
	caddyProcRoot = zroot
	response2 := httptest.NewRecorder()
	router.ServeHTTP(response2, httptest.NewRequest(http.MethodGet, "/status", nil))
	// Then 僵尸不计运行 → stopped
	var body2 struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response2.Body.Bytes(), &body2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body2.Data["status"] != "stopped" {
		t.Fatalf("zombie view: status=%q, want stopped（僵尸≠运行）", body2.Data["status"])
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

// I-K（第 14 轮审计发现）：手动重载失败必须留痕（操作者归因 + 错误详情）——
// 此前仅成功路径写「重载」审计，失败只有 recordCaddyApplyResult 的系统级
// 「应用失败」，无法追溯"谁触发的手动重载、为何失败"。
func TestReloadCaddy_records_failure_audit_with_error_detail(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	failingCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			http.Error(w, "admin api exploded", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(failingCaddy.Close)
	h.cfg = &config.Config{CaddyAdminURL: failingCaddy.URL}
	h.caddyService = services.NewCaddyService(failingCaddy.URL)
	router := gin.New()
	router.POST("/config/reload", h.ReloadCaddy)
	request := httptest.NewRequest(http.MethodPost, "/config/reload", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT COALESCE(detail,'') FROM audit_log WHERE action='重载失败' AND detail LIKE '%结果：failure%'").Scan(&detail); err != nil {
		t.Fatalf("reload failure audit row missing: %v", err)
	}
	if !strings.Contains(detail, "admin api exploded") {
		t.Fatalf("audit detail=%q, want Caddy error detail", detail)
	}
}
