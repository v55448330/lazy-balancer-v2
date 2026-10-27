package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestCaddyLifecycleHandlers_wait_for_rule_operation_lock(t *testing.T) {
	// 测试隔离——注入临时 pause/pid 路径与失败命令桩，避免
	// 写真实 /tmp/lazy-balancer-caddy-paused 或执行真实 caddy run/stop。
	// 命令桩恒失败，锁释放后的 handler 快速返回，不会走到 nil caddyService。
	oldPause, oldPidFile := caddyPauseFile, caddySupervisorPidFile
	oldRun, oldStop := caddyRunCommand, caddyStopCommand
	dir := t.TempDir()
	caddyPauseFile = filepath.Join(dir, "paused")
	caddySupervisorPidFile = filepath.Join(dir, "supervisor.pid")
	caddyRunCommand = func() *exec.Cmd { return exec.Command("sh", "-c", "exit 7") }
	caddyStopCommand = func(string) *exec.Cmd { return exec.Command("sh", "-c", "exit 8") }
	t.Cleanup(func() {
		caddyPauseFile, caddySupervisorPidFile = oldPause, oldPidFile
		caddyRunCommand, caddyStopCommand = oldRun, oldStop
	})
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

// caddyLivePID 展示口径必须确定：监督器 churn 窗口内同时存在两个存活 caddy
// 时，取最小 pid（而非 ReadDir 返回序首个）——否则仪表盘 pid 会在两次轮询间
// 跳动。
func TestCaddyLivePID_picksLowestLivePid(t *testing.T) {
	root := t.TempDir()
	seedProcStat(t, root, "900", "caddy", 'S')
	seedProcStat(t, root, "400", "caddy", 'S')
	seedProcStat(t, root, "100", "caddy", 'Z') // 僵尸更低 pid，不得入选
	seedProcStat(t, root, "200", "lazy-balancer", 'S')
	original := caddyProcRoot
	caddyProcRoot = root
	t.Cleanup(func() { caddyProcRoot = original })

	if got := caddyLivePID(); got != 400 {
		t.Fatalf("caddyLivePID()=%d, want 400（存活进程中的最小 pid）", got)
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
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_lifecycle", strings.NewReader(`{"name":"updated","listen_port":8081}`))
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
	env := newStopCaddyEnv(t, "exit 8")
	env.seedCaddy(t, "5353", 'S')
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
	// 2026-09-06 裁定 ④' 收口：本端点改走 caddy CLI 真 validate-only——校验
	// 零运行时扰动（与 apidocs「不触发 Caddy」承诺对齐）；CLI 不可用回退
	// c 的 load+回弹口径。
	newBackupTestHandlers(t)
	var requests atomic.Int32
	handlerErrs := make(chan string, 4)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		// GET /config/ = 同字节短路门的只读快照（2026-09-25 审计真实性改造），
		// 零运行时扰动，与 validate-only 语义兼容——不计数；仅 /load POST 计入。
		if request.Method == http.MethodGet && request.URL.Path == "/config/" {
			_, _ = response.Write([]byte(`{}`))
			return
		}
		if request.URL.Path != "/load" {
			// httptest handler 运行在 server goroutine：t.Fatalf 只能从测试
			// goroutine 调用，这里回传错误由主 goroutine 断言。
			handlerErrs <- fmt.Sprintf("validation request path=%q query=%q", request.URL.Path, request.URL.RawQuery)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		requests.Add(1)
		var config map[string]any
		if err := json.NewDecoder(request.Body).Decode(&config); err != nil {
			handlerErrs <- fmt.Sprintf("decode submitted config: %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
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

	// Given：CLI 校验桩可用（生产由 main 装配启用）
	h.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		var config map[string]any
		if err := json.Unmarshal(rendered, &config); err != nil {
			return err
		}
		if invalid, _ := config["invalid"].(bool); invalid {
			return errors.New("invalid config")
		}
		return nil
	})
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
	if got := requests.Load(); got != 0 {
		t.Fatalf("CLI 校验路径不应触碰 admin（requests=%d, want 0）", got)
	}
	select {
	case msg := <-handlerErrs:
		t.Fatalf("fake admin handler 报告错误: %s", msg)
	default:
	}

	// And：CLI 不可用回退——valid 用例回到 -c 的 load+回弹（2 次 /load）。
	h.caddyService.SetCLIValidatorForTest(func(rendered []byte) error {
		return services.ErrCLIValidatorUnavailable
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(`{"apps":{"http":{}}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fallback status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("fallback /load requests=%d, want 2（校验 + 回弹）", got)
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

// PutCaddyConfig 对 chunked/未知 ContentLength 的超大请求体（绕过预检、
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

// 键集合一致性——planConfigChanges 中归属「Caddy配置」分组的 add() 键
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
	// 判空必须先于切片：caddySrc[updateStart:] 在 -1 时直接 panic，
	// 后面的 <0 检查成不可达分支。
	if updateStart < 0 {
		t.Fatal("cannot locate UPDATE global_config block in caddy.go")
	}
	updateEnd := strings.Index(string(caddySrc[updateStart:]), "WHERE id = 1")
	if updateEnd < 0 {
		t.Fatal("cannot locate UPDATE global_config WHERE clause in caddy.go")
	}
	updateBlock := string(caddySrc[updateStart : updateStart+updateEnd])
	colRe := regexp.MustCompile(`(?m)^\s*([a-z0-9_]+)\s*=\s*(?:COALESCE|CASE WHEN|\?)`)
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

// 手动重载失败必须留痕（操作者归因 + 错误详情）——
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
	// failure 结果码补中文映射后渲染为「结果：失败」（此前
	// 未映射原样输出英文 "failure"），断言随渲染口径同步。
	if err := db.AuditDB.QueryRow("SELECT COALESCE(detail,'') FROM audit_log WHERE action='重载失败' AND detail LIKE '%结果：失败%'").Scan(&detail); err != nil {
		t.Fatalf("reload failure audit row missing: %v", err)
	}
	if !strings.Contains(detail, "admin api exploded") {
		t.Fatalf("audit detail=%q, want Caddy error detail", detail)
	}
}

// 裁定 2026-09-07：撤 UpdateConfig 的 pre-tx /load 探针（与 ④'「探针已撤除」
// 对齐；SQL 失败分支不再有已交换的运行配置需回弹= 根因消解）。
func TestUpdateConfig_appliesExactlyOnce(t *testing.T) {
	preserveApplicationLogLevel(t, "")
	newBackupTestHandlers(t)
	var loads atomic.Int32
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: fakeCaddy.URL}, caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"caddy_log_size_mb":123}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("/load calls=%d, want 1（探针已撤，仅事务内应用）", got)
	}
	// 成功路径不得留下失败横幅（recordCaddyApplyResult 在成功时清空）。
	var banner string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner != "" {
		t.Fatalf("caddy_apply_error=%q, want 空（成功路径清横幅）", banner)
	}
}

// 监督器在场（pid 标记）但 admin 等待超时——不得落
// 直启回退。修复前超时后直启 caddy：与活监督器双启抢 127.0.0.1:2019/监听端口，
// 败者触发监督器崩溃重拉 churn（败者=监督器实例时无限循环+就绪探针被幸存实例
// 应答→reapply_last_good churn；败者=直启实例时假 500）。修复后返回明确错误，
// 留给监督器继续拉起。
func TestStartCaddy_supervisorTimeoutDoesNotDirectSpawn(t *testing.T) {
	// Given：监督器标记在场（pid 存活——自此在场判定含 pid 校验，
	// 伪 /proc 种活 pid）+ admin 死端口不就绪 + 调小委托等待
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "supervisor.pid")
	if err := os.WriteFile(pidFile, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	procRoot := t.TempDir()
	seedProcStat(t, procRoot, "12345", "caddy-superv", 'S')
	oldPid, oldPause, oldTimeout, oldProc := caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot
	caddySupervisorPidFile = pidFile
	caddyPauseFile = filepath.Join(dir, "paused")
	caddySupervisorWaitTimeout = 300 * time.Millisecond
	caddyProcRoot = procRoot
	t.Cleanup(func() {
		caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot = oldPid, oldPause, oldTimeout, oldProc
	})

	startInvoked := make(chan struct{})
	original := caddyRunCommand
	caddyRunCommand = func() *exec.Cmd {
		close(startInvoked)
		return exec.Command("sh", "-c", "exit 7")
	}
	t.Cleanup(func() { caddyRunCommand = original })

	// When
	err := startCaddy("http://127.0.0.1:1")

	// Then：明确报错（点名监督器委托超时）且未直启
	if err == nil || !strings.Contains(err.Error(), "监督器") {
		t.Fatalf("err=%v, want 监督器委托超时错误", err)
	}
	select {
	case <-startInvoked:
		t.Fatal("监督器在场且委托超时——不得落直启回退（双启竞态）")
	case <-time.After(200 * time.Millisecond):
	}
}

// 监督器 pid 标记在场但 pid 已死（监督器被杀/容器
// 异常重启残留）——陈旧标记不得让 startCaddy 走委托路径空等超时后报错；
// 应落直启（与标记不在场同语义）。直启路径不再删除
// 陈旧标记——标记留存无害（supervisorAlive 按 pid 存活判定消化），而误删
// 监督器并发首写的在位标记会永久失标（直启与监督器拉起双启抢口）。
func TestStartCaddy_staleSupervisorMarkerFallsBackToDirectSpawn(t *testing.T) {
	// Given：标记在场记死 pid + 空 /proc 视图 + 就绪 admin
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "supervisor.pid")
	if err := os.WriteFile(pidFile, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPid, oldPause, oldTimeout, oldProc := caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot
	caddySupervisorPidFile = pidFile
	caddyPauseFile = filepath.Join(dir, "paused")
	caddySupervisorWaitTimeout = 300 * time.Millisecond
	caddyProcRoot = t.TempDir() // 空伪 /proc：pid 12345 不在=死
	t.Cleanup(func() {
		caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot = oldPid, oldPause, oldTimeout, oldProc
	})

	startInvoked := make(chan struct{}, 1)
	original := caddyRunCommand
	caddyRunCommand = func() *exec.Cmd {
		startInvoked <- struct{}{}
		return exec.Command("sh", "-c", "sleep 1")
	}
	t.Cleanup(func() { caddyRunCommand = original })

	fakeAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeAdmin.Close)

	// When
	err := startCaddy(fakeAdmin.URL)

	// Then：直启成功 + 陈旧标记留存但不再劫持后续判定（直启路径不删
	// 标记；死 pid 由 supervisorAlive 的存活校验消化，下次 startCaddy 仍直启）
	if err != nil {
		t.Fatalf("陈旧监督器标记应走直启: %v", err)
	}
	select {
	case <-startInvoked:
	case <-time.After(time.Second):
		t.Fatal("未落直启路径（仍被陈旧标记劫持到委托路径）")
	}
	if _, statErr := os.Stat(pidFile); statErr != nil {
		t.Fatalf("直启路径不得删除 pid 标记（历史修复）, stat err=%v", statErr)
	}
	if supervisorAlive() {
		t.Fatal("陈旧标记（死 pid）不得判活——留存标记不得劫持下次 startCaddy")
	}
}

// supervisorAlive 不排僵尸态——监督器 kill -9 后
// 父进程（PID1 app，Go 不回收非 exec 子进程）未回收期间僵尸滞留 /proc
// （目录在场、状态字节 Z）。修复前只验目录在场 → 恒判活 → startCaddy 恒
// 委托空等 5s 超时报错，直启兜底永不可达。修复后读 /proc/<pid>/stat 状态
// 字节，Z 视死 → 落直启恢复。
func TestStartCaddy_zombieSupervisorFallsBackToDirectSpawn(t *testing.T) {
	// Given：标记在场记僵尸监督器 pid + 伪 /proc 种 Z 状态 + 就绪 admin
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "supervisor.pid")
	if err := os.WriteFile(pidFile, []byte("10"), 0o644); err != nil {
		t.Fatal(err)
	}
	procRoot := t.TempDir()
	seedProcStat(t, procRoot, "10", "caddy-superv", 'Z')
	oldPid, oldPause, oldTimeout, oldProc := caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot
	caddySupervisorPidFile = pidFile
	caddyPauseFile = filepath.Join(dir, "paused")
	caddySupervisorWaitTimeout = 300 * time.Millisecond
	caddyProcRoot = procRoot
	t.Cleanup(func() {
		caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot = oldPid, oldPause, oldTimeout, oldProc
	})

	startInvoked := make(chan struct{}, 1)
	original := caddyRunCommand
	caddyRunCommand = func() *exec.Cmd {
		startInvoked <- struct{}{}
		return exec.Command("sh", "-c", "sleep 1")
	}
	t.Cleanup(func() { caddyRunCommand = original })

	fakeAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeAdmin.Close)

	// When
	err := startCaddy(fakeAdmin.URL)

	// Then：僵尸监督器视死 → 直启成功（而非委托超时报错）
	if err != nil {
		t.Fatalf("僵尸监督器应视死直启: %v", err)
	}
	select {
	case <-startInvoked:
	case <-time.After(time.Second):
		t.Fatal("未落直启路径（僵尸被误判为活，劫持到委托路径）")
	}
}

// 采样契约（用户裁定）：threat_traffic_sample_n 仅 -1（自适应）/0（关闭）；
// 全量与固定 2..64 已废除，写侧 400。
func TestUpdateConfig_samplingContractOnlyAdaptiveOffFull(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	readSampleN := func() int64 {
		t.Helper()
		var value int64
		if err := db.DB.QueryRow(`SELECT COALESCE(threat_traffic_sample_n, -999) FROM global_config WHERE id=1`).Scan(&value); err != nil {
			t.Fatalf("read threat_traffic_sample_n: %v", err)
		}
		return value
	}
	baseline := readSampleN()
	for _, value := range []string{"1", "2", "4", "8", "64", "-2"} {
		response := put(`{"source":"basic","threat_traffic_sample_n":` + value + `}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "仅支持 -1（自适应）或 0（关闭）") {
			t.Fatalf("sample_n=%s status=%d body=%s, want 400 contract", value, response.Code, response.Body.String())
		}
		// 拒绝不得部分落库：写侧校验先于 UPDATE，坏值不能进库。
		if got := readSampleN(); got != baseline {
			t.Fatalf("sample_n=%s 拒绝后库值=%d, want 原值 %d", value, got, baseline)
		}
	}
	for _, value := range []string{"-1", "0"} {
		response := put(`{"source":"basic","threat_traffic_sample_n":` + value + `}`)
		if response.Code != http.StatusOK {
			t.Fatalf("sample_n=%s status=%d body=%s, want 200", value, response.Code, response.Body.String())
		}
	}
	if got := readSampleN(); got != 0 {
		t.Fatalf("threat_traffic_sample_n=%d after 0, want 0（末次合法写入落库）", got)
	}
}

// 预览与保存共用同一组校验——保存必 400 的载荷
// 不得在预览给出「可变更」清单。
func TestPreviewConfigUpdate_matchesSaveSideValidation(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", h.PreviewConfigUpdate)
	router.PUT("/config", h.UpdateConfig)

	post := func(handler gin.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	// 每组非法值：预览与保存必须同为 400（此前预览仅校验受信代理，其余直接 200）。
	for _, body := range []string{
		`{"source":"basic","log_level":"verbose"}`,
		`{"source":"basic","timezone":"Not/AZone"}`,
		// 空串不是合法库值：time.LoadLocation("") 返回 UTC（Go 特殊值），
		// 放行即让全站展示/审计窗口静默切 UTC。
		`{"source":"basic","timezone":""}`,
		`{"source":"basic","threat_traffic_sample_n":4}`,
		`{"source":"basic","security_events_retention_days":0}`,
		`{"source":"basic","security_events_row_cap":0}`,
		`{"source":"basic","caddy_log_size_mb":1}`,
		`{"source":"caddy","access_log_format":"request>remote_ip->delete"}`,
	} {
		preview := post(h.PreviewConfigUpdate, http.MethodPost, "/config/preview", body)
		if preview.Code != http.StatusBadRequest {
			t.Fatalf("preview body=%s status=%d resp=%s, want 400（与保存同组校验）", body, preview.Code, preview.Body.String())
		}
		save := post(h.UpdateConfig, http.MethodPut, "/config", body)
		if save.Code != http.StatusBadRequest {
			t.Fatalf("save body=%s status=%d resp=%s, want 400", body, save.Code, save.Body.String())
		}
	}
	// 合法形态：预览 200 且归一后的变更清单可见（"DEBUG" 归一为 debug，与保存
	// 同口径——归一在校验函数内回写 req）。
	preview := post(h.PreviewConfigUpdate, http.MethodPost, "/config/preview", `{"source":"basic","log_level":"DEBUG"}`)
	if preview.Code != http.StatusOK {
		t.Fatalf("valid preview status=%d body=%s, want 200", preview.Code, preview.Body.String())
	}
}

// apply 失败且回弹也失败时，除响应/审计外必须持久化
// caddy_apply_error 横幅（重启后真实失败仍可见）。
func TestUpdateConfig_rollbackFailurePersistsApplyBanner(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write([]byte(`{"old":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"basic","proxy_dial_timeout":5}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatalf("status=%d body=%s, want apply/rollback failure", response.Code, response.Body.String())
	}
	var banner string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(banner, "Caddy 配置应用失败") {
		t.Fatalf("caddy_apply_error=%q, want persisted failure banner", banner)
	}
}

// 配置拒绝（Caddy 4xx/CLI 校验拒绝）不写 caddy_apply_error 横幅：候选未
// /load、事务已回滚，库态与运行态仍是提交前形态，无分叉事实（与
// finishTxApply 拒绝分支同口径）。传输/恢复失败仍写横幅（上方用例）。
func TestUpdateConfig_configRejectionDoesNotPersistBanner(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 1)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"request_body_max_size_mb":9}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（配置拒绝）", response.Code, response.Body.String())
	}
	if banner := readApplyError(t); banner != "" {
		t.Fatalf("配置拒绝不得写失败横幅（无分叉事实）, got %q", banner)
	}
}

// 安全事件保留两列 0=自动语义废除，写侧 1..max。
func TestUpdateConfig_rejectsZeroRetentionValues(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	readRetention := func() (int64, int64) {
		t.Helper()
		var days, cap int64
		if err := db.DB.QueryRow(`SELECT COALESCE(security_events_retention_days, -999), COALESCE(security_events_row_cap, -999) FROM global_config WHERE id=1`).Scan(&days, &cap); err != nil {
			t.Fatalf("read retention columns: %v", err)
		}
		return days, cap
	}
	baseDays, baseCap := readRetention()
	for _, body := range []string{
		`{"source":"basic","security_events_retention_days":0}`,
		`{"source":"basic","security_events_row_cap":0}`,
		`{"source":"basic","security_events_retention_days":-1}`,
	} {
		if res := put(body); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "必须在 1 到") {
			t.Fatalf("body=%s status=%d resp=%s, want 400 1..N", body, res.Code, res.Body.String())
		}
		// 拒绝不得部分落库（同 body 只含单列，另一列也必须原样）。
		if days, cap := readRetention(); days != baseDays || cap != baseCap {
			t.Fatalf("body=%s 拒绝后=(%d,%d), want 原值 (%d,%d)", body, days, cap, baseDays, baseCap)
		}
	}
	for _, body := range []string{
		`{"source":"basic","security_events_retention_days":1}`,
		`{"source":"basic","security_events_row_cap":1}`,
	} {
		if res := put(body); res.Code != http.StatusOK {
			t.Fatalf("body=%s status=%d resp=%s, want 200", body, res.Code, res.Body.String())
		}
	}
	if days, cap := readRetention(); days != 1 || cap != 1 {
		t.Fatalf("retention after valid writes=(%d,%d), want (1,1)", days, cap)
	}
}

// 校验回退（CLI 不可用 → load+回弹）中「恢复权威配置」失败必须持久化横幅：
// 运行配置可能停留在校验载荷，请求响应丢失后仍需在状态接口可见（与
// UpdateConfig/PutCaddyConfig 同一事实源），否则重启后无任何痕迹。
func TestValidateConfig_restoreFailurePersistsApplyBanner(t *testing.T) {
	newBackupTestHandlers(t)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte("caddy unavailable"))
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{
		cfg:          &config.Config{CaddyAdminURL: fakeCaddy.URL},
		caddyService: services.NewCaddyService(fakeCaddy.URL),
	}
	// CLI 校验器不可用 → 走 load+回弹回退路径。
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfig)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(`{"apps":{"http":{}}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var banner string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	// 断言两态标签的具体取值：横幅模板恒含「配置」，用 Contains("配置")
	// 兜底等于恒真（标签写错也不会红）。
	if !strings.Contains(banner, "Caddy 配置应用失败") || !strings.Contains(banner, caddyApplyRestoreFailedLabel) {
		t.Fatalf("横幅未持久化恢复失败事实（want %q）: %q", caddyApplyRestoreFailedLabel, banner)
	}
}

// 校验回退路径的系统故障分流：admin 对 /load?validate=true 返回 5xx 时，
// 必须映射 500「配置校验请求失败（运行配置已恢复）」而不是 400「配置验证
// 失败」——基础设施故障不得被表述成用户配置错误（4xx 才是候选配置被拒）。
func TestValidateConfig_adminSystemFailureMapsTo500(t *testing.T) {
	newBackupTestHandlers(t)
	var restoreLoads atomic.Int32
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/config/":
			_, _ = response.Write([]byte(`{}`))
		case request.Method == http.MethodPost && request.URL.Path == "/load" && request.URL.Query().Get("validate") == "true":
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write([]byte(`{"error":"provision panic"}`))
		case request.Method == http.MethodPost && request.URL.Path == "/load":
			restoreLoads.Add(1)
			_, _ = response.Write([]byte(`{}`))
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{
		cfg:          &config.Config{CaddyAdminURL: fakeCaddy.URL},
		caddyService: services.NewCaddyService(fakeCaddy.URL),
	}
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfig)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(`{"apps":{"http":{}}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（系统故障不得伪装成配置无效）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "配置校验请求失败（运行配置已恢复）") {
		t.Fatalf("message=%s, want 系统故障文案", response.Body.String())
	}
	if restoreLoads.Load() == 0 {
		t.Fatal("失败后必须回弹权威配置（/load）")
	}
}

// pause 生命周期（与 entrypoint 监督器协议）：stopCaddy 先建 pause 抑制
// 监督器重启，**停止失败且 Caddy 仍在运行**时必须回滚删除——否则监督器被
// 永久抑制，Caddy 停摆。（已停止态的重复停止是成功而非失败，见
// caddy_stop_idempotency_test.go。）
func TestStopCaddy_failureRemovesPauseFile(t *testing.T) {
	env := newStopCaddyEnv(t, "exit 9")
	env.seedCaddy(t, "5252", 'S')

	if err := stopCaddy("http://127.0.0.1:1"); err == nil {
		t.Fatal("stopping with failing command while caddy is alive must return error")
	}
	if env.pauseExists() {
		t.Fatalf("停止失败必须回滚 pause（监督器需继续看护）, pause=%s", env.pauseFile)
	}
}

// 监督器委托成功路径同样要解除 pause：pause 残留会让监督器永不重启 Caddy
// （admin 就绪=委托完成即返回，不能靠后续操作兜底清理）。
func TestStartCaddy_supervisorDelegationClearsPause(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "supervisor.pid")
	if err := os.WriteFile(pidFile, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	procRoot := t.TempDir()
	seedProcStat(t, procRoot, "12345", "caddy-superv", 'S')
	oldPid, oldPause, oldTimeout, oldProc := caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot
	caddySupervisorPidFile = pidFile
	caddyPauseFile = filepath.Join(dir, "paused")
	caddySupervisorWaitTimeout = time.Second
	caddyProcRoot = procRoot
	t.Cleanup(func() {
		caddySupervisorPidFile, caddyPauseFile, caddySupervisorWaitTimeout, caddyProcRoot = oldPid, oldPause, oldTimeout, oldProc
	})
	if err := os.WriteFile(caddyPauseFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	fakeAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeAdmin.Close)

	if err := startCaddy(fakeAdmin.URL); err != nil {
		t.Fatalf("supervisor delegation should succeed: %v", err)
	}
	if _, err := os.Stat(caddyPauseFile); !os.IsNotExist(err) {
		t.Fatalf("委托成功必须解除 pause, stat err=%v", err)
	}
}

// PutCaddyConfig 请求体上限边界：恰好 1MB 放行、1MB+1 拒绝（ContentLength
// 快速门与 MaxBytesReader 兜底同界，边界差一字节的配置不得被误拒/误收）。
func TestPutCaddyConfig_acceptsExactLimitRejectsOneByteOver(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/caddy/config", handler.PutCaddyConfig)

	const limit = 1 << 20
	// 端点入参是 {"content":"<JSON 字符串>"}；content 本身须是对象。
	// content 必须保留面板自管的 admin 端点（逃生口护栏拒绝 admin off / 改址），
	// 因此先用空填充量定长，再按差额补 pad。
	adminListen := strings.TrimPrefix(handler.cfg.CaddyAdminURL, "http://")
	build := func(total int) string {
		makeBody := func(pad int) string {
			content := `{"admin":{"listen":"` + adminListen + `"},"a":"` + strings.Repeat("b", pad) + `"}`
			payload, err := json.Marshal(map[string]string{"content": content})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			return string(payload)
		}
		pad := total - len(makeBody(0))
		if pad < 0 {
			t.Fatalf("total=%d 小于固定开销 %d", total, len(makeBody(0)))
		}
		body := makeBody(pad)
		if len(body) != total {
			t.Fatalf("fixture length=%d, want %d", len(body), total)
		}
		return body
	}

	within := httptest.NewRecorder()
	bodyWithin := build(limit)
	request := httptest.NewRequest(http.MethodPut, "/caddy/config", strings.NewReader(bodyWithin))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(within, request)
	if within.Code != http.StatusOK {
		t.Fatalf("exact-limit status=%d body=%.200s, want 200", within.Code, within.Body.String())
	}

	over := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, "/caddy/config", strings.NewReader(build(limit+1)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(over, request)
	if over.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit+1 status=%d body=%.200s, want 413", over.Code, over.Body.String())
	}
}

// 无变化载荷的短路必须在预览与保存两端一致：存量坏规则不得让「未提交任何
// 变更」的预览 400（保存对同一载荷 200「配置无变化」——无写入即无需预检）。
// 两端对「这份配置能否保存」必须给同一答案。
func TestPreviewConfigUpdate_noChangeShortCircuitMatchesSave(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", h.PreviewConfigUpdate)
	router.PUT("/config", h.UpdateConfig)
	// 存量两条 80 端口 TLS 跳转自环规则：聚合预校验恒失败。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_http_redirect) VALUES
		('lb_nc_a','无变化甲','http','nc-a.example.test',80,1,1,1),
		('lb_nc_b','无变化乙','http','nc-b.example.test',80,1,1,1)`); err != nil {
		t.Fatalf("seed bad rules: %v", err)
	}
	post := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	for _, tc := range []struct{ name, method, path string }{
		{"保存", http.MethodPut, "/config"},
		{"预览", http.MethodPost, "/config/preview"},
	} {
		rec := post(tc.method, tc.path, `{}`)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "配置无变化") {
			t.Fatalf("%s：status=%d body=%s, want 200 配置无变化（无变化载荷短路两端同判据）", tc.name, rec.Code, rec.Body.String())
		}
	}
}

// 预览的聚合预校验失败必须复用保存侧分类器：DB 故障不得被回成 400 携带底层
// 错误文本（管理员会误判为载荷非法），纯配置错误才 400 展示全部问题。
func TestPreviewConfigUpdate_serverFaultIsNotReportedAsBadRequest(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", h.PreviewConfigUpdate)
	router.PUT("/config", h.UpdateConfig)
	// 模拟 DB 故障（非配置问题）：规则表不可读。
	if _, err := db.DB.Exec(`ALTER TABLE lb_rules RENAME TO lb_rules_unreadable`); err != nil {
		t.Fatalf("rename rule table: %v", err)
	}
	post := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	body := `{"source":"basic","request_body_max_size_mb":9}`
	save := post(http.MethodPut, "/config", body)
	if save.Code != http.StatusInternalServerError {
		t.Fatalf("save status=%d body=%s, want 500", save.Code, save.Body.String())
	}
	preview := post(http.MethodPost, "/config/preview", body)
	if preview.Code != http.StatusInternalServerError {
		t.Fatalf("preview status=%d body=%s, want 500（DB 故障不得折成 400 配置问题）", preview.Code, preview.Body.String())
	}
	if strings.Contains(preview.Body.String(), "lb_rules_unreadable") || strings.Contains(preview.Body.String(), "no such table") {
		t.Fatalf("5xx 响应不得携带底层错误文本: %s", preview.Body.String())
	}
}
