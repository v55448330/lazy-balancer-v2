package handlers

// Caddy 进程启停三端点的导入窗口门：导入会话全程持有 caddyOpMu（分钟级），
// 排队的启停请求会在导入提交后才按陈旧意图执行——Stop 尤其不可逆（pause
// 文件同时抑制监督器自愈）。门必须在取锁之前给出 409 fast-fail，且不得触碰
// 进程命令/pause 文件。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

// newProcessControlTestHandlers 装配启停端点所需的测试缝：命令恒失败（证明
// 请求确实走到了命令执行），pause 文件与监督器标记指向临时目录。
func newProcessControlTestHandlers(t *testing.T) (*Handlers, *int32, *int32) {
	t.Helper()
	var runs, stops int32
	origRun, origStop := caddyRunCommand, caddyStopCommand
	origPause, origPid, origWait := caddyPauseFile, caddySupervisorPidFile, caddySupervisorWaitTimeout
	tempDir := t.TempDir()
	caddyRunCommand = func() *exec.Cmd {
		atomic.AddInt32(&runs, 1)
		return exec.Command("sh", "-c", "exit 7")
	}
	caddyStopCommand = func(string) *exec.Cmd {
		atomic.AddInt32(&stops, 1)
		return exec.Command("sh", "-c", "exit 8")
	}
	caddyPauseFile = filepath.Join(tempDir, "paused")
	caddySupervisorPidFile = filepath.Join(tempDir, "supervisor.pid")
	caddySupervisorWaitTimeout = 200 * time.Millisecond
	t.Cleanup(func() {
		caddyRunCommand, caddyStopCommand = origRun, origStop
		caddyPauseFile, caddySupervisorPidFile = origPause, origPid
		caddySupervisorWaitTimeout = origWait
	})
	return &Handlers{cfg: &config.Config{CaddyAdminURL: "http://127.0.0.1:2019"}}, &runs, &stops
}

func TestCaddyProcessControlRejectsDuringImportWindow(t *testing.T) {
	handler, runs, stops := newProcessControlTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/caddy/start", handler.StartCaddy)
	router.POST("/caddy/stop", handler.StopCaddy)
	router.POST("/caddy/restart", handler.RestartCaddy)

	// 模拟进行中的导入会话：窗口计数非零 = configImportBusy()==true。
	beginImportWindowForTest(t)
	// 预持写锁：若 409 门被挪到取锁之后，请求会在这里阻塞而不是 fast-fail。
	handler.caddyOpMu.Lock()
	defer handler.caddyOpMu.Unlock()

	for _, endpoint := range []string{"/caddy/start", "/caddy/stop", "/caddy/restart"} {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, endpoint, nil))
			done <- response
		}()
		var response *httptest.ResponseRecorder
		select {
		case response = <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s 在 caddyOpMu 预持期间未 fast-fail——409 门被挪到取锁之后", endpoint)
		}
		if response.Code != http.StatusConflict {
			t.Fatalf("%s status=%d body=%s, want 409", endpoint, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "配置导入进行中") {
			t.Fatalf("%s body=%s, want 导入窗口文案", endpoint, response.Body.String())
		}
	}
	if got := atomic.LoadInt32(runs); got != 0 {
		t.Fatalf("导入窗口内启动了 Caddy %d 次，want 0（门必须在取锁/执行命令之前）", got)
	}
	if got := atomic.LoadInt32(stops); got != 0 {
		t.Fatalf("导入窗口内停止了 Caddy %d 次，want 0", got)
	}
	if _, err := os.Stat(caddyPauseFile); err == nil {
		t.Fatalf("导入窗口内不得创建 pause 文件 %s", caddyPauseFile)
	}
}

// 对照：门不是恒拒——窗口外请求照常到达命令层（桩命令失败 → 500）。
func TestCaddyProcessControlAllowedOutsideImportWindow(t *testing.T) {
	handler, runs, stops := newProcessControlTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/caddy/start", handler.StartCaddy)
	router.POST("/caddy/stop", handler.StopCaddy)

	startResp := httptest.NewRecorder()
	router.ServeHTTP(startResp, httptest.NewRequest(http.MethodPost, "/caddy/start", nil))
	if startResp.Code != http.StatusInternalServerError {
		t.Fatalf("start status=%d body=%s, want 500（桩命令失败）", startResp.Code, startResp.Body.String())
	}
	stopResp := httptest.NewRecorder()
	router.ServeHTTP(stopResp, httptest.NewRequest(http.MethodPost, "/caddy/stop", nil))
	if stopResp.Code != http.StatusInternalServerError {
		t.Fatalf("stop status=%d body=%s, want 500（桩命令失败）", stopResp.Code, stopResp.Body.String())
	}
	if atomic.LoadInt32(runs) != 1 {
		t.Fatalf("窗口外 start 必须执行命令，runs=%d", atomic.LoadInt32(runs))
	}
	if atomic.LoadInt32(stops) != 1 {
		t.Fatalf("窗口外 stop 必须执行命令，stops=%d", atomic.LoadInt32(stops))
	}
}
