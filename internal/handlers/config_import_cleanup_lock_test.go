package handlers

// 提交后产物清理的阶段边界：锁内（caddyOpMu + 导入会话锁）只收集待删集并在
// 事务内完成 cert_jobs 必要删除，实际删除在 caddyOpMu 释放后执行；导入会话锁、
// 导入窗口与任务暂停则延长到清理完成，防止下一代导入/签发与旧清理跨代交错。
// 本钉测分别证明 Caddy 锁已释放、会话锁仍持有，并验证清理确实执行。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestImportV1PostCommitCleanupRunsOutsideCaddyLockInsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	// 旧规则 + 证书文件：导入整体替换规则面后它消失，清理计划非空。
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_lock_old','old','old.example.test','http',8570,1,1,'manual','CERT','KEY')`); err != nil {
		t.Fatalf("seed old rule: %v", err)
	}
	if err := services.WriteCertFiles("lb_lock_old", "CERT", "KEY"); err != nil {
		t.Fatalf("write old rule cert files: %v", err)
	}

	var caddyFree, sessionFree, windowActive atomic.Bool
	oldHook := importPostCommitCleanupHook
	importPostCommitCleanupHook = func() {
		if h.caddyOpMu.TryLock() {
			h.caddyOpMu.Unlock()
			caddyFree.Store(true)
		}
		if configImportBeginMu.TryLock() {
			configImportBeginMu.Unlock()
			sessionFree.Store(true)
		}
		windowActive.Store(configImportBusy())
	}
	t.Cleanup(func() { importPostCommitCleanupHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(v1ImportFailureBackup("v1-lock-probe")))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	// 提交后清理已异步执行（响应不再等清理跑完）：等它结束再断言。
	waitImportCleanup()
	// Then ① 清理执行时刻 caddyOpMu 已释放，但导入会话锁仍持有；
	// 窗口感知同样保持活动，直到清理结束。
	if !caddyFree.Load() {
		t.Fatal("提交后清理仍在 caddyOpMu 临界区内执行（会阻塞配置写/重载窗口）")
	}
	if sessionFree.Load() {
		t.Fatal("提交后清理提前释放导入会话锁（下一代导入可与旧清理跨代交错）")
	}
	if !windowActive.Load() {
		t.Fatal("提交后清理期间导入窗口提前关闭")
	}
	// Then ② 清理确实执行：消失规则的证书/私钥文件已删除
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_lock_old"+suffix)); err == nil {
			t.Fatalf("消失规则 lb_lock_old%s 的证书材料残留（清理未执行）", suffix)
		}
	}
}

// Given 提交后产物清理耗时（千级规则逐条删文件/指标/日志的真实形态）。
// When v1 导入完成。
// Then HTTP handler 不等清理结束就返回响应（客户端不再「导入卡住」），清理在
// 后台继续并在放行后完成——清理已与请求生命周期解耦（WithoutCancel + 预算）。
func TestImportV1PostCommitCleanupRunsAsync(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_async_old','old','old.example.test','http',8571,1,1,'manual','CERT','KEY')`); err != nil {
		t.Fatalf("seed old rule: %v", err)
	}
	if err := services.WriteCertFiles("lb_async_old", "CERT", "KEY"); err != nil {
		t.Fatalf("write old rule cert files: %v", err)
	}

	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	oldHook := importPostCommitCleanupHook
	importPostCommitCleanupHook = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	t.Cleanup(func() { importPostCommitCleanupHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(v1ImportFailureBackup("v1-async-probe")))
	request.Header.Set("Content-Type", "application/json")

	done := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		done <- recorder.Code
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("提交后清理未开始（异步派发失效）")
	}
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("status=%d, want 200", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP handler 仍等待提交后清理完成（客户端被清理拖住）")
	}
	windowActiveDuringCleanup := configImportBusy()

	// 清理仍在后台阻塞：证书文件此时应尚未删除；放行后清理完成。
	close(release)
	waitImportCleanup()
	if !windowActiveDuringCleanup {
		t.Fatal("后台清理尚未完成时导入窗口已关闭")
	}
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_async_old"+suffix)); err == nil {
			t.Fatalf("消失规则 lb_async_old%s 的证书材料残留（后台清理未完成）", suffix)
		}
	}
	if configImportBusy() {
		t.Fatal("清理完成后导入窗口未关闭")
	}
}
