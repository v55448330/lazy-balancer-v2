package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

// 启动竞态修复测试夹具：临时监督器 pid 标记 + 临时回放标记路径
// + 短超时——与 caddy_test.go 监督器委托测试同注入缝模式（包级 var）。
// supervisorAlive=true 形态用**伪 /proc**（caddyProcRoot 指向 t.TempDir()，
// seedProcStat 种入固定 pid 12345，存活、状态非 Z）冒充监督器——不读真
// /proc，也不占用本测试进程 pid。
func setupStartupReplayFixture(t *testing.T, supervisorUp bool) string {
	withIsolatedGlobal(t)
	t.Helper()
	oldPid, oldMarker, oldTimeout, oldProc := caddySupervisorPidFile, caddyStartupReplayMarkerFile, startupReplayWaitTimeout, caddyProcRoot
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "supervisor.pid")
	markerFile := filepath.Join(dir, "startup-replayed")
	procRoot := t.TempDir() // 伪 /proc（macOS 无 /proc——caddy_test.go seedProcStat 同模式）
	if supervisorUp {
		// 伪 /proc 种活 pid（存活、状态非 Z）——supervisorAlive 真
		if err := os.WriteFile(pidFile, []byte("12345"), 0o600); err != nil {
			t.Fatal(err)
		}
		seedProcStat(t, procRoot, "12345", "caddy-superv", 'S')
	} // else：pid 文件不落盘 = supervisorAlive false
	caddySupervisorPidFile = pidFile
	caddyStartupReplayMarkerFile = markerFile
	startupReplayWaitTimeout = 2 * time.Second
	caddyProcRoot = procRoot
	t.Cleanup(func() {
		caddySupervisorPidFile, caddyStartupReplayMarkerFile, startupReplayWaitTimeout, caddyProcRoot = oldPid, oldMarker, oldTimeout, oldProc
	})
	return markerFile
}

// Given 监督器不在场（测试/裸跑环境）。When waitStartupReplayDone。
// Then 立即返回——协议关闭，不得等满超时拖慢启动。
func TestWaitStartupReplayDone_noSupervisorReturnsImmediately(t *testing.T) {
	setupStartupReplayFixture(t, false)

	start := time.Now()
	waitStartupReplayDone()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("监督器不在场应立即返回，实际耗时 %s", elapsed)
	}
}

// Given 监督器在位且回放标记已写（启动回放阶段已完成）。When wait。
// Then 立即返回——手动重载 / caddy-restart 重应用的常态路径。
func TestWaitStartupReplayDone_markerPresentReturnsImmediately(t *testing.T) {
	marker := setupStartupReplayFixture(t, true)
	if err := os.WriteFile(marker, []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	waitStartupReplayDone()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("标记在场应立即返回，实际耗时 %s", elapsed)
	}
}

// Given 监督器在位、标记延迟 300ms 才落盘（监督器等 admin 就绪+回放中）。
// When wait。Then 阻塞至标记落盘后返回——等待真实发生且被释放（时序定死：
// 回放→标记→app 应用）。
func TestWaitStartupReplayDone_waitsForMarkerThenReturns(t *testing.T) {
	marker := setupStartupReplayFixture(t, true)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(marker, []byte("done"), 0o600)
	}()

	start := time.Now()
	waitStartupReplayDone()
	elapsed := time.Since(start)
	if elapsed < 250*time.Millisecond {
		t.Fatalf("标记未落盘时应等待，实际仅 %s 即返回", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("标记落盘后应及时返回，实际耗时 %s", elapsed)
	}
}

// Given 监督器在位、标记永不出现（监督器夭折病理态）。When wait。
// Then 有界超时后放行——退化语义=修复前（app 直接应用），不得挂死启动。
func TestWaitStartupReplayDone_timesOutAndProceeds(t *testing.T) {
	setupStartupReplayFixture(t, true) // 超时注入为 2s

	start := time.Now()
	waitStartupReplayDone()
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("应等满超时（%s）再放行，实际 %s 即返回", startupReplayWaitTimeout, elapsed)
	}
}

// 生产调用点钉测：ApplyConfigOnStartup 必须等到回放标记才应用配置——
// 只测 waitStartupReplayDone 无法发现调用点被删/移位。标记延迟落盘期间
// 采样 /load 次数为 0，落盘后才 >0。
func TestApplyConfigOnStartup_waitsForReplayMarkerBeforeApplying(t *testing.T) {
	markerFile := setupStartupReplayFixture(t, true)

	var loads int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			atomic.AddInt32(&loads, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fake.Close)
	h := newBackupTestHandlers(t)
	h.cfg = &config.Config{CaddyAdminURL: fake.URL}
	h.caddyService = services.NewCaddyService(fake.URL)

	done := make(chan error, 1)
	go func() { done <- h.ApplyConfigOnStartup("") }()

	// 标记未落盘：应用必须仍在等待（零 /load）。
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&loads); got != 0 {
		t.Fatalf("回放标记缺失期间 /load=%d, want 0（应用不得先于监督器回放）", got)
	}

	if err := os.WriteFile(markerFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ApplyConfigOnStartup: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("标记落盘后应用仍未返回")
	}
	if got := atomic.LoadInt32(&loads); got == 0 {
		t.Fatal("标记落盘后必须实际应用配置（/load > 0）")
	}
}
