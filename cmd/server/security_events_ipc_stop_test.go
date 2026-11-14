package main

// 安全事件 IPC 关停的预算派生钉：外层 runWithin 与内层 Stop ctx 必须共用
// 同一预算派生段。内层 ctx 曾固定 ipcStopSegmentMax——HTTP/排水段吃满预算
// 后，内层仍按 500ms 等待在途入库，超出共享 deadline。
//
// 观测点=内层 ctx 的 deadline（经 ipcStopContext 注入缝捕获）：它直接反映
// Stop 拿到的等待预算。用真实 IPC 服务端驱动 Stop（无在途请求时立即返回），
// 断言 ctx deadline ≈ 剩余预算而非固定段上限——不依赖壁钟测量，并行负载下
// 也确定性可判。

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

// startIPCServerForStopTest 在短前缀临时目录起一个真实 IPC 服务端
// （UDS sun_path 有长度上限，t.TempDir 路径过长会 bind 失败）。
func startIPCServerForStopTest(t *testing.T) *handlers.SecurityEventsIPCServer {
	t.Helper()
	sockDir, err := os.MkdirTemp("/tmp", "lbipcstop")
	if err != nil {
		t.Fatalf("create short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "security-events.sock")
	t.Setenv(services.SecurityEventsIPCSocketEnv, sockPath)
	srv, err := handlers.StartSecurityEventsIPCServer()
	if err != nil {
		t.Fatalf("start IPC server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})
	return srv
}

// captureIPCStopContext 替换 ipcStopContext 缝：记录每次派生的预算时长，
// 仍返回真实 ctx（Stop 行为不变）。返回捕获的时长切片与恢复函数。
func captureIPCStopContext(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	got := make([]time.Duration, 0, 1)
	orig := ipcStopContext
	ipcStopContext = func(d time.Duration) (context.Context, context.CancelFunc) {
		mu.Lock()
		got = append(got, d)
		mu.Unlock()
		return context.WithTimeout(context.Background(), d)
	}
	t.Cleanup(func() { ipcStopContext = orig })
	return &got
}

func TestStopSecurityEventsIPCWithin_innerCtxFollowsRemainingBudget(t *testing.T) {
	srv := startIPCServerForStopTest(t)
	got := captureIPCStopContext(t)

	// Given 关停预算已被前方段（HTTP/排水）耗到只剩 80ms——远小于段上限
	// 500ms。内层 ctx 若仍固定 500ms，Stop 会按 500ms 等待在途入库。
	now := time.Now()
	b := &shutdownBudget{now: func() time.Time { return now }, deadline: now.Add(80 * time.Millisecond)}

	stopSecurityEventsIPCWithin(srv, b)

	// Then 内层 ctx 拿到的预算=剩余预算（80ms），不是固定段上限。
	if len(*got) != 1 {
		t.Fatalf("内层 ctx 派生 %d 次，want 1", len(*got))
	}
	if d := (*got)[0]; d != 80*time.Millisecond {
		t.Fatalf("内层 ctx 预算=%s，want 80ms（剩余预算）；固定 %s 会超出共享 deadline", d, ipcStopSegmentMax)
	}
}

func TestStopSecurityEventsIPCWithin_fullBudgetUsesSegmentCap(t *testing.T) {
	srv := startIPCServerForStopTest(t)
	got := captureIPCStopContext(t)

	// 预算充足（未起算）：内层 ctx 用满段上限，且 Stop 正常路径立即退出、
	// socket 移除。
	b := newShutdownBudget()
	stopSecurityEventsIPCWithin(srv, b)
	if len(*got) != 1 || (*got)[0] != ipcStopSegmentMax {
		t.Fatalf("预算充足时内层 ctx 预算=%v，want [%s]", *got, ipcStopSegmentMax)
	}
	if _, err := os.Stat(services.SecurityEventsIPCSocketPath()); !os.IsNotExist(err) {
		t.Fatalf("关停后 socket 文件必须移除，stat err=%v", err)
	}
}

func TestStopSecurityEventsIPCWithin_exhaustedBudgetSkipsWait(t *testing.T) {
	srv := startIPCServerForStopTest(t)
	got := captureIPCStopContext(t)

	// 预算已耗尽：runWithin d<=0 直接跳过等待（不启动收尾 goroutine），
	// 内层 ctx 根本不派生——不得阻塞在固定段上限上。
	now := time.Now()
	b := &shutdownBudget{now: func() time.Time { return now }, deadline: now.Add(-time.Second)}
	started := time.Now()
	stopSecurityEventsIPCWithin(srv, b)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("预算耗尽时 IPC 关停耗时 %s，应立即跳过等待", elapsed)
	}
	if len(*got) != 0 {
		t.Fatalf("预算耗尽不得派生内层 ctx（不启动收尾），got %v", *got)
	}
}
