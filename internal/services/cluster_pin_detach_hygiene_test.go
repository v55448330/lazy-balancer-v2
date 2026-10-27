package services

// 两条资源卫生回归钉：
//  ① 脱离通知的 per-call client+Transport 用完必须关闭空闲连接（否则连接与
//     其读写 goroutine 滞留到 90s 空闲超时，反复升降主时累积残留 transport）。
//  ② pin 清理的待重试项按路径保存：第二次清理失败不得覆盖第一次的待重试项，
//     否则先前的 pin 文件既无重试也无审计，只能人工删盘。

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNotifyMasterDetach_closesIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state != http.StateClosed {
			return
		}
		select {
		case closed <- struct{}{}:
		default:
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	notifyMasterDetach(context.Background(), server.URL, "cluster-token", "")

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("脱离通知未关闭空闲连接（连接与读循环会滞留到 90s 空闲超时）")
	}
}

func TestCleanupClusterPin_keepsEveryFailedPathForRetry(t *testing.T) {
	service, _ := newClusterTestService(t)
	root := t.TempDir()
	// 两个 pin 路径各自「清理失败」：用非空目录让 os.Remove 报 ENOTEMPTY。
	obstruct := func(path string) {
		if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
			t.Fatalf("obstruct pin path: %v", err)
		}
	}
	pathA := filepath.Join(root, "master-a.pin")
	pathB := filepath.Join(root, "master-b.pin")
	obstruct(pathA)
	obstruct(pathB)

	// When：连续两次清理失败（先 A 后 B）——单槽实现会用 B 覆盖 A。
	service.cleanupClusterPin(pathA, "https://old-a:8000")
	service.cleanupClusterPin(pathB, "https://old-b:8000")

	service.pinCleanupMu.Lock()
	pending := len(service.pendingPins)
	service.pinCleanupMu.Unlock()
	if pending != 2 {
		t.Fatalf("待重试 pin 条数=%d, want 2（后一次失败不得覆盖先前待重试项）", pending)
	}

	// When：障碍解除（pin 变回普通文件）后巡检重试
	for _, path := range []string{pathA, pathB} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fingerprint\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	service.retryPendingPinCleanup()

	// Then：两枚 pin 都被重试删除，待重试表清空。
	for _, path := range []string{pathA, pathB} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("pin %s 未被重试清理（stat=%v）：先前待重试项被覆盖", filepath.Base(path), err)
		}
	}
	service.pinCleanupMu.Lock()
	pending = len(service.pendingPins)
	service.pinCleanupMu.Unlock()
	if pending != 0 {
		t.Fatalf("重试成功后待重试 pin 条数=%d, want 0", pending)
	}
}

// 并发形态：两条路径同时失败/重试不得互相清空或重复入表（map 由同一把锁保护）。
func TestCleanupClusterPin_concurrentFailuresKeepDistinctEntries(t *testing.T) {
	service, _ := newClusterTestService(t)
	root := t.TempDir()
	const paths = 8
	var waitGroup sync.WaitGroup
	for index := range paths {
		path := filepath.Join(root, "pin-"+string(rune('a'+index)))
		if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		waitGroup.Add(1)
		go func(path string) {
			defer waitGroup.Done()
			service.cleanupClusterPin(path, "https://old:8000")
		}(path)
	}
	waitGroup.Wait()

	service.pinCleanupMu.Lock()
	pending := len(service.pendingPins)
	service.pinCleanupMu.Unlock()
	if pending != paths {
		t.Fatalf("待重试 pin 条数=%d, want %d", pending, paths)
	}
}
