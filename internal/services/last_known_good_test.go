package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 2026-09-06 裁定 ③（last-known-good 启动兜底）：每次成功 /load 后把已应用
// JSON 原子落盘；启动时 DB 渲染被拒可回退应用该文件，保证负载均衡可用性。
// 本文件锁定两个可观察契约：落盘内容=已应用载荷；ApplyLastKnownGood 把文件
// 原样送达 /load。

func TestCaddyService_persistsLastGoodConfigOnSuccessfulApply(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "last_good.json")
	svc := NewCaddyService(server.URL)
	svc.SetLastGoodPath(path)

	// When：应用一份配置
	config := map[string]interface{}{"apps": map[string]interface{}{"test": true}}
	if err := svc.ApplyConfig(config); err != nil {
		t.Fatalf("apply config: %v", err)
	}

	// Then：落盘文件包含已应用的 JSON 载荷
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("last-good file missing: %v", err)
	}
	if !strings.Contains(string(data), `"test":true`) {
		t.Fatalf("last-good content=%s, want applied payload", string(data))
	}
}

func TestCaddyService_ApplyLastKnownGood_sendsFileContentToLoad(t *testing.T) {
	// Given：落盘文件 + 记录 /load 载荷的假 admin
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			buf := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(buf)
			mu.Lock()
			bodies = append(bodies, string(buf))
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "last_good.json")
	payload := `{"apps":{"fallback":true}}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewCaddyService(server.URL)
	svc.SetLastGoodPath(path)

	// When
	if err := svc.ApplyLastKnownGood(); err != nil {
		t.Fatalf("apply last-known-good: %v", err)
	}

	// Then：/load 收到文件原样内容
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"fallback":true`) {
		t.Fatalf("loads=%v, want file content delivered", bodies)
	}
}

// 裁定 2026-09-07 K1：从节点启动 last-good 回退后写 apply_ok_reload_failed
// 补偿标记——Pull 的 304 分支识别后全量重拉，消除「同步正常+运行旧配置」的
// 静默窗口（主节点长期静态时从节点不再卡旧配置直到人工干预）。
func TestMarkStartupFallbackPending_writesCompensationMarker(t *testing.T) {
	_, database := newClusterTestService(t)
	if err := MarkStartupFallbackPending(context.Background(), database); err != nil {
		t.Fatalf("mark: %v", err)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ := decodeSyncError(stored)
	if !strings.HasPrefix(msg, "apply_ok_reload_failed") {
		t.Fatalf("last_sync_error=%q, want apply_ok_reload_failed marker（304 分支据此触发补偿重拉）", msg)
	}
}
