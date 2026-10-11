package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
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
			// LBS-B-L2（第 69 轮）：单次 Read 不保证读满——短读会截断断言
			// 内容致偶发红，改 io.ReadFull。
			buf := make([]byte, r.ContentLength)
			_, _ = io.ReadFull(r.Body, buf)
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

// F-L5-68-03（第 68 轮审计 P5）：ApplyLastKnownGood 的 /load 此前仅持 s.mu——
// 与持 CaddyOpLock 的并发「渲染+/load」写者（handler 写路径/后台 Force 重载）
// 无互斥，last-good 的旧配置可后到覆盖新配置。修复=入 CaddyOpLock（与
// GenerateAndApplyConfigForce 同型：CaddyOpLock→s.mu 持锁序，叶操作无 AB-BA）。
// 唯一生产调用方 ApplyConfigOnStartup（handlers.go 启动兜底）在 applyCaddyConfigE
// 返回后调用、不持锁（R-2.5 反向枚举：无 InLock 变体需求）。
func TestCaddyService_ApplyLastKnownGood_blocks_while_caddy_op_lock_held(t *testing.T) {
	// Given：落盘文件 + 就绪的假 admin；CaddyOpLock 被预持（模拟并发写临界区）
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "last_good.json")
	if err := os.WriteFile(path, []byte(`{"apps":{"fallback":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewCaddyService(server.URL)
	svc.SetLastGoodPath(path)

	// When：持锁期间调用 ApplyLastKnownGood
	CaddyOpLock.Lock()
	done := make(chan error, 1)
	go func() {
		done <- svc.ApplyLastKnownGood()
	}()

	// Then：必须阻塞至 CaddyOpLock 释放（持锁期间完成=未入锁）
	select {
	case err := <-done:
		CaddyOpLock.Unlock()
		t.Fatalf("ApplyLastKnownGood 在 CaddyOpLock 被预持期间完成（last-good /load 未入锁）, err=%v", err)
	case <-time.After(300 * time.Millisecond):
	}
	CaddyOpLock.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("锁释放后 ApplyLastKnownGood 失败: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 ApplyLastKnownGood 10s 内未完成")
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

// F-L5-68-02（第 68 轮审计 P4）：启动渲染被拒且 last-known-good 回退也失败的
// 双失败路径此前不写任何补偿标记——运行配置与数据库处于未知分叉态，而 Pull 的
// 304 分支只认 apply_ok_reload_failed 标记，自愈失明（「同步正常+运行未知旧
// 配置」静默到下次真实变更或重启）。修复=双失败同样落标记，下轮 Pull 打破 304
// 强制全量重放。本测试钉：标记写入 + 304 触发器（syncReloadFailureMarkerPresent）
// 识别（全量重拉机制本身由 cluster_r31/r32 既有测试覆盖）。
func TestMarkStartupFallbackFailed_writesCompensationMarker(t *testing.T) {
	_, database := newClusterTestService(t)
	cause := errors.New("apply last-known-good config failed: connection refused")
	if err := MarkStartupFallbackFailed(context.Background(), database, cause); err != nil {
		t.Fatalf("mark: %v", err)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ := decodeSyncError(stored)
	if !strings.HasPrefix(msg, "apply_ok_reload_failed") {
		t.Fatalf("last_sync_error=%q, want apply_ok_reload_failed marker（双失败必须触发 304 补偿重拉）", msg)
	}
	if !strings.Contains(msg, "last-known-good") {
		t.Fatalf("marker message=%q, want 标明 last-known-good 回退失败根因", msg)
	}
	// 304 分支的标记检测（cluster_sync.go Pull）必须识别该标记——否则重拉通道
	// 依旧失明。
	syncService := NewSyncService(database, &config.Config{}, nil)
	if !syncService.syncReloadFailureMarkerPresent(context.Background()) {
		t.Fatal("syncReloadFailureMarkerPresent=false——Pull 304 分支不会触发全量重拉，补偿通道失明")
	}
}
