package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
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

	// Then：落盘文件内容=已应用的 JSON 载荷（逐字节），权限 0600
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("last-good file missing: %v", err)
	}
	if string(data) != `{"apps":{"test":true}}` {
		t.Fatalf("last-good content=%s, want applied payload bytes", string(data))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat last-good file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("last-good perm=%o, want 600", perm)
	}
}

func TestCaddyService_ApplyLastKnownGood_sendsFileContentToLoad(t *testing.T) {
	// Given：落盘文件 + 记录 /load 载荷的假 admin
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			// io.ReadAll：chunked 请求的 ContentLength=-1，按长度分配会 panic。
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, string(body))
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

	// Then：/load 收到文件原样字节
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || bodies[0] != payload {
		t.Fatalf("loads=%v, want file content delivered verbatim", bodies)
	}
}

// 失败 apply 不得覆盖已有的 last-known-good：落盘只发生在 2xx 之后，
// 失败路径（含 5xx 系统错误）保留上一次可用的配置。
func TestCaddyService_failedApplyDoesNotOverwriteLastGood(t *testing.T) {
	// Given：已落盘的旧载荷 + 恒 500 的假 admin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			http.Error(w, "load failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "last_good.json")
	previous := `{"apps":{"previous":true}}`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewCaddyService(server.URL)
	svc.SetLastGoodPath(path)

	// When：应用一份新配置但 /load 失败
	err := svc.ApplyConfig(map[string]interface{}{"apps": map[string]interface{}{"next": true}})

	// Then：报错且旧载荷原样保留
	if err == nil {
		t.Fatal("/load 失败必须返回错误")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read last-good: %v", readErr)
	}
	if string(data) != previous {
		t.Fatalf("失败 apply 覆写了 last-good: %s", string(data))
	}
}

// ApplyLastKnownGood 的 /load 此前仅持 s.mu——
// 与持 CaddyOpLock 的并发「渲染+/load」写者（handler 写路径/后台 Force 重载）
// 无互斥，last-good 的旧配置可后到覆盖新配置。修复=入 CaddyOpLock（与
// GenerateAndApplyConfigForce 同型：CaddyOpLock→s.mu 持锁序，叶操作无 AB-BA）。
// 唯一生产调用方 ApplyConfigOnStartup（handlers.go 启动兜底）在 applyCaddyConfigE
// 返回后调用、不持锁（.5 反向枚举：无 InLock 变体需求）。
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
	started := make(chan struct{})
	go func() {
		close(started)
		done <- svc.ApplyLastKnownGood()
	}()
	// 正向握手：必须确认 goroutine 已进入调用，再断言「未完成」——否则慢
	// 调度下 300ms 窗口在零证据时空转通过（用例对锁语义零信息量）。
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		CaddyOpLock.Unlock()
		t.Fatal("ApplyLastKnownGood goroutine 未启动")
	}

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

// 裁定 2026-09-07：从节点启动 last-good 回退后写 apply_ok_reload_failed
// 补偿标记——Pull 的 304 分支识别后全量重拉，消除「同步正常+运行旧配置」的
// 静默窗口（主节点长期静态时从节点不再卡旧配置直到人工干预）。
func TestMarkStartupFallbackPending_writesCompensationMarker(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false) // 标记只在从端语境落库（304 补偿只发生在从端 Pull）
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

// 启动渲染被拒且 last-known-good 回退也失败的
// 双失败路径此前不写任何补偿标记——运行配置与数据库处于未知分叉态，而 Pull 的
// 304 分支只认 apply_ok_reload_failed 标记，自愈失明（「同步正常+运行未知旧
// 配置」静默到下次真实变更或重启）。修复=双失败同样落标记，下轮 Pull 打破 304
// 强制全量重放。本测试钉：标记写入 + 304 触发器（syncMarkerPresent + syncReloadFailureMarkerPrefix）
// 识别（全量重拉机制本身由既有集群重拉测试覆盖）。
func TestMarkStartupFallbackFailed_writesCompensationMarker(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false) // 标记只在从端语境落库（304 补偿只发生在从端 Pull）
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
	if !syncService.syncMarkerPresent(context.Background(), syncReloadFailureMarkerPrefix) {
		t.Fatal("重载失败标记探测=false——Pull 304 分支不会触发全量重拉，补偿通道失明")
	}
}

// persistLastGoodLocked 的 .tmp 写失败（RLIMIT_FSIZE 部分写）此前留下孤儿
// .tmp——与 certstore 临时文件自清理同口径修复。注入真实失败机制：把文件
// 大小上限压到新载荷之下，writeSyncedFile 的 Write 真实触发 EFBIG；断言终态
// （零 .tmp 残留 + 既有 last-good 主文件不被破坏）而非仅返回值。
func TestCaddyService_persistLastGood_writeFailureLeavesNoTmpOrphan(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("RLIMIT_FSIZE 注入仅支持 unix 形态")
	}
	// Given：既有 last-good 主文件（上一次可用配置）。
	dir := t.TempDir()
	path := filepath.Join(dir, "last_good.json")
	const previous = `{"apps":{"previous":true}}`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatalf("seed last-good: %v", err)
	}
	svc := NewCaddyService("http://127.0.0.1:1") // 不触网，直接调 persistLastGoodLocked
	svc.SetLastGoodPath(path)

	// 文件大小上限压到新载荷字节数之下——Write 超限真实失败（EFBIG）。
	payload := []byte(`{"apps":{"new-longer-than-limit":true}}`)
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Fatalf("read RLIMIT_FSIZE: %v", err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(len(payload) - 1), Max: original.Max}); err != nil {
		t.Fatalf("set RLIMIT_FSIZE: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original) })

	// When
	svc.mu.Lock()
	svc.persistLastGoodLocked(payload)
	svc.mu.Unlock()

	// Then：零 .tmp 残留，且既有 last-good 主文件逐字节不变。
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read dir: %v", readErr)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("写盘失败后残留 .tmp 孤儿 %s（失败路径必须清理暂存）", entry.Name())
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("last-good main file missing after failed persist: %v", err)
	}
	if string(got) != previous {
		t.Fatalf("last-good main file=%s, want previous payload unchanged", string(got))
	}
}
