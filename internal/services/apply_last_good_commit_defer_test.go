package services

// 事务内 apply 不得落 last-known-good：apply 在 commit 之前执行，进程若在
// apply→commit 窗口中断（SIGKILL/OOM/容器被杀），启动兜底会把从未提交的配置
// 当作「最后已知正确」真实回放。LKG 只能由调用方在 commit 成功后用返回的
// 应用字节补齐。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func newLastGoodDeferTestService(t *testing.T) (*CaddyService, *string, func() string) {
	t.Helper()
	newClusterTestService(t)

	var mu sync.Mutex
	loads := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			// 运行配置与候选恒不同 → 每次 apply 都发生真实 /load。
			_, _ = w.Write([]byte(`{"apps":{"running":true}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			loads = string(body)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	lkgPath := filepath.Join(t.TempDir(), "last_good.json")
	previous := `{"apps":{"previous":true}}`
	if err := os.WriteFile(lkgPath, []byte(previous), 0o600); err != nil {
		t.Fatalf("seed last-good: %v", err)
	}
	service := NewCaddyService(server.URL)
	service.SetLastGoodPath(lkgPath)
	readLoad := func() string {
		mu.Lock()
		defer mu.Unlock()
		return loads
	}
	return service, &previous, readLoad
}

func TestApplyConfigFromTx_defersLastKnownGoodUntilCommit(t *testing.T) {
	service, previous, lastLoad := newLastGoodDeferTestService(t)
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	applied, err := service.ApplyConfigFromTx(tx, false)
	if err != nil {
		t.Fatalf("tx apply: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("真实 /load 必须返回已下发字节（commit 后据此补写 last-known-good）")
	}
	if got := lastLoad(); got != string(applied) {
		t.Fatalf("/load 载荷=%q, want 返回字节 %q", got, string(applied))
	}
	// 关键断言：commit 之前 LKG 必须停在上一份已提交配置。
	if got := readFile(t, service.lastGoodPath); got != *previous {
		t.Fatalf("commit 之前 last-known-good 被改写为 %q（want 保留 %q）", got, *previous)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	service.PersistLastGoodBytesInLock(applied)
	if got := readFile(t, service.lastGoodPath); got != string(applied) {
		t.Fatalf("commit 后 last-known-good=%q, want 已下发字节 %q", got, string(applied))
	}
}

func TestApplyConfigReportingForCommit_defersLastKnownGood(t *testing.T) {
	service, previous, lastLoad := newLastGoodDeferTestService(t)

	applied, loaded, err := service.ApplyConfigReportingForCommit(map[string]interface{}{"apps": map[string]interface{}{"candidate": true}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !loaded || len(applied) == 0 || lastLoad() != string(applied) {
		t.Fatalf("loaded=%t applied=%q lastLoad=%q", loaded, applied, lastLoad())
	}
	if got := readFile(t, service.lastGoodPath); got != *previous {
		t.Fatalf("pre-commit last-known-good=%q, want previous %q", got, *previous)
	}

	service.PersistLastGoodBytesInLock(applied)
	if got := readFile(t, service.lastGoodPath); got != string(applied) {
		t.Fatalf("post-commit last-known-good=%q, want applied %q", got, applied)
	}
}

// 同字节短路（无真实 /load）返回空字节：调用方补写必须是 no-op，LKG 保持
// 原样（运行配置本就未变化）。
func TestPersistLastGoodBytesInLock_emptyPayloadIsNoop(t *testing.T) {
	service, previous, _ := newLastGoodDeferTestService(t)
	service.PersistLastGoodBytesInLock(nil)
	if got := readFile(t, service.lastGoodPath); got != *previous {
		t.Fatalf("空载荷不得改写 last-known-good, got %q", got)
	}
}

// 非事务 apply 仍在成功 /load 后立即落盘（规则族拒绝分支的恢复语义依赖
// 「运行配置即 LKG」的时间点）。
func TestApplyConfig_nontransactionalStillPersistsLastGood(t *testing.T) {
	service, _, _ := newLastGoodDeferTestService(t)
	if err := service.ApplyConfig(map[string]interface{}{"apps": map[string]interface{}{"direct": true}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := readFile(t, service.lastGoodPath); got != `{"apps":{"direct":true}}` {
		t.Fatalf("非事务 apply 必须立即落盘, got %q", got)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
