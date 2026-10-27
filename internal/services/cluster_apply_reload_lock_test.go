package services

// 从端 applySnapshot 末段「渲染+强制重载」绕过
// CaddyOpLock——与重启 watcher（渲染 DB→/load，持 CaddyOpLock）交错时，跨同步
// commit 点的旧渲染可后到覆盖新配置，从节点静默回退上一版本（三通道自愈全
// 探不到）。修复=重载段包入 CaddyOpLock（Pull 路径锁不反向嵌套——锁内仅
// ApplyConfigForce 的 s.mu，叶操作）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// Given 从端 SyncService 指向就绪的 Caddy stub；临界区入口观察点在重载段。
// When applySnapshot 执行到末段「渲染+ApplyConfigForce 强制重载」。
// Then 进入临界区时 CaddyOpLock 必须已被持有（TryLock 失败），完成后 /load
// 恰一次；锁序护栏不再依赖固定时间窗。
func TestSyncService_applySnapshot_reload_holds_caddy_op_lock(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	var loadMu sync.Mutex
	loads := 0
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		// 按路径计数：只证明「取到了 CaddyOpLock」不够——ApplyConfigForce 退化为
		// no-op（不 POST /load）时本条仍会绿。锁语义必须与真实重载请求绑定。
		if request.Method == http.MethodPost && request.URL.Path == "/load" {
			loadMu.Lock()
			loads++
			loadMu.Unlock()
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       7,
		Users:         []models.ClusterUser{{ID: 7, Username: "lock-order-admin", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: new("info"), Timezone: new("Asia/Shanghai")},
	})

	// 临界区入口观察点：钩子在 applySnapshot 已持 CaddyOpLock 后被调用。
	// 用例在此停住钩子，用 TryLock 直接断言「锁被持有时才进入重载段」——
	// 不再用固定时间窗猜测进度（机器慢/前置阶段变慢时负向断言假绿）。
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHook := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHook)
	syncReloadLockHook = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { syncReloadLockHook = nil })

	done := make(chan error, 1)
	go func() {
		done <- syncService.applySnapshot(context.Background(), snapshot)
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("applySnapshot 未进入重载临界区即完成, err=%v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("applySnapshot 30s 内未进入重载临界区（前置阶段挂起）")
	}
	// 钩子运行中=临界区内：锁必须不可再获取。
	if CaddyOpLock.TryLock() {
		CaddyOpLock.Unlock()
		releaseHook()
		t.Fatal("重载段未持 CaddyOpLock（临界区外执行渲染+/load，可被并发渲染覆盖）")
	}
	releaseHook()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("applySnapshot 失败: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("applySnapshot 10s 内未完成")
	}
	// 真实 POST /load 必须发生且恰一次：锁内路径退化为空操作时本条变红。
	loadMu.Lock()
	finalLoads := loads
	loadMu.Unlock()
	if finalLoads != 1 {
		t.Fatalf("Caddy /load 次数=%d, want 1（重载请求必须真实发出）", finalLoads)
	}
}

// 重载段渲染源必须绑定 SyncService 自身句柄：GenerateCaddyConfig() 恒用包级
// db.DB，多库形态（测试网关/嵌入式多实例）会把 A 库快照提交后按 B 库内容
// 渲染并 /load（写入 A、渲染 B，静默错配）。生产单库装配（s.db==db.DB）与
// 任意 db.DB 构造的夹具都观察不到差异——行为断言不可达，故用机制级钉测
// 固定调用形态（与 render_anti_fallback_scan_test 同口径）。
func TestSyncService_applySnapshot_renderUsesServiceDBHandle(t *testing.T) {
	source, err := os.ReadFile("cluster_apply.go")
	if err != nil {
		t.Fatalf("read cluster_apply.go: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "ApplyConfigForce(GenerateCaddyConfig())") {
		t.Fatal("applySnapshot 重载段用包级 db.DB 渲染（多库形态会写入 A 库、渲染 B 库）")
	}
	if !strings.Contains(text, "generateCaddyConfigWithCertSource(s.db, s.db, true)") {
		t.Fatal("applySnapshot 重载段必须用服务句柄渲染：generateCaddyConfigWithCertSource(s.db, s.db, true)")
	}
}
