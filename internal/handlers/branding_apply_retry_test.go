package handlers

// 公开 GET /branding 触发的幂等同步消费指纹后才异步应用 Caddy 配置。应用侧
// 失败（角色读失败 / /load 失败）不得把「本轮已处理」固化：否则运行时 Caddy
// 会继续用旧文案/旧拦截页，直到有人手工重载或再次改文件——自动同步承诺失效。
// 清指纹保留 60s 采样窗：恢复后的下一轮（≥60s）重试，公开端点不会被刷成
// 每请求 /load。从节点正常跳过不是失败，不得清指纹。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// brandingApplyFixture 构造「指纹已消费」形态：文件在场且本轮同步门已放行。
func brandingApplyFixture(t *testing.T) (*Handlers, string) {
	t.Helper()
	handler := newBackupTestHandlers(t)
	dir := t.TempDir()
	handler.cfg.DataDir = dir
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"甲"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	resetBrandingStore()
	resetBrandingSyncGateForTest()
	t.Cleanup(func() {
		resetBrandingStore()
		resetBrandingSyncGateForTest()
	})
	if !brandingSyncGateAllow(dir) {
		t.Fatal("fixture: 文件首见应放行一轮同步")
	}
	return handler, dir
}

// expireBrandingSyncWindow 让 60s 采样窗过期（模拟 ≥60s 后的下一轮）。
func expireBrandingSyncWindow() {
	brandingSyncMu.Lock()
	brandingSyncLast = time.Now().Add(-2 * time.Minute)
	brandingSyncMu.Unlock()
}

// failingLoadCaddy 只让 /load 失败：返回的应用错误形态与真实传输/拒绝一致。
func failingLoadCaddy(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			http.Error(w, "admin api exploded", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestBrandingApplyFailureAllowsRetryAfterWindow(t *testing.T) {
	handler, dir := brandingApplyFixture(t)
	adminURL := failingLoadCaddy(t)
	handler.cfg.CaddyAdminURL = adminURL
	handler.caddyService = services.NewCaddyService(adminURL)

	handler.brandingApplyAfterSync()

	// 采样窗仍在：窗内不重试（公开端点不得被刷成每请求 /load）。
	if brandingSyncGateAllow(dir) {
		t.Fatal("应用失败后采样窗内不得立即重试")
	}
	expireBrandingSyncWindow()
	if !brandingSyncGateAllow(dir) {
		t.Fatal("Caddy 应用失败必须清指纹：窗过后下一轮要能重试并收敛到新文案")
	}
}

func TestBrandingRoleReadFailureAllowsRetryAfterWindow(t *testing.T) {
	handler, dir := brandingApplyFixture(t)
	// 角色读取失败（临时移走 global_config，等价于查询故障形态）。
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_hidden`); err != nil {
		t.Fatalf("hide global_config: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`ALTER TABLE global_config_hidden RENAME TO global_config`)
	})

	handler.brandingApplyAfterSync()

	if brandingSyncGateAllow(dir) {
		t.Fatal("角色读失败后采样窗内不得立即重试")
	}
	expireBrandingSyncWindow()
	if !brandingSyncGateAllow(dir) {
		t.Fatal("角色读取失败必须清指纹：恢复后下一轮要能重试")
	}
}

func TestBrandingSlaveRoleSkipKeepsFingerprint(t *testing.T) {
	handler, dir := brandingApplyFixture(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	// 从节点不做本地应用；此处应用端点必然失败，用于证明「跳过」不等于「失败」。
	handler.caddyService = services.NewCaddyService("http://127.0.0.1:1")

	handler.brandingApplyAfterSync()

	expireBrandingSyncWindow()
	if brandingSyncGateAllow(dir) {
		t.Fatal("从节点正常跳过不得清指纹（否则每 60s 重复跑一轮同步/镜像）")
	}
}

// waitBrandingApply 等异步应用收尾：调用数达到 want 且待办标记落在 wantPending。
func waitBrandingApply(t *testing.T, loads *atomic.Int32, want int32, wantPending bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if loads.Load() >= want && brandingApplyPending.Load() == wantPending {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("异步应用未收尾：调用=%d（want≥%d）待办=%v（want %v）", loads.Load(), want, brandingApplyPending.Load(), wantPending)
}

// 端到端收敛：首轮 /load 失败后，同步已落库（重试轮 needApply=false），必须靠
// 待办标记在下一个 60s 窗口再次重应用——只清指纹不够，运行配置会一直停在旧
// 文案/旧拦截页，自动同步承诺仍然失效。
func TestGetBranding_retriesApplyOnNextWindowWhenFirstLoadFails(t *testing.T) {
	handler := newBackupTestHandlers(t)
	dir := t.TempDir()
	handler.cfg.DataDir = dir
	content := `{"app_name":"甲","landing_text":"重试文案"}`
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	resetBrandingStore()
	resetBrandingSyncGateForTest()
	t.Cleanup(func() {
		resetBrandingStore()
		resetBrandingSyncGateForTest()
	})
	var loads atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			if loads.Add(1) == 1 {
				http.Error(w, "admin api exploded", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(admin.Close)
	handler.cfg.CaddyAdminURL = admin.URL
	handler.caddyService = services.NewCaddyService(admin.URL)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/branding", handler.GetBranding)
	getBranding := func() {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/branding", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
		}
	}

	// 首轮：同步成功、/load 失败。
	getBranding()
	waitBrandingApply(t, &loads, 1, true)

	// 采样窗过期后的下一轮匿名读：同步已是 no-op，仍必须重应用。
	expireBrandingSyncWindow()
	getBranding()
	waitBrandingApply(t, &loads, 2, false)
}
