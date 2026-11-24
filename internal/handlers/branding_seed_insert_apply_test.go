package handlers

// 内置拦截页行缺失（导入全量替换 / 旧快照 / 带外改库）后的自愈闭环：播种经
// INSERT OR IGNORE 补回库存行，必须把「插入」计入 changed 并触发 Caddy 重应用。
// 缺页期间运行配置是按回落页渲染的——只补库不重应用 = 库已恢复、运行态停在
// 回落页，直到下一次配置变更/重启（与函数注释「漂移修复必须无条件完成」相悖）。
// 反向：库存值完整时 changed=false，公开端点不得每个采样窗都 /load。

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

// deleteBuiltinBlockPageRow 真实故障注入：库存先到稳态，再带外删掉一行内置页
// （模拟缺行形态），并校验该行确实缺失。
func deleteBuiltinBlockPageRow(t *testing.T, dir string) int {
	t.Helper()
	if _, err := SeedDefaultBlockPage(dir); err != nil {
		t.Fatalf("seed steady state: %v", err)
	}
	missing := builtinBlockPageIdentities[0]
	if _, err := db.DB.Exec(`DELETE FROM security_block_pages WHERE id=?`, missing.id); err != nil {
		t.Fatalf("delete builtin page %d: %v", missing.id, err)
	}
	var present int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id=?`, missing.id).Scan(&present); err != nil {
		t.Fatalf("count builtin page %d: %v", missing.id, err)
	}
	if present != 0 {
		t.Fatalf("夹具失效：内置页 %d 行未删（用例无法判别）", missing.id)
	}
	return missing.id
}

// 确定性信号：仅插入路径（UPDATE 在库存值上零命中）必须声明 changed。
func TestSeedDefaultBlockPage_insertOnlyPathCountsAsChanged(t *testing.T) {
	newBackupTestHandlers(t)
	dir := t.TempDir()
	missingID := deleteBuiltinBlockPageRow(t, dir)

	seeded, err := SeedDefaultBlockPage(dir)
	if err != nil {
		t.Fatalf("seed after row loss: %v", err)
	}
	var present int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id=?`, missingID).Scan(&present); err != nil {
		t.Fatalf("count restored row: %v", err)
	}
	if present != 1 {
		t.Fatalf("缺行未补回（present=%d）", present)
	}
	if !seeded {
		t.Fatal("缺行自愈 changed=false：INSERT OR IGNORE 补回库存行不计入变化，GetBranding 不会重应用（回落页持续）")
	}

	// 反向：库存值完整时不得再声明变化（否则公开端点每个采样窗都 /load）。
	again, err := SeedDefaultBlockPage(dir)
	if err != nil {
		t.Fatalf("seed on steady state: %v", err)
	}
	if again {
		t.Fatal("库存值完整时 changed=true（稳态重应用回归）")
	}
}

// settleBrandingLoads 等在途异步应用收尾（调用数连续 150ms 不变且无待办），
// 返回当前 /load 基线——用于隔离「后续一轮」的增量归因。
func settleBrandingLoads(loads *atomic.Int32) int32 {
	last := loads.Load()
	stableSince := time.Now()
	for time.Since(stableSince) < 150*time.Millisecond {
		time.Sleep(5 * time.Millisecond)
		if brandingApplyPending.Load() {
			stableSince = time.Now()
		}
		if current := loads.Load(); current != last {
			last, stableSince = current, time.Now()
		}
	}
	return last
}

// 端到端：GET /branding 触发的缺行播种必须重应用（可观察信号=Caddy admin
// POST /load 调用数）；库存完整后的下一轮采样窗不得再 /load。
func TestGetBranding_seedingMissingBuiltinPageReappliesConfig(t *testing.T) {
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
	var loads atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads.Add(1)
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

	// 预热一轮：把 landing 同步/镜像等其它变化源收敛掉，隔离后续增量归因。
	getBranding()
	baseline := settleBrandingLoads(&loads)

	// 真实故障注入 + 指纹变化后的下一采样窗匿名读。brandingSyncGateAllow 有两道
	// 门：branding.json 指纹未变化即整轮跳过同步（仅过期采样窗不够）。追加惰性
	// 字段只改指纹、不改 app_name/landing_text 等渲染输入——landing 同步保持
	// changed=false，本轮的应用增量只能来自缺行播种。
	deleteBuiltinBlockPageRow(t, dir)
	rewriteBrandingFingerprint(t, dir, "probe-22")
	expireBrandingSyncWindow()
	getBranding()
	waitBrandingApply(t, &loads, baseline+1, false)

	// 反向：库存已完整，指纹再次变化 + 采样窗过期也不得再触发 /load。
	rewriteBrandingFingerprint(t, dir, "probe-333")
	expireBrandingSyncWindow()
	getBranding()
	if got := settleBrandingLoads(&loads); got != baseline+1 {
		t.Fatalf("库存完整时仍重应用（/load=%d, want %d）——公开端点每个采样窗都会 /load", got, baseline+1)
	}
}

// rewriteBrandingFingerprint 追加惰性字段改变 branding.json 的 mtime/size 指纹，
// 不触碰任何渲染输入（app_name 保持不变、landing_text 仍缺省）。
func rewriteBrandingFingerprint(t *testing.T, dir, tag string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"甲","_sync_probe":"`+tag+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}
