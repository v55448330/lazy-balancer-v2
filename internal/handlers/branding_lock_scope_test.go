package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// 热重载留痕（操作日志的同步 INSERT）不得发生在 brandingStore 写锁内：
// 该锁是进程级单写锁，锁内做 DB 写会让审计库慢写时全部 branding 读者
// （公开 GET /branding、/system/info、拦截页播种）排队。
func TestLoadBrandingConfig_reloadAuditRunsOutsideStoreLock(t *testing.T) {
	withIsolatedGlobal(t)
	resetBrandingStore()
	t.Cleanup(resetBrandingStore)
	oldAudit := db.AuditDB
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	t.Cleanup(func() { db.AuditDB = oldAudit })

	dir := t.TempDir()
	path := filepath.Join(dir, "branding.json")
	if err := os.WriteFile(path, []byte(`{"app_name":"甲"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	loadBrandingConfig(dir) // boot 首载建立前值基线（不产生重载留痕）

	entered := make(chan struct{})
	release := make(chan struct{})
	var released bool
	closeRelease := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(closeRelease)
	brandingReloadAuditHook = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { brandingReloadAuditHook = nil })

	// 手工编辑触发一次热重载；留痕钩子在场内阻塞（模拟审计库慢写）。
	if err := os.WriteFile(path, []byte(`{"app_name":"甲乙"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		loadBrandingConfig(dir)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("热重载留痕未触发（钩子未到达）")
	}

	// 留痕未完成期间并发读必须立即返回（快照已换新，且不持有写锁）。
	readerDone := make(chan brandingConfig, 1)
	go func() { readerDone <- loadBrandingConfig(dir) }()
	select {
	case cfg := <-readerDone:
		if cfg.AppName != "甲乙" {
			t.Fatalf("并发读拿到 %q, want 甲乙", cfg.AppName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("热重载留痕持有 brandingStore 写锁：并发读者被阻塞")
	}
	closeRelease()
	<-reloadDone
}

// 配置导入窗口内 GET /branding 的幂等写副作用（landing 注入/拦截页播种/
// 品牌镜像）必须跳过：三者都写导入的全量替代表，窗口内提交会阻塞至
// busy_timeout 后被导入覆盖。
func TestGetBranding_skipsWriteSideEffectsDuringImport(t *testing.T) {
	handler := newBackupTestHandlers(t)
	dir := t.TempDir()
	handler.cfg = &config.Config{DataDir: dir}
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"镜像验证","landing_text":"导入窗口内的文案"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	resetBrandingStore()
	resetBrandingSyncGateForTest()
	t.Cleanup(func() {
		resetBrandingStore()
		resetBrandingSyncGateForTest()
	})

	// Given：配置导入会话进行中（窗口计数非零 = configImportBusy()==true）。
	beginImportWindowForTest(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/branding", handler.GetBranding)

	// When
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/branding", nil))

	// Then：读取本身成功，且库内没有任何写副作用（品牌镜像仍为空）。
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var mirrored string
	if err := db.DB.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored); err != nil {
		t.Fatalf("read branding_json: %v", err)
	}
	if mirrored != "" {
		t.Fatalf("导入窗口内仍触发了品牌镜像写入: %q", mirrored)
	}
}

// 品牌镜像的接线点：主节点修改 branding.json → 越过 60s 采样门 → GET /branding
// → global_config.branding_json 与文件原文一致（触发器 bump cluster_version，
// 快照把变更带到从节点）。handlers 包内此前只有反向用例（导入窗口内镜像必须
// 为空），正向链路只在 services 直调层验证——删除 GetBranding 内的镜像调用后
// 从节点只能等配置备份/导入路径推进，品牌变更静默滞留主节点。
func TestGetBranding_mirrorsFileChangeForClusterSnapshot(t *testing.T) {
	handler := newBackupTestHandlers(t)
	dir := t.TempDir()
	handler.cfg.DataDir = dir
	content := `{"app_name":"镜像正向","landing_text":"镜像正向文案"}`
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	resetBrandingStore()
	resetBrandingSyncGateForTest()
	t.Cleanup(func() {
		resetBrandingStore()
		resetBrandingSyncGateForTest()
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/branding", handler.GetBranding)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/branding", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	var mirrored string
	if err := db.DB.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored); err != nil {
		t.Fatalf("read branding_json: %v", err)
	}
	if mirrored != content {
		t.Fatalf("branding_json=%q, want 文件原文 %q（镜像接线缺失/漂移，从节点收不到品牌变更）", mirrored, content)
	}
}
