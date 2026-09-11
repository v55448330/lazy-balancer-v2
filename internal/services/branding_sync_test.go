package services

import (
	"context"
	"time"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// RefreshBrandingMirror(2026-09-11 裁定):branding.json 原文镜像到
// global_config.branding_json——内容变化才写(触发器 bump cluster_version,
// 快照自然流出),内容不变零写入零版本扰动。
func TestRefreshBrandingMirror_bumpsVersionOnFileChange(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()

	// 文件缺失→镜像空,建库态
	if changed, err := RefreshBrandingMirror(dir); err != nil || changed {
		t.Fatalf("mirror on missing file: changed=%v err=%v", changed, err)
	}

	// 写自定义内容 → 镜像 + 版本 bump
	os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"X","landing_text":"欢迎"}`), 0644)
	changed, err := RefreshBrandingMirror(dir)
	if err != nil || !changed {
		t.Fatalf("mirror on change: changed=%v err=%v", changed, err)
	}
	var mirrored string
	database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored)
	if mirrored != `{"app_name":"X","landing_text":"欢迎"}` {
		t.Errorf("mirror content=%q", mirrored)
	}
	// 注:cluster_version bump 由中间件触发器负责(branding_json 已入 OF 列表,
	// cluster_version_test.go 验证);services 层测试库无中间件触发器,此处断言
	// 镜像列已更新(变化传递的输入条件)。

	// 内容不变 → 零写入(幂等)
	if changed, err := RefreshBrandingMirror(dir); err != nil || changed {
		t.Errorf("mirror on unchanged: changed=%v err=%v (must be idempotent)", changed, err)
	}
}

// 快照携带:sync_global_config 开→BasicSettings.BrandingJSON 有值;关→裁剪为空。
func TestBuildSnapshot_carriesBrandingUnderGlobalSwitch(t *testing.T) {
	svc, database := newClusterTestService(t)
	database.Exec(`UPDATE global_config SET branding_json='{"app_name":"Y"}' WHERE id=1`)

	snap, err := svc.SnapshotForTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.BasicSettings.BrandingJSON != `{"app_name":"Y"}` {
		t.Errorf("switch on: BrandingJSON=%q, want mirror content", snap.BasicSettings.BrandingJSON)
	}

	database.Exec(`UPDATE global_config SET sync_global_config=0 WHERE id=1`)
	clusterSnapshotCaches.Delete(database)
	snap2, err := svc.SnapshotForTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap2.BasicSettings.BrandingJSON != "" {
		t.Errorf("switch off: BrandingJSON=%q, must be stripped (branding 不同步)", snap2.BasicSettings.BrandingJSON)
	}
}

// 从节点应用:快照 branding 写本地文件 + landing 注入;幂等零重写。
func TestApplySnapshot_writesBrandingFileAndLanding(t *testing.T) {
	_, database := newClusterTestService(t)
	dataDir := t.TempDir()
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	defer SetDefaultLandingBody(DefaultLandingText)
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL, DataDir: dataDir}, NewCaddyService(caddyServer.URL))

	snapshot := models.ClusterSnapshot{
		Version: 5,
		BasicSettings: models.ClusterBasicSettings{
			BrandingJSON: `{"app_name":"我的网关","landing_text":"欢迎使用我的网关"}`,
		},
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dataDir, "branding.json"))
	if err != nil {
		t.Fatalf("branding file not written: %v", err)
	}
	if string(content) != `{"app_name":"我的网关","landing_text":"欢迎使用我的网关"}` {
		t.Errorf("local file=%q", content)
	}
	if got := DefaultLandingBody(); got != "欢迎使用我的网关" {
		t.Errorf("landing body=%q, want injected custom text", got)
	}

	// 幂等:同内容二次应用零重写(mtime 不动)
	st, _ := os.Stat(filepath.Join(dataDir, "branding.json"))
	snapshot2 := snapshot
	snapshot2.Version = 6
	snapshot2.SectionHashes = ComputeSnapshotSectionHashes(&snapshot2)
	if err := syncService.applySnapshot(context.Background(), snapshot2); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	st2, _ := os.Stat(filepath.Join(dataDir, "branding.json"))
	if !st2.ModTime().Equal(st.ModTime()) {
		t.Error("unchanged branding must not rewrite file (mtime churned)")
	}
}

// SR-1(第 7 轮审计):Go json.Marshal 对 <>& 产 \uXXXX 转义——手工提取器
// 不解 \u 时从节点 landing 注入乱码,与主节点 encoding/json 分叉。
// 修复:提取值经 json.Unmarshal 值级解析。
func TestInjectLandingFromBranding_unicodeEscape(t *testing.T) {
	defer SetDefaultLandingBody(DefaultLandingText)
	injectLandingFromBranding(`{"app_name":"网关","landing_text":"欢迎\u003c使用\u003e"}`)
	if got := DefaultLandingBody(); got != "欢迎<使用>" {
		t.Errorf("landing=%q, want 欢迎<使用> (\\uXXXX must decode)", got)
	}
	// 畸形值(非字符串/截断)回退默认
	injectLandingFromBranding(`{"landing_text":123}`)
	if got := DefaultLandingBody(); got != DefaultLandingText {
		t.Errorf("non-string landing=%q, want default", got)
	}
}

// 镜像校验(2026-09-11):半截写(非法 JSON)不得镜像——坏内容永不流向从节点。
func TestRefreshBrandingMirror_skipsInvalidJSON(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"好"}`), 0644)
	if changed, err := RefreshBrandingMirror(dir); err != nil || !changed {
		t.Fatalf("initial mirror: changed=%v err=%v", changed, err)
	}
	// 半截写(内容变化但非法)
	st, _ := os.Stat(filepath.Join(dir, "branding.json"))
	os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"坏`), 0644)
	for i := 0; i < 20; i++ {
		st2, _ := os.Stat(filepath.Join(dir, "branding.json"))
		if st2.ModTime().After(st.ModTime()) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if changed, err := RefreshBrandingMirror(dir); err != nil {
		t.Fatalf("mirror on invalid: %v", err)
	} else if changed {
		t.Error("invalid JSON must not be mirrored")
	}
	var mirrored string
	database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored)
	if mirrored != `{"app_name":"好"}` {
		t.Errorf("mirror polluted by partial write: %q", mirrored)
	}
}
