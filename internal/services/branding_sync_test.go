package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// 三分类合并:全局配置并入系统数据(恒同步)——BrandingJSON 恒随快照携带,
// 不再受开关裁剪。
func TestBuildSnapshot_alwaysCarriesBranding(t *testing.T) {
	svc, database := newClusterTestService(t)
	database.Exec(`UPDATE global_config SET branding_json='{"app_name":"Y"}' WHERE id=1`)

	snap, err := svc.SnapshotForTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.BasicSettings.BrandingJSON != `{"app_name":"Y"}` {
		t.Errorf("BrandingJSON=%q, want mirror content always carried", snap.BasicSettings.BrandingJSON)
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

// CL41-2(第 41 轮):三分类合并后 users 节恒同步+schema v3 强制,BrandingJSON
// 空串可判定为「主端无品牌文件」(旧语义「开关关闭/旧主节点」随三分类消失)。
// 从端必须收敛默认品牌:本地文件重置为全空模板(与 handlers.EnsureBrandingFile
// 缺失再生形态一致——其唯一调用点在启动期 main.go,运行期由同步代行);不直接
// 删除——loadBrandingConfig 对缺失文件保内存上一份旧值(2026-09-11 半截写窗口
// 裁定),删除会让从端 /branding 长期陈旧。landing 同步重置默认。
func TestApplySnapshotBranding_emptyContentResetsToDefaultTemplate(t *testing.T) {
	dataDir := t.TempDir()
	defer SetDefaultLandingBody(DefaultLandingText)
	path := filepath.Join(dataDir, "branding.json")
	custom := `{"app_name":"我的网关","landing_text":"欢迎使用"}`
	if err := os.WriteFile(path, []byte(custom), 0644); err != nil {
		t.Fatal(err)
	}
	injectLandingFromBranding(custom) // 模拟此前同步已注入的自定义 landing

	applySnapshotBranding(dataDir, "")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reset must leave a template file: %v", err)
	}
	var fields map[string]string
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("reset file must stay valid JSON: %v", err)
	}
	for _, k := range []string{"app_name", "footer_text", "landing_text", "version"} {
		v, ok := fields[k]
		if !ok {
			t.Fatalf("template missing field %s (EnsureBrandingFile 同形态)", k)
		}
		if v != "" {
			t.Fatalf("template field %s=%q, want empty (default branding)", k, v)
		}
	}
	if got := DefaultLandingBody(); got != DefaultLandingText {
		t.Errorf("landing=%q, want reset to default", got)
	}

	// 幂等:已是模板再次应用零重写(mtime 不动)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	applySnapshotBranding(dataDir, "")
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st2.ModTime().Equal(st.ModTime()) {
		t.Error("template reset must be idempotent (mtime churned)")
	}

	// dataDir 守卫保留:空目录不动作不 panic
	applySnapshotBranding("", "")
}

// 三分类合并勘误(2026-09-19 生产实证):users 节哈希并入 basic_settings
// 后,branding_json 镜像列必须随 apply 落库——RefreshBrandingMirror 带
// is_master=1 守卫(仅主端快照构建路径),从端只写文件不写列,导致从端
// 本地重建 users 哈希与主端永久分歧(hover 恒 LAG+每次变更多一轮重放)。
// 修复:updateSnapshotSettings SET 清单补 branding_json(事务内,原子)。
func TestUpdateSnapshotSettings_mirrorsBrandingColumn(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	apply := func(snapshot models.ClusterSnapshot) {
		t.Helper()
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
			t.Fatalf("apply settings: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	apply(models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		BrandingJSON: `{"app_name":"我的网关"}`, JWTExpireMinutes: 20,
	}})
	var mirrored string
	if err := database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored); err != nil || mirrored != `{"app_name":"我的网关"}` {
		t.Fatalf("branding mirror=%q err=%v, want snapshot content", mirrored, err)
	}
	// 主端镜像清空(文件缺失形态)同样传播——空串是合法收敛值。
	apply(models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		BrandingJSON: "", JWTExpireMinutes: 20,
	}})
	if err := database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored); err != nil || mirrored != "" {
		t.Fatalf("cleared mirror=%q err=%v, want empty", mirrored, err)
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

// CL12-P1-1(第 12 轮审计):无白名单 Key 快照同步——主端 ” → 从端必须落 ”
// 而非 json.Marshal(nil) 的字面量 "null"(中间件把非空当白名单配置,
// Unmarshal null 成功但 0 CIDR → 全来源 403)。
func TestApplySnapshot_emptyWhitelistLandsEmptyString(t *testing.T) {
	_, database := newClusterTestService(t)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := models.ClusterSnapshot{
		Version: 4,
		APIKeys: []models.ClusterAPIKey{{ID: 1, Name: "k", KeyHash: "h", KeyPrefix: "p", CreatedBy: 1, MCPIPWhitelist: nil}},
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var stored string
	database.QueryRow(`SELECT COALESCE(mcp_ip_whitelist,'') FROM api_keys WHERE id=1`).Scan(&stored)
	if stored != "" {
		t.Fatalf("empty whitelist stored=%q, want empty string (not \"null\")", stored)
	}
}
