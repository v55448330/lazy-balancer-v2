package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type brandingRowsAffectedErrorConnector struct{}

func (brandingRowsAffectedErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return brandingRowsAffectedErrorConn{}, nil
}
func (brandingRowsAffectedErrorConnector) Driver() driver.Driver {
	return brandingRowsAffectedErrorDriver{}
}

type brandingRowsAffectedErrorDriver struct{}

func (brandingRowsAffectedErrorDriver) Open(string) (driver.Conn, error) {
	return brandingRowsAffectedErrorConn{}, nil
}

type brandingRowsAffectedErrorConn struct{}

func (brandingRowsAffectedErrorConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (brandingRowsAffectedErrorConn) Close() error { return nil }
func (brandingRowsAffectedErrorConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected Begin")
}
func (brandingRowsAffectedErrorConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return brandingRowsAffectedErrorResult{}, nil
}

type brandingRowsAffectedErrorResult struct{}

func (brandingRowsAffectedErrorResult) LastInsertId() (int64, error) { return 0, nil }
func (brandingRowsAffectedErrorResult) RowsAffected() (int64, error) {
	return 0, errors.New("injected RowsAffected failure")
}

func TestRefreshBrandingMirror_returnsRowsAffectedError(t *testing.T) {
	// Given a successful Exec whose driver cannot determine the affected count.
	newClusterTestService(t)
	realDB := db.DB
	fake := sql.OpenDB(brandingRowsAffectedErrorConnector{})
	db.DB = fake
	t.Cleanup(func() { db.DB = realDB; _ = fake.Close() })

	// When mirroring a missing branding file (empty content is a valid shape).
	changed, err := RefreshBrandingMirror(t.TempDir())

	// Then the unknown write result is an error, never "unchanged, no error".
	if err == nil || changed {
		t.Fatalf("RefreshBrandingMirror changed=%v err=%v, want false plus RowsAffected error", changed, err)
	}
}

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

	snap, err := svc.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.BasicSettings.BrandingJSON == nil || *snap.BasicSettings.BrandingJSON != `{"app_name":"Y"}` {
		t.Errorf("BrandingJSON=%v, want mirror content always carried", snap.BasicSettings.BrandingJSON)
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
			BrandingJSON: new(`{"app_name":"我的网关","landing_text":"欢迎使用我的网关"}`),
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

// 原子 rename 替换不得在原 inode 上截断写入。硬链接作为旧 inode
// 观测点：新路径读到新内容时，旧链接必须仍保留旧字节。
func TestMaterializeBranding_atomicReplaceDoesNotMutateExistingInode(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")
	oldContent := `{"app_name":"old","landing_text":"old"}`
	if err := os.WriteFile(path, []byte(oldContent), 0644); err != nil {
		t.Fatal(err)
	}
	oldLink := filepath.Join(dataDir, "branding-old-inode.json")
	if err := os.Link(path, oldLink); err != nil {
		t.Fatal(err)
	}
	newContent := `{"app_name":"new","landing_text":"new"}`
	if _, err := MaterializeBranding(dataDir, newContent); err != nil {
		t.Fatal(err)
	}
	gotOld, err := os.ReadFile(oldLink)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotOld) != oldContent {
		t.Fatalf("existing inode was truncated in place: %q", gotOld)
	}
	gotNew, err := os.ReadFile(path)
	if err != nil || string(gotNew) != newContent {
		t.Fatalf("new branding content=%q err=%v", gotNew, err)
	}
	// 临时文件名由原子落盘单源生成（.<base>-*.tmp），断言口径随之通用化。
	matches, err := filepath.Glob(filepath.Join(dataDir, "*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("atomic temp files remain: %v err=%v", matches, err)
	}
}

// 旧主端未携带 branding_json 时是缺席而非显式空串；
// 本地文件与 landing 必须保留，只有非 nil 空串才执行默认模板重置。
func TestApplySnapshot_absentLegacyBrandingPreservesLocalFile(t *testing.T) {
	_, database := newClusterTestService(t)
	dataDir := t.TempDir()
	custom := `{"app_name":"local","landing_text":"local-landing"}`
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(custom), 0644); err != nil {
		t.Fatal(err)
	}
	defer SetDefaultLandingBody(DefaultLandingText)
	injectLandingFromBranding(custom)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL, DataDir: dataDir}, NewCaddyService(caddyServer.URL))
	snapshot := models.ClusterSnapshot{Version: 5}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dataDir, "branding.json"))
	if err != nil || string(content) != custom {
		t.Fatalf("legacy absent branding replaced local file=%q err=%v", content, err)
	}
	if got := DefaultLandingBody(); got != "local-landing" {
		t.Fatalf("legacy absent branding reset landing=%q", got)
	}
}

// 三分类合并后 users 节恒同步+schema v3 强制,BrandingJSON
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

	if _, err := applySnapshotBranding(dataDir, ""); err != nil {
		t.Fatalf("reset branding: %v", err)
	}

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
	if _, err := applySnapshotBranding(dataDir, ""); err != nil {
		t.Fatalf("idempotent reset branding: %v", err)
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st2.ModTime().Equal(st.ModTime()) {
		t.Error("template reset must be idempotent (mtime churned)")
	}

	// dataDir 守卫保留:空目录不动作不 panic
	if written, err := applySnapshotBranding("", ""); err != nil || written {
		t.Fatalf("empty dataDir must be a no-op, written=%v err=%v", written, err)
	}
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
		BrandingJSON: new(`{"app_name":"我的网关"}`), JWTExpireMinutes: new(20),
	}})
	var mirrored string
	if err := database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored); err != nil || mirrored != `{"app_name":"我的网关"}` {
		t.Fatalf("branding mirror=%q err=%v, want snapshot content", mirrored, err)
	}
	// 主端镜像清空(文件缺失形态)同样传播——空串是合法收敛值。
	apply(models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		BrandingJSON: new(""), JWTExpireMinutes: new(20),
	}})
	if err := database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1`).Scan(&mirrored); err != nil || mirrored != "" {
		t.Fatalf("cleared mirror=%q err=%v, want empty", mirrored, err)
	}
}

// Go json.Marshal 对 <>& 产 \uXXXX 转义——手工提取器
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

// 无白名单 Key 快照同步——主端 ” → 从端必须落 ”
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
		APIKeys: []models.ClusterAPIKey{{ID: 1, Name: "k", KeyHash: "h", KeyPrefix: "p", CreatedBy: 1, MCPIPWhitelist: []string{"10.0.0.0/8"}}},
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply non-empty whitelist: %v", err)
	}
	var stored string
	if err := database.QueryRow(`SELECT COALESCE(mcp_ip_whitelist,'') FROM api_keys WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read non-empty whitelist: %v", err)
	}
	if !strings.Contains(stored, "10.0.0.0/8") {
		t.Fatalf("前置非零哨兵未落库: %q", stored)
	}

	// 从非空名单收敛为空，避免 Scan 失败后的零值与目标值相同而假绿。
	snapshot.APIKeys[0].MCPIPWhitelist = nil
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply empty whitelist: %v", err)
	}
	if err := database.QueryRow(`SELECT COALESCE(mcp_ip_whitelist,'') FROM api_keys WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read empty whitelist: %v", err)
	}
	if stored != "" {
		t.Fatalf("empty whitelist stored=%q, want empty string (not \"null\")", stored)
	}
}

// 家族收敛：品牌落盘失败的审计同样按内容节流。
func TestApplySnapshotBrandingChecked_throttlesRepeatedFailureAudit(t *testing.T) {
	_, database := newClusterTestService(t)
	sync := NewSyncService(database, nil, nil)
	t.Cleanup(func() { unregisterSyncDrainer(sync) })
	// 确定性失败：非对象 JSON 会被 MaterializeBranding 拒绝（错误串固定，
	// 不含临时文件随机名——节流键=动作+类别+错误内容）。
	cfg := &config.Config{DataDir: t.TempDir()}
	for range 2 {
		if _, err := sync.applySnapshotBrandingChecked(cfg, `[1,2]`); err == nil {
			t.Fatal("non-object branding JSON must be rejected")
		}
	}
	if got := countAuditRows(t, db.AuditDB, "同步失败", "集群同步"); got != 1 {
		t.Fatalf("repeated branding failures wrote %d audit rows, want 1 (throttle)", got)
	}
}

// brandingMirrorProbe 是 零写断言的观测驱动：记录 UPDATE 执行次数，
// 并让镜像列预读返回指定内容（与文件内容一致时应完全不执行写语句）。
type brandingMirrorProbe struct {
	execCount atomic.Int32
	content   string
}

func (probe *brandingMirrorProbe) Connect(context.Context) (driver.Conn, error) {
	return brandingMirrorProbeConn{probe: probe}, nil
}
func (probe *brandingMirrorProbe) Driver() driver.Driver {
	return brandingMirrorProbeDriver{probe: probe}
}

type brandingMirrorProbeDriver struct{ probe *brandingMirrorProbe }

func (d brandingMirrorProbeDriver) Open(string) (driver.Conn, error) {
	return brandingMirrorProbeConn{probe: d.probe}, nil
}

type brandingMirrorProbeConn struct{ probe *brandingMirrorProbe }

func (brandingMirrorProbeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (brandingMirrorProbeConn) Close() error              { return nil }
func (brandingMirrorProbeConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected Begin") }
func (conn brandingMirrorProbeConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	conn.probe.execCount.Add(1)
	return driver.RowsAffected(1), nil
}
func (conn brandingMirrorProbeConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &brandingMirrorProbeRows{content: conn.probe.content}, nil
}

type brandingMirrorProbeRows struct {
	content string
	done    bool
}

func (*brandingMirrorProbeRows) Columns() []string { return []string{"branding_json"} }
func (*brandingMirrorProbeRows) Close() error      { return nil }
func (rows *brandingMirrorProbeRows) Next(dest []driver.Value) error {
	if rows.done {
		return io.EOF
	}
	rows.done = true
	dest[0] = rows.content
	return nil
}

// 内容未变时零写（先读短路），且显式库句柄决定落点。
func TestRefreshBrandingMirrorDB_zeroWriteWhenUnchanged(t *testing.T) {
	newClusterTestService(t)
	dir := t.TempDir()
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	content := `{"app_name":"A"}`
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := RefreshBrandingMirror(dir); err != nil || !changed {
		t.Fatalf("first mirror changed=%v err=%v", changed, err)
	}
	if changed, err := RefreshBrandingMirror(dir); err != nil || changed {
		t.Fatalf("unchanged mirror changed=%v err=%v", changed, err)
	}

	// 观测驱动：镜像列与文件内容一致 → 不得执行任何 UPDATE。
	same := &brandingMirrorProbe{content: content}
	sameDB := sql.OpenDB(same)
	t.Cleanup(func() { _ = sameDB.Close() })
	if changed, err := RefreshBrandingMirrorDB(sameDB, dir); err != nil || changed {
		t.Fatalf("unchanged mirror on probe handle changed=%v err=%v", changed, err)
	}
	if got := same.execCount.Load(); got != 0 {
		t.Fatalf("unchanged mirror executed %d UPDATE statement(s), want 0 (read short-circuit)", got)
	}

	// 镜像列不同 → 必须执行一次 UPDATE，且落点是指定句柄而非全局 db.DB。
	stale := &brandingMirrorProbe{content: `{"app_name":"old"}`}
	staleDB := sql.OpenDB(stale)
	t.Cleanup(func() { _ = staleDB.Close() })
	if changed, err := RefreshBrandingMirrorDB(staleDB, dir); err != nil || !changed {
		t.Fatalf("stale mirror on probe handle changed=%v err=%v", changed, err)
	}
	if got := stale.execCount.Load(); got != 1 {
		t.Fatalf("stale mirror executed %d UPDATE statement(s), want 1", got)
	}
	var globalMirrored string
	if err := db.DB.QueryRow("SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1").Scan(&globalMirrored); err != nil {
		t.Fatal(err)
	}
	if globalMirrored != content {
		t.Fatalf("explicit handle mirror leaked into global DB: %q", globalMirrored)
	}
}

// MaterializeBranding 必须回报是否实际写入——调用方据此区分「写了」与
// 「没写」，内容一致时零 mtime 扰动且 changed=false。
func TestMaterializeBranding_reportsChanged(t *testing.T) {
	dir := t.TempDir()
	content := `{"app_name":"gw"}`
	changed, err := MaterializeBranding(dir, content)
	if err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	if !changed {
		t.Fatal("首次物化必须报告 changed=true")
	}
	changed, err = MaterializeBranding(dir, content)
	if err != nil {
		t.Fatalf("second materialize: %v", err)
	}
	if changed {
		t.Fatal("内容一致必须报告 changed=false（零重写）")
	}
}

// 品牌同步审计只针对真实变更：users/basic_settings 节任意变更（branding_json
// 未变）不得在从端产生「品牌配置已同步生效」的误导审计。
func TestApplySnapshotBranding_auditsOnlyWhenContentChanges(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// db.Close() 会把原子句柄 SetDB(nil)——只还原三个包级变量会让
		// db.GetDB() 与 db.DB 分叉，后续用例（尤其 -shuffle 顺序）读到
		// 已关闭/临时目录已删的库。恢复协议必须成对执行并自证。
		db.SetDB(oldDB)
		if got := db.GetDB(); got != oldDB {
			t.Errorf("清理后 db.GetDB()=%p, want 原句柄 %p（原子句柄未随包级变量一同恢复）", got, oldDB)
		}
	})
	defer SetDefaultLandingBody(DefaultLandingText)

	dir := t.TempDir()
	content := `{"app_name":"gw"}`
	countAudits := func() int {
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='同步' AND detail LIKE '%品牌配置已同步生效%'`).Scan(&n); err != nil {
			t.Fatalf("query audit: %v", err)
		}
		return n
	}
	if _, err := applySnapshotBranding(dir, content); err != nil {
		t.Fatalf("apply content: %v", err)
	}
	if got := countAudits(); got != 1 {
		t.Fatalf("首次同步审计条数=%d, want 1", got)
	}
	if _, err := applySnapshotBranding(dir, content); err != nil {
		t.Fatalf("re-apply unchanged content: %v", err)
	}
	if got := countAudits(); got != 1 {
		t.Fatalf("内容未变时审计条数=%d, want 1（不得重复写品牌同步审计）", got)
	}
}
