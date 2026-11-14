package services

// 从端 applySnapshot 尾段此前无条件
// CaddyOpLock{ApplyConfigForce}——主节点排程列/状态列等纯簿记变更（版本行
// next_update/update_status/last_checked 族，不进节哈希，经
// snapshotSecurityVersionRowsDiffer 差分门控重放） bump 快照版本后，从端渲染
// 输入零变化也整轮 /load（Caddy 全量 provision 重放）。修复=渲染数据未变跳过
// /load：三节哈希跳过 + WAF 数据文件无变化 + 证书轴无变化 + 无重载失败补偿
// 标记（标记在=上轮重载失败，本轮必须强制重载，304 补偿通道的语义终点；
// 标记由事务内「记录同步状态」清空，须在事务前捕获）。last_good 兼容：渲染
// 未变则既有 last_good 仍是当前运行配置的准确快照。

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// seedConditionalReloadRows 播种条件重载用例的基线行。种子不含 security 表行——
// 安全节经 JSON 文本列回放存在字节归一差异（applySecurityTables 的
// snapshotJSONText 通道），回放后重建哈希与记账哈希分叉会走漂移重放而非哈希
// 跳过，干扰「无变化」形态。users/rules 节经显式列回放，往返哈希稳定
// （生产漂移守卫依赖的同一不变式）。
func seedConditionalReloadRows(t *testing.T, database *sql.DB) {
	t.Helper()
	for _, stmt := range []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_dg','dg','http','dg.example',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_dg','127.0.0.1',8080,1,1)`,
		`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_dg',0,'prefix','/api')`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
		`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,last_used) VALUES ('k','kh','kp',1,1,datetime('now'))`,
		`INSERT INTO security_crs_version (id,version) VALUES (1,'v4.0.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
		`INSERT INTO security_ip2region_version (id,version) VALUES (1,'v3.17.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
}

func TestSyncService_applySnapshot_skipsReloadWhenOnlyBookkeepingChanges(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	var mu sync.Mutex
	loads := 0
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			mu.Lock()
			loads++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	seedConditionalReloadRows(t, database)
	loadCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return loads
	}
	// 基准快照取本地规范构建（与 applySnapshot 的 previous 同源）——载荷即
	// 从端重建口径，二次应用时节判定走「哈希一致」而非漂移重放。
	base, err := service.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build canonical snapshot: %v", err)
	}
	withVersion := func(v int) models.ClusterSnapshot {
		snap := base
		snap.Version = v
		return snap
	}

	// Given 首轮应用（v7：节哈希记账为空，全节首次应用）——必须 /load。
	if err := syncService.applySnapshot(context.Background(), withVersion(7)); err != nil {
		t.Fatalf("apply v7: %v", err)
	}
	if got := loadCount(); got != 1 {
		t.Fatalf("首轮应用后 /load 次数=%d, want 1（全节首次应用必须重载）", got)
	}

	// When v8 节载荷逐字节相同、仅版本/簿记推进（版本行排程列变化为载体）。
	v8 := withVersion(8)
	v8.SecurityCRSVersion = append([]models.ClusterSecurityCRSVersion{}, base.SecurityCRSVersion...)
	if len(v8.SecurityCRSVersion) > 0 {
		v8.SecurityCRSVersion[0].NextUpdate = "2026-10-06 04:00:00"
		v8.SecurityCRSVersion[0].LastChecked = "2026-10-05 04:00:00"
	}
	if err := syncService.applySnapshot(context.Background(), v8); err != nil {
		t.Fatalf("apply v8: %v", err)
	}
	// Then 不发生 /load（渲染输入零变化）。
	if got := loadCount(); got != 1 {
		t.Fatalf("仅簿记变化的快照应用后 /load 次数=%d, want 1（渲染输入无变化应跳过重载）", got)
	}

	// When v9 载荷不变但重载失败补偿标记在（上轮 apply 后 /load 失败的 304 补偿轮）。
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=? WHERE id=1",
		encodeSyncError("apply_ok_reload_failed: probe", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatalf("seed reload failure marker: %v", err)
	}
	if err := syncService.applySnapshot(context.Background(), withVersion(9)); err != nil {
		t.Fatalf("apply v9: %v", err)
	}
	// Then 补偿标记击穿跳过——必须 /load（304 漂移守卫兼容）。
	if got := loadCount(); got != 2 {
		t.Fatalf("补偿标记在时 /load 次数=%d, want 2（标记在必须强制重载）", got)
	}

	// When v10 渲染输入真实变化（新增规则→rules 节哈希变化）。
	v10 := withVersion(10)
	v10.Rules = append(append([]models.LbRule{}, base.Rules...),
		models.LbRule{CaddyID: "lb_reload_pin", Name: "pin", Protocol: "http", Domain: "pin.example.com", ListenPort: 8081, Enabled: true})
	v10.SectionHashes = ComputeSnapshotSectionHashes(&v10)
	if err := syncService.applySnapshot(context.Background(), v10); err != nil {
		t.Fatalf("apply v10: %v", err)
	}
	// Then 规则变化仍重载（回归钉）。
	if got := loadCount(); got != 3 {
		t.Fatalf("规则变化后 /load 次数=%d, want 3（渲染输入变化必须重载）", got)
	}
}

// reloadFactorFixture 为条件重载因子矩阵搭建「主节点文件树 + 从端文件树 +
// 可计数的 Caddy /load 计数」环境：从端每次 apply 都走真实 WAF 落盘与证书
// 物化路径，因子变化只能来自被测分量。
type reloadFactorFixture struct {
	t        *testing.T
	service  *SyncService
	slaveCRS string
	slaveXdb string
	slaveWaf string
	base     models.ClusterSnapshot
	wafRef   *models.ClusterWafFilesRef
	bundle   WafFileBundle
	server   *httptest.Server
	mu       sync.Mutex
	loads    int
	version  int
}

func newReloadFactorFixture(t *testing.T) *reloadFactorFixture {
	t.Helper()
	fixture := &reloadFactorFixture{t: t}
	clusterService, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}

	// 主节点文件树：CRS 规则树 + VERSION、IP2Region 库、单个威胁源 .fast。
	masterTree := t.TempDir()
	masterCRS := filepath.Join(masterTree, "crs")
	masterXdb := filepath.Join(masterTree, "ip2region.xdb")
	masterWaf := filepath.Join(masterTree, "waf")
	if err := os.MkdirAll(filepath.Join(masterCRS, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(masterWaf, 0755); err != nil {
		t.Fatal(err)
	}
	for path, payload := range map[string]string{
		filepath.Join(masterCRS, "rules", "a.conf"):         "SecRule ARGS 1",
		filepath.Join(masterCRS, "VERSION"):                 "v4.0.0\n",
		masterXdb:                                           "XDB-MASTER-1",
		filepath.Join(masterWaf, "threat-ustc.iplist.fast"): "MASTER-FAST-1",
	} {
		if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
			t.Fatal(err)
		}
	}
	restoreMasterPaths := OverrideWafLivePathsForTest(masterCRS, masterXdb)
	restoreMasterWaf := OverrideThreatWafDirForTest(masterWaf)
	bundle := BuildWafFileBundle()
	ref := BuildWafFileRef()
	restoreMasterWaf()
	restoreMasterPaths()
	if bundle == nil || ref == nil {
		t.Fatal("主节点 WAF bundle/ref 构建失败")
	}
	fixture.bundle, fixture.wafRef = *bundle, ref

	// 从端文件树：空 CRS / 空 xdb / 空威胁目录。
	slaveTree := t.TempDir()
	fixture.slaveCRS = filepath.Join(slaveTree, "crs")
	fixture.slaveXdb = filepath.Join(slaveTree, "ip2region.xdb")
	fixture.slaveWaf = filepath.Join(slaveTree, "waf")
	if err := os.MkdirAll(fixture.slaveCRS, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fixture.slaveWaf, 0755); err != nil {
		t.Fatal(err)
	}
	restoreSlavePaths := OverrideWafLivePathsForTest(fixture.slaveCRS, fixture.slaveXdb)
	restoreSlaveWaf := OverrideThreatWafDirForTest(fixture.slaveWaf)
	restoreCertDir := SetCertDirForTest(filepath.Join(slaveTree, "certs"))
	t.Cleanup(func() {
		restoreCertDir()
		restoreSlaveWaf()
		restoreSlavePaths()
	})

	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/sync/waf-files" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": fixture.bundle})
	}))
	t.Cleanup(fixture.server.Close)
	if _, err := database.Exec("UPDATE global_config SET master_url=?, cluster_token=? WHERE id=1", fixture.server.URL, "probe-token"); err != nil {
		t.Fatalf("seed master endpoint: %v", err)
	}

	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			fixture.mu.Lock()
			fixture.loads++
			fixture.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(caddyServer.Close)
	fixture.service = NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	base, err := clusterService.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build canonical snapshot: %v", err)
	}
	base.WafFiles = ref
	fixture.base = base
	return fixture
}

func (fixture *reloadFactorFixture) loadCount() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.loads
}

// apply 以递增版本重放快照；mutate 用于只改动被测分量。
func (fixture *reloadFactorFixture) apply(mutate func(*models.ClusterSnapshot)) {
	fixture.t.Helper()
	fixture.version++
	snapshot := fixture.base
	snapshot.Version = fixture.version
	snapshot.WafFiles = fixture.wafRef
	if mutate != nil {
		mutate(&snapshot)
	}
	if err := fixture.service.applySnapshot(context.Background(), snapshot); err != nil {
		fixture.t.Fatalf("apply v%d: %v", fixture.version, err)
	}
}

// 条件重载的每个 OR 因子都必须有「仅该因子变化 → /load+1」的独立用例：
// 此前只覆盖 renderInputsChanged 与 reloadCompensation，删除证书轴与
// CRS/xdb/威胁库四条文件态因子后其余 apply 用例全绿——回归会让证书轮换或
// 安全数据更新后 Caddy 继续使用旧文件。
func TestSyncService_applySnapshot_reloadsOnEachConditionalFactor(t *testing.T) {
	fixture := newReloadFactorFixture(t)

	// 首轮全节首次应用必须重载。
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 1 {
		t.Fatalf("首轮 apply 后 /load=%d, want 1", got)
	}
	// 全因子无变化：不重载。
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 1 {
		t.Fatalf("全因子无变化的 apply 后 /load=%d, want 1", got)
	}

	// 因子：CRS 数据文件变化（JSON 节载荷不变）。
	if err := os.WriteFile(filepath.Join(fixture.slaveCRS, "rules", "a.conf"), []byte("TAMPERED"), 0644); err != nil {
		t.Fatal(err)
	}
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 2 {
		t.Fatalf("CRS 文件变化后 /load=%d, want 2（crsChanged 是条件重载因子）", got)
	}

	// 因子：IP2Region 数据文件变化。
	if err := os.WriteFile(fixture.slaveXdb, []byte("XDB-TAMPERED"), 0644); err != nil {
		t.Fatal(err)
	}
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 3 {
		t.Fatalf("IP2Region 文件变化后 /load=%d, want 3（xdbChanged 是条件重载因子）", got)
	}

	// 因子：威胁库名单文件变化。
	if err := os.WriteFile(filepath.Join(fixture.slaveWaf, "threat-ustc.iplist.fast"), []byte("TAMPERED-FAST"), 0644); err != nil {
		t.Fatal(err)
	}
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 4 {
		t.Fatalf("威胁库文件变化后 /load=%d, want 4（threatChanged 是条件重载因子）", got)
	}
}

// 证书轴单独一条用例：证书文件路径确定性意味着内容轮换时渲染 JSON 字节不变，
// certsChanged 是唯一信号（删除该因子后其余 apply 用例全绿，证书过期不会重载）。
func TestSyncService_applySnapshot_reloadsOnCertAxisChanges(t *testing.T) {
	fixture := newReloadFactorFixture(t)
	certPEM := func(marker string) models.ClusterCertificate {
		return models.ClusterCertificate{
			RuleID:  "lb_factor_cert",
			Domain:  "factor.example.com",
			CertPEM: "-----BEGIN CERTIFICATE-----\n" + marker + "\n-----END CERTIFICATE-----\n",
			KeyPEM:  "KEY-A-" + marker + "\n",
		}
	}
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 1 {
		t.Fatalf("首轮 apply 后 /load=%d, want 1", got)
	}
	// 新增证书（生效面从无到有）。
	fixture.apply(func(snapshot *models.ClusterSnapshot) {
		snapshot.Certs = []models.ClusterCertificate{certPEM("CERT-A")}
	})
	if got := fixture.loadCount(); got != 2 {
		t.Fatalf("证书新增后 /load=%d, want 2（证书轴是条件重载因子）", got)
	}
	// 证书内容轮换（路径不变、JSON 不变）。
	fixture.apply(func(snapshot *models.ClusterSnapshot) {
		snapshot.Certs = []models.ClusterCertificate{certPEM("CERT-B")}
	})
	if got := fixture.loadCount(); got != 3 {
		t.Fatalf("证书内容变更后 /load=%d, want 3（内容轮换必须强制重载）", got)
	}
}

// 品牌文件是派生状态（branding.json 不是节哈希的输入，只有镜像列
// branding_json 属 users 节）：304 补偿重拉轮三节哈希可能全一致，若「本轮
// 实际写出品牌文件」不并入重载判据，默认站点内嵌的落地文案会滞留旧值——
// 快照事务已清空 last_sync_error，品牌节又不在漂移口径内，没有第二次自愈。
// 本用例钉住补偿轮写出即重载且 /load 载荷携带新落地文案；文件已一致时
// 仍按「渲染输入无变化」跳过重载（反向回归）。
func TestSyncService_applySnapshot_reloadsWhenBrandingFileRewrittenInCompensationRound(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	defer SetDefaultLandingBody(DefaultLandingText)
	const landing = "补偿轮新落地文案"
	branding := `{"app_name":"gw","landing_text":"` + landing + `"}`
	if _, err := database.Exec("UPDATE global_config SET branding_json=? WHERE id=1", branding); err != nil {
		t.Fatalf("seed branding mirror: %v", err)
	}
	// 种子与前一条用例同口径（seedConditionalReloadRows）。
	seedConditionalReloadRows(t, database)
	dataDir := t.TempDir()
	var mu sync.Mutex
	loads := 0
	var lastBody string
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			loads++
			lastBody = string(raw)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	loadCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return loads
	}
	loadPayload := func() string {
		mu.Lock()
		defer mu.Unlock()
		return lastBody
	}
	base, err := service.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build canonical snapshot: %v", err)
	}
	if base.BasicSettings.BrandingJSON == nil || *base.BasicSettings.BrandingJSON != branding {
		t.Fatalf("canonical snapshot branding=%v, want mirror value", base.BasicSettings.BrandingJSON)
	}
	withVersion := func(v int) models.ClusterSnapshot {
		snap := base
		snap.Version = v
		return snap
	}
	brandingPath := filepath.Join(dataDir, "branding.json")
	assertBrandingFile := func() {
		t.Helper()
		raw, readErr := os.ReadFile(brandingPath)
		if readErr != nil {
			t.Fatalf("read branding file: %v", readErr)
		}
		if string(raw) != branding {
			t.Fatalf("branding file=%q, want mirror content %q", raw, branding)
		}
	}
	seedBrandingFailureMarker := func() {
		t.Helper()
		if _, execErr := database.Exec("UPDATE global_config SET last_sync_error=? WHERE id=1",
			encodeSyncError(syncBrandingFailureMarkerPrefix+": 品牌配置落盘失败（数据库已应用，文件未收敛，下轮同步重试）", models.SyncErrorCodeApplyFailed)); execErr != nil {
			t.Fatalf("seed branding failure marker: %v", execErr)
		}
	}

	// Given 首轮应用：全节首次应用 → 品牌文件落盘 + /load（基准）。
	if err := syncService.applySnapshot(context.Background(), withVersion(7)); err != nil {
		t.Fatalf("apply v7: %v", err)
	}
	if got := loadCount(); got != 1 {
		t.Fatalf("首轮应用后 /load=%d, want 1", got)
	}
	assertBrandingFile()
	if payload := loadPayload(); !strings.Contains(payload, landing) {
		t.Fatalf("/load 载荷未携带新落地文案")
	}

	// When 模拟上轮品牌落盘失败：文件停在旧内容，标记留在 last_sync_error，
	// 本轮 304 补偿重拉（版本推进但三节载荷逐字节相同）。
	if err := os.WriteFile(brandingPath, []byte(`{"app_name":"old","landing_text":"旧文案"}`), 0o644); err != nil {
		t.Fatalf("simulate stale branding file: %v", err)
	}
	seedBrandingFailureMarker()
	if err := syncService.applySnapshot(context.Background(), withVersion(8)); err != nil {
		t.Fatalf("apply v8 (compensation): %v", err)
	}
	// Then 品牌文件收敛且必须重载——默认站点落地文案随之更新。
	assertBrandingFile()
	if got := loadCount(); got != 2 {
		t.Fatalf("补偿轮 /load=%d, want 2（本轮写出品牌文件必须重载）", got)
	}
	if payload := loadPayload(); !strings.Contains(payload, landing) {
		t.Fatalf("补偿轮 /load 载荷未携带新落地文案")
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read last_sync_error: %v", err)
	}
	if stored != "" {
		t.Fatalf("last_sync_error=%q, want cleared after branding write succeeded", stored)
	}

	// When 下一轮三节仍全跳过、品牌文件已一致（无需写出）。
	seedBrandingFailureMarker()
	if err := syncService.applySnapshot(context.Background(), withVersion(9)); err != nil {
		t.Fatalf("apply v9: %v", err)
	}
	// Then 反向回归：只读一致文件不算渲染输入变化，仍跳过重载
	// （重试标记本身不属于「文件已变」，补偿轮的唯一语义是重试落盘）。
	assertBrandingFile()
	if got := loadCount(); got != 2 {
		t.Fatalf("品牌文件已一致时 /load=%d, want 2（不得为无变化重试重载）", got)
	}
}
