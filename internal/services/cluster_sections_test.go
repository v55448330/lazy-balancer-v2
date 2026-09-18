package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func seedAppliedSection(t *testing.T, dbh *sql.DB, section, hash string) {
	t.Helper()
	dbh.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at) VALUES (?,?,1,datetime('now'))
		ON CONFLICT(section) DO UPDATE SET hash=excluded.hash`, section, hash)
}

// overrideWafPathsForServicesTest 重定向 CRS/xdb 活动路径到临时目录并预建
// rules 子目录(services 层测试自用,handlers 层同款见其测试包)。
func overrideWafPathsForServicesTest(t *testing.T) (crsDir, xdbPath string) {
	t.Helper()
	crsDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	xdbPath = filepath.Join(t.TempDir(), "ip2region.xdb")
	t.Cleanup(OverrideWafLivePathsForTest(crsDir, xdbPath))
	return crsDir, xdbPath
}

func TestComputeSectionSkips_switchOffAndHashMatch(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.ExecContext(ctx, "UPDATE global_config SET sync_rules=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{Version: 5}
	snapshot.SectionHashes = map[string]string{
		"users": "u1", "rules": "r1", "security": "s1",
	}
	seedAppliedSection(t, database, "users", "u1")
	seedAppliedSection(t, database, "rules", "r1")

	switches, err := readSyncSwitches(database)
	if err != nil {
		t.Fatal(err)
	}
	sk := computeSectionSkips(database, snapshot, switches, nil)

	if !sk.disabled["rules"] {
		t.Fatal("rules switch off must mark section disabled")
	}
	if !sk.unchanged["users"] {
		t.Fatal("matching hash must mark section unchanged")
	}
	if !sk.skip("rules") || !sk.skip("users") {
		t.Fatal("rules(disabled)/users(unchanged) must be skipped")
	}
	// 三分类合并(2026-09-19 用户裁定):global_config/waf_files 不再是同步节,
	// skip 判定不得再为它们产生任何记录。
	for _, legacy := range []string{"global_config", "waf_files"} {
		if sk.disabled[legacy] || sk.unchanged[legacy] {
			t.Fatalf("legacy section %s must not be iterated by computeSectionSkips", legacy)
		}
	}
}

func TestComputeSectionSkips_allOnFirstSyncAppliesEverything(t *testing.T) {
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{Version: 1}
	snapshot.SectionHashes = map[string]string{"rules": "r1", "security": "s1"}
	switches, err := readSyncSwitches(database)
	if err != nil {
		t.Fatal(err)
	}
	sk := computeSectionSkips(database, snapshot, switches, nil)
	for _, key := range []string{"users", "rules", "security"} {
		if sk.skip(key) {
			t.Fatalf("first sync with all switches on must apply %s", key)
		}
	}
}

// 三分类合并(2026-09-19 用户裁定):同步节收敛为 users/rules/security 三节
// (全局配置并入系统数据、规则库并入安全防护),标签与备份分类一致;
// ComputeSnapshotSectionHashes 只产出 3 键。
func TestSyncSections_threeCategoryMerge(t *testing.T) {
	if len(syncSections) != 3 {
		t.Fatalf("syncSections=%#v, want exactly 3 sections", syncSections)
	}
	want := map[string]string{"users": "系统数据", "rules": "负载规则", "security": "安全防护"}
	for _, sec := range syncSections {
		if want[sec.Key] == "" || sec.NewLabel != want[sec.Key] {
			t.Fatalf("section %q label=%q, want %q", sec.Key, sec.NewLabel, want[sec.Key])
		}
	}
	hashes := ComputeSnapshotSectionHashes(&models.ClusterSnapshot{})
	if len(hashes) != 3 {
		t.Fatalf("section hashes=%#v, want exactly users/rules/security keys", hashes)
	}
	for _, key := range []string{"users", "rules", "security"} {
		if _, ok := hashes[key]; !ok {
			t.Fatalf("section hashes missing %s: %#v", key, hashes)
		}
	}
}

// 三分类合并:users 节 payload 并入全局配置(basic_settings+caddy_config,
// 字段顺序固定);security 节保持纯表域——WafFiles ref 不入节哈希(入哈希
// 会让文件拉取持续失败时 security 哈希主从域永久乒乓,文件态由
// wafFilesDrifted 专用通道独占)。
func TestSectionPayload_usersCarriesGlobalConfig(t *testing.T) {
	caddy := `{"apps":{}}`
	s := &models.ClusterSnapshot{
		BasicSettings: models.ClusterBasicSettings{LogLevel: "debug"},
		CaddyConfig:   &caddy,
		WafFiles:      &models.ClusterWafFilesRef{CRSVersion: "v4.28.0", CRSSha256: "abc"},
	}
	usersJSON, err := json.Marshal(sectionPayloadFor("users", s))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"users"`, `"api_keys"`, `"basic_settings"`, `"caddy_config"`, `"debug"`} {
		if !strings.Contains(string(usersJSON), want) {
			t.Fatalf("users payload=%s, must contain %s", usersJSON, want)
		}
	}
	securityJSON, err := json.Marshal(sectionPayloadFor("security", s))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(securityJSON), "waf_files") || strings.Contains(string(securityJSON), "v4.28.0") {
		t.Fatalf("security payload=%s, must stay tables-only (file state owns the dedicated waf channel)", securityJSON)
	}
}

// users 节哈希必须随全局设置变化(并入),且漂移守卫本地重建与全量快照
// 构建保持同一口径(哈希奇偶不变式——driftGuardSectionHashes 必须装载
// BasicSettings/CaddyConfig,复用 BuildSnapshot 同一装载函数)。
func TestDriftGuardSectionHashes_usersIncludesGlobalSettings(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()

	before, err := service.clusterSnapshotBypassingCache(ctx)
	if err != nil {
		t.Fatal(err)
	}
	baseHash := ComputeSnapshotSectionHashes(&before)["users"]

	if _, err := database.Exec(`UPDATE global_config SET log_level='debug' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	after, err := service.clusterSnapshotBypassingCache(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changedHash := ComputeSnapshotSectionHashes(&after)["users"]
	if baseHash == changedHash {
		t.Fatal("global config change must change the users section hash (basic settings merged into users payload)")
	}

	guard, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if guard["users"] != changedHash {
		t.Fatalf("drift guard users hash=%s, want parity with full snapshot hash=%s (must rebuild with global settings)", guard["users"], changedHash)
	}
	if guard["security"] != ComputeSnapshotSectionHashes(&after)["security"] {
		t.Fatalf("drift guard security hash=%s, want parity (waf ref must not enter the guard rebuild)", guard["security"])
	}
}

// 三分类合并·方案A(2026-09-19 裁定):文件态记账落 global_config 专用列
// (applied_waf_ref_hash/applied_waf_ref_version,哈希域=纯 ref 含版本标签),
// cluster_applied_sections 严格 3 行与 syncSections 同构——wafFilesDrifted
// 的 304 兜底重拉与 R57 A-#4 标签自愈依赖该记录;随安全防护开关写入/冻结。
func TestRecordAppliedSectionHashes_wafFilesBookkeepingFollowsSecuritySwitch(t *testing.T) {
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{Version: 9, WafFiles: &models.ClusterWafFilesRef{CRSSha256: "abc", CRSVersion: "v9"}}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	recordAppliedSectionHashes(database, snapshot, sk, switches, nil)

	wantHash, err := wafFilesSectionHash(snapshot.WafFiles)
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	var version int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''), COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&hash, &version); err != nil || hash != wantHash || version != 9 {
		t.Fatalf("waf bookkeeping columns=(%q,%d) err=%v, want (%q,9)", hash, version, err, wantHash)
	}
	var rowCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections WHERE section='waf_files'`).Scan(&rowCount); err != nil || rowCount != 0 {
		t.Fatalf("waf_files bookkeeping row count=%d err=%v, want 0 (columns carry the bookkeeping)", rowCount, err)
	}

	// 安全防护开关关闭:列冻结(不得更新)。
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_hash='stale' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	recordAppliedSectionHashes(database, snapshot, sk, SyncSwitches{Users: true, Rules: true, Security: false}, nil)
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,'') FROM global_config WHERE id=1`).Scan(&hash); err != nil || hash != "stale" {
		t.Fatalf("security off must freeze the bookkeeping columns, got hash=%q err=%v", hash, err)
	}
}

// 必须返回 false(镜像 driftedSections 的开关豁免语义)。
func TestWafFilesDrifted_securitySwitchOffReturnsFalse(t *testing.T) {
	_, database := newClusterTestService(t)
	crsDir, xdbPath := overrideWafPathsForServicesTest(t)
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "a.conf"), []byte("SecRule x 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdbPath, []byte("XDB"), 0o644); err != nil {
		t.Fatal(err)
	}
	localHash, err := wafFilesSectionHash(BuildWafFileRef())
	if err != nil {
		t.Fatal(err)
	}
	seedAppliedWafRefHash(t, database, "definitely-different-hash")
	if _, err := database.Exec(`UPDATE global_config SET sync_security=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{}, nil)
	if service.wafFilesDrifted() {
		t.Fatal("wafFilesDrifted must return false when security switch is off (file state exempt from sync)")
	}
	// 开关开启 + 本地文件与已应用记录分叉 → 必须检出漂移。
	if _, err := database.Exec(`UPDATE global_config SET sync_security=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if !service.wafFilesDrifted() {
		t.Fatal("wafFilesDrifted must detect local/applied divergence with security switch on")
	}
	_ = localHash
}

// seedAppliedWafRefHash 直写文件态记账列(方案A:global_config 专用列,
// 替代旧 waf_files 记账行的测试播种)。
func seedAppliedWafRefHash(t *testing.T, dbh *sql.DB, hash string) {
	t.Helper()
	if _, err := dbh.Exec(`UPDATE global_config SET applied_waf_ref_hash=? WHERE id=1`, hash); err != nil {
		t.Fatal(err)
	}
}

func TestRecordAppliedSectionHashes_persistsAndUpdates(t *testing.T) {
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{Version: 7}
	snapshot.SectionHashes = map[string]string{"rules": "r7"}
	switches := SyncSwitches{Rules: true}
	recordAppliedSectionHashes(database, snapshot, &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}, switches, nil)

	var hash string
	var version int
	if err := database.QueryRow("SELECT hash, applied_version FROM cluster_applied_sections WHERE section='rules'").Scan(&hash, &version); err != nil || hash != "r7" || version != 7 {
		t.Fatalf("persisted rules hash=%q version=%d err=%v", hash, version, err)
	}

	// switch-off sections must not be recorded
	snapshot.SectionHashes = map[string]string{"users": "u7"}
	recordAppliedSectionHashes(database, snapshot, &sectionSkips{disabled: map[string]bool{"users": true}, unchanged: map[string]bool{}}, SyncSwitches{Users: false}, nil)
	var count int
	database.QueryRow("SELECT COUNT(*) FROM cluster_applied_sections WHERE section='users'").Scan(&count)
	if count != 0 {
		t.Fatal("disabled section must not persist applied hash")
	}
}

// oldBuildSecuritySectionHash 复现 I-2 COALESCE 加固前旧构建的 security 节哈希：
// 裸列直出（NULL 序列化为 null 字面量），构造混合版本场景的旧口径参照。
// 列清单取自加固前 snapshotSecurityPolicies 的原始 SELECT（git 63e05fa5^）。
func oldBuildSecuritySectionHash(t *testing.T, service *ClusterService, database *sql.DB) string {
	t.Helper()
	ctx := context.Background()
	const oldColumns = "id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,geoip_countries,geoip_mode,waf_check_response"
	var snapshot models.ClusterSnapshot
	var err error
	if snapshot.SecurityPolicies, err = service.dumpTableAsJSON(ctx, database, "security_policies", oldColumns, "id"); err != nil {
		t.Fatalf("旧口径 dump security_policies: %v", err)
	}
	if !strings.Contains(string(snapshot.SecurityPolicies), `"geoip_mode":null`) {
		t.Fatalf("旧口径 dump 必须在 COALESCE 列携带 null 字面量: %s", snapshot.SecurityPolicies)
	}
	if snapshot.SecurityBindings, err = service.snapshotSecurityBindings(ctx, database); err != nil {
		t.Fatalf("旧口径 dump bindings: %v", err)
	}
	if snapshot.SecurityCustomRules, err = service.snapshotSecurityCustomRules(ctx, database); err != nil {
		t.Fatalf("旧口径 dump custom rules: %v", err)
	}
	if snapshot.SecurityBlockPages, err = service.snapshotSecurityBlockPages(ctx, database); err != nil {
		t.Fatalf("旧口径 dump block pages: %v", err)
	}
	if snapshot.SecurityCRSVersion, err = service.snapshotSecurityCRSVersion(ctx, database); err != nil {
		t.Fatalf("旧口径 dump crs version: %v", err)
	}
	if snapshot.SecurityIP2RegionVersion, err = service.snapshotSecurityIP2RegionVersion(ctx, database); err != nil {
		t.Fatalf("旧口径 dump ip2region version: %v", err)
	}
	data, err := json.Marshal(sectionPayloadFor("security", &snapshot))
	if err != nil {
		t.Fatalf("序列化旧口径 security payload: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestRecordAppliedSectionHashes_driftedSectionStoresLocalRebuiltHash(t *testing.T) {
	// Given：E3 N-01 混合版本循环场景——新构建从节点（COALESCE 口径）对旧构建
	// 主节点（裸列口径）。本地 security_policies 在 COALESCE 列上含 NULL。
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `INSERT INTO security_policies (name, description, mode, geoip_mode, ip_acl_list) VALUES ('p1', NULL, NULL, NULL, NULL)`); err != nil {
		t.Fatal(err)
	}
	// 本地重建口径（driftGuardSectionHashes，新 COALESCE 视图）：
	local, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	localView := local["security"]
	if localView == "" {
		t.Fatal("本地 security 节哈希必须非空")
	}
	// 旧主节点口径（裸列视图），二者必须真实分歧，否则夹具不成立：
	oldView := oldBuildSecuritySectionHash(t, service, database)
	if oldView == localView {
		t.Fatal("夹具必须复现跨构建口径分歧（NULL 裸列 vs COALESCE）")
	}
	// 已应用记录与快照侧均为旧口径（首轮快照由旧主节点写入）：
	seedAppliedSection(t, database, "security", oldView)
	snapshot := models.ClusterSnapshot{Version: 9}
	snapshot.SectionHashes = map[string]string{"security": oldView}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}, drifted: []string{"security"}}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}

	// When：漂移强制重放后记录已应用节哈希
	recordAppliedSectionHashes(database, snapshot, sk, switches, local)

	// Then：漂移节必须落本地重建口径——下一 304 周期 driftGuardSectionHashes
	// 与 cluster_applied_sections 一致（收敛），不再触发全量重拉。
	applied := readAppliedSectionHashes(database)
	if applied["security"] != localView {
		t.Fatalf("漂移节必须存本地重建哈希作为稳定参照：got %q, want local %q（存快照侧旧口径 %q 会让漂移判定每周期复发）", applied["security"], localView, oldView)
	}
}

func TestRecordAppliedSectionHashes_sameBuildDriftedChoiceImmaterial(t *testing.T) {
	// Given：同构建场景——本地重建哈希 == 快照侧哈希，漂移节存哪个口径都相同，
	// 同构建行为必须保持不变（回归护栏）。
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{Version: 3}
	snapshot.SectionHashes = map[string]string{"security": "same-hash"}
	local := map[string]string{"security": "same-hash"}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}, drifted: []string{"security"}}

	// When
	recordAppliedSectionHashes(database, snapshot, sk, SyncSwitches{Security: true}, local)

	// Then
	if applied := readAppliedSectionHashes(database); applied["security"] != "same-hash" {
		t.Fatalf("同构建：落库哈希必须等于双方一致值，got %q", applied["security"])
	}
}

// N+12 G7-F1/G7-F2 处置证据：从节点 apply 期归一化（R41 B1 双默认页降级）造成
// 本地重建哈希与主节点快照哈希持久分歧时，同步周期必须收敛到稳态 304——
// 首轮 changed 路径落快照侧哈希 h → 下一 304 周期漂移判定触发一次补偿全量
// 重拉 → 漂移重放后 E3 N-01 drifted 分支落本地重建哈希 lh → 此后
// local==applied 不再触发漂移。锁定「无每周期 ping-pong」不变式；残余成本
// （每个主节点版本递增一次补偿周期）见上方裁定，接受为已知边界。
func TestSectionSyncCycle_normalizationDivergenceConvergesAfterOneDriftCycle(t *testing.T) {
	// Given：pre-R40 形态主节点快照——security 节携带两个 is_default=1 拦截页；
	// 从节点 apply 后 R41 B1 降级仅保留 MIN(id)，本地重建哈希与快照侧持久分歧。
	service, database := newClusterTestService(t)
	ctx := context.Background()
	for _, page := range []struct {
		id   int
		name string
	}{
		{41, "default-a"}, {42, "default-b"},
	} {
		if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,content,is_default) VALUES (?,?,'page',1)`, page.id, page.name); err != nil {
			t.Fatal(err)
		}
	}
	var master models.ClusterSnapshot
	var err error
	if master.SecurityPolicies, err = service.snapshotSecurityPolicies(ctx, database); err != nil {
		t.Fatal(err)
	}
	if master.SecurityBindings, err = service.snapshotSecurityBindings(ctx, database); err != nil {
		t.Fatal(err)
	}
	if master.SecurityCustomRules, err = service.snapshotSecurityCustomRules(ctx, database); err != nil {
		t.Fatal(err)
	}
	if master.SecurityBlockPages, err = service.snapshotSecurityBlockPages(ctx, database); err != nil {
		t.Fatal(err)
	}
	if master.SecurityCRSVersion, err = service.snapshotSecurityCRSVersion(ctx, database); err != nil {
		t.Fatal(err)
	}
	if master.SecurityIP2RegionVersion, err = service.snapshotSecurityIP2RegionVersion(ctx, database); err != nil {
		t.Fatal(err)
	}
	master.Version = 5
	master.SectionHashes = ComputeSnapshotSectionHashes(&master)
	snapshotHash := master.SectionHashes["security"]
	// 从节点落库 + R41 B1 降级（cluster_apply.go applySecurityBlockPages 同语句）：
	if _, err := database.Exec(`UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		t.Fatal(err)
	}
	local, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	localHash := local["security"]
	if localHash == "" || localHash == snapshotHash {
		t.Fatalf("夹具必须复现归一化分歧：local=%q snapshot=%q", localHash, snapshotHash)
	}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}

	// When：模拟同步周期序列（首轮 changed 应用 → 304 漂移补偿 → 漂移重放 → 稳态）
	sk1 := computeSectionSkips(database, master, switches, local)
	recordAppliedSectionHashes(database, master, sk1, switches, local)
	firstApplied := readAppliedSectionHashes(database)["security"]
	if firstApplied != snapshotHash {
		t.Fatalf("首轮 changed 路径应落快照侧哈希：got %q want %q", firstApplied, snapshotHash)
	}
	// 304 周期漂移判定（镜像 driftedSections 口径：local vs applied）——必须触发
	// 一次补偿全量重拉（残余成本），随后漂移重放收敛：
	drifted := localHash != firstApplied
	if !drifted {
		t.Fatal("归一化分歧下首轮后必须触发一次漂移补偿（夹具退化）")
	}
	if _, err := database.Exec(`UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		t.Fatal(err)
	}
	localReplay, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sk3 := computeSectionSkips(database, master, switches, localReplay)
	if !sk3.wasDrifted("security") {
		t.Fatal("漂移重放周期必须把 security 标记为 drifted")
	}
	recordAppliedSectionHashes(database, master, sk3, switches, localReplay)

	// Then：收敛——稳态 304 周期 local==applied，不再触发漂移补偿
	applied := readAppliedSectionHashes(database)
	if applied["security"] != localHash {
		t.Fatalf("漂移重放后应落本地重建哈希：got %q want %q", applied["security"], localHash)
	}
	steady, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if steady["security"] != applied["security"] {
		t.Fatalf("稳态必须 local==applied（无每周期 ping-pong）：local=%q applied=%q", steady["security"], applied["security"])
	}
}

func TestComputeSnapshotSectionHashes_stableAcrossRuns(t *testing.T) {
	a := models.ClusterSnapshot{Version: 1, Users: []models.ClusterUser{{ID: 1, Username: "u"}}}
	b := models.ClusterSnapshot{Version: 1, Users: []models.ClusterUser{{ID: 1, Username: "u"}}}
	ha := ComputeSnapshotSectionHashes(&a)
	hb := ComputeSnapshotSectionHashes(&b)
	if ha["users"] == "" || ha["users"] != hb["users"] {
		t.Fatalf("users hash must be stable and non-empty: %q vs %q", ha["users"], hb["users"])
	}
	b.Users[0].Username = "changed"
	if ComputeSnapshotSectionHashes(&b)["users"] == ha["users"] {
		t.Fatal("users hash must change when payload changes")
	}
}

func TestComputeSnapshotSectionHashes_ignoresLocalBookkeepingTimes(t *testing.T) {
	// last_login / last_used 是节点本地记账，不应参与 users 节哈希——
	// 否则从节点登录一次就改变本地哈希、触发永久全量重拉循环。
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	build := func(username, role string, withLocalTimes bool) models.ClusterSnapshot {
		user := models.ClusterUser{ID: 1, Username: username, PasswordHash: "h", Role: role, IsEnabled: true}
		key := models.ClusterAPIKey{ID: 1, Name: "k", KeyHash: "kh", KeyPrefix: "kp", IsEnabled: true}
		if withLocalTimes {
			user.LastLogin = models.JSONNullTime{NullTime: sql.NullTime{Valid: true, Time: now}}
			key.LastUsed = models.JSONNullTime{NullTime: sql.NullTime{Valid: true, Time: now}}
		}
		return models.ClusterSnapshot{Users: []models.ClusterUser{user}, APIKeys: []models.ClusterAPIKey{key}}
	}

	base := build("admin", "admin", false)
	withLocalTimes := build("admin", "admin", true)
	if ComputeSnapshotSectionHashes(&base)["users"] != ComputeSnapshotSectionHashes(&withLocalTimes)["users"] {
		t.Fatal("users hash must ignore last_login/last_used")
	}

	changedName := build("admin2", "admin", true)
	if h := ComputeSnapshotSectionHashes(&changedName)["users"]; h == ComputeSnapshotSectionHashes(&withLocalTimes)["users"] {
		t.Fatal("users hash must change when username changes")
	}
	changedRole := build("admin", "viewer", true)
	if h := ComputeSnapshotSectionHashes(&changedRole)["users"]; h == ComputeSnapshotSectionHashes(&withLocalTimes)["users"] {
		t.Fatal("users hash must change when role changes")
	}
}

// 系统数据恒同步(2026-09-11 裁定):sync_users 不可禁用——读取强制 true、
// 设置拒绝 false、节跳过永不命中、存量 0 值启动回填 1。
func TestReadSyncSwitches_forcesUsersOn(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET sync_users=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	sw, err := readSyncSwitches(database)
	if err != nil {
		t.Fatal(err)
	}
	if !sw.Users {
		t.Error("readSyncSwitches must force Users=true even when DB=0 (恒同步裁定)")
	}
}

func TestUpdateSettings_rejectsDisablingSyncUsers(t *testing.T) {
	svc, database := newClusterTestService(t)
	no := false
	err := svc.UpdateSettings(context.Background(), models.ClusterSettingsRequest{SyncUsers: &no})
	if err == nil {
		t.Fatal("UpdateSettings must reject sync_users=false")
	}
	if !strings.Contains(err.Error(), "系统数据") && !strings.Contains(err.Error(), "恒同步") {
		t.Errorf("rejection should explain 系统数据恒同步, got: %v", err)
	}
	var v int
	database.QueryRow(`SELECT COALESCE(sync_users,1) FROM global_config WHERE id=1`).Scan(&v)
	if v != 1 {
		t.Errorf("sync_users=%d, must stay 1", v)
	}
}

func TestComputeSectionSkips_neverDisablesUsers(t *testing.T) {
	_, database := newClusterTestService(t)
	sw := SyncSwitches{Users: false, Rules: true, Security: true}
	sk := computeSectionSkips(database, models.ClusterSnapshot{SectionHashes: map[string]string{}}, sw, nil)
	if sk.disabled["users"] {
		t.Error("users section must never be disabled (恒同步裁定)")
	}
}

// CRS/IP2Region 版本行不进任何节哈希(2026-09-11 修正:差分门控应用,
// 哈希保持文件态纯 ref 语义——进哈希会让主从行状态强耦合,漂移不可收敛)。
func TestSectionPayload_wafFilesExcludesCRSVersions(t *testing.T) {
	snap := models.ClusterSnapshot{
		WafFiles:                 nil,
		SecurityCRSVersion:       []models.ClusterSecurityCRSVersion{{ID: 1, Version: "4.28.0"}},
		SecurityIP2RegionVersion: []models.ClusterSecurityIP2RegionVersion{{ID: 1, Version: "202607"}},
	}
	wafData, err := json.Marshal(sectionPayloadFor("waf_files", &snap))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wafData), "crs_version") || strings.Contains(string(wafData), "4.28.0") {
		t.Errorf("waf_files payload must stay ref-only, got: %s", wafData)
	}
	secData, err := json.Marshal(sectionPayloadFor("security", &snap))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(secData), "crs_version") || strings.Contains(string(secData), "ip2region_version") {
		t.Errorf("security payload must exclude version rows, got: %s", secData)
	}
}

// 版本行差分门控:快照行与本地行不同→重放;相同→零写。
func TestApplySnapshot_versionRowsDiffGating(t *testing.T) {
	_, database := newClusterTestService(t)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// 快照携带与本地不同的 CRS 行 → 差分命中 → 重放
	snapshot := models.ClusterSnapshot{Version: 3, SecurityCRSVersion: []models.ClusterSecurityCRSVersion{{ID: 1, Version: "9.9.9"}}}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var v string
	database.QueryRow(`SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&v)
	if v != "9.9.9" {
		t.Errorf("CRS version=%q, want 9.9.9 (diff must apply)", v)
	}

	// 相同行 → 零写(mtime 无关,断言行值不变即可幂等语义)
	snapshot2 := snapshot
	snapshot2.Version = 4
	if err := syncService.applySnapshot(context.Background(), snapshot2); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	database.QueryRow(`SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&v)
	if v != "9.9.9" {
		t.Errorf("CRS version=%q after idempotent apply, want stable 9.9.9", v)
	}
}

// 三分类合并:版本行随安全防护开关——security 关闭时快照版本行不落库
// (规则库已并入安全防护域,单开关统策略行与文件差量通道)。
func TestApplySnapshot_securitySwitchOffSkipsCRSVersionRows(t *testing.T) {
	_, database := newClusterTestService(t)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := models.ClusterSnapshot{
		Version: 3,
		MasterSyncSwitches: &models.ClusterSyncSwitchesPayload{
			Users: true, Rules: true, Security: false,
		},
		SecurityCRSVersion:       []models.ClusterSecurityCRSVersion{{ID: 1, Version: "9.9.9"}},
		SecurityIP2RegionVersion: []models.ClusterSecurityIP2RegionVersion{{ID: 1, Version: "999909"}},
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var v string
	database.QueryRow(`SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&v)
	if v == "9.9.9" {
		t.Error("CRS version row must NOT apply when security switch off")
	}
	var x string
	database.QueryRow(`SELECT COALESCE(version,'') FROM security_ip2region_version WHERE id=1`).Scan(&x)
	if x == "999909" {
		t.Error("IP2Region version row must NOT apply when security switch off")
	}
}
