package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
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

// driver.Rows.Next 的非 EOF 错误只能经 rows.Err 观测。
// 已应用哈希读到部分结果时必须回退全量重放，不得把截断视图当完整记录。
func TestReadAppliedSectionHashes_iterationErrorDropsPartialView(t *testing.T) {
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "FROM cluster_applied_sections"})
	t.Cleanup(func() { _ = fake.Close() })
	if got := readAppliedSectionHashes(context.Background(), fake); got != nil {
		t.Fatalf("iteration error returned partial applied hashes: %#v", got)
	}
}

// 逐行 Scan 失败（驱动/连接异常形态）必须与行遍历错误同口径：留痕并返回 nil，
// 不得返回「部分 map」——残留记录会让 driftedSections 用残缺 applied 记录比对，
// 把未漂移节误判为漂移（多一轮全量重拉），且故障本身零信号。
func TestReadAppliedSectionHashes_scanErrorDropsPartialView(t *testing.T) {
	buf := captureLogf(t)
	fake := sql.OpenDB(&fakeIterErrConnector{scanFailNeedle: "FROM cluster_applied_sections"})
	t.Cleanup(func() { _ = fake.Close() })

	got := readAppliedSectionHashes(context.Background(), fake)
	if got != nil {
		t.Fatalf("scan error returned partial applied hashes: %#v", got)
	}
	if !strings.Contains(buf.String(), "读取已应用节哈希失败") {
		t.Fatalf("scan error must be logged (fail-visible), logs=%q", buf.String())
	}
}

// 版本行差分读取失败时偏向重放；空快照与截断本地视图不得误判为一致。
func TestSnapshotSecurityVersionRowsDiffer_iterationErrorForcesReplay(t *testing.T) {
	for _, needle := range []string{"FROM security_crs_version", "FROM security_ip2region_version"} {
		t.Run(needle, func(t *testing.T) {
			fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: needle})
			t.Cleanup(func() { _ = fake.Close() })
			tx, err := fake.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			snapshot := models.ClusterSnapshot{
				SecurityCRSVersion:       []models.ClusterSecurityCRSVersion{},
				SecurityIP2RegionVersion: []models.ClusterSecurityIP2RegionVersion{},
			}
			if !snapshotSecurityVersionRowsDiffer(context.Background(), tx, snapshot) {
				t.Fatalf("%s iteration error was treated as identical versions", needle)
			}
		})
	}
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

	switches, err := readSyncSwitches(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	sk := computeSectionSkips(context.Background(), database, snapshot, switches, nil)

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
	switches, err := readSyncSwitches(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	sk := computeSectionSkips(context.Background(), database, snapshot, switches, nil)
	for _, key := range []string{"users", "rules", "security"} {
		if sk.skip(key) {
			t.Fatalf("first sync with all switches on must apply %s", key)
		}
	}
}

// 三分类合并(2026-09-19 用户裁定):同步节收敛为 users/rules/security 三节
// (全局配置并入系统数据、规则库并入安全防护);:rules 节标签
// 与集群设置卡/主面板开关行统一为「负载均衡规则」(备份分类标签不在此口径)。
// ComputeSnapshotSectionHashes 只产出 3 键。
func TestSyncSections_threeCategoryMerge(t *testing.T) {
	if len(syncSections) != 3 {
		t.Fatalf("syncSections=%#v, want exactly 3 sections", syncSections)
	}
	want := map[string]string{"users": "系统数据", "rules": "负载均衡规则", "security": "安全防护"}
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
		BasicSettings: models.ClusterBasicSettings{LogLevel: new("debug")},
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
// 的 304 兜底重拉与标签自愈依赖该记录;随安全防护开关写入/冻结。
func TestRecordAppliedSectionHashes_wafFilesBookkeepingFollowsSecuritySwitch(t *testing.T) {
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{Version: 9, WafFiles: &models.ClusterWafFilesRef{CRSSha256: "abc", CRSVersion: "v9"}}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, switches, nil); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}

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
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, SyncSwitches{Users: true, Rules: true, Security: false}, nil); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}
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
	seedAppliedWafRefHash(t, database, "definitely-different-hash")
	if _, err := database.Exec(`UPDATE global_config SET sync_security=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{}, nil)
	if service.wafFilesDrifted(context.Background()) {
		t.Fatal("wafFilesDrifted must return false when security switch is off (file state exempt from sync)")
	}
	// 开关开启 + 本地文件与已应用记录分叉 → 必须检出漂移。
	if _, err := database.Exec(`UPDATE global_config SET sync_security=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if !service.wafFilesDrifted(context.Background()) {
		t.Fatal("wafFilesDrifted must detect local/applied divergence with security switch on")
	}
}

// 开关读取失败必须留痕（与 driftedSections 的「重建失败，跳过漂移检测」同族）：
// 静默返回 false 会让 WAF 文件态检测被无声关闭，本地文件与主端永久分叉无信号。
func TestWafFilesDrifted_warnsOnSwitchReadFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewSyncService(database, &config.Config{}, nil)
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	if service.wafFilesDrifted(context.Background()) {
		t.Fatal("读失败时必须按未漂移处理（不得误触发全量重拉）")
	}
	if !strings.Contains(logs.String(), "读取同步开关失败") {
		t.Fatalf("logs=%q, want 含「读取同步开关失败」告警", logs.String())
	}
}

// 文件态记账哈希读取失败必须留痕：读失败此前被当成「从未记录」，检测静默跳过。
func TestWafFilesDrifted_warnsOnBookkeepingHashReadFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewSyncService(database, &config.Config{}, nil)
	if _, err := database.Exec(`ALTER TABLE global_config RENAME COLUMN applied_waf_ref_hash TO applied_waf_ref_hash_unavailable`); err != nil {
		t.Fatalf("hide bookkeeping column: %v", err)
	}
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	if service.wafFilesDrifted(context.Background()) {
		t.Fatal("记账哈希不可读时必须按未漂移处理")
	}
	if !strings.Contains(logs.String(), "读取文件态记账哈希失败") {
		t.Fatalf("logs=%q, want 含「读取文件态记账哈希失败」告警", logs.String())
	}
}

// 集群状态展示的同步开关必须与运行时同一读取口径（readSyncSwitches）：
// sync_users 恒同步（存量 0 值按 1 读取），Status() 直读列会把禁用态展示成
// 「系统数据不同步」，与实际同步行为相悖。
func TestStatus_syncSwitchesUseSingleSourceRead(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET sync_users=0, sync_rules=0, sync_security=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("read cluster status: %v", err)
	}
	if !status.SyncUsers {
		t.Fatal("Status().SyncUsers=false——系统数据恒同步，必须与 readSyncSwitches 同口径为 true")
	}
	if status.SyncRules {
		t.Fatal("Status().SyncRules=true, want 存量 0 值按关闭展示")
	}
	if !status.SyncSecurity {
		t.Fatal("Status().SyncSecurity=false, want 1")
	}
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
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}, switches, nil); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}

	var hash string
	var version int
	if err := database.QueryRow("SELECT hash, applied_version FROM cluster_applied_sections WHERE section='rules'").Scan(&hash, &version); err != nil || hash != "r7" || version != 7 {
		t.Fatalf("persisted rules hash=%q version=%d err=%v", hash, version, err)
	}

	// switch-off sections must not be recorded
	snapshot.SectionHashes = map[string]string{"users": "u7"}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, &sectionSkips{disabled: map[string]bool{"users": true}, unchanged: map[string]bool{}}, SyncSwitches{Users: false}, nil); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM cluster_applied_sections WHERE section='users'").Scan(&count); err != nil {
		t.Fatalf("count applied users section: %v", err)
	}
	if count != 0 {
		t.Fatal("disabled section must not persist applied hash")
	}
}

// oldBuildSecuritySectionHash 复现 COALESCE 加固前旧构建的 security 节哈希
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
	// Given：问题 混合版本循环场景——新构建从节点（COALESCE 口径）对旧构建
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
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, switches, local); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}

	// Then：漂移节必须落本地重建口径——下一 304 周期 driftGuardSectionHashes
	// 与 cluster_applied_sections 一致（收敛），不再触发全量重拉。
	applied := readAppliedSectionHashes(context.Background(), database)
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
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, SyncSwitches{Security: true}, local); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}

	// Then
	if applied := readAppliedSectionHashes(context.Background(), database); applied["security"] != "same-hash" {
		t.Fatalf("同构建：落库哈希必须等于双方一致值，got %q", applied["security"])
	}
}

func legacySecuritySectionHashWithoutBlockPageNormalization(t *testing.T, master *models.ClusterSnapshot) string {
	t.Helper()
	currentPayload, err := json.Marshal(sectionPayloadFor("security", master))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(currentPayload, &fields); err != nil {
		t.Fatal(err)
	}
	originalPages, err := json.Marshal(master.SecurityBlockPages)
	if err != nil {
		t.Fatal(err)
	}
	fields["block_pages"] = originalPages
	legacyPayload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(legacyPayload)
	return hex.EncodeToString(sum[:])
}

// 处置证据：从节点 apply 期归一化造成
// 本地重建哈希与主节点快照哈希持久分歧时，同步周期必须收敛到稳态 304——
// 首轮 changed 路径落快照侧哈希 h → 下一 304 周期漂移判定触发一次补偿全量
// 重拉 → 漂移重放后问题 drifted 分支落本地重建哈希 lh → 此后
// local==applied 不再触发漂移。锁定「无每周期 ping-pong」不变式；残余成本
// （每个主节点版本递增一次补偿周期）见上方裁定，接受为已知边界。
func TestSectionSyncCycle_normalizationDivergenceConvergesAfterOneDriftCycle(t *testing.T) {
	// Given：形态主节点快照——security 节携带两个 is_default=1 拦截页；
	// 从节点 apply 后降级仅保留 MIN(id)，本地重建哈希与快照侧持久分歧。
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
	if err := service.loadSectionHashInputs(ctx, database, &master); err != nil {
		t.Fatal(err)
	}
	master.Version = 5
	master.SectionHashes = ComputeSnapshotSectionHashes(&master)
	currentSnapshotHash := master.SectionHashes["security"]
	// 从节点落库 + 降级（cluster_apply.go applySecurityBlockPages 同语句）
	if _, err := database.Exec(`UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		t.Fatal(err)
	}
	local, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	localHash := local["security"]
	if localHash == "" || localHash != currentSnapshotHash {
		t.Fatalf("同构建归一化哈希必须一致：local=%q snapshot=%q", localHash, currentSnapshotHash)
	}
	snapshotHash := legacySecuritySectionHashWithoutBlockPageNormalization(t, &master)
	master.SectionHashes["security"] = snapshotHash
	if localHash == snapshotHash {
		t.Fatalf("夹具必须复现旧构建归一化分歧：local=%q legacy=%q", localHash, snapshotHash)
	}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}

	// When：模拟同步周期序列（首轮 changed 应用 → 304 漂移补偿 → 漂移重放 → 稳态）
	sk1 := computeSectionSkips(context.Background(), database, master, switches, local)
	if err := recordAppliedSectionHashes(context.Background(), database, master, sk1, switches, local); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}
	firstApplied := readAppliedSectionHashes(context.Background(), database)["security"]
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
	sk3 := computeSectionSkips(context.Background(), database, master, switches, localReplay)
	if !sk3.wasDrifted("security") {
		t.Fatal("漂移重放周期必须把 security 标记为 drifted")
	}
	if err := recordAppliedSectionHashes(context.Background(), database, master, sk3, switches, localReplay); err != nil {
		t.Fatalf("record applied section hashes: %v", err)
	}

	// Then：收敛——稳态 304 周期 local==applied，不再触发漂移补偿
	applied := readAppliedSectionHashes(context.Background(), database)
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
	sw, err := readSyncSwitches(context.Background(), database)
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
	if err := database.QueryRow(`SELECT COALESCE(sync_users,1) FROM global_config WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read sync_users: %v", err)
	}
	if v != 1 {
		t.Errorf("sync_users=%d, must stay 1", v)
	}
}

func TestComputeSectionSkips_neverDisablesUsers(t *testing.T) {
	_, database := newClusterTestService(t)
	sw := SyncSwitches{Users: false, Rules: true, Security: true}
	sk := computeSectionSkips(context.Background(), database, models.ClusterSnapshot{SectionHashes: map[string]string{}}, sw, nil)
	if sk.disabled["users"] {
		t.Error("users section must never be disabled (恒同步裁定)")
	}
}

// CRS/IP2Region 版本行不进任何节哈希(2026-09-11 修正:差分门控应用,
// 哈希保持文件态纯 ref 语义——进哈希会让主从行状态强耦合,漂移不可收敛)。
func TestSectionPayload_wafFilesExcludesCRSVersions(t *testing.T) {
	// 夹具必须给真实 ref 载荷：WafFiles=nil 时 sectionPayloadFor 返回 nil →
	// JSON "null"，任何 Contains 断言恒假（用例名承诺的不变量从未被钉住）。
	ref := &models.ClusterWafFilesRef{
		CRSVersion:   "4.28.0",
		CRSSha256:    "sha256:crs",
		IP2RegionTag: "202607",
		IP2RegionSha: "sha256:xdb",
	}
	snap := models.ClusterSnapshot{
		WafFiles:                 ref,
		SecurityCRSVersion:       []models.ClusterSecurityCRSVersion{{ID: 1, Version: "4.28.0"}},
		SecurityIP2RegionVersion: []models.ClusterSecurityIP2RegionVersion{{ID: 1, Version: "202607"}},
	}
	payload := sectionPayloadFor("waf_files", &snap)
	if payload == nil {
		t.Fatal("waf_files 载荷为 nil：ref 未进入节载荷（断言会恒假）")
	}
	// 等值断言而非「不含某子串」：ref 自身就带 crs_version/ip2region_version
	// 字段（版本串是 ref 的一部分），子串断言形态必然假绿/必假。
	want, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	wafData, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(wafData) != string(want) {
		t.Fatalf("waf_files payload=%s, want ref 本体 %s（版本行表不得混入）", wafData, want)
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
	if err := database.QueryRow(`SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read crs version: %v", err)
	}
	if v != "9.9.9" {
		t.Errorf("CRS version=%q, want 9.9.9 (diff must apply)", v)
	}

	// 相同行 → 零写(mtime 无关,断言行值不变即可幂等语义)
	snapshot2 := snapshot
	snapshot2.Version = 4
	if err := syncService.applySnapshot(context.Background(), snapshot2); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if err := database.QueryRow(`SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read crs version after idempotent apply: %v", err)
	}
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
	// 本地先落哨兵版本行：从库没有任何版本行时，「未被 9.9.9 覆盖」的断言
	// 在 Scan 失败（零值）下也会通过——哨兵让「保留本地」成为可区分事实。
	if _, err := database.Exec(`INSERT INTO security_crs_version (id, version) VALUES (1,'local-keep') ON CONFLICT(id) DO UPDATE SET version=excluded.version`); err != nil {
		t.Fatalf("seed local crs row: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip2region_version (id, version) VALUES (1,'local-xdb') ON CONFLICT(id) DO UPDATE SET version=excluded.version`); err != nil {
		t.Fatalf("seed local ip2region row: %v", err)
	}
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
	if err := database.QueryRow(`SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read crs version: %v", err)
	}
	if v != "local-keep" {
		t.Errorf("CRS version=%q, want local-keep（security 开关关闭时快照版本行不得覆盖本地）", v)
	}
	var x string
	if err := database.QueryRow(`SELECT COALESCE(version,'') FROM security_ip2region_version WHERE id=1`).Scan(&x); err != nil {
		t.Fatalf("read ip2region version: %v", err)
	}
	if x != "local-xdb" {
		t.Errorf("IP2Region version=%q, want local-xdb（security 开关关闭时快照版本行不得覆盖本地）", x)
	}
}

// 同步开关关闭告警的「版本去重」必须早于 WAF 文件全树哈希：同版本重放
// （重载失败补偿重拉对同一版本重复 apply）本应被去重直接跳过，不得持
// WafFileLock 重算 CRS 全树打包 + xdb 全文件 sha256（数十至数百毫秒，阻塞
// 三库更新器与 lbbak 导入文件相位）。以「预持锁后调用必须立即返回」实证：
// 若仍先算哈希，调用会阻塞直至 2s 超时。
func TestLogSyncSwitchGuards_sameVersionDoesNotHashWafFiles(t *testing.T) {
	_, database := newClusterTestService(t)
	overrideWafPathsForServicesTest(t)
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_version=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:  7,
		WafFiles: &models.ClusterWafFilesRef{CRSVersion: "v1", CRSSha256: "deadbeef"},
	}
	sk := &sectionSkips{disabled: map[string]bool{"security": true}, unchanged: map[string]bool{}}

	WafFileLock().Lock()
	done := make(chan struct{})
	go func() {
		logSyncSwitchGuards(context.Background(), database, snapshot, sk, SyncSwitches{})
		close(done)
	}()
	select {
	case <-done:
		WafFileLock().Unlock()
	case <-time.After(2 * time.Second):
		WafFileLock().Unlock()
		t.Fatal("同版本告警去重前重算了 WAF 文件哈希（持 WafFileLock 全树打包）")
	}
}

// 回归：版本推进时仍要走到文件比对与告警（去重不得把新版本也短路），
// 并把去重版本推进到快照版本。
func TestLogSyncSwitchGuards_newVersionHashesAndAdvancesDedup(t *testing.T) {
	_, database := newClusterTestService(t)
	overrideWafPathsForServicesTest(t)
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_version=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:  8,
		WafFiles: &models.ClusterWafFilesRef{CRSVersion: "v1", CRSSha256: "deadbeef"},
	}
	sk := &sectionSkips{disabled: map[string]bool{"security": true}, unchanged: map[string]bool{}}

	logSyncSwitchGuards(context.Background(), database, snapshot, sk, SyncSwitches{})

	var applied int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 8 {
		t.Fatalf("applied_waf_ref_version=%d, want 8（新版本必须走到文件比对并推进去重）", applied)
	}
}

// Caddy 全局数值设置（body 上限 / 三类 HTTP 超时 / 日志尺寸）的归一必须由
// 主端装载与从端 apply 共用：单边归一会让 users 节哈希主从恒不等，每次版本
// 递增都多一轮「配置无变化但本地数据不一致」的全量重拉 + 强制重载。
func TestSnapshotUsersSection_hashParityWithCaddyNumericClamp(t *testing.T) {
	masterService, masterDB := newClusterTestService(t)
	// 带外写入的越界值（写侧校验拦不住直改库/同步快照）：apply 侧会归一后落库，
	// 主端装载侧必须同口径，否则两侧哈希分叉。
	if _, err := masterDB.Exec(`UPDATE global_config SET request_body_max_size_mb=8192, http_read_timeout=0,
		http_write_timeout=-3, http_idle_timeout=0, caddy_log_size_mb=0 WHERE id=1`); err != nil {
		t.Fatalf("seed out-of-range caddy settings: %v", err)
	}
	masterSnapshot, err := masterService.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build master snapshot: %v", err)
	}
	masterHash := masterSnapshot.SectionHashes["users"]
	if masterHash == "" {
		t.Fatal("主端快照缺少 users 节哈希")
	}
	if settings := masterSnapshot.BasicSettings; settings.RequestBodyMaxSizeMB == nil || *settings.RequestBodyMaxSizeMB != 4096 ||
		settings.HTTPReadTimeout == nil || *settings.HTTPReadTimeout != db.DefaultHTTPReadTimeout {
		t.Fatalf("主端装载侧未归一越界值：body=%v read=%v", settings.RequestBodyMaxSizeMB, settings.HTTPReadTimeout)
	}

	slaveService, slaveDB := newClusterTestService(t)
	if err := replaceSnapshotDB(context.Background(), slaveDB, masterSnapshot); err != nil {
		t.Fatalf("从端应用快照: %v", err)
	}
	slaveHashes, err := slaveService.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("从端重建节哈希: %v", err)
	}
	if masterHash != slaveHashes["users"] {
		t.Fatalf("主端 users 节哈希 %s ≠ 从端重建 %s——数值归一仅单边生效", masterHash[:16], slaveHashes["users"][:16])
	}
}
