package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func seedAppliedSection(t *testing.T, dbh *sql.DB, section, hash string) {
	t.Helper()
	dbh.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at) VALUES (?,?,1,datetime('now'))
		ON CONFLICT(section) DO UPDATE SET hash=excluded.hash`, section, hash)
}

func TestComputeSectionSkips_switchOffAndHashMatch(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.ExecContext(ctx, "UPDATE global_config SET sync_rules=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{Version: 5}
	snapshot.SectionHashes = map[string]string{
		"global_config": "g1", "users": "u1", "rules": "r1", "waf_files": "w1", "security": "s1",
	}
	seedAppliedSection(t, database, "global_config", "g1")
	seedAppliedSection(t, database, "users", "old")

	switches, err := readSyncSwitches(database)
	if err != nil {
		t.Fatal(err)
	}
	sk := computeSectionSkips(database, snapshot, switches, nil)

	if !sk.disabled["rules"] {
		t.Fatal("rules switch off must mark section disabled")
	}
	if !sk.unchanged["global_config"] {
		t.Fatal("matching hash must mark section unchanged")
	}
	if sk.unchanged["users"] || sk.disabled["users"] {
		t.Fatal("users hash differs and switch on → must apply")
	}
	if sk.skip("users") {
		t.Fatal("users should not be skipped")
	}
	if !sk.skip("rules") || !sk.skip("global_config") {
		t.Fatal("rules/global_config must be skipped")
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
	for _, key := range []string{"global_config", "users", "rules", "waf_files", "security"} {
		if sk.skip(key) {
			t.Fatalf("first sync with all switches on must apply %s", key)
		}
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
	switches := SyncSwitches{GlobalConfig: true, Users: true, Rules: true, WafFiles: true, Security: true}

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
