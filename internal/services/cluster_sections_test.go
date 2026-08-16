package services

import (
	"context"
	"database/sql"
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
	recordAppliedSectionHashes(database, snapshot, &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}, switches)

	var hash string
	var version int
	if err := database.QueryRow("SELECT hash, applied_version FROM cluster_applied_sections WHERE section='rules'").Scan(&hash, &version); err != nil || hash != "r7" || version != 7 {
		t.Fatalf("persisted rules hash=%q version=%d err=%v", hash, version, err)
	}

	// switch-off sections must not be recorded
	snapshot.SectionHashes = map[string]string{"users": "u7"}
	recordAppliedSectionHashes(database, snapshot, &sectionSkips{disabled: map[string]bool{"users": true}, unchanged: map[string]bool{}}, SyncSwitches{Users: false})
	var count int
	database.QueryRow("SELECT COUNT(*) FROM cluster_applied_sections WHERE section='users'").Scan(&count)
	if count != 0 {
		t.Fatal("disabled section must not persist applied hash")
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
