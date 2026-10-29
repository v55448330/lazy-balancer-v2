package services

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// 主端快照装载必须与从端 apply 同口径归一 sync_interval。
// 否则残留脏值（<10 / >86400）时主端按脏值算 users 节哈希、从端按归一值重建，
// 每次版本递增都重放 users 节并触发一次漂移补偿全量重拉。
func TestLoadSnapshotGlobalSettings_normalizesSyncInterval(t *testing.T) {
	cases := []struct {
		name   string
		stored int
		want   int
	}{
		{"below minimum", 0, 60},
		{"one second", 3, 60},
		{"above maximum", 200000, 86400},
		{"valid value untouched", 300, 300},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, database := newClusterTestService(t)
			if _, err := database.Exec("UPDATE global_config SET sync_interval=? WHERE id=1", tc.stored); err != nil {
				t.Fatal(err)
			}
			var snapshot models.ClusterSnapshot
			if err := service.loadSnapshotGlobalSettings(context.Background(), database, &snapshot); err != nil {
				t.Fatalf("load snapshot settings: %v", err)
			}
			if snapshot.BasicSettings.SyncInterval == nil {
				t.Fatal("sync_interval 未装载")
			}
			if got := *snapshot.BasicSettings.SyncInterval; got != tc.want {
				t.Fatalf("sync_interval=%d, want %d（主端装载必须与从端 apply 同口径归一）", got, tc.want)
			}
		})
	}
}

// 空 dataDir 不得把 CWD 下同名文件镜像进
// global_config.branding_json（与写入侧同款守卫）。
func TestRefreshBrandingMirrorDB_ignoresEmptyDataDir(t *testing.T) {
	service, database := newClusterTestService(t)
	_ = service
	var before string
	if err := database.QueryRow("SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}

	changed, err := RefreshBrandingMirrorDB(database, "")
	if err != nil {
		t.Fatalf("RefreshBrandingMirrorDB: %v", err)
	}
	if changed {
		t.Fatal("changed=true, want false（空 dataDir 必须视为未配置）")
	}
	var after string
	if err := database.QueryRow("SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("branding_json 被空 dataDir 改写: %q → %q", before, after)
	}
}

// unchanged 分支的记账必须真正落到行——UPDATE 命中 0 行
// 时不得静默 continue（否则下一次 304 多一轮漂移重放）。
func TestRecordAppliedSectionHashes_unchangedBranchInsertsMissingRow(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM cluster_applied_sections"); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{Version: 42, SectionHashes: map[string]string{}}
	sk := &sectionSkips{unchanged: map[string]bool{}}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}
	for _, sec := range syncSections {
		snapshot.SectionHashes[sec.Key] = "hash-" + sec.Key
		sk.unchanged[sec.Key] = true
	}

	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, switches, nil); err != nil {

		t.Fatalf("record applied section hashes: %v", err)

	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections WHERE applied_version=42`).Scan(&count); err != nil {
		t.Fatalf("count applied sections: %v", err)
	}
	if count != len(syncSections) {
		t.Fatalf("applied rows=%d, want %d（unchanged 分支行缺失时必须补插）", count, len(syncSections))
	}
	for _, sec := range syncSections {
		var stored string
		if err := database.QueryRow(`SELECT hash FROM cluster_applied_sections WHERE section=?`, sec.Key).Scan(&stored); err != nil {
			t.Fatalf("read applied hash for %s: %v", sec.Key, err)
		}
		if want := "hash-" + sec.Key; stored != want {
			t.Fatalf("applied hash for %s=%q, want %q", sec.Key, stored, want)
		}
	}
}

// 业务摘要行不得输出字面量「<nil>」。
func TestClusterSyncFailureSummaryOmitsNilSide(t *testing.T) {
	newTaskLogDir(t)
	TaskLogf("cluster-sync", "sync", "%s", clusterSyncFailureSummary(errors.New("pull failed"), nil))
	TaskLogf("cluster-sync", "sync", "%s", clusterSyncFailureSummary(nil, errors.New("report failed")))
	TaskLogf("cluster-sync", "sync", "%s", clusterSyncFailureSummary(errors.New("pull failed"), errors.New("report failed")))
	data, err := os.ReadFile(taskengine.TaskLogPath("cluster-sync"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if strings.Contains(string(data), "<nil>") {
		t.Fatalf("task log=%q, 不得出现 <nil>", string(data))
	}
	if !strings.Contains(string(data), "拉取 pull failed") || !strings.Contains(string(data), "上报 report failed") {
		t.Fatalf("task log=%q, want 分别点名单侧失败", string(data))
	}
}
