package services

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// 2026-10-03 用户裁定：从节点同步审计「同步」汇总行语义修复钉测试——
// 汇总行必须反映节级实际应用面，不得打印与「哈希一致跳过」自相矛盾的
// 内容清单（用户截图形态：汇总称「基本设置：已同步；用户 N 个」而同秒
// 系统数据节被跳过）。

// syncAuditDetails 取审计库中指定动作的明细（按 id 序）。
func syncAuditDetails(t *testing.T, action string) []string {
	t.Helper()
	rows, err := db.AuditDB.Query("SELECT detail FROM audit_log WHERE action=? ORDER BY id", action)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// syncSemanticsEnv 主从同库形态：harness DB 同时充当主节点快照源与从节点
// 应用目标；bump 版本+重建缓存后取当前快照。
func syncSemanticsEnv(t *testing.T) (*ClusterService, *sql.DB, *SyncService, func(version int)) {
	t.Helper()
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_syncsem','sem','http','sem.example.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	caddyStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(caddyStub.Close)
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyStub.URL}, NewCaddyService(caddyStub.URL))
	bump := func(version int) {
		if _, err := database.Exec("UPDATE global_config SET cluster_version=?", version); err != nil {
			t.Fatalf("bump version: %v", err)
		}
		clusterSnapshotCaches.Delete(database)
	}
	return cluster, database, syncService, bump
}

// Given 同内容快照连续应用两次（第二次仅版本号+1：全部节哈希一致）。
// When 第二次 applySnapshot。
// Then：全部节无变化时汇总行只点名哈希一致、不打印内容清单。
func TestApplySnapshot_summaryAuditReflectsSectionOutcomes(t *testing.T) {
	cluster, _, syncService, bump := syncSemanticsEnv(t)
	ctx := context.Background()
	bump(100)
	snap, _, err := cluster.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before := len(syncAuditDetails(t, "同步"))
	bump(101)
	snap2, _, err := cluster.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("snapshot2: %v", err)
	}
	if err := syncService.applySnapshot(ctx, snap2); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	details := syncAuditDetails(t, "同步")
	if len(details) <= before {
		t.Fatalf("第二次应用应产生同步汇总行, %d→%d", before, len(details))
	}
	summary := details[len(details)-1]
	if strings.Contains(summary, "基本设置：已同步") || strings.Contains(summary, "个；") {
		t.Fatalf("汇总行不应打印内容清单（与哈希一致跳过自相矛盾）: %s", summary)
	}
	if !strings.Contains(summary, "哈希一致") {
		t.Fatalf("全部节无变化时汇总应点名哈希一致: %s", summary)
	}
}

// Given 部分节变化形态（rules 变、users/security 哈希一致）。
// Then 汇总行点名「本轮应用」与「跳过」各是哪些节。
func TestApplySnapshot_summaryListsAppliedAndSkipped(t *testing.T) {
	cluster, database, syncService, bump := syncSemanticsEnv(t)
	ctx := context.Background()
	bump(200)
	snap, _, err := cluster.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// rules 节变化：追加第二条规则
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_syncsem2','sem2','http','sem2.example.test',8081,1)`); err != nil {
		t.Fatalf("seed second rule: %v", err)
	}
	bump(201)
	snap2, _, err := cluster.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("snapshot2: %v", err)
	}
	if err := syncService.applySnapshot(ctx, snap2); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	details := syncAuditDetails(t, "同步")
	summary := details[len(details)-1]
	if !strings.Contains(summary, "本轮应用：负载均衡规则") {
		t.Fatalf("汇总应点名应用的节: %s", summary)
	}
	if !strings.Contains(summary, "跳过（哈希一致）：系统数据、安全防护") {
		t.Fatalf("汇总应点名跳过的节: %s", summary)
	}
}
