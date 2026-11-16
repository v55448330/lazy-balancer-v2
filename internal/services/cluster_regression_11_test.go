package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// v2 快照读取器的独立夹具（快照结构 + 签发）在 testhelpers_shared_test.go，
// 仅用于构造「主节点仍是 schema v2」的历史形态；其自身正确性不由产品测试
// 负责——本文件只断言产品代码对 v2 载荷的行为。
func TestSyncService_Pull_rejectsValidV2PublisherFixture(t *testing.T) {
	// Given
	const token = "cluster-token"
	_, database := newClusterTestService(t)
	v2 := signedSnapshotV2Fixture(1, token)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{"data": v2})
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())

	// Then
	if pullErr == nil || !strings.Contains(pullErr.Error(), "快照 schema v2 过旧：主节点需升级到支持 schema v3 的版本") {
		t.Fatalf("v3 reader error=%v", pullErr)
	}
}

func TestClusterSnapshot_HTTPPublisherPullAndFingerprint304(t *testing.T) {
	// Given
	const token = "cluster-token"
	publisher, pubDB := newClusterTestService(t)
	if _, err := pubDB.Exec("UPDATE global_config SET cluster_version=7"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := publisher.Snapshot(context.Background(), 0, "", token); err != nil {
		t.Fatal(err)
	}
	var fullResponses, notModifiedResponses int
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		sinceVersion, _ := strconv.Atoi(request.URL.Query().Get("since_version"))
		snapshot, changed, err := publisher.Snapshot(request.Context(), sinceVersion, request.URL.Query().Get("fingerprint"), request.Header.Get("X-Cluster-Token"))
		if err != nil {
			t.Errorf("publish snapshot: %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !changed {
			notModifiedResponses++
			response.WriteHeader(http.StatusNotModified)
			return
		}
		fullResponses++
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddy.Close()
	// 快照读取是主节点-only 契约（读路径 SQL 角色复核）：发布方与拉取方
	// 不得共用同一库句柄（回环形态下拉取侧把共享库降级为从角色后，发布侧
	// 快照会被正确拒绝）——从端独立建库，与生产双进程形态一致。
	pubGlobalsDB, pubGlobalsMetrics, pubGlobalsAudit, pubGlobalsCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	slaveDB := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		restoreGlobalDBHandles(pubGlobalsDB, pubGlobalsMetrics, pubGlobalsAudit, pubGlobalsCurrent)
	})
	if _, err := slaveDB.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=?, applied_version=0, sync_fingerprint='' WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(slaveDB, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddy.URL}, NewCaddyService(caddy.URL))

	// When
	first, firstErr := service.Pull(context.Background())
	second, secondErr := service.Pull(context.Background())

	// Then
	if firstErr != nil || !first.Changed || first.AppliedVersion != 7 {
		t.Fatalf("first pull=%#v error=%v", first, firstErr)
	}
	if secondErr != nil || second.Changed || second.AppliedVersion != 7 {
		t.Fatalf("second pull=%#v error=%v", second, secondErr)
	}
	if fullResponses != 1 || notModifiedResponses != 1 {
		t.Fatalf("full responses=%d not-modified responses=%d", fullResponses, notModifiedResponses)
	}
}
