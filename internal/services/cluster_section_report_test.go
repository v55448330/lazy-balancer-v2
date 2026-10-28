package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func insertApprovedClusterNode(t *testing.T, database *sql.DB, name string) int {
	t.Helper()
	insert, err := database.Exec(`INSERT INTO nodes (name,ip_address,port,is_approved,status) VALUES (?, '127.0.0.1', 8000, 1, 'online')`, name)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	nodeID, err := insert.LastInsertId()
	if err != nil {
		t.Fatalf("read node id: %v", err)
	}
	return int(nodeID)
}

func masterSectionHashesForTest(t *testing.T, service *ClusterService) map[string]string {
	t.Helper()
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build master snapshot: %v", err)
	}
	if len(snapshot.SectionHashes) != len(syncSections) {
		t.Fatalf("master section hashes=%#v", snapshot.SectionHashes)
	}
	return snapshot.SectionHashes
}

func reportForVersion(version int) models.ClusterReport {
	return models.ClusterReport{AppliedVersion: version, ServiceStatus: "ok"}
}

func TestClusterService_ReportNode_storesSectionHashesAndNodesAggregates(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-a")
	masterHashes := masterSectionHashesForTest(t, service)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	// When：上报哈希与主节点完全一致
	report := reportForVersion(3)
	report.SectionHashes = masterHashes
	if err := service.ReportNode(context.Background(), nodeID, report, now); err != nil {
		t.Fatalf("report node: %v", err)
	}

	// Then：全部节 synced=true，哈希与主端一致
	nodes, err := service.Nodes(context.Background(), now)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 || len(nodes[0].SectionSync) != len(syncSections) {
		t.Fatalf("nodes=%#v", nodes)
	}
	for _, status := range nodes[0].SectionSync {
		if !status.Synced || status.Hash != status.MasterHash || status.Label == "" {
			t.Fatalf("section %+v must be synced with label", status)
		}
	}

	// When：rules 节漂移、users 节缺失记录
	drifted := make(map[string]string, len(masterHashes))
	for key, hash := range masterHashes {
		drifted[key] = hash
	}
	drifted["rules"] = "stale-rules-hash"
	delete(drifted, "users")
	if err := service.ReportNode(context.Background(), nodeID, withSectionHashes(reportForVersion(4), drifted), now); err != nil {
		t.Fatalf("report drifted node: %v", err)
	}

	// Then：rules/users 滞后，其余同步(三分类合并后仅 3 节)
	nodes, err = service.Nodes(context.Background(), now)
	if err != nil {
		t.Fatalf("list drifted nodes: %v", err)
	}
	bySection := map[string]models.ClusterSectionSyncStatus{}
	for _, status := range nodes[0].SectionSync {
		bySection[status.Section] = status
	}
	if bySection["rules"].Synced || bySection["rules"].Hash != "stale-rules-hash" || bySection["rules"].MasterHash != masterHashes["rules"] {
		t.Fatalf("rules status=%+v", bySection["rules"])
	}
	if bySection["users"].Synced || bySection["users"].Hash != "" {
		t.Fatalf("missing users record must lag: %+v", bySection["users"])
	}
	if !bySection["security"].Synced {
		t.Fatalf("unchanged security must stay synced: %#v", bySection)
	}
	if _, ok := bySection["global_config"]; ok {
		t.Fatal("global_config must not appear in section_sync after 3-category merge")
	}
	if _, ok := bySection["waf_files"]; ok {
		t.Fatal("waf_files must not appear in section_sync after 3-category merge")
	}
}

func TestClusterService_Nodes_sectionSyncFilteredByMasterSwitches(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-a")
	report := reportForVersion(2)
	report.SectionHashes = masterSectionHashesForTest(t, service)
	if err := service.ReportNode(context.Background(), nodeID, report, time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}
	// 系统数据恒同步(2026-09-11 裁定)不可关——过滤语义改用 rules/security 验证。
	if _, err := database.Exec("UPDATE global_config SET sync_rules=0, sync_security=0 WHERE id=1"); err != nil {
		t.Fatalf("disable switches: %v", err)
	}

	// When
	nodes, err := service.Nodes(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}

	// Then：关闭的节不出现在 sectionSync，开启的节保持
	if len(nodes) != 1 {
		t.Fatalf("nodes=%#v", nodes)
	}
	for _, status := range nodes[0].SectionSync {
		if status.Section == "rules" || status.Section == "security" {
			t.Fatalf("disabled section leaked into section_sync: %+v", status)
		}
	}
	if len(nodes[0].SectionSync) != len(syncSections)-2 {
		t.Fatalf("section_sync=%#v", nodes[0].SectionSync)
	}
}

func TestClusterService_ReportNode_oldSlaveWithoutSectionHashesOmitsSectionSync(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-old")
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	// When：旧版本从节点上报（无 section_hashes 字段）
	if err := service.ReportNode(context.Background(), nodeID, reportForVersion(5), now); err != nil {
		t.Fatalf("report old slave: %v", err)
	}
	nodes, err := service.Nodes(context.Background(), now)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}

	// Then：SectionSync 为 nil，JSON 省略该字段
	if len(nodes) != 1 || nodes[0].SectionSync != nil {
		t.Fatalf("old slave section_sync=%#v", nodes[0].SectionSync)
	}
	encoded, err := json.Marshal(nodes[0])
	if err != nil {
		t.Fatalf("marshal node view: %v", err)
	}
	if strings.Contains(string(encoded), "section_sync") {
		t.Fatalf("section_sync must be omitted for old slaves: %s", encoded)
	}
}

// 106-07：从节点一次瞬时读失败（SQLITE_BUSY）会让上报载荷缺 section_hashes，
// 主节点若把「空哈希」一律当「旧版本从节点」，就删掉了该节点历史分区状态——
// 节点列表的 section_sync 随即整体消失，运维信号从「某节滞后」退化为「无数据」。
// 修复=上报侧显式标记「本轮读取失败」（section_hashes_unavailable），主节点仅对
// 「旧版从节点」（两字段都不带）执行清理语义。
func TestClusterService_ReportNode_unavailableSectionHashesKeepsPreviousReport(t *testing.T) {
	// Given：节点已上报过一轮分区哈希
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-busy")
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	first := reportForVersion(5)
	first.SectionHashes = map[string]string{"users": "u1", "rules": "r1", "security": "s1"}
	if err := service.ReportNode(context.Background(), nodeID, first, now); err != nil {
		t.Fatalf("seed report: %v", err)
	}

	// When：下一轮从节点读 cluster_applied_sections 失败（无哈希 + 显式标志）
	stale := reportForVersion(6)
	stale.SectionHashes = nil
	stale.SectionHashesUnavailable = true
	if err := service.ReportNode(context.Background(), nodeID, stale, now.Add(time.Minute)); err != nil {
		t.Fatalf("report with unavailable hashes: %v", err)
	}

	// Then：历史分区状态保留（节点列表继续展示 section_sync）
	service.sectionMu.Lock()
	stored := service.sectionReports[nodeID]
	service.sectionMu.Unlock()
	if stored == nil || stored["rules"] != "r1" {
		t.Fatalf("stored section hashes=%#v, want 保留上一轮（读失败≠旧版本从节点）", stored)
	}

	// 反向对照：真正的旧版本从节点（两字段都不带）仍走清理语义
	oldSlave := reportForVersion(7)
	if err := service.ReportNode(context.Background(), nodeID, oldSlave, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("report old slave: %v", err)
	}
	service.sectionMu.Lock()
	stored = service.sectionReports[nodeID]
	service.sectionMu.Unlock()
	if stored != nil {
		t.Fatalf("stored section hashes=%#v, want 旧版从节点清理语义", stored)
	}
}

// 上报载荷必须把「读失败」编成显式标志：JSON 里缺字段=旧版本从节点（清理），
// 带上 section_hashes_unavailable=true 才是「本轮读失败」（保留）。
// 注入方式=DROP 掉 cluster_applied_sections（其余读取照常可用），只让节哈希
// 读取失败，不牵连 Report 的其他查询。
func TestSyncService_Report_marksSectionHashesUnavailableOnReadFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	var captured map[string]interface{}
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/nodes/report" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DROP TABLE cluster_applied_sections"); err != nil {
		t.Fatalf("drop applied sections: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(master.URL))

	// When：上报（读取已应用节哈希必然失败）
	_ = syncService.Report(context.Background())

	// Then
	if captured == nil {
		t.Fatal("上报未到达主节点")
	}
	if unavailable, _ := captured["section_hashes_unavailable"].(bool); !unavailable {
		t.Fatalf("payload 未标记 section_hashes_unavailable: %#v", captured)
	}
	if _, present := captured["section_hashes"]; present {
		t.Fatalf("读失败时不得发送 section_hashes（会让主节点按旧版从节点清理）: %#v", captured)
	}
}

func TestClusterService_ReportNode_sectionHashesDecodeFromWirePayload(t *testing.T) {
	// Given：新从节点上报线格式（JSON 解码进 ClusterReport）
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-wire")
	var report models.ClusterReport
	payload := `{"applied_version":3,"service_status":"ok","health":{"caddy_ok":true},"section_hashes":{"rules":"abc123","users":"def456"}}`
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}

	// When
	if err := service.ReportNode(context.Background(), nodeID, report, time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}
	// 调用后篡改上报载荷，验证存储是防御性拷贝
	report.SectionHashes["rules"] = "tampered"

	// Then
	service.sectionMu.Lock()
	stored := service.sectionReports[nodeID]
	service.sectionMu.Unlock()
	if stored == nil || stored["rules"] != "abc123" || stored["users"] != "def456" {
		t.Fatalf("stored section hashes=%#v", stored)
	}
}

func TestClusterService_DeleteNode_clearsSectionReport(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-a")
	report := reportForVersion(1)
	report.SectionHashes = map[string]string{"rules": "r1"}
	if err := service.ReportNode(context.Background(), nodeID, report, time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}

	// When
	if err := service.DeleteNode(context.Background(), nodeID); err != nil {
		t.Fatalf("delete node: %v", err)
	}

	// Then：内存态清除（防节点 ID 复用后残留旧哈希）
	service.sectionMu.Lock()
	_, remains := service.sectionReports[nodeID]
	service.sectionMu.Unlock()
	if remains {
		t.Fatal("section report survived node deletion")
	}
}

func TestClusterService_roleFlipClearsSectionReports(t *testing.T) {
	t.Run("become slave", func(t *testing.T) {
		service, database := newClusterTestService(t)
		nodeID := insertApprovedClusterNode(t, database, "slave-before-demote")
		if err := service.ReportNode(context.Background(), nodeID, models.ClusterReport{SectionHashes: map[string]string{"rules": "stale"}}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := service.BecomeSlave(context.Background(), "https://new-master.example", models.ClusterRegistration{RegistrationID: 9}); err != nil {
			t.Fatalf("become slave: %v", err)
		}
		service.sectionMu.Lock()
		defer service.sectionMu.Unlock()
		if len(service.sectionReports) != 0 {
			t.Fatalf("stale master-era section reports=%v, want cleared", service.sectionReports)
		}
	})
	t.Run("promote", func(t *testing.T) {
		service, database := newClusterTestService(t)
		nodeID := insertApprovedClusterNode(t, database, "slave-before-promote")
		if err := service.ReportNode(context.Background(), nodeID, models.ClusterReport{SectionHashes: map[string]string{"rules": "stale"}}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='https://old-master.example' WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		if err := service.Promote(context.Background()); err != nil {
			t.Fatalf("promote: %v", err)
		}
		service.sectionMu.Lock()
		defer service.sectionMu.Unlock()
		if len(service.sectionReports) != 0 {
			t.Fatalf("stale slave-era section reports=%v, want cleared", service.sectionReports)
		}
	})
}

func TestClusterService_RegisterNode_upsertClearsSectionReport(t *testing.T) {
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-reregister")
	if err := service.ReportNode(context.Background(), nodeID, models.ClusterReport{SectionHashes: map[string]string{"rules": "stale"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "slave-reregister", IPAddress: "127.0.0.1", Port: 8000,
	}, "127.0.0.1", now); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	service.sectionMu.Lock()
	defer service.sectionMu.Unlock()
	if _, remains := service.sectionReports[nodeID]; remains {
		t.Fatal("section report survived node re-registration")
	}
}

func TestSyncService_Report_includesAppliedSectionHashes(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	var gotBody []byte
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		gotBody, _ = io.ReadAll(request.Body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='tok-1', applied_version=3 WHERE id=1", master.URL); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	seedAppliedSection(t, database, "rules", "r9")
	seedAppliedSection(t, database, "security", "s9")
	syncService := NewSyncService(database, &config.Config{}, NewCaddyService(master.URL))

	// When
	if err := syncService.Report(context.Background()); err != nil {
		t.Fatalf("report: %v", err)
	}

	// Then：上报载荷携带已应用节哈希
	var decoded models.ClusterReport
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("decode report payload: %v", err)
	}
	if decoded.SectionHashes["rules"] != "r9" || decoded.SectionHashes["security"] != "s9" {
		t.Fatalf("reported section hashes=%#v payload=%s", decoded.SectionHashes, gotBody)
	}
}

func withSectionHashes(report models.ClusterReport, hashes map[string]string) models.ClusterReport {
	report.SectionHashes = hashes
	return report
}
