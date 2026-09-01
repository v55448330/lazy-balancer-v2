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

	// Then：rules/users 滞后，其余同步
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
	if !bySection["security"].Synced || !bySection["global_config"].Synced || !bySection["waf_files"].Synced {
		t.Fatalf("unchanged sections must stay synced: %#v", bySection)
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
	if _, err := database.Exec("UPDATE global_config SET sync_users=0, sync_security=0 WHERE id=1"); err != nil {
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
		if status.Section == "users" || status.Section == "security" {
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
