package services

// CL40-C1-1/2/3(第 40 轮集群域):
// C1-1 同步包声明哈希非空但未携带内容 → 拒绝应用(主端瞬态 IO 下轮自愈);
// C1-2 ReportNode 落库前 last_sync_error 与从端写侧同口径截断(≤512B);
// C1-3 ApproveNode 重复审批(非 pending)→ 409 语义错误而非 404。

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func osReadFileForTest(t *testing.T, path string) (string, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	return string(data), err
}

// CL40-C1-1:声明哈希非空但内容为空——主端 BuildWafFileBundle 瞬态读失败会
// 产出该形状,从端应用「无操作」后漂移永不收敛;必须拒绝。
func TestApplyWafFileBundle_rejectsHashWithoutContent(t *testing.T) {
	crsDir := t.TempDir()
	xdbPath := t.TempDir() + "/ip2region.xdb"
	t.Cleanup(OverrideWafLivePathsForTest(crsDir, xdbPath))
	// 预置 live 内容,断言拒绝后 live 树未动
	writeTestFile(t, xdbPath, "LOCAL-XDB")

	bundle := &WafFileBundle{IP2RegionSha: "deadbeef", IP2RegionTag: "v1"}
	if _, _, err := ApplyWafFileBundle(bundle); err == nil || !strings.Contains(err.Error(), "未携带内容") {
		t.Fatalf("hash-without-content must be rejected, got %v", err)
	}
	gotRaw, rerr := osReadFileForTest(t, xdbPath)
	if rerr != nil || gotRaw != "LOCAL-XDB" {
		t.Fatalf("live tree must be untouched after rejection, got %q err=%v", gotRaw, rerr)
	}

	crsBundle := &WafFileBundle{CRSSha256: "deadbeef"}
	if _, _, err := ApplyWafFileBundle(crsBundle); err == nil || !strings.Contains(err.Error(), "未携带内容") {
		t.Fatalf("crs hash-without-content must be rejected, got %v", err)
	}
	_ = crsDir
}

// CL40-C1-2:64KB 上报错误串落库前截断 ≤512B(与从端写侧 truncateValidUTF8Tail
// 口径对齐,health_json 里的长错误不再撑大 nodes 行)。
func TestReportNode_truncatesLastSyncError(t *testing.T) {
	svc, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-trunc")

	bigError := strings.Repeat("错", 64*1024)
	report := models.ClusterReport{AppliedVersion: 1, LastSyncError: bigError}
	if err := svc.ReportNode(context.Background(), nodeID, report, time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}
	var stored []byte
	if err := database.QueryRow("SELECT last_sync_error FROM nodes WHERE id=?", nodeID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) > 512 {
		t.Fatalf("last_sync_error len=%d, want ≤512", len(stored))
	}
}

// CL40-C1-3:重复审批已批准节点 → ErrNodeNotPending(409 语义);
// 不存在的节点维持 ErrNodeNotFound(404 语义)。
func TestApproveNode_conflictVsNotFound(t *testing.T) {
	svc, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-approved")

	if err := svc.ApproveNode(context.Background(), nodeID); !errors.Is(err, ErrNodeNotPending) {
		t.Fatalf("re-approve must return ErrNodeNotPending, got %v", err)
	}
	if err := svc.ApproveNode(context.Background(), 99999); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node must return ErrNodeNotFound, got %v", err)
	}
}
