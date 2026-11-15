package services

// DeleteNode 伴随的 pin 清理失败必须进入 pendingPins 重试链（与 Promote 的
// cleanupClusterPin 同构）：裸 os.Remove 失败只留一行日志，pin 文件从此既无
// 周期重试也无节流审计，只能人工删盘。真实失败机制=非空目录（os.Remove
// ENOTEMPTY），断言系统终态（pendingPins 登记 + 重试收敛 + 审计节流）。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 一枚待删除节点，其 pin 路径被非空目录占据（os.Remove 必然失败）。
// When DeleteNode。
// Then 删除本身成功；pin 清理失败进入 pendingPins 并留一条「清理失败」审计；
// 障碍移除后 retryPendingPinCleanup 收敛（磁盘 pin 消失、pending 清空）。
func TestClusterService_DeleteNode_pinCleanupFailureEntersPendingRetry(t *testing.T) {
	cluster, database := newClusterTestService(t)
	auditDB := db.AuditDB
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,is_approved)
		VALUES (31,'slave-b','172.18.0.9',8000,'http','https://node-b.example:8443',1)`); err != nil {
		t.Fatal(err)
	}
	pinPath, err := clusterPinPath("", database, "node-b.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	// 真实失败机制：非空目录让 os.Remove 返回 ENOTEMPTY（稳定复现）。
	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pinPath, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinPath) })

	// When：删除节点（pin 清理失败不得阻断删除）。
	if err := cluster.DeleteNode(context.Background(), 31); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	// Then：失败进入待重试表并留痕（裸 Remove 只打日志，两处皆空）。
	cluster.pinCleanupMu.Lock()
	pending := len(cluster.pendingPins)
	_, tracked := cluster.pendingPins[pinPath]
	cluster.pinCleanupMu.Unlock()
	if pending != 1 || !tracked {
		t.Fatalf("pin 清理失败未进入 pendingPins（pending=%d tracked=%v）：无周期重试通道，只能人工删盘", pending, tracked)
	}
	if got := countAuditRows(t, auditDB, "清理失败", "证书指纹"); got != 1 {
		t.Fatalf("清理失败审计=%d, want 1（失败必须显性化）", got)
	}

	// 同一失败稳定复现（巡检重试）不得刷屏审计。
	cluster.retryPendingPinCleanup()
	if got := countAuditRows(t, auditDB, "清理失败", "证书指纹"); got != 1 {
		t.Fatalf("重复失败审计=%d, want 1（节流与 Promote 清理链同口径）", got)
	}

	// When：障碍移除（pin 变为可删除形态），巡检重试一轮。
	if err := os.RemoveAll(pinPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cluster.retryPendingPinCleanup()

	// Then：系统终态收敛——磁盘 pin 消失、pending 清空、成功审计一条。
	if _, err := os.Stat(pinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("重试后磁盘 pin 未删除: %v", err)
	}
	cluster.pinCleanupMu.Lock()
	pending = len(cluster.pendingPins)
	cluster.pinCleanupMu.Unlock()
	if pending != 0 {
		t.Fatalf("重试成功后 pendingPins=%d, want 0", pending)
	}
	if got := countAuditRows(t, auditDB, "清理", "证书指纹"); got != 1 {
		t.Fatalf("清理成功审计=%d, want 1", got)
	}
}
