package services

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// pin 清理失败会被 Snapshot（每次 Pull）与主节点巡检按周期重试，同一失败
// 稳定复现时只应留一条「清理失败」审计；恢复成功清空状态后再次失败须重记。
func TestCleanupClusterPin_failureAuditThrottledAcrossRetries(t *testing.T) {
	service, _ := newClusterTestService(t)
	auditDB := db.AuditDB
	root := t.TempDir()
	pinPath := filepath.Join(root, "pin")
	obstructPin := func() {
		t.Helper()
		if err := os.MkdirAll(pinPath, 0o755); err != nil {
			t.Fatal(err)
		}
		// 非空目录让 os.Remove 返回 ENOTEMPTY（稳定复现的失败形态，
		// 不会被当作 pin 已不存在而静默跳过）。
		if err := os.WriteFile(filepath.Join(pinPath, "child"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	obstructPin()

	// When：失败形态不变，直接调用与重试路径各触发多次
	service.cleanupClusterPin(pinPath, "http://master.example:8000")
	for range 3 {
		service.retryPendingPinCleanup()
	}
	// Then：只留一条失败审计
	if got := countAuditRows(t, auditDB, "清理失败", "证书指纹"); got != 1 {
		t.Fatalf("repeated pin cleanup failures wrote %d audit rows, want 1", got)
	}

	// When：恢复（pin 变为普通文件并清理成功）
	if err := os.RemoveAll(pinPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service.retryPendingPinCleanup()
	if got := countAuditRows(t, auditDB, "清理", "证书指纹"); got != 1 {
		t.Fatalf("successful pin cleanup wrote %d audit rows, want 1", got)
	}

	// When：恢复后再次出现同一失败（成功分支已清空去重状态）→ 须重新留痕
	obstructPin()
	service.cleanupClusterPin(pinPath, "http://master.example:8000")
	if got := countAuditRows(t, auditDB, "清理失败", "证书指纹"); got != 2 {
		t.Fatalf("failure after recovery wrote %d audit rows, want 2", got)
	}
}

// Given 从节点已对两台主节点 TOFU 钉扎（磁盘 pin 文件 + 内存指纹缓存）。
// When ForgetPins（主节点更换管理面板证书、运维确认后放弃全部旧指纹）。
// Then 内存缓存清空、磁盘 pin 文件全部删除并返回删除数；旧指纹不再参与校验，
// 下一次握手按当前证书重新钉扎成功（清空=重钉入口真的打开了）。
func TestSyncService_ForgetPins_clearsMemoryAndDiskPins(t *testing.T) {
	_, database := newClusterTestService(t)
	dataDir := t.TempDir()
	service := NewSyncService(database, &config.Config{DataDir: dataDir}, nil)
	t.Cleanup(func() { unregisterSyncDrainer(service) })

	hosts := []string{"10.0.0.31:8000", "10.0.0.32:8000"}
	pinPaths := make([]string, 0, len(hosts))
	for _, host := range hosts {
		pinPath, err := clusterPinPath(dataDir, database, host)
		if err != nil {
			t.Fatalf("pin 路径（%s）: %v", host, err)
		}
		if err := os.MkdirAll(filepath.Dir(pinPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pinPath, []byte("old-fingerprint\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		service.pinMu.Lock()
		service.verifiedPins[pinPath] = "old-fingerprint"
		service.pinMu.Unlock()
		pinPaths = append(pinPaths, pinPath)
	}
	// 前置：旧指纹仍在时不同证书指纹必须被拒（否则「清空后重钉」断言无意义）。
	if err := verifyClusterPinIfPresent(pinPaths[0], "another-fingerprint"); !errors.Is(err, errClusterPinMismatch) {
		t.Fatalf("前置：pin 文件存在且指纹不一致时应报 mismatch, got %v", err)
	}

	removed, err := service.ForgetPins()
	if err != nil {
		t.Fatalf("ForgetPins: %v", err)
	}
	if removed != len(hosts) {
		t.Fatalf("ForgetPins removed=%d, want %d（删除数=pin 文件数）", removed, len(hosts))
	}
	service.pinMu.Lock()
	remaining := len(service.verifiedPins)
	service.pinMu.Unlock()
	if remaining != 0 {
		t.Fatalf("内存指纹缓存残留 %d 条, want 0（内存/磁盘 TOFU 生命周期须对齐：pin 文件已删而内存旧指纹仍在，后续握手会按旧指纹复核，重钉入口打不开）", remaining)
	}
	for _, pinPath := range pinPaths {
		if _, err := os.Stat(pinPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("磁盘 pin 未删除: %s（stat err=%v）", pinPath, err)
		}
	}

	// 旧指纹已失效：文件缺失不再判 mismatch，握手路径按当前证书重新钉扎。
	if err := verifyClusterPinIfPresent(pinPaths[0], "old-fingerprint"); err != nil {
		t.Fatalf("pin 文件已删除时不得再报旧指纹错误: %v", err)
	}
	if err := verifyOrStoreClusterPin(pinPaths[0], "new-fingerprint"); err != nil {
		t.Fatalf("重新钉扎新指纹失败: %v", err)
	}
	if err := verifyClusterPinIfPresent(pinPaths[0], "new-fingerprint"); err != nil {
		t.Fatalf("重新钉扎后新指纹应通过校验: %v", err)
	}
	if err := verifyClusterPinIfPresent(pinPaths[0], "old-fingerprint"); !errors.Is(err, errClusterPinMismatch) {
		t.Fatalf("重新钉扎后旧指纹必须被拒, got %v", err)
	}
}
