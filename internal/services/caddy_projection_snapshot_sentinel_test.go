package services

// 投影快照 IO 失败的错误分类钉：快照不完整时渲染不可回滚，必须以专用哨兵
// ErrProjectionSnapshot 上抛（写路径按乱填保障回滚，不得按「校验器不可用」
// 退化提交）。故障注入为真实不可读目录（chmod 000），不 mock 返回值。

import (
	"errors"
	"os"
	"testing"
)

func TestValidateTxRenderViaCLI_snapshotFailureIsRollbackClass(t *testing.T) {
	dir := t.TempDir()
	oldDir := IPListDataDir
	IPListDataDir = dir
	t.Cleanup(func() {
		IPListDataDir = oldDir
		_ = os.Chmod(dir, 0o755) // 恢复可写，t.TempDir 清理才能删除
	})
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod snapshot dir: %v", err)
	}
	if entries, err := os.ReadDir(dir); err == nil {
		t.Skipf("目录 000 仍可列举（特权运行？），无法构造真实读失败: %d entries", len(entries))
	}

	s := NewCaddyService("http://127.0.0.1:1")
	s.SetCLIValidatorForTest(func([]byte) error {
		t.Fatal("快照失败时不得进入渲染/校验")
		return nil
	})
	err := s.ValidateTxRenderViaCLI(nil, false)
	if err == nil {
		t.Fatal("投影目录不可读必须显式失败")
	}
	if !errors.Is(err, ErrProjectionSnapshot) {
		t.Fatalf("快照失败分类=%v, want ErrProjectionSnapshot（写路径据此回滚而非退化提交）", err)
	}
	if errors.Is(err, ErrCLIValidatorUnavailable) {
		t.Fatalf("快照失败不得归为校验器不可用（会放行退化提交）: %v", err)
	}
	if IsConfigRejected(err) {
		t.Fatalf("快照失败不得归为配置被拒（会 400 误导用户改配置）: %v", err)
	}
}
