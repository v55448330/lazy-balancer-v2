package services

// RemoveRuleLogFiles 必须回报删除失败：规则访问日志是磁盘残留，删除失败
// （权限/只读挂载/IO）此前被 os.Remove 的返回值丢弃——调用方（DeleteRule /
// 导入清理 / 集群规则替换）无从审计，残留永久不可见。口径与证书任务日志
// RemoveCertJobLogFiles 一致：不存在=成功（nil），其余错误聚合返回。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRemoveRuleLogFiles_reportsFailureAggregated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	restore := SetRuleLogDirForTest(dir)
	t.Cleanup(restore)

	names := []string{"lb_ro.log", "lb_ro.log.1", "lb_ro-20260910T15-04-05.123-size.log"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// 扫描前的真实文件先移到旁路，再以普通文件占据目录路径。活动文件与
	// 五份位移副本的删除都会返回 ENOTDIR，不依赖目录权限或运行用户。
	savedDir := dir + "-saved"
	if err := os.Rename(dir, savedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := RemoveRuleLogFiles("lb_ro")
	if err == nil {
		t.Fatal("ENOTDIR 删除失败必须回报错误（否则残留不可见）")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("error=%v, want ENOTDIR", err)
	}
	if !strings.Contains(err.Error(), "lb_ro") {
		t.Fatalf("error=%v, want 含规则 id（便于定位残留）", err)
	}
	// 目录不可枚举本身就是残留风险：扫描失败原因必须进错误面，不得被
	// 「逐项删除错误」吞掉（逐项只是枚举失败时的退化路径）。
	if !strings.Contains(err.Error(), "读取规则日志目录") {
		t.Fatalf("目录枚举失败原因未进错误面（残留不可见）: %v", err)
	}
	if got := strings.Count(err.Error(), "删除规则日志"); got < 1 {
		t.Fatalf("聚合删除错误数=%d, want ≥1（枚举失败时退化为活动文件+确定性 .1..5 逐项尝试）: %v", got, err)
	}

	// 恢复真实目录后重试必须清零活动文件与轮转副本（幂等重试通道）。
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedDir, dir); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRuleLogFiles("lb_ro"); err != nil {
		t.Fatalf("恢复目录后重试失败: %v", err)
	}
	for _, name := range names {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("重试后日志 %s 仍存在: %v", name, statErr)
		}
	}
}

// 回归形状：无日志文件 = 成功（不存在的错误不得外泄为「清理失败」）。
func TestRemoveRuleLogFiles_absentRuleIsSuccess(t *testing.T) {
	restore := SetRuleLogDirForTest(t.TempDir())
	t.Cleanup(restore)
	if err := RemoveRuleLogFiles("lb_absent"); err != nil {
		t.Fatalf("不存在的规则日志应返回 nil: %v", err)
	}
}

// 认领与删除必须覆盖同一文件族：外来 logrotate 可留下任意代次及压缩后缀，
// 不能只认 .1..5 就让清理摘要把仍在盘上的副本报成已收敛。
func TestRemoveRuleLogFiles_removesAllRecognizedShiftRotations(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	removed := []string{"lb_legacy.log.12", "lb_legacy.log.3.gz", "lb_legacy.log.4.zst"}
	for _, name := range removed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const sibling = "lb_legacy_other.log.12.gz"
	if err := os.WriteFile(filepath.Join(dir, sibling), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := RemoveRuleLogFiles("lb_legacy"); err != nil {
		t.Fatalf("remove recognized rotations: %v", err)
	}
	for _, name := range removed {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("recognized rotation %s remains: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, sibling)); err != nil {
		t.Fatalf("sibling rule log must remain: %v", err)
	}
}
