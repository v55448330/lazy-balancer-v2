// Package testsupport 提供跨包共享的测试环境护栏。
//
// 只允许测试代码导入（TestMain / *_test.go）：生产二进制不得链接本包。
package testsupport

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsureUsableTempDir 校验 os.TempDir() 存在且可写，并尝试幂等重建。
//
// 为什么需要（MCP 沙箱/CI 实证）：MCP 沙箱/CI 在用例运行中回收 TMPDIR 后，
// t.TempDir() 会级联报 `stat .../.ctx-mode-*/...: no such file or directory`，
// 数十个用例同时红——把真正的产品回归埋在一堆环境错误里，也让「定向测试红」
// 无法归因。这里把该形态收敛成一条显式的环境失败（并在可重建时自动修复），
// 而不是让它伪装成产品缺陷。
func EnsureUsableTempDir() error {
	dir := os.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("TMPDIR 不可用（%s）: %w —— 后续 t.TempDir() 会级联失败，这是环境问题而非产品回归", dir, err)
	}
	probe, err := os.CreateTemp(dir, ".lb-tmp-probe-*")
	if err != nil {
		return fmt.Errorf("TMPDIR 不可写（%s）: %w —— 后续 t.TempDir() 会级联失败，这是环境问题而非产品回归", dir, err)
	}
	name := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return fmt.Errorf("TMPDIR 探针关闭失败（%s）: %w", filepath.Dir(name), closeErr)
	}
	if removeErr != nil {
		return fmt.Errorf("TMPDIR 探针删除失败（%s）: %w", name, removeErr)
	}
	return nil
}
