package services

// 旧日志迁移候选根：固定 legacy 根（/app/logs）必须始终参与，否则自定义
// 日志根部署的固化期旧文件永不迁移。

import (
	"path/filepath"
	"testing"
)

func TestCertJobLogLegacyRoots_includesFixedLegacyRoot(t *testing.T) {
	custom := filepath.Join(string(filepath.Separator), "srv", "custom-logs", "tasks")
	roots := certJobLogLegacyRoots(custom)
	sawLegacy := false
	for _, root := range roots {
		if root == legacyCertJobLogRoot {
			sawLegacy = true
		}
	}
	if !sawLegacy {
		t.Fatalf("候选根 %v 未包含固定 legacy 根 %q（自定义日志根下旧文件不会迁移）", roots, legacyCertJobLogRoot)
	}
	// 默认布局（容器内 tasks 的父目录就是 legacy 根）不得重复扫描。
	roots = certJobLogLegacyRoots(filepath.Join(legacyCertJobLogRoot, "tasks"))
	if len(roots) != 1 || roots[0] != legacyCertJobLogRoot {
		t.Fatalf("默认布局候选根=%v, want [%s]", roots, legacyCertJobLogRoot)
	}
}
