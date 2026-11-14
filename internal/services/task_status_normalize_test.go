package services

// 启动归一的版本表读失败必须留痕：静默跳过会让版本表不可读时残留活动态
// 恒显「更新中」，排障零信号（与同函数写失败分支的 warn 同形）。

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestNormalizeInterruptedUpdateStatuses_versionTableReadFailureLogged(t *testing.T) {
	newClusterTestService(t)
	// 版本表不可读形态（表缺失=驱动级读失败；库句柄本身健康）。
	if _, err := db.DB.Exec(`ALTER TABLE security_crs_version RENAME TO security_crs_version_norm_bak`); err != nil {
		t.Fatal(err)
	}
	buf := captureApplicationLogs(t)

	normalizeInterruptedUpdateStatuses()

	logged := buf.String()
	if !strings.Contains(logged, "crs") || !strings.Contains(logged, "读取失败") {
		t.Fatalf("log=%q, want crs 版本表读取失败的 warn 留痕（归一跳过不得静默）", logged)
	}
}
