package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// countCRSAudits 按 action 统计 CRS规则库 的操作日志条数。
func countCRSAudits(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='CRS规则库' AND action=?", action).Scan(&n); err != nil {
		t.Fatalf("count audit entries: %v", err)
	}
	return n
}

// TestNormalizeLegacySecurityPolicyEnums_bumpsOnce_whenRowTriggerInstalled 验证
// R55-B-F1：二次启动起行级版本触发器已持久化于库（middleware 首次启动时安装），
// 归一的每条 UPDATE 会按命中行数触发 bump——与显式 bump 叠加后一次启动净增
// 必须仍为 +1（版本只需单调递增；测试环境无触发器，断言 before+1，两处口径
// 必须一致）。
func TestNormalizeLegacySecurityPolicyEnums_bumpsOnce_whenRowTriggerInstalled(t *testing.T) {
	// Given 主节点 + 生产形态的行级 UPDATE 版本触发器 + 一条遗留空串行
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER cluster_version_security_policies_update
		AFTER UPDATE ON security_policies
		WHEN (SELECT COALESCE(is_master,0) FROM global_config WHERE id=1)=1
		BEGIN
			UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
		END`); err != nil {
		t.Fatal(err)
	}
	insertLegacyPolicyRow(t, "legacy-all", "", "", "")
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 触发器 bump 与显式 bump 合并为净 +1（生产与测试口径一致）
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want %d (trigger + explicit bump must coalesce into exactly one)", v, before+1)
	}
}

// TestCRSUpdateRun_snapshotPersistFailureIsAudited 验证 R55-B-F2：更新本身成功
// 但数据卷快照持久化失败时，除组件日志外必须写一条操作日志——否则未挂载
// /app/waf 的部署在容器重建后静默回退到镜像捆绑版本，重建前无任何可见信号。
func TestCRSUpdateRun_snapshotPersistFailureIsAudited(t *testing.T) {
	// Given 一次可成功的更新 + 不可写的快照目录（父路径是普通文件）
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0644); err != nil {
		t.Fatal(err)
	}
	oldSnapshotDir := crsSnapshotDir
	crsSnapshotDir = filepath.Join(blocker, "snap")
	t.Cleanup(func() { crsSnapshotDir = oldSnapshotDir })

	// When 更新跑完（快照持久化失败）
	m.run("manual")

	// Then 更新仍按成功落库（磁盘规则树已是新版本）
	version, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "success" || version != "v4.15.0" {
		t.Fatalf("update row=(%q,%q), want success at v4.15.0 (persist failure must not fail the update)", status, version)
	}
	// And 快照持久化失败留有操作日志，重建前运维可见
	if got := countCRSAudits(t, "写入失败"); got != 1 {
		t.Fatalf("persist-failure audits=%d, want 1 (degraded snapshot state must be operator-visible)", got)
	}
}
