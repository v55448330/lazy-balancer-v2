package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 完整但过期的快照必须自愈：更新时快照持久化失败会留下「live/DB 是新版本、
// 快照是完整旧版本」的合法状态；liveV==dbV 时 planCRSReconcile 判 none，旧快照
// 再无刷新入口——此后 /app/waf 挂载卷重建，启动播种会优先选该快照，把用户已
// 安装的更新静默回退。
func TestReconcileCRSState_healsStaleCompleteSnapshotFromLive(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")

	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule live-new")
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), "SecRule live 942")
	writeTestFile(t, filepath.Join(liveDir, "crs-setup.conf"), "# live setup")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.30.0\n")
	// 完整但落后一代的快照（更新后的快照持久化失败形态）
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule snapshot-old")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), "SecRule snapshot 942")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.29.0\n")

	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.30.0")

	if got := readCRSVersionMarker(snapshotDir); got != "v4.30.0" {
		t.Fatalf("快照 VERSION=%q, want v4.30.0（完整但落后的快照必须用 live 重建）", got)
	}
	snapshotRules, err := os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile))
	if err != nil || string(snapshotRules) != "SecRule live-new" {
		t.Fatalf("快照规则树=%q,%v；want live 内容（否则卷重建会装回旧规则）", snapshotRules, err)
	}
	// live 不得被旧快照覆盖
	if got := readCRSVersionMarker(liveDir); got != "v4.30.0" {
		t.Fatalf("live VERSION=%q, want v4.30.0（健康 live 不得被旧快照回退）", got)
	}

	// 端到端后果：清空 live（挂载卷重建）后播种必须选新版本快照而非旧规则。
	if err := os.RemoveAll(filepath.Join(liveDir, "rules")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(liveDir, crsVersionFile)); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule dist-bundled")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)
	if data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule live-new" {
		t.Fatalf("重建后播种结果=%q,%v；want 自愈后的快照内容", data, err)
	}
}

// 合法恢复路径不得被新鲜度自愈重写：snapV==dbV!=liveV 时快照是唯一恢复源，
// live 会被快照覆盖，快照自身必须保持原样。
func TestReconcileCRSState_keepsSnapshotWhenItIsTheRecoverySource(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule reverted")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.29.0\n")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule updated")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.30.0\n")

	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.30.0")

	if data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule updated" {
		t.Fatalf("live 规则树=%q,%v；want 从快照恢复的内容", data, err)
	}
	if got := readCRSVersionMarker(snapshotDir); got != "v4.30.0" {
		t.Fatalf("快照 VERSION=%q, want v4.30.0（恢复源不得被回退的 live 覆盖）", got)
	}
}

// bundled live 已存在完整但不同版本的快照时必须重建；缺席快照仍由既有
// skipsSnapshotRebuildForBundledLive 用例保持不写，避免无意义复制。
func TestReconcileCRSState_bundledLiveHealsStaleCompleteSnapshot(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule bundled")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), CRSBundledVersion+"\n")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule snapshot-stale")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v3.0.0\n")

	reconcileCRSStateFrom(liveDir, snapshotDir, CRSBundledVersion)

	if got := readCRSVersionMarker(snapshotDir); got != CRSBundledVersion {
		t.Fatalf("快照 VERSION=%q, want %q（陈旧快照必须按健康 live 自愈）", got, CRSBundledVersion)
	}
	if data, err := os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule bundled" {
		t.Fatalf("快照规则树=%q,%v；want bundled live 内容", data, err)
	}
}
