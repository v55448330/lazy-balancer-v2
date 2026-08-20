package services

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSeedCRSRules_degenerateSnapshotFallsBackToDist 验证 R51 F2(a)：快照源
// 本身退化（persistCRSSnapshotFrom 崩溃窗口：RemoveAll 中途，VERSION 尚存 +
// rules 部分残留、探针缺失）时不得作种——播成退化 live 后下次启动探针
// 再清再播同源，形成跨重启循环。应回退 dist 并保留快照现场供诊断。
func TestSeedCRSRules_degenerateSnapshotFallsBackToDist(t *testing.T) {
	// Given 退化快照（rules 存在、含 .conf、缺探针，VERSION 完好）与完好的 dist
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule partial-snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When 播种
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then 回退 dist：live 携带探针、版本标记落 bundled，退化快照内容不进 live
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("degenerate snapshot must not seed live, want dist content: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatal("partial snapshot content must not land in live rules")
	}
	if got := readCRSVersionMarker(liveDir); got != CRSBundledVersion {
		t.Fatalf("live marker=%q, want bundled %q", got, CRSBundledVersion)
	}
	// 快照留现场供诊断（与 restoreRulesBackup 的「拒绝+留现场」语义一致）
	if got := readCRSVersionMarker(snapshotDir); got != "v4.15.0" {
		t.Fatalf("snapshot marker=%q, want preserved v4.15.0", got)
	}
}

// TestSeedCRSRules_degenerateSnapshotNoCrossRestartLoop 验证 R51 F2 的循环
// 闭合：同一退化快照下模拟两次启动，第二次必须是 no-op（live 完好即早退），
// 不得出现「live 退化 → 清空 → 从同一退化快照重播 → 仍退化」。
func TestSeedCRSRules_degenerateSnapshotNoCrossRestartLoop(t *testing.T) {
	// Given 退化快照与完好的 dist（同 F2 布景）
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule partial-snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When 模拟两次启动播种
	seedCRSRulesFrom(liveDir, snapshotDir, distDir) // boot 1：从 dist 播种
	seedCRSRulesFrom(liveDir, snapshotDir, distDir) // boot 2：live 完好，no-op

	// Then boot 2 后 live 仍是完好的 dist 树（未发生清空重播）
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("second boot must be a no-op on the intact dist-seeded tree: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatal("partial snapshot content must never land in live rules across boots")
	}
	if got := readCRSVersionMarker(liveDir); got != CRSBundledVersion {
		t.Fatalf("live marker=%q, want bundled %q", got, CRSBundledVersion)
	}
}

// TestRestoreCRSFromSnapshot_degenerateSnapshotRefused 验证 R51 F2(b)：
// 对账恢复在装入前对快照执行同一完整性探针——退化快照拒绝恢复（报错并
// 保留 live 现场），不得把弱化树装成权威树。
func TestRestoreCRSFromSnapshot_degenerateSnapshotRefused(t *testing.T) {
	// Given 完好的 live 树与退化快照（rules 存在、缺探针，VERSION 完好）
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule live")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule partial")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")

	// When 尝试从退化快照恢复
	err := restoreCRSFromSnapshot(liveDir, snapshotDir, "v4.15.0")

	// Then 拒绝恢复且 live 原样保留
	if err == nil {
		t.Fatal("restoreCRSFromSnapshot()=nil, want error for a degenerate snapshot")
	}
	data, rErr := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if rErr != nil || string(data) != "SecRule live" {
		t.Fatalf("live rules must be untouched when snapshot is degenerate: %q,%v", data, rErr)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatal("partial snapshot content must not land in live rules")
	}
}

// TestReconcileCRSState_degenerateSnapshotNotAuthoritative 验证 R51 F2(c)：
// liveV=="" 且探针不匹配时，旧逻辑拿快照覆盖 live
// （crsReconcileRestoreSnapshot）——快照自身退化时该分支把退化树当权威。
// 修复后退化快照按「无快照」处理：拒绝覆盖 live，仅记录。
func TestReconcileCRSState_degenerateSnapshotNotAuthoritative(t *testing.T) {
	// Given 无版本标记的 legacy live 树（与快照探针不匹配）+ 退化快照，
	// DB 记录版本等于快照版本（旧逻辑必走 RestoreSnapshot 分支）
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule legacy-live")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule partial")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")

	// When 启动对账
	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.15.0")

	// Then 拒绝把退化快照当权威：live 不被覆盖
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule legacy-live" {
		t.Fatalf("degenerate snapshot must not overwrite live: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "rules", "REQUEST-900.conf")); !os.IsNotExist(err) {
		t.Fatal("partial snapshot content must not land in live rules")
	}
}

// TestValidateCRSStaging_missingProbeRejected 验证 R51 F3：探针文件
// 「每个 CRS 发布必然携带」从假设变成安装期契约——缺探针的发布包（未来
// CRS 重组 rules/）在安装时即被拒绝，而不是装出退化树后触发 F2 循环。
func TestValidateCRSStaging_missingProbeRejected(t *testing.T) {
	// Given staging 有 setup 模板与 ≥1 个 .conf，但缺发布不变探针文件
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "crs-setup.conf.example"), "# setup")
	writeTestFile(t, filepath.Join(dir, "rules", "REQUEST-900.conf"), "SecRule 1")

	// When 校验
	// Then 拒绝（探针是 backup restore / seed / snapshot 消费门的公共契约）
	if err := validateCRSStaging(dir); err == nil {
		t.Fatal("validateCRSStaging()=nil, want error for rules tree missing the probe file")
	}
}
