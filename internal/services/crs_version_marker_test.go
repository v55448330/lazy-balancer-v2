package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCRSUpdateRun_versionMarkerFailureRollsBackTreeAndVersion(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# old setup")
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.14.0\n")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":                "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901-INITIALIZATION.conf": "SecRule new\n",
	})
	oldWrite := crsVersionMarkerWrite
	crsVersionMarkerWrite = func(path string, data []byte, mode os.FileMode) error {
		if string(data) == "v4.15.0\n" {
			return errors.New("version marker write blocked")
		}
		return oldWrite(path, data, mode)
	}
	t.Cleanup(func() { crsVersionMarkerWrite = oldWrite })

	m.run("manual", nil)

	version, status, message, _, _, _, _ := crsVersionRow(t)
	if status == "success" || version != "v4.14.0" {
		t.Fatalf("marker failure produced version=%q status=%q message=%q, want rolled-back failed update", version, status, message)
	}
	data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("rules were not restored: data=%q err=%v", data, err)
	}
	if got := readCRSVersionMarker(m.crsDir); got != "v4.14.0" {
		t.Fatalf("marker=%q, want old version", got)
	}
}

// 回滚段（重载失败）的 VERSION 回写失败必须进入本轮结果门：规则树已还原、
// 版本行已回滚（下轮可重试），但磁盘标记仍指向更新后的版本——终态信息必须
// 显式披露这一跨代状态，不得按「回滚完成」收尾（否则面板只报「重载失败」，
// 运维无法知道版本追踪需要重启对账恢复）。
func TestCRSRun_rollbackVersionMarkerFailureSurfacedInResult(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# old setup")
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.14.0\n")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":                "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901-INITIALIZATION.conf": "SecRule new\n",
	})
	m.reloader = func() error { return errors.New("caddy reload failed") }
	// 安装段（写新版本标记）照常落盘；回滚段（写回旧版本）注入写失败。
	oldWrite := crsVersionMarkerWrite
	crsVersionMarkerWrite = func(path string, data []byte, mode os.FileMode) error {
		if string(data) == "v4.14.0\n" {
			return errors.New("disk full")
		}
		return oldWrite(path, data, mode)
	}
	t.Cleanup(func() { crsVersionMarkerWrite = oldWrite })

	m.run("manual", nil)

	version, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" || version != "v4.14.0" {
		t.Fatalf("version=%q status=%q，want 回滚后的 failed（版本行回滚保留重试能力）", version, status)
	}
	if !strings.Contains(message, "重载 Caddy") || !strings.Contains(message, "回滚") {
		t.Fatalf("终态 message=%q 未披露回滚期 VERSION 回写失败（按回滚完成收尾）", message)
	}
	// 写失败不得伪造成功：磁盘标记仍是安装段写入的新版本。
	if got := readCRSVersionMarker(m.crsDir); got != "v4.15.0" {
		t.Fatalf("marker=%q，want v4.15.0（写失败时标记保持原值）", got)
	}
	// 规则树必须已还原（回滚本身生效）。
	if data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule old" {
		t.Fatalf("规则树未还原: data=%q err=%v", data, err)
	}
}

// 启动对账补写 VERSION 标记失败同样不得按「对账完成」静默收尾：写函数只报底层
// IO 错误，上层必须声明本代对账未完成、下次启动重试同一分支（磁盘版本仍不可知）。
func TestReconcileCRS_writeMarkerFailureIsSurfaced(t *testing.T) {
	setupIsolatedDB(t)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule bundled")
	failCRSVersionMarkerWrite(t)
	buf := captureLogf(t)

	reconcileCRSStateFrom(liveDir, snapshotDir, CRSBundledVersion)

	out := buf.String()
	if !strings.Contains(out, "VERSION") || !strings.Contains(out, "对账") {
		t.Fatalf("补写标记失败未被对账层披露，日志=%q", out)
	}
	// 标记仍缺失（不得伪造落盘），下次启动重复同一分支。
	if got := readCRSVersionMarker(liveDir); got != "" {
		t.Fatalf("marker=%q，want 空（写失败不得伪造落盘）", got)
	}
}

func TestPersistCRSSnapshot_versionMismatchReturnsErrorAndKeepsOldSnapshot(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "live")
	snapshotDir := filepath.Join(root, "snapshot")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "other\n")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "previous\n")

	err := persistCRSSnapshotFrom(liveDir, snapshotDir, "expected")
	if !errors.Is(err, errCRSSnapshotVersionMismatch) {
		t.Fatalf("snapshot generation mismatch must fail with its typed error, got %v", err)
	}
	if got := readCRSVersionMarker(snapshotDir); got != "previous" {
		t.Fatalf("old snapshot was changed: marker=%q", got)
	}
}
