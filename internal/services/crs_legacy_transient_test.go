package services

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W6 行为锚定测试：cleanupLegacyCRSTransient 的可观察契约是「删除具名瞬态
// 目标与 *.bak/*.old 后缀条目、保留其余全部内容，且清理动作留审计日志行、
// 目录缺失时静默无操作」。先于重构编写并在旧实现上验证通过（锁定现行为），
// 重构（单次 ReadDir + 集合判断）后必须保绿。

func TestCleanupLegacyCRSTransient_removesOnlyLegacyTransientArtifacts(t *testing.T) {
	// Given：crsDir 内种入四类具名瞬态目标、.bak/.old 后缀条目（文件与目录）
	// 以及必须保留的正式内容与边界形态
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// 具名瞬态目标（目录形态，内含残留文件）
	for _, name := range []string{".staging", "rules.bak", "rules.bak.tmp", "rules.old"} {
		write(filepath.Join(name, "leftover"), "x")
	}
	// 后缀形态：文件形（历史备份残件）与目录形
	write("crs-setup.conf.bak", "old setup")
	write("zz-user-overrides.conf.bak", "old overrides")
	write(filepath.Join("tree.old", "leftover.conf"), "x")
	// 正式内容：必须保留
	write(filepath.Join("rules", "REQUEST-901-INITIALIZATION.conf"), "SecRule")
	write("crs-setup.conf", "setup")
	write("VERSION", "v4.28.0\n")
	// 边界形态：非具名点前缀与 .bak 中缀（非后缀）——现行为不删，
	// 点前缀文件由 skipWafSyncTransient 的 tar 过滤另行兜底
	write(".hidden-marker", "keep")
	write("foo.bak.tmp", "keep")

	// When：成功更新路径执行遗留清理（捕获审计日志行）
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = dir
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	m.cleanupLegacyCRSTransient()

	// Then：瞬态目标全删（目录整树消失）
	for _, gone := range []string{".staging", "rules.bak", "rules.bak.tmp", "rules.old", "crs-setup.conf.bak", "zz-user-overrides.conf.bak", "tree.old"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed, stat err=%v", gone, err)
		}
	}
	// And：正式内容与边界形态全留
	for _, keep := range []string{
		filepath.Join("rules", "REQUEST-901-INITIALIZATION.conf"),
		"crs-setup.conf", "VERSION", ".hidden-marker", "foo.bak.tmp",
	} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("%s must be kept: %v", keep, err)
		}
	}
	// And：清理动作留痕——审计日志行点名删除数量（本用例恰为 7 个目标）
	if out := logBuf.String(); !strings.Contains(out, "cleaned 7 legacy transient artifacts") {
		t.Fatalf("expected cleanup audit log line, got %q", out)
	}
}

func TestCleanupLegacyCRSTransient_missingDirIsSilentNoop(t *testing.T) {
	// Given：crsDir 不存在（异常形态，如外置卷未挂载）
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = filepath.Join(t.TempDir(), "nonexistent")

	// When：执行遗留清理
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	m.cleanupLegacyCRSTransient() // 不得 panic

	// Then：静默无操作，不输出清理日志
	if logBuf.Len() != 0 {
		t.Fatalf("missing crsDir must be a silent no-op, got log: %q", logBuf.String())
	}
}
