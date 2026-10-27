package services

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 行为锚定测试：cleanupLegacyCRSTransient 的可观察契约是「删除本产品自己产生
// 的具名瞬态目标、保留其余全部内容（含管理员手工留底的 *.bak/*.old 与任意
// 非具名条目），且清理动作留审计日志行（点名被删目标）、目录缺失时静默无操作」。
// 具名集合放宽为后缀兜底曾是数据丢失面：/app/waf/crs 下的 backup-2026.bak、
// ops-notes.bak、tree.old 会在一次成功更新后被静默删除。

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
	// 具名文件形瞬态（事务备份残件）
	write("crs-setup.conf.bak", "old setup")
	write("crs-setup.stock.conf.bak", "old stock")
	write("zz-user-overrides.conf.bak", "old overrides")
	// 正式内容：必须保留
	write(filepath.Join("rules", "REQUEST-901-INITIALIZATION.conf"), "SecRule")
	write("crs-setup.conf", "setup")
	write("VERSION", "v4.28.0\n")
	// 管理员手工留底/边界形态：一律保留——非具名点前缀由
	// skipWafSyncTransient 的 tar 过滤另行兜底，.bak/.old 后缀本身不再是删除判据
	write(".hidden-marker", "keep")
	write("foo.bak.tmp", "keep")
	write("backup-2026.bak", "ops backup")
	write("ops-notes.old", "ops notes")
	write(filepath.Join("tree.old", "leftover.conf"), "x")

	// When：成功更新路径执行遗留清理（捕获审计日志行）
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = dir
	var logBuf bytes.Buffer
	oldWriter, oldLevel := log.Writer(), CurrentLogLevel()
	log.SetOutput(&logBuf)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		// 级别是全局状态：只还原 writer 不够，任何前序用例把级别降到 warn
		// 都会让本用例（info 行）假红。
		_ = ConfigureLogLevel(oldLevel)
	})
	if err := ConfigureLogLevel("info"); err != nil {
		t.Fatal(err)
	}
	m.cleanupLegacyCRSTransient()

	// Then：瞬态目标全删（目录整树消失）
	for _, gone := range []string{".staging", "rules.bak", "rules.bak.tmp", "rules.old", "crs-setup.conf.bak", "crs-setup.stock.conf.bak", "zz-user-overrides.conf.bak"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed, stat err=%v", gone, err)
		}
	}
	// And：正式内容与边界形态全留
	for _, keep := range []string{
		filepath.Join("rules", "REQUEST-901-INITIALIZATION.conf"),
		"crs-setup.conf", "VERSION", ".hidden-marker", "foo.bak.tmp",
		// 运维投放物：.bak/.old 后缀不是删除判据
		"backup-2026.bak", "ops-notes.old",
		filepath.Join("tree.old", "leftover.conf"),
	} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("%s must be kept: %v", keep, err)
		}
	}
	// And：清理动作留痕——审计日志行点名删除数量与被删目标（本用例恰为 7 个）。
	// 只钉「动作 + 数量 + 具名目标」语义片段，不钉整句（文案打磨不应让守卫假红）。
	out := logBuf.String()
	if !strings.Contains(out, "cleaned 7") {
		t.Fatalf("expected cleanup audit log line with count 7, got %q", out)
	}
	for _, named := range []string{"rules.old", "crs-setup.stock.conf.bak"} {
		if !strings.Contains(out, named) {
			t.Fatalf("cleanup log 未点名被删目标 %q（不可归因）: %q", named, out)
		}
	}
}

func TestCleanupLegacyCRSTransient_missingDirIsSilentNoop(t *testing.T) {
	// Given：crsDir 不存在（异常形态，如外置卷未挂载）
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = filepath.Join(t.TempDir(), "nonexistent")

	// When：执行遗留清理
	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	m.cleanupLegacyCRSTransient() // 不得 panic

	// Then：静默无操作，不输出清理日志
	if logBuf.Len() != 0 {
		t.Fatalf("missing crsDir must be a silent no-op, got log: %q", logBuf.String())
	}
}
