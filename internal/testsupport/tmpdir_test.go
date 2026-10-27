package testsupport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureUsableTempDirRecoversReclaimedDir(t *testing.T) {
	root := t.TempDir()
	reclaimed := filepath.Join(root, "reclaimed-tmp")
	if err := os.MkdirAll(reclaimed, 0o700); err != nil {
		t.Fatal(err)
	}
	// 模拟沙箱在运行中回收 TMPDIR：目录被删、env 仍指向它。
	if err := os.RemoveAll(reclaimed); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", reclaimed)

	if err := EnsureUsableTempDir(); err != nil {
		t.Fatalf("被回收但可重建的 TMPDIR 必须自愈: %v", err)
	}
	if _, err := os.Stat(reclaimed); err != nil {
		t.Fatalf("TMPDIR 未被重建: %v", err)
	}
	if entries, err := os.ReadDir(reclaimed); err == nil && len(entries) != 0 {
		t.Fatalf("探针文件未清理: %v", entries)
	}
}

func TestEnsureUsableTempDirReportsUnusablePath(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 父路径是文件：既不能 MkdirAll 也不能写探针。
	t.Setenv("TMPDIR", filepath.Join(blocker, "tmp"))

	err := EnsureUsableTempDir()
	if err == nil {
		t.Fatal("不可用的 TMPDIR 必须显式报错（否则 t.TempDir() 会级联假红）")
	}
	if !strings.Contains(err.Error(), "TMPDIR") {
		t.Fatalf("error=%v, want 点名 TMPDIR（环境问题而非产品回归）", err)
	}
}
