package taskengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendTaskLogLine_rotatesBeforeWriteAtConfiguredThreshold(t *testing.T) {
	// Given：两个独立日志文件，共享 64B 阈值；A 已超阈，B 未超阈
	dir := t.TempDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir("") })
	SetTaskLogSizeBytesFn(func() int64 { return 64 })
	t.Cleanup(func() { SetTaskLogSizeBytesFn(nil) })
	if err := os.WriteFile(filepath.Join(dir, "a.log"), []byte(strings.Repeat("a", 60)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.log"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：A 写入导致 size+line 超阈；B 写入仍低于阈值
	taskLogAppend("a", "next")
	taskLogAppend("b", "next")

	// Then：只有 A 在写入前滚动；活动文件只剩新内容，B 不受影响
	rotated, err := os.ReadFile(filepath.Join(dir, "a.log.1"))
	if err != nil {
		t.Fatalf("A 未在写入前滚动: %v", err)
	}
	if len(rotated) != 60 {
		t.Errorf("A.1 大小=%d want 60（真实文件大小驱动）", len(rotated))
	}
	active, err := os.ReadFile(filepath.Join(dir, "a.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(active), strings.Repeat("a", 60)) || !strings.Contains(string(active), "next") {
		t.Errorf("A 活动文件未在滚动后重建: %q", active)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.log.1")); !os.IsNotExist(err) {
		t.Errorf("B 不应滚动: err=%v", err)
	}
}
