package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadIplistTextBounded_rejectsOversize：.iplist 文本读取有体积门——
// 超限报错（引擎侧 .fast 同款口径），不做无界分配。
func TestReadIplistTextBounded_rejectsOversize(t *testing.T) {
	old := iplistTextMaxBytes
	iplistTextMaxBytes = 16
	t.Cleanup(func() { iplistTextMaxBytes = old })
	path := filepath.Join(t.TempDir(), "x.iplist")
	if err := os.WriteFile(path, []byte(strings.Repeat("1.2.3.4\n", 4)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIplistTextBounded(path); err == nil {
		t.Fatal("超限文件应报错，不得无界读入")
	}
}

// TestReadIplistTextBounded_normalFile：门内文件正常读取。
func TestReadIplistTextBounded_normalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.iplist")
	if err := os.WriteFile(path, []byte("1.2.3.4\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := readIplistTextBounded(path)
	if err != nil {
		t.Fatalf("门内读取失败: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("len=%d, want 16", len(raw))
	}
}
