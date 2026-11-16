package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/wafiplist"
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

// Given 收窄的条目门（3 条）与 4 条合法 CIDR 的 .iplist 文本。
// When 三处生产消费（威胁装载有界读 / .fast 编译 / 从文本重建威胁 .fast）。
// Then 三处都返回拒绝错误（不是静默截断到上限）——条目门此前只有体积门
// 测试，三个消费点的拒绝形态零覆盖（门值被误删/改 >= 都不会红）。
func TestIplistEntryCap_rejectedAtEveryConsumer(t *testing.T) {
	oldCap := iplistTextMaxEntries
	iplistTextMaxEntries = 3
	t.Cleanup(func() { iplistTextMaxEntries = oldCap })

	entries := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}
	writeList := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("readIplistEntriesBounded", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "x.iplist")
		writeList(path)
		if _, err := readIplistEntriesBounded(path); err == nil || !strings.Contains(err.Error(), "条目数超过上限") {
			t.Fatalf("有界行展开必须拒绝超门文本, err=%v", err)
		}
	})

	t.Run("CompileFromIplistFile", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "y.iplist")
		writeList(path)
		if err := CompileFromIplistFile(path); err == nil || !strings.Contains(err.Error(), "条目数超过上限") {
			t.Fatalf(".fast 编译必须拒绝超门文本, err=%v", err)
		}
		if _, statErr := os.Stat(wafiplist.FastPath(path)); !os.IsNotExist(statErr) {
			t.Fatalf("拒绝形态不得写出 .fast（stat err=%v）", statErr)
		}
	})

	t.Run("healThreatFastFromText", func(t *testing.T) {
		dir := t.TempDir()
		t.Cleanup(OverrideThreatWafDirForTest(dir))
		writeList(filepath.Join(dir, "threat-ustc.iplist"))
		if _, ok := healThreatFastFromText("ustc"); ok {
			t.Fatal("文本重建必须拒绝超门 .iplist（保留上次快照）")
		}
	})
}
