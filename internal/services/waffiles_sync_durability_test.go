package services

// 从节点 waf 包解包（untarGzTo）的落盘耐久性钉：逐文件 fsync 与 CRS 发行包
// 解包（extractCRSTarball）同口径——staging 树随后换入 live，掉电窗口内未
// fsync 的页可能留下 0 字节/截断规则文件，静默削弱 WAF。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Given 注入真实失败机制的落盘同步缝（Sync 失败只能经缝构造——磁盘故障
// 无法用真实文件注入，与 ip2RegionDownloadSync 同款约定）。
// When 解包一个合法规则包。
// Then 同步失败必须上抛且 live 树零变化（未 fsync 的 staging 不得换入）。
func TestUntarGzTo_syncFailureRejectsInstallAndKeepsLiveTree(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "crs")
	liveFile := filepath.Join(destDir, "rules", "REQUEST-900.conf")
	if err := os.MkdirAll(filepath.Dir(liveFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveFile, []byte("SecRule OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-901.conf", body: []byte("SecRule NEW")},
	})

	oldSync := wafSyncExtractSync
	wafSyncExtractSync = func(*os.File) error { return errors.New("injected sync failure") }
	t.Cleanup(func() { wafSyncExtractSync = oldSync })

	err := untarGzTo(payload, destDir, "")
	if err == nil || !strings.Contains(err.Error(), "落盘同步失败") {
		t.Fatalf("同步失败必须上抛落盘同步错误, got %v", err)
	}
	data, rerr := os.ReadFile(liveFile)
	if rerr != nil || string(data) != "SecRule OLD" {
		t.Fatalf("同步失败后 live 树必须原样: data=%q err=%v", data, rerr)
	}
	if _, serr := os.Stat(filepath.Join(destDir, "rules", "REQUEST-901.conf")); !os.IsNotExist(serr) {
		t.Fatalf("未 fsync 的新文件不得进入 live 树: %v", serr)
	}
}

// 回归形状：正常路径逐文件真实 fsync（缝默认 (*os.File).Sync），解包成功
// 且内容完整—— durability 门不得误伤正常同步。
func TestUntarGzTo_successPathSyncsEveryFile(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "crs")
	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-901.conf", body: []byte("SecRule NEW-A")},
		{name: "rules/REQUEST-902.conf", body: []byte("SecRule NEW-B")},
	})

	oldSync := wafSyncExtractSync
	synced := 0
	wafSyncExtractSync = func(f *os.File) error {
		synced++
		return f.Sync()
	}
	t.Cleanup(func() { wafSyncExtractSync = oldSync })

	if err := untarGzTo(payload, destDir, ""); err != nil {
		t.Fatalf("untar: %v", err)
	}
	if synced != 2 {
		t.Fatalf("逐文件 fsync 次数=%d, want 2（每个常规文件一次）", synced)
	}
	for name, want := range map[string]string{
		"rules/REQUEST-901.conf": "SecRule NEW-A",
		"rules/REQUEST-902.conf": "SecRule NEW-B",
	} {
		data, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil || string(data) != want {
			t.Fatalf("%s 内容=%q err=%v, want %q", name, data, err, want)
		}
	}
}
