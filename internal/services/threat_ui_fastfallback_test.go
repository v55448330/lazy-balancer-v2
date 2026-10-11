package services

// SEC-U2（第 69 轮 P2）：从节点 .iplist 文本缺失（waf_files 只同步 .fast）时
// UI 详情读面 ReadThreatIplistForUI 返回空集，与引擎按 .fast 全量拦截分裂。
// 修复：UI 读面补 .fast 回退（与渲染侧 readThreatIplistEntries 同口径）。

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

func TestReadThreatIplistForUI_fallsBackToFastOnSlave(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()

	// Given：从节点形态——仅 .fast 在场（无 .iplist 文本）
	v4 := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := wafiplist.WriteFastFile(wafiplist.FastPath(iplistPath), v4, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(iplistPath); !os.IsNotExist(err) {
		t.Fatalf("precondition: .iplist must be absent, stat err=%v", err)
	}

	// When
	vals, err := ReadThreatIplistForUI("中科大恶意 IP 名单（USTC）")

	// Then：.fast 回退展开，不返回空集
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(vals) != 1 || vals[0] != "192.0.2.0/24" {
		t.Fatalf("vals=%v, want [192.0.2.0/24]（.fast 回退展开）", vals)
	}
}
