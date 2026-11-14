package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lbbak 导入编译链（WriteThreatIplistCompiled）必须有可解析率门（与下载/heal
// 同源阈值 threatMinParseRatio）：垃圾备份大面积不可解析时拒绝落盘并保留本地
// 文件，不得静默削弱 live 威胁名单（聚合归零后照常落盘=拦截面静默缩水）。

// Given 文本名单大面积损坏（可解析率 <50%）。
// When WriteThreatIplistCompiled 尝试编译落盘。
// Then 拒绝（返回错误）、不触碰 live .iplist/.fast（保留本地文件）。
func TestWriteThreatIplistCompiled_rejectsLowParseRatio(t *testing.T) {
	dir := t.TempDir()
	iplistPath := filepath.Join(dir, "threat-ustc.iplist")
	oldText := []byte("192.0.2.1\n")
	if err := WriteThreatIplistCompiled(iplistPath, oldText); err != nil {
		t.Fatalf("seed compiled threat files: %v", err)
	}
	oldFast, err := os.ReadFile(iplistPath + ".fast")
	if err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	sb.WriteString("203.0.113.1\n") // 1 条合法
	for range 9 {
		sb.WriteString("not-an-ip-garbage-line\n")
	}
	err = WriteThreatIplistCompiled(iplistPath, []byte(sb.String()))
	if err == nil {
		t.Fatal("可解析率 1/10 低于 50% 必须拒绝落盘")
	}
	if !strings.Contains(err.Error(), "可解析") {
		t.Fatalf("错误须点名可解析率门: %v", err)
	}
	// live 文件逐字节保留（拒绝不得覆盖本地文件）。
	gotText, err := os.ReadFile(iplistPath)
	if err != nil || string(gotText) != string(oldText) {
		t.Fatalf("拒绝后 live .iplist 必须保留: %q err=%v", gotText, err)
	}
	gotFast, err := os.ReadFile(iplistPath + ".fast")
	if err != nil || string(gotFast) != string(oldFast) {
		t.Fatalf("拒绝后 live .fast 必须保留: err=%v", err)
	}
}

// 回归形状：可解析率 ≥50% 的文本照常编译落盘。
func TestWriteThreatIplistCompiled_acceptsHealthyRatio(t *testing.T) {
	dir := t.TempDir()
	iplistPath := filepath.Join(dir, "threat-ustc.iplist")
	content := "203.0.113.1\n198.51.100.0/24\n10.0.0.0/8\nbogus-line\n"
	if err := WriteThreatIplistCompiled(iplistPath, []byte(content)); err != nil {
		t.Fatalf("可解析率 3/4 应通过编译门: %v", err)
	}
	if _, err := os.Stat(iplistPath + ".fast"); err != nil {
		t.Fatalf("编译成功须落 .fast: %v", err)
	}
}

// 边界形状：空/仅注释文本（total=0）拒绝——不得以空集编译落盘。
func TestWriteThreatIplistCompiled_rejectsEmptyText(t *testing.T) {
	dir := t.TempDir()
	iplistPath := filepath.Join(dir, "threat-ustc.iplist")
	if err := WriteThreatIplistCompiled(iplistPath, []byte("# only comment\n\n")); err == nil {
		t.Fatal("空/仅注释文本必须拒绝（不得以空集落盘）")
	}
	if _, err := os.Stat(iplistPath); !os.IsNotExist(err) {
		t.Fatal("拒绝不得产生 live 文件")
	}
}
