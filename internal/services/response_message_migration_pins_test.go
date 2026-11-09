package services_test

import (
	"os"
	"strings"
	"testing"
)

// 2026-11 响应消息迁移批的行为钉（源码级断言——三条修复的运行时模拟成本高：
// D3-1 需叠加三方 I/O 故障、D3-2/D3-3 为日志与文案口径，源码断言即能防回退；
// 若后续改造为可注入形态，应升级为行为钉）。

// D3-1：moveTree 在 dst 就位后 src 清理失败必须降级 warn+成功——不得把清理
// 失败当整体失败（上层回滚会搬回旧树，而版本行已按新树落库=跨代静默）。
func TestCrsInstallMoveTreeSrcCleanupIsSoftFail(t *testing.T) {
	raw, err := os.ReadFile("crsinstall.go")
	if err != nil {
		t.Fatalf("读取 crsinstall.go: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, "kept new tree") {
		t.Fatalf("moveTree 缺少 src 清理失败的软失败分支（kept new tree）——回退清理失败当整体失败的旧形态会造成跨代静默")
	}
	// moveTree 尾部不得直接 return os.RemoveAll(src)（旧形态：清理失败=整体失败）
	if strings.Contains(src, "return os.RemoveAll(src)") {
		t.Fatalf("moveTree 仍直接返回 os.RemoveAll(src)——src 清理失败会再次被当整体失败")
	}
}

// D3-2：crawler 排程不可读必须 Logf 可见化（noop 兜底行为不变，但不得双零信号）。
func TestCrawlerSlotAdvanceAssignFailureIsLogged(t *testing.T) {
	raw, err := os.ReadFile("crawler_update.go")
	if err != nil {
		t.Fatalf("读取 crawler_update.go: %v", err)
	}
	if !strings.Contains(string(raw), "slot advance assign failed") {
		t.Fatalf("crawlerSlotAdvanceAssign 排程失败缺少 Logf 可见化——双零信号（无日志+无排程）会掩盖排程层故障")
	}
}

// D3-3：v6 探针未命中的文案必须与「结构损坏」区分（上游库重组缺探针段时
// 合法库被误判损坏且不可排障）。
func TestIP2RegionV6ProbeMissMessageDistinguishesFromCorruption(t *testing.T) {
	raw, err := os.ReadFile("ip2region.go")
	if err != nil {
		t.Fatalf("读取 ip2region.go: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, "非结构损坏") {
		t.Fatalf("v6 探针未命中文案缺少「非结构损坏」区分——与结构损坏同文案会误导排障方向")
	}
}
