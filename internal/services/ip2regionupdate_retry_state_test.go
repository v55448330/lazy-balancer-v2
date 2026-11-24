package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	ip2regionService "github.com/lionsoul2014/ip2region/binding/golang/service"
)

// v6 源安装结果按「每次下载安装尝试」复位，而不是只在整轮运行开始时复位：
// 下载安装在任务内重试里会被重复调用，上一轮尝试遗留的 attempted=true 会让
// 第二轮里已成功下载并通过校验的 v6 库被安装门挡住——工件丢在 staging、
// 源状态停在上一轮的失败文案，直到下一排程轮才纠正。
func TestIP2RegionUpdate_downloadAndInstallResetsV6OutcomePerAttempt(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	seedV6Row(t, true, "")
	writeTestXDB(t, ip2regionLivePath, testSegments)
	withIP2RegionV6Paths(t, filepath.Join(filepath.Dir(ip2regionLivePath), "ip2region_v6.xdb"), filepath.Join(filepath.Dir(ip2regionLivePath), "missing-dist-v6.xdb"))
	m.downloadXDBV6 = fakeV6Download(t, true)
	oldReload := reloadIP2RegionSearcher
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })
	var reloaded *ip2regionService.Ip2Region
	reloadIP2RegionSearcher = func(searcher *ip2regionService.Ip2Region) error {
		reloaded = searcher
		return nil
	}

	// Given 上一轮尝试遗留的 v6 失败态（第一轮 v6 下载/校验失败、v4 安装
	// 失败触发任务内重试——第二轮入口的真实形态）。
	m.v6InstallAttempted = true
	m.v6InstallSucceeded = false
	m.v6InstallError = "下载失败: injected first-attempt failure"

	// When 第二轮 v6 下载成功（v4 已是最新，无需重装）。
	if err := m.downloadAndInstall(context.Background(), "v3.1.0", false, true); err != nil {
		t.Fatalf("download and install: %v", err)
	}
	if reloaded != nil {
		defer reloaded.Close()
	}

	// Then 已成功下载的 v6 库必须落盘，源状态不得停在上一轮的失败文案。
	if !m.v6InstallSucceeded || m.v6InstallError != "" {
		t.Fatalf("第二轮 v6 成功必须安装: succeeded=%v error=%q", m.v6InstallSucceeded, m.v6InstallError)
	}
	if _, err := os.Stat(ip2regionV6LivePath); err != nil {
		t.Fatalf("v6 live 文件必须已安装: %v", err)
	}
	// 版本行仍由 run() 成功路径写入（集群语义列的 bump 时点不在本修复范围）。
}
