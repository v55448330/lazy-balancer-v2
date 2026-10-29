package services

// lbbak 导入与三库更新器无写者互斥——CRS 树
// 交换、威胁库 .iplist+.fast 写编译、ip2region xdb 安装段各自为政，交错产生
// 混合/残缺 rules 树（部分防护静默失效）与撕裂 .iplist。修复=包级 wafFileMu
// 串行化四方文件相位。本文件用「预持锁→调用文件相位→必须阻塞至释放」的
// 确定性探针钉住互斥（今日无锁→不阻塞→RED；接线后阻塞→GREEN）。

import (
	"context"
	"testing"
	"time"
)

// probeBlocksUnderWafFileLock 预持 wafFileMu 运行 probe，断言其在持锁期间
// 不得完成（文件相位必须排队），释放后必须完成。
//
// 两个防假绿/假红要点：
//   - 探针真正启动后才开始计时（started 信号）——固定 300ms 判「未完成」会把
//     goroutine 调度延迟误当成「被锁阻塞」；
//   - 探针返回的错误必须外露（不再 t.Logf 吞）——被测函数在取锁前早退时，
//     探针会立即完成并返回业务错误，若吞错会被后续断言误报成「未入锁」。
func probeBlocksUnderWafFileLock(t *testing.T, name string, probe func() error) {
	t.Helper()
	WafFileLock().Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- probe()
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		WafFileLock().Unlock()
		t.Fatalf("%s 探针未在 5s 内启动（无法判定阻塞语义）", name)
	}
	select {
	case err := <-done:
		WafFileLock().Unlock()
		if err != nil {
			t.Fatalf("%s 在 wafFileMu 被预持期间完成并返回错误（取锁前早退，未入锁）：%v", name, err)
		}
		t.Fatalf("%s 在 wafFileMu 被预持期间完成——文件相位未入锁", name)
	case <-time.After(300 * time.Millisecond):
	}
	WafFileLock().Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s 锁释放后返回错误：%v", name, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s 在锁释放后 10s 内未完成", name)
	}
}

// Given wafFileMu 被预持（模拟并发的 lbbak 导入文件相位）。
// When 威胁库更新器的 writeThreatIplist+CompileFromIplistFile 写编译对执行。
// Then 必须阻塞至锁释放（.iplist/.fast 文件相位互斥）。
func TestWafFileWriters_threat_pair_blocks_while_waf_file_lock_held(t *testing.T) {
	dir := t.TempDir()
	restore := OverrideThreatWafDirForTest(dir)
	defer restore()
	setupIsolatedDB(t)

	probeBlocksUnderWafFileLock(t, "威胁库 .iplist+.fast 写编译对", func() error {
		_, err := writeThreatSystemList("ustc", []string{"1.2.3.4"})
		return err
	})
}

// Given wafFileMu 被预持。
// When ip2region 更新器 downloadAndInstall 进入安装文件段（备份+rename）。
// Then 必须阻塞至锁释放（下载在锁外——staging 先行，不受锁影响）。
func TestWafFileWriters_ip2region_install_blocks_while_waf_file_lock_held(t *testing.T) {
	m := newTestIP2RegionManager(t)
	m.downloadXDB = fakeIP2RegionDownload(t, true)

	probeBlocksUnderWafFileLock(t, "ip2region xdb 安装段", func() error {
		return m.downloadAndInstall(context.Background(), "v3.1.0")
	})
}

// Given wafFileMu 被预持。
// When CRS 更新器 downloadAndInstall 进入树交换段（RemoveAll+moveTree+setup 落盘）。
// Then 必须阻塞至锁释放；网络下载（已桩化）与 Caddy 重载（reloader）在锁外。
func TestWafFileWriters_crs_tree_swap_blocks_while_waf_file_lock_held(t *testing.T) {
	m := newTestCRSManager(t)
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})

	probeBlocksUnderWafFileLock(t, "CRS 树交换段", func() error {
		return m.downloadAndInstall(context.Background(), "v4.15.0")
	})
}

// Given wafFileMu 被预持（模拟并发的 lbbak 导入 / 集群同步文件相位）。
// When 启动对账的崩溃残留收敛执行（快照目录清理 / 点前缀 .conf 清理 / 孤儿威胁
// 名单删除——三项都直接改写 live 文件面）。
// Then 必须阻塞至锁释放：对账在锁外删 live 文件会与在途导入/同步的「写入→
// 提交」窗口交错，删掉对方刚 rename 的产物或读到半完成的树。
func TestWafFileReconcile_crashLeftovers_block_while_waf_file_lock_held(t *testing.T) {
	setupIsolatedDB(t)
	probeBlocksUnderWafFileLock(t, "崩溃残留对账（快照/点前缀规则/孤儿威胁名单）", func() error {
		ReconcileWafFileCrashLeftovers()
		return nil
	})
}
