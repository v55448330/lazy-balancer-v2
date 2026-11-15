package services

// xdb 安装段（备份+rename，
// wafFileMu 互斥段内）与 security_ip2region_version 版本行/.version sidecar
// 写入（此前在锁外 run() 成功路径）分离——写相位中段（xdb 已换、行/sidecar
// 未写）导出侧（BuildWafFileBundle/BuildWafFileRef 读相位持同一锁）可打出
// 「文件新/行旧」偏斜（新 xdb sha + 旧 tag），沿 lbbak/集群 waf_files 通道扩散
// 并致 wafFilesDrifted 误判。修复=版本行与 sidecar 写入移入安装段同一互斥区
// （单行 UPDATE+小文件原子写毫秒级，与段内 rename 同量级）；重载失败的
// restored 回滚分支同步回滚行与 sidecar 到 prevVersion（磁盘已还原旧 xdb，
// 行/sidecar 必须跟随——否则引入新三方分叉）。

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Given wafFileMu 被预持（模拟并发的 lbbak 导入文件相位）。
// When ip2region 安装段（备份+rename+版本行/sidecar 写入）执行。
// Then 必须阻塞至锁释放；释放后 xdb、版本行、sidecar 同互斥区一致落成。
func TestIP2RegionUpdateManager_install_writes_version_state_inside_waf_file_lock(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.downloadXDB = fakeIP2RegionDownload(t, true)

	// 阻塞判定复用共享探针（started 正握手 + 探针错误外露）；固定负窗口
	// 无法区分「被锁阻塞」与「goroutine 调度延迟」——慢机上未入锁的实现
	// 也可能在窗口内未完成（假绿），此精度局限由探针的启动握手收敛，
	// 残余调度窗口内的区分力由释放后的终态断言承载。
	probeBlocksUnderWafFileLock(t, "ip2region install writes version state", func() error {
		return m.downloadAndInstall(context.Background(), "v3.1.0", true, false)
	})
	// 版本行随安装段落库——导出读相位（持同一锁）永远读不到文件新/行旧偏斜。
	if version, _, _, _, _, _, _ := ip2RegionVersionRow(t); version != "v3.1.0" {
		t.Fatalf("version row=%q, want v3.1.0（版本行写入必须随安装段同互斥区完成）", version)
	}
	// .version sidecar 同互斥区落盘（BuildWafFileRef 读它推导 ref.IP2RegionTag）。
	raw, err := os.ReadFile(ip2regionLivePath + ".version")
	if err != nil || strings.TrimSpace(string(raw)) != "v3.1.0" {
		t.Fatalf(".version sidecar=%q err=%v, want v3.1.0（sidecar 必须随安装段同互斥区完成）", strings.TrimSpace(string(raw)), err)
	}
	// prevVersion 锁内记录，供重载失败回滚（行/sidecar 跟随磁盘还原）。
	if m.prevVersion != "v3.0.0" {
		t.Fatalf("prevVersion=%q, want v3.0.0（锁内记录供 restored 分支回滚）", m.prevVersion)
	}
}
