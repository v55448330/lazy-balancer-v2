package caddyl4sec

// L4 事件管线生产收尾冲刷钉测：FlushL4Pipeline 必须有生产收尾冲刷，
// 进程退出/Cleanup 时环内+批内尾部行不得静默丢失（镜像 HTTP FlushAuditPipelines）。
// 合并窗口钉测：多实例 Cleanup 收尾总时长与实例数解耦（claimL4Flush），
// 窗口内省等待不省冲刷；idle-seal 失败告警节流（rotate 节流同族补位）。

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// FlushL4Pipeline 冲刷进程级管线尾部行（不关闭管线，进程级单例裁决不变）。
func TestFlushL4Pipeline_drainsTailEvents(t *testing.T) {
	socket, bodies := startUnixIngestServer(t, http.StatusNoContent)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	defer p.resetForTest()

	l1 := buildL4EventLine(2, "IP 黑名单拒绝", "r1", "203.0.113.1", time.Unix(1, 11), [4]byte{1, 2, 3, 4}, true)
	p.enqueueEvent(l1)
	// 不手动 flushQuiescedForTest，直接调生产收尾函数——尾部行必须送达。
	FlushL4Pipeline()

	got := bodies()
	if len(got) == 0 {
		t.Fatal("FlushL4Pipeline 必须冲刷尾部行到 ingest（停机静默丢失回归钉）")
	}
	sent, _, _, _ := p.shipperCounters()
	if sent != 1 {
		t.Fatalf("sent = %d, want 1（尾部行经 FlushL4Pipeline 送达）", sent)
	}
}

// 无管线时 FlushL4Pipeline 安全 no-op（未创建=nil）。
func TestFlushL4Pipeline_nilSafe(t *testing.T) {
	FlushL4Pipeline() // 不得 panic
}

// 合并窗口领取语义：首个领取成功，窗口内重复领取快进，窗口过后可再领取。
func TestL4FlushCoalescing_claimWindow(t *testing.T) {
	oldWindow := l4FlushCoalesceWindow
	l4FlushCoalesceWindow = 20 * time.Millisecond
	t.Cleanup(func() {
		l4FlushCoalesceWindow = oldWindow
		l4LastFlushNano.Store(0)
	})
	l4LastFlushNano.Store(0)

	if !claimL4Flush() {
		t.Fatal("首次领取必须成功")
	}
	if claimL4Flush() {
		t.Fatal("窗口内重复领取必须快进")
	}
	time.Sleep(30 * time.Millisecond)
	if !claimL4Flush() {
		t.Fatal("窗口过后必须可再次领取")
	}
}

// Given 持续事件流量（submit 落点卡住在途行，pending 恒 >0）。
// When 3 个安全路由实例并发调 Cleanup 收尾冲刷（镜像 HTTP 侧同代际形态）。
// Then 总墙钟 ≈ 单窗口（首个等满 + 其余小额有界排空），不得 N×满窗叠加；
// 窗口内后续实例必须快进（收尾成本与实例数解耦）。
func TestFlushL4Pipeline_multiInstanceCleanupCoalesced(t *testing.T) {
	socket, _ := startUnixIngestServer(t, http.StatusNoContent)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	oldWindow := l4FlushCoalesceWindow
	l4FlushCoalesceWindow = l4FlushDrainWait
	t.Cleanup(func() {
		l4FlushCoalesceWindow = oldWindow
		l4LastFlushNano.Store(0)
	})
	l4LastFlushNano.Store(0)

	// 在途行卡在 submit 落点（环已空、pending>0）——首个 Cleanup 必须等它。
	entered := make(chan struct{})
	release := make(chan struct{})
	p.setSubmitSinkForTest(func(line []byte) {
		close(entered)
		<-release
		p.shipper.submit(line)
	})
	var releaseOnce sync.Once
	releaseSubmit := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() {
		releaseSubmit()
		p.resetForTest()
	}()
	p.enqueueEvent(buildL4EventLine(5, "IP 黑名单拒绝", "r-coalesce", "203.0.113.5", time.Unix(5, 55), [4]byte{5, 5, 5, 5}, true))
	<-entered

	const instances = 3
	start := time.Now()
	var wg sync.WaitGroup
	for range instances {
		wg.Add(1)
		go func() {
			defer wg.Done()
			FlushL4Pipeline()
		}()
	}
	// 给并发 Cleanup 一点时间领取资格/进入等待，再放掉在途行。
	time.Sleep(100 * time.Millisecond)
	releaseSubmit()
	wg.Wait()
	elapsed := time.Since(start)
	budget := l4FlushDrainWait + time.Duration(instances)*l4FlushCoalescedDrainWait + 500*time.Millisecond
	if elapsed > budget {
		t.Fatalf("%d 实例 Cleanup 总墙钟 %v > %v——合并窗口缺失，各等满 %v 叠加", instances, elapsed, budget, l4FlushDrainWait)
	}
}

// 串行形态（E1 复现口径）：持续事件流量下逐个实例 Cleanup，首个等满后
// 其余必须落在合并窗口内快进——总墙钟 ≈ 单窗口，不得 N×满窗叠加。
// 用生产默认窗口（2×l4FlushDrainWait）：首个等满 l4FlushDrainWait 返回时
// 仍在窗口内，后续实例快进（小额有界排空）。
func TestFlushL4Pipeline_serialCleanupCoalesced(t *testing.T) {
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	defer p.resetForTest()
	t.Cleanup(func() { l4LastFlushNano.Store(0) })
	l4LastFlushNano.Store(0)

	p.blockDrainForTest(true)
	defer p.blockDrainForTest(false)
	p.enqueueEvent([]byte(`{"ts":1786447300123,"rule_id":"lb-serial","kind":"blocked"}`))

	const instances = 3
	start := time.Now()
	for range instances {
		FlushL4Pipeline()
	}
	elapsed := time.Since(start)
	// 首个 Cleanup 等满 l4FlushDrainWait（pending 恒 >0）；后续实例窗口内
	// 快进（小额有界排空）。总墙钟应 ≈ 单窗口，远小于 N×满窗。
	budget := l4FlushDrainWait + time.Duration(instances)*l4FlushCoalescedDrainWait + 400*time.Millisecond
	if elapsed > budget {
		t.Fatalf("%d 实例串行 Cleanup 总墙钟 %v > %v——合并窗口缺失，各等满 %v 叠加", instances, elapsed, budget, l4FlushDrainWait)
	}
}

// 窗口内 Cleanup 省掉的只能是等待时长，不能是冲刷本身：批内滞留行必须在
// 有界排空后照常投递（窗口内紧跟进程停止时这是唯一收尾机会）。
func TestFlushL4Pipeline_coalescedStillFlushes(t *testing.T) {
	socket, bodies := startUnixIngestServer(t, http.StatusNoContent)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	defer p.resetForTest()
	oldWindow := l4FlushCoalesceWindow
	l4FlushCoalesceWindow = time.Minute
	t.Cleanup(func() {
		l4FlushCoalesceWindow = oldWindow
		l4LastFlushNano.Store(0)
	})
	l4LastFlushNano.Store(0)

	// Given 上一次 reload 已领到冲刷资格（本次 Cleanup 落在合并窗口内）。
	if !claimL4Flush() {
		t.Fatal("首个冲刷资格必须领取成功（前置条件）")
	}
	// 一行直接进批（批龄未到周期阈值，滞留批内）。
	p.shipper.submit(buildL4EventLine(2, "IP 黑名单拒绝", "r-coalesced", "203.0.113.2", time.Unix(2, 22), [4]byte{2, 2, 2, 2}, true))

	FlushL4Pipeline()

	got := bodies()
	if len(got) == 0 {
		t.Fatal("窗口内 Cleanup 必须照常冲刷批内滞留行（省等待不省冲刷）")
	}
	sent, _, _, _ := p.shipperCounters()
	if sent != 1 {
		t.Fatalf("sent = %d, want 1（窗口内 Cleanup 冲刷送达）", sent)
	}
}

// 窗口内 Cleanup 的小额有界排空必须等到在途 submit 完成后再冲刷——省掉的
// 只能是等待时长，在队/在途行都要尽量送达。
func TestFlushL4Pipeline_coalescedDrainsInFlightRows(t *testing.T) {
	socket, bodies := startUnixIngestServer(t, http.StatusNoContent)
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", socket)
	setSpoolDirForTest(t, filepath.Join(t.TempDir(), "spool"))
	p := acquirePipelineForTest()
	oldWindow := l4FlushCoalesceWindow
	l4FlushCoalesceWindow = time.Minute
	t.Cleanup(func() {
		l4FlushCoalesceWindow = oldWindow
		l4LastFlushNano.Store(0)
	})
	l4LastFlushNano.Store(0)

	entered := make(chan struct{})
	release := make(chan struct{})
	p.setSubmitSinkForTest(func(line []byte) {
		close(entered)
		<-release
		p.shipper.submit(line)
	})
	var releaseOnce sync.Once
	releaseSubmit := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() {
		releaseSubmit()
		p.resetForTest()
	}()

	if !claimL4Flush() {
		t.Fatal("首个冲刷资格必须领取成功（前置条件）")
	}
	p.enqueueEvent(buildL4EventLine(3, "IP 黑名单拒绝", "r-inflight", "203.0.113.3", time.Unix(3, 33), [4]byte{3, 3, 3, 3}, true))
	<-entered // drain 已弹出（环空），submit 在途。
	// 在途行 50ms 后提交完成：窗口内 Cleanup 的有界排空必须等到它。
	go func() {
		time.Sleep(50 * time.Millisecond)
		releaseSubmit()
	}()
	start := time.Now()
	FlushL4Pipeline()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("窗口内 Cleanup 等待 %v；有界排空必须 ≤%v", elapsed, l4FlushCoalescedDrainWait)
	}
	if got := bodies(); len(got) == 0 {
		t.Fatal("窗口内 Cleanup 必须在有界窗口内排空在途行并冲刷送达")
	}
	sent, _, _, _ := p.shipperCounters()
	if sent != 1 {
		t.Fatalf("sent = %d, want 1（在途行经窗口内 Cleanup 送达）", sent)
	}
}

// idle-seal 失败告警必须节流（首次立即，其后每分钟一条并携带被抑制数）：
// 持续封存故障下 drain ticker 每 l4FlushInterval 重试一次，不节流即按
// ticker 频率洪泛 ERROR 日志（与 rotateLocked 的 sealLog 同族同口径）。
func TestShipperIdleSealFailureLogThrottled(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "spool")
	setSpoolDirForTest(t, spoolDir)
	shipper := newL4Shipper(filepath.Join(t.TempDir(), "absent.sock"))
	defer func() { _ = shipper.spool.close() }()
	if n, err := shipper.spool.appendLines([][]byte{[]byte(`{"k":"v"}`)}); err != nil || n != 1 {
		t.Fatalf("baseline appendLines = %d, %v; want 1, nil", n, err)
	}
	// 真实故障注入：spool 目录改为只读（r-x）——active fd 仍有效（flush
	// 成功），sealIfIdle 的 os.Rename 需要目录写权限，真实失败（EACCES）；
	// active 保持打开，每次 flushIfDue 都重试并失败（持续故障形态）。
	if err := os.Chmod(spoolDir, 0o500); err != nil {
		t.Fatalf("chmod spool dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(spoolDir, 0o750) })

	var mu sync.Mutex
	var logs []string
	oldLog := l4IOLogf
	l4IOLogf = func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { l4IOLogf = oldLog })

	future := time.Now().Add(2 * l4SpoolIdleSeal)
	for range 20 {
		shipper.flushIfDue(future)
	}
	mu.Lock()
	n := len(logs)
	var first string
	if n > 0 {
		first = logs[0]
	}
	mu.Unlock()
	if n != 1 {
		t.Fatalf("20 次持续 idle-seal 失败告警 %d 条, want 1（首次立即，窗口内抑制）", n)
	}
	if !strings.Contains(first, "idle seal failed") {
		t.Fatalf("首条告警文案失真: %q", first)
	}
}
