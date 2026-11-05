package caddygeoip

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// sweepTimingRegistryForStress 直接触发一次全片清扫（生产 sweeper 周期路径
// 同形：auditTimingSweepExpired 逐片加锁）。
var sweepTimingRegistryForStress = auditTimingSweepExpired

// 计时注册表并发正确性钉测（R-1 基线钉测试：钉既有正确行为，豁免 RED——
// 单锁与分片实现都必须绿）：并行注册/分段写/终态/读取/清扫交错下，
// ①不丢分段（每 id 的 pre/end/closed 全部可见）②清扫最终收敛（TTL 过期
// 条目全部回收，无死锁无泄漏）。门禁以 -race 运行本文件。
func TestAuditTimingRegistry_parallelStress(t *testing.T) {
	useTestAuditPipeline(t)
	// 清扫周期收窄到 50ms：并发写与周期清扫真实交错（TTL 50ms 由
	// useTestAuditPipeline 已置），收敛断言不用等默认 10s 周期。
	origSweep := auditTimingSweepIntervalNs.Load()
	auditTimingSweepIntervalNs.Store(int64(50 * time.Millisecond))
	t.Cleanup(func() {
		auditTimingSweepIntervalNs.Store(origSweep)
	})

	const workers = 8
	const opsPerWorker = 1500
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range opsPerWorker {
				id := fmt.Sprintf("%08x%08x", w, i)
				auditTimingRecord(id, timingSegmentPre, int64(i))
				auditTimingRecord(id, timingSegmentEnd, int64(i)+1)
				if auditTimingLogged(id) {
					t.Errorf("logged flag must default to false for fresh id %s", id)
				}
				auditTimingClose(id)
				snap := auditTimingWait(id, 200*time.Millisecond)
				if !snap.closed || !snap.preSet || !snap.endSet {
					t.Errorf("id %s snapshot = %+v; want closed with pre+end segments (no lost segments)", id, snap)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	// 清扫收敛：全部条目过期（TTL 50ms）后被周期清扫回收，注册表归零。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := len(auditTimingEntriesSnapshotForTest(t)); got == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("sweep must eventually reclaim all expired entries, %d remain (deadlock/leak suspicion)",
		len(auditTimingEntriesSnapshotForTest(t)))
}

// 并发 close 与 sweep 竞争同一批条目：sweep 的「删前先置终态」不变量
// 必须让 wait 侧永远不因删除而丢终态（锁分片后逐片清扫仍成立）。
func TestAuditTimingRegistry_parallelCloseAndSweep(t *testing.T) {
	useTestAuditPipeline(t)
	origSweep := auditTimingSweepIntervalNs.Load()
	auditTimingSweepIntervalNs.Store(int64(20 * time.Millisecond))
	t.Cleanup(func() { auditTimingSweepIntervalNs.Store(origSweep) })

	const ids = 400
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		for i := range ids {
			id := fmt.Sprintf("fedc%012x", i)
			auditTimingRecord(id, timingSegmentPre, 7)
			auditTimingClose(id)
		}
	}()
	// 与写侧并发地反复触发全表清扫（生产 sweeper 周期路径同形）。
	for done := false; !done; {
		select {
		case <-closeDone:
			done = true
		default:
			sweepTimingRegistryForStress(time.Now())
		}
	}
	<-closeDone

	// 每个 close 过的 id：要么仍在注册表（终态 closed），要么已被清扫
	// （wait 经未知 tid 降级返回）——两者都不得死锁或 panic。
	for i := range ids {
		id := fmt.Sprintf("fedc%012x", i)
		snap := auditTimingWait(id, time.Millisecond)
		if snap.preSet && !snap.closed {
			t.Fatalf("id %s has pre segment but no terminal state (sweep must close before delete)", id)
		}
	}
}
