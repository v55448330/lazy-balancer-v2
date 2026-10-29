package caddygeoip

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// geoip fail-stale/重建失败告警必须按（路径+原因）节流：一次 reload 会为
// 每条地域规则各调一次 sharedGeoIPSearcher，不节流则 50 条规则 = 50 行相同
// WARN/次 reload；恢复成功后清除记录（再次故障即时上报）。
func TestGeoIPWarnThrottled_dedupesPerPathAndClears(t *testing.T) {
	oldInterval := geoipWarnThrottle.interval
	geoipWarnThrottle.interval = time.Minute
	t.Cleanup(func() {
		geoipWarnThrottle.interval = oldInterval
		geoipWarnThrottle.reset()
		geoipWarnCallsForTest.Store(0)
	})
	geoipWarnThrottle.reset()
	geoipWarnCallsForTest.Store(0)

	geoipWarnThrottled("stat", "/data/ip2region.xdb", "m")
	geoipWarnThrottled("stat", "/data/ip2region.xdb", "m")
	if got := geoipWarnCallsForTest.Load(); got != 1 {
		t.Fatalf("同路径同原因告警次数=%d, want 1（按窗口节流）", got)
	}
	// 不同原因独立节流（stat 失败与重建失败不是同一事件）
	geoipWarnThrottled("rebuild", "/data/ip2region.xdb", "m")
	if got := geoipWarnCallsForTest.Load(); got != 2 {
		t.Fatalf("不同原因告警次数=%d, want 2", got)
	}
	// 恢复后清除：再次故障必须立即上报
	clearGeoIPWarnLogs("/data/ip2region.xdb")
	geoipWarnThrottled("stat", "/data/ip2region.xdb", "m")
	if got := geoipWarnCallsForTest.Load(); got != 3 {
		t.Fatalf("恢复后再次故障告警次数=%d, want 3（清除节流记录）", got)
	}
}

// 无缓存失败形态（库尚未落地/权限错/带外损坏）必须走同一节流：这是最常见
// 的失败分支，且 Provision 按每条地域规则调用一次——不节流则 WARN 按规则数
// 放大。重启节流记录后连续 N 次调用只允许一条 WARN。
func TestSharedGeoIPSearcher_noCacheFailuresWarnOnce(t *testing.T) {
	oldInterval := geoipWarnThrottle.interval
	geoipWarnThrottle.interval = time.Minute
	t.Cleanup(func() {
		geoipWarnThrottle.interval = oldInterval
		geoipWarnThrottle.reset()
		geoipWarnCallsForTest.Store(0)
	})
	geoipWarnThrottle.reset()
	geoipWarnCallsForTest.Store(0)

	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.xdb")
	for i := 0; i < 5; i++ {
		if _, err := sharedGeoIPSearcher(missing); err == nil {
			t.Fatal("缺失的 xdb 必须返回 error（无缓存可 fail-stale）")
		}
	}
	if got := geoipWarnCallsForTest.Load(); got != 1 {
		t.Fatalf("无缓存 stat 失败告警次数=%d, want 1（按路径+原因节流）", got)
	}

	// 重建失败且无缓存：独立原因键，同样只报一次。
	corrupt := filepath.Join(dir, "corrupt.xdb")
	if err := os.WriteFile(corrupt, []byte("not an ip2region database"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := sharedGeoIPSearcher(corrupt); err == nil {
			t.Fatal("损坏的 xdb 在无缓存时必须返回 error")
		}
	}
	if got := geoipWarnCallsForTest.Load(); got != 2 {
		t.Fatalf("无缓存重建失败告警次数=%d, want 2（独立原因键新增一条）", got)
	}
}
