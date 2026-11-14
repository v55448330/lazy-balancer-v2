package handlers

// 总览 rollup 读路径 Top10 recency 有界性钉测：recency（10m/1h/24h 三窗）
// 只消费 Top10 展示行——全量 GROUP BY 落 map 会把 24h 内全部 IP 的聚合搬进
// 进程内存（IP 基数无界），而消费面恒 ≤10 行。钉住：先取 Top10，再按这 10 个
// IP 有界 IN 重查 recency；结果与全量口径逐字段一致（纯性能收敛零口径变化）。

import (
	"fmt"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestSecurityOverviewRollupTopIP_recencyMatchesFullScan(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	metrics := db.MetricsDB

	now := time.Now().UTC().Truncate(time.Minute)
	minuteOf := func(d time.Duration) string { return now.Add(d).Format("2006-01-02 15:04") }
	windowStart := now.AddDate(0, 0, -6).Truncate(24 * time.Hour)
	seedRollupCoverage(t, windowStart, true)

	seedIPRollup := func(ip, minute, action string, count int) {
		t.Helper()
		if _, err := metrics.Exec(`INSERT INTO security_event_ip_rollup (minute, client_ip, action, count) VALUES (?, ?, ?, ?)`,
			minute, ip, action, count); err != nil {
			t.Fatalf("seed ip rollup %s: %v", ip, err)
		}
	}
	// Top10：7 天总量 100+i（降序排名稳定），各带三窗 recency 行。
	for i := range 10 {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		seedIPRollup(ip, minuteOf(-48*time.Hour), "blocked", 100+i)
		seedIPRollup(ip, minuteOf(-5*time.Minute), "blocked", 2)
		seedIPRollup(ip, minuteOf(-30*time.Minute), "logged", 3)
		seedIPRollup(ip, minuteOf(-2*time.Hour), "blocked", 4)
	}
	// 榜外 IP：仅 24h 窗口内的行（旧全量 GROUP BY 会全部落 map，新实现不得消费）。
	for i := range 25 {
		seedIPRollup(fmt.Sprintf("203.0.113.%d", i+1), minuteOf(-15*time.Minute), "blocked", 1)
	}
	// 榜外 IP：仅 24h 窗口之外的行（连 recency 重查都不应命中）。
	seedIPRollup("192.0.2.9", minuteOf(-48*time.Hour), "logged", 9)

	dayStarts := securityOverviewDayStarts(now)
	src, err := loadOverviewAggregatesFromRollup(metrics, dayStarts, now, now)
	if err != nil {
		t.Fatalf("rollup aggregates: %v", err)
	}
	if len(src.topRows) != 10 {
		t.Fatalf("topRows=%d, want 10", len(src.topRows))
	}
	for i, row := range src.topRows {
		wantIP := fmt.Sprintf("198.51.100.%d", 10-i)
		if row.ip != wantIP {
			t.Fatalf("topRows[%d].ip=%s, want %s（b+l 降序）", i, row.ip, wantIP)
		}
		if row.blocked != 100+(9-i)+2+4 || row.detected != 3 {
			t.Fatalf("topRows[%d]=(b=%d,l=%d), want (b=%d,l=3)", i, row.blocked, row.detected, 100+(9-i)+2+4)
		}
		if row.recent10m != 2 || row.recent1h != 5 || row.recent24h != 9 {
			t.Fatalf("topRows[%d] recency=(%d,%d,%d), want (2,5,9)（三窗合并与全量口径一致）",
				i, row.recent10m, row.recent1h, row.recent24h)
		}
		if row.lastTime != minuteOf(-5*time.Minute)+":00" {
			t.Fatalf("topRows[%d].lastTime=%s, want %s:00（7 天窗 MAX(minute)）", i, row.lastTime, minuteOf(-5*time.Minute))
		}
	}
}
