package handlers

// 威胁大屏「活跃攻击源」计数的短 TTL 缓存：同窗口锚点内不重复扫描原始
// 事件表；窗口前移/缓存过期后重查；失败不缓存。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestThreatActiveSourcesCount_cachedWithinWindow(t *testing.T) {
	newBackupTestHandlers(t)
	resetThreatActiveSourcesCacheForTest()
	oldTTL := threatActiveSourcesCacheTTL
	threatActiveSourcesCacheTTL = 10 * time.Second
	t.Cleanup(func() { threatActiveSourcesCacheTTL = oldTTL; resetThreatActiveSourcesCacheForTest() })

	now := time.Now().UTC()
	since := now.Add(-10 * time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04:05")
	insert := func(ip string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (client_ip, action) VALUES (?, 'blocked')`, ip); err != nil {
			t.Fatal(err)
		}
	}
	insert("93.184.216.10")
	insert("93.184.216.11")
	insert("10.0.0.5")     // 私网/保留：不计入
	insert("203.0.113.13") // RFC 5737 文档段：同保留地址排除

	got, err := threatActiveSourcesCount(db.MetricsDB, since, now)
	if err != nil {
		t.Fatalf("first count: %v", err)
	}
	if got != 2 {
		t.Fatalf("首次活跃源=%d, want 2（保留地址排除）", got)
	}

	// 同窗口内新增源 IP：TTL 内必须命中缓存、不重查。
	insert("93.184.216.12")
	got, err = threatActiveSourcesCount(db.MetricsDB, since, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("cached count: %v", err)
	}
	if got != 2 {
		t.Fatalf("TTL 内活跃源=%d, want 2（缓存命中不得重查）", got)
	}

	// 过期后必须重查。
	got, err = threatActiveSourcesCount(db.MetricsDB, since, now.Add(11*time.Second))
	if err != nil {
		t.Fatalf("expired count: %v", err)
	}
	if got != 3 {
		t.Fatalf("过期后活跃源=%d, want 3（必须重查）", got)
	}

	// 窗口前移（新锚点）→ 新键，独立计数（此处窗口起点晚于全部事件之外时
	// 查询为空属预期，仅断言不返回旧窗口缓存值）。
	laterSince := now.Add(10 * time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04:05")
	got, err = threatActiveSourcesCount(db.MetricsDB, laterSince, now.Add(12*time.Second))
	if err != nil {
		t.Fatalf("shifted window count: %v", err)
	}
	if got != 0 {
		t.Fatalf("窗口前移后活跃源=%d, want 0（不得复用旧窗口缓存）", got)
	}
}

// 失败不缓存：指标库不可用时错误必须上抛且不落缓存（下一轮重试自愈）。
func TestThreatActiveSourcesCount_failureNotCached(t *testing.T) {
	newBackupTestHandlers(t)
	resetThreatActiveSourcesCacheForTest()
	t.Cleanup(resetThreatActiveSourcesCacheForTest)

	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := threatActiveSourcesCount(closed, "2026-10-22 00:00:00", time.Now()); err == nil {
		t.Fatal("关闭的指标库必须显式报错")
	}
	cached := threatActiveSourcesCache.Len()
	if cached != 0 {
		t.Fatalf("失败结果被缓存（%d 条）", cached)
	}
}

// —— ttlCache 单源的全形状覆盖（两种淘汰策略 + TTL 判定 + 同键覆盖）——

// TTL 判定：到期时刻之后按 miss 处理，到期前命中；同键重写覆盖旧值。
func TestTTLCache_getHonoursExpiryAndOverwrite(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cache := newTTLCache[string, int](0)
	cache.Set("k", 1, now, time.Second)
	if v, ok := cache.Get("k", now.Add(500*time.Millisecond)); !ok || v != 1 {
		t.Fatalf("到期前 Get=(%d,%v), want (1,true)", v, ok)
	}
	if _, ok := cache.Get("k", now.Add(2*time.Second)); ok {
		t.Fatal("到期后必须按 miss 处理")
	}
	cache.Set("k", 2, now, time.Second)
	if v, ok := cache.Get("k", now); !ok || v != 2 {
		t.Fatalf("同键重写后 Get=(%d,%v), want (2,true)", v, ok)
	}
	if _, ok := cache.Get("missing", now); ok {
		t.Fatal("不存在的键必须 miss")
	}
}

// 策略一（maxEntries>0）：条目数超过上限整体重建，再插入新条目——内存封顶
// 优先于逐出策略精度。
func TestTTLCache_resetAllEvictionBoundsFootprint(t *testing.T) {
	now := time.Now()
	cache := newTTLCache[int, int](4)
	for i := 0; i < 5; i++ {
		cache.Set(i, i, now, time.Minute)
	}
	if got := cache.Len(); got != 5 {
		t.Fatalf("未超上限时条目数=%d, want 5（上限 4 只在已超时重建）", got)
	}
	cache.Set(5, 5, now, time.Minute)
	if got := cache.Len(); got != 1 {
		t.Fatalf("超上限后条目数=%d, want 1（整体重建后只留本次写入）", got)
	}
	if !cache.Has(5) {
		t.Fatal("重建后必须保留本次写入的条目")
	}
}

// 策略二（maxEntries==0）：写入时逐键清扫过期项，仍在有效期的条目必须保留
// ——分钟锚定键族整体重置会打掉同屏其它维度条目，造成轮询抖动。
func TestTTLCache_sweepEvictionKeepsLiveEntries(t *testing.T) {
	now := time.Now()
	cache := newTTLCache[string, int](0)
	cache.Seed("expired", 1, now.Add(-time.Second))
	cache.Seed("live", 2, now.Add(time.Minute))
	cache.Set("fresh", 3, now, time.Minute)
	if cache.Has("expired") {
		t.Fatal("过期条目必须被写入侧清扫")
	}
	if !cache.Has("live") || !cache.Has("fresh") {
		t.Fatalf("有效条目不得被清扫（live=%v fresh=%v）", cache.Has("live"), cache.Has("fresh"))
	}
	if got := cache.Len(); got != 2 {
		t.Fatalf("清扫后条目数=%d, want 2", got)
	}
}

// 测试缝自身：Seed/ExpireMatching/Reset 必须与 Get 的到期判定同源。
func TestTTLCache_seamsMatchExpiryJudgement(t *testing.T) {
	now := time.Now()
	cache := newTTLCache[string, int](0)
	cache.Seed("k", 7, now.Add(time.Minute))
	if v, ok := cache.Get("k", now); !ok || v != 7 {
		t.Fatalf("Seed 后 Get=(%d,%v), want (7,true)", v, ok)
	}
	cache.ExpireMatching(func(k string) bool { return k == "k" })
	if _, ok := cache.Get("k", now); ok {
		t.Fatal("ExpireMatching 后必须按 miss 处理")
	}
	cache.Reset()
	if cache.Len() != 0 {
		t.Fatalf("Reset 后条目数=%d, want 0", cache.Len())
	}
}
