package middleware

import (
	"testing"
	"time"
)

// 窗口换代防线：旧窗口的在途预占在换代后释放时不得扣减新窗口计数。
// 生产形态=机器端点请求跨分钟窗完成（认证+DB 查询 + 慢 handler），释放时
// 桶已被新一轮 reserve 重置 generation；若照常 count-- 会把新窗口的首个
// 请求额度「退」回去，等效放宽限流。
func TestReleaseRateLimitReservation_ignoresStaleWindow(t *testing.T) {
	withIsolatedRateLimitBuckets(t)

	base := time.Now()
	const ip, scope, limit = "198.51.100.9", "generation-probe", 10
	oldBucket, oldGeneration, ok, _ := reserveRateLimitBucket(ip, scope, base, limit)
	if !ok {
		t.Fatal("首轮预占应放行")
	}
	if oldBucket.count != 1 {
		t.Fatalf("首轮预占后 count=%d, want 1", oldBucket.count)
	}

	// When 跨窗：同一桶被新一轮请求重置并重新计数
	newBucket, newGeneration, ok, _ := reserveRateLimitBucket(ip, scope, base.Add(2*time.Minute), limit)
	if !ok {
		t.Fatal("新窗口预占应放行")
	}
	if newBucket != oldBucket {
		t.Fatal("同键应复用同一桶实例（换代只重置计数）")
	}
	if newGeneration != oldGeneration+1 {
		t.Fatalf("换代编号=%d, want %d", newGeneration, oldGeneration+1)
	}
	if newBucket.count != 1 {
		t.Fatalf("新窗口计数=%d, want 1", newBucket.count)
	}

	// Then 旧窗口的在途请求释放（成功语义=回滚预占）必须被忽略
	releaseRateLimitReservation(oldBucket, oldGeneration, false)
	if newBucket.count != 1 {
		t.Fatalf("旧窗口释放污染了新窗口计数：count=%d, want 1", newBucket.count)
	}

	// 同窗口释放照常回滚（防回归：守卫不得退化为「永不释放」）
	releaseRateLimitReservation(newBucket, newGeneration, false)
	if newBucket.count != 0 {
		t.Fatalf("同窗口成功释放后 count=%d, want 0", newBucket.count)
	}

	// 失败语义（401）保留额度——同窗口
	keptBucket, keptGeneration, ok, _ := reserveRateLimitBucket(ip, scope, base.Add(3*time.Minute), limit)
	if !ok {
		t.Fatal("新窗口预占应放行")
	}
	releaseRateLimitReservation(keptBucket, keptGeneration, true)
	if keptBucket.count != 1 {
		t.Fatalf("失败请求不得回滚预占：count=%d, want 1", keptBucket.count)
	}
}

func TestReserveRateLimitBucket_computesRetryAfterWithRejection(t *testing.T) {
	withIsolatedRateLimitBuckets(t)
	now := time.Now()
	const ip, scope = "198.51.100.10", "retry-after-atomic"
	loginRateBuckets.Lock()
	loginRateBuckets.entries[ip+"|"+scope] = &loginRateBucket{count: 1, until: now.Add(17 * time.Second)}
	loginRateBuckets.Unlock()

	_, _, allowed, retryAfter := reserveRateLimitBucket(ip, scope, now, 1)
	if allowed {
		t.Fatal("bucket at its limit must reject the reservation")
	}
	if retryAfter != 17 {
		t.Fatalf("Retry-After=%d, want 17 from the rejection critical section", retryAfter)
	}
}
