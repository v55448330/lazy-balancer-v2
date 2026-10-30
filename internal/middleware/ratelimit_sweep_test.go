package middleware

import (
	"testing"
	"time"
)

// TestSweepExpiredRateLimitBuckets_onlyRemovesClosedWindows 钉住清扫语义：
// 过窗桶删除、未过窗桶原样保留（含计数），清扫本身不越界扩容。
func TestSweepExpiredRateLimitBuckets_onlyRemovesClosedWindows(t *testing.T) {
	withIsolatedRateLimitBuckets(t)
	now := time.Now()

	expired := &loginRateBucket{count: 7, until: now.Add(-time.Second)}
	active := &loginRateBucket{count: 3, until: now.Add(time.Minute)}
	loginRateBuckets.Lock()
	loginRateBuckets.entries["192.0.2.1|login"] = expired
	loginRateBuckets.entries["192.0.2.2|login"] = active
	loginRateBuckets.Unlock()

	if removed := SweepRateLimitBuckets(now); removed != 1 {
		t.Fatalf("removed=%d, want 1（仅过窗桶可删）", removed)
	}
	loginRateBuckets.Lock()
	defer loginRateBuckets.Unlock()
	if _, exists := loginRateBuckets.entries["192.0.2.1|login"]; exists {
		t.Error("过窗桶未被删除")
	}
	retained, exists := loginRateBuckets.entries["192.0.2.2|login"]
	if !exists {
		t.Fatal("未过窗桶被误删")
	}
	if retained != active || retained.count != 3 {
		t.Errorf("未过窗桶状态被改动：%+v", retained)
	}
}

// TestSweepExpiredRateLimitBuckets_emptyTable 钉住空表安全（无锁序反转、返回 0）。
func TestSweepExpiredRateLimitBuckets_emptyTable(t *testing.T) {
	withIsolatedRateLimitBuckets(t)
	if removed := SweepRateLimitBuckets(time.Now()); removed != 0 {
		t.Fatalf("removed=%d, want 0", removed)
	}
}
