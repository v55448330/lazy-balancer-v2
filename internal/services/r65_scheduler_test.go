package services

import (
	"testing"
	"time"
)

// R65 B-S2：rearmAfterCRSUpdate 的 overtaken 归属校验回归锁定（R64 B-F2）——
// 等待结束后若 m.runDone 已被更新的 run 接管（手动更新插队），本 tick 的失败
// 退避不得按他人终态重写；未接管且失败时正常写入退避排程。
func TestRearmAfterCRSUpdate_overtakenSkipsBackoffRewrite(t *testing.T) {
	_, database := newClusterTestService(t)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	prewritten := now.Add(24 * time.Hour).Format(crsTimeLayout)

	seed := func(failures int) {
		t.Helper()
		if _, err := database.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, next_update, consecutive_failures)
			VALUES (1, 'v', ?, ?)`, prewritten, failures); err != nil {
			t.Fatalf("seed crs version: %v", err)
		}
	}
	readNext := func() time.Time {
		t.Helper()
		var next string
		if err := database.QueryRow("SELECT next_update FROM security_crs_version WHERE id=1").Scan(&next); err != nil {
			t.Fatalf("read next_update: %v", err)
		}
		// SQLite 驱动可能把字符串归一为 RFC3339 读回，统一解析为时间比较。
		for _, layout := range []string{crsTimeLayout, time.RFC3339} {
			if parsed, err := time.Parse(layout, next); err == nil {
				return parsed
			}
		}
		t.Fatalf("next_update=%q 不可解析", next)
		return time.Time{}
	}
	prewrittenAt := now.Add(24 * time.Hour)

	t.Run("接管时跳过退避重写", func(t *testing.T) {
		seed(1)
		captured := make(chan struct{})
		close(captured) // 本 tick 的 run 已结束
		m := &CRSUpdateManager{runDone: make(chan struct{}), state: crsTaskState{status: CRSStatusFailed}}
		// m.runDone ≠ captured：模拟手动 run 已接管（微秒窗口插队）。

		m.rearmAfterCRSUpdate(now, make(chan struct{}), captured)

		if got := readNext(); !got.Equal(prewrittenAt) {
			t.Fatalf("next_update=%v, want 保持预写 %v（接管者的终态归操作者/后续 tick）", got, prewrittenAt)
		}
	})

	t.Run("未接管且失败时写入退避", func(t *testing.T) {
		seed(1)
		captured := make(chan struct{})
		close(captured)
		m := &CRSUpdateManager{runDone: captured, state: crsTaskState{status: CRSStatusFailed}}

		m.rearmAfterCRSUpdate(now, make(chan struct{}), captured)

		want := now.Add(time.Hour)
		if got := readNext(); !got.Equal(want) {
			t.Fatalf("next_update=%v, want 退避 %v", got, want)
		}
	})

	t.Run("成功终态不重写", func(t *testing.T) {
		seed(0)
		captured := make(chan struct{})
		close(captured)
		m := &CRSUpdateManager{runDone: captured, state: crsTaskState{status: CRSStatusSuccess}}

		m.rearmAfterCRSUpdate(now, make(chan struct{}), captured)

		if got := readNext(); !got.Equal(prewrittenAt) {
			t.Fatalf("next_update=%v, want 保持预写 %v", got, prewrittenAt)
		}
	})
}
