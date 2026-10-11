package services

// SEC-C-U2（第 69 轮 P3）：schedulerTick 先触发后写槽——在途（含手动插队）时
// StartUpdate 是唯一原子门，不推进 next_update；旧序先写槽会空耗排程槽且不回填。

import (
	"context"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestCRSSchedulerTick_inFlightDoesNotAdvanceSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	// 排程槽到期（过去时刻）
	past := time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1", past); err != nil {
		t.Fatal(err)
	}
	// 手动更新在途（阻塞 fetch 持锁）
	release := make(chan struct{})
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		select {
		case <-release:
			return "", errors.New("查询失败")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("manual StartUpdate: %v", err)
	}
	defer func() { close(release); <-done }()

	// When：在途期间 tick 到期槽
	m.schedulerTick(time.Now().UTC())

	// Then：槽不推进（仍为过期的原槽）
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if nextUpdate != past {
		t.Fatalf("next_update=%q, want 原槽 %q（在途不推进）", nextUpdate, past)
	}
}
