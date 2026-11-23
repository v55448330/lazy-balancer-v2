package services

// 审计保留 cutoff 按日历月回退并钳到目标月末：time.AddDate 在月末会溢出
// （3-31 回退 1 月 → Go 归一为 3-3，cutoff 偏移 3 天），保留时长随运行日期漂移。

import (
	"testing"
	"time"
)

func TestAuditRetentionCutoff_clampsToTargetMonthEnd(t *testing.T) {
	cases := []struct {
		name   string
		now    time.Time
		months int
		want   time.Time
	}{
		{
			name:   "normal day",
			now:    time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC),
			months: 1,
			want:   time.Date(2025, 12, 15, 8, 30, 0, 0, time.UTC),
		},
		{
			name:   "month end clamps",
			now:    time.Date(2026, 3, 31, 8, 30, 0, 0, time.UTC),
			months: 1,
			want:   time.Date(2026, 2, 28, 8, 30, 0, 0, time.UTC),
		},
		{
			name:   "leap year february",
			now:    time.Date(2024, 3, 31, 0, 0, 0, 0, time.UTC),
			months: 1,
			want:   time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC),
		},
		{
			name:   "year boundary",
			now:    time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC),
			months: 1,
			want:   time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name:   "multi month",
			now:    time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
			months: 3,
			want:   time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditRetentionCutoff(tc.now, tc.months); !got.Equal(tc.want) {
				t.Fatalf("auditRetentionCutoff(%s, %d)=%s, want %s", tc.now, tc.months, got, tc.want)
			}
		})
	}
}
