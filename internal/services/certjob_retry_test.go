package services

import (
	"database/sql"
	"testing"
	"time"
)

// 下发口径的唯一语义：剩余时长按 updated_at 起算扣减（CA 退避窗口取到期时刻），
// 因此同一任务在时间流逝后下发的秒数递减，到期即为 0（现在可重试）。四态齐测，
// 防止「只对 waiting_ca 做过差」再次演化成静态时长。
//
// 期望秒数（wantSeconds）在表内**写死**，不得由被测的
// CertJobRetryCooldownSeconds 现算：取整口径（向上取整、剩余不足 1s 下发 1）
// 一旦回归成向下取整/0，现算表恒绿（恒等式）。表中带亚秒余量的行
// （90.4s→91、59.4s→60、0.1s→1、59.5s→60）即是取整口径的判别点。
func TestCertJobRetryRemaining_fourStatesWithTimePassage(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) sql.NullTime { return sql.NullTime{Time: now.Add(-d), Valid: true} }
	until := func(d time.Duration) sql.NullTime { return sql.NullTime{Time: now.Add(d), Valid: true} }
	var missing sql.NullTime

	cases := []struct {
		name          string
		status        string
		updatedAt     sql.NullTime
		createdAt     sql.NullTime
		caAvailableAt sql.NullTime
		wantRemaining time.Duration
		wantSeconds   int64
		wantRetryable bool
	}{
		{
			name: "waiting_ca 处于 CA 退避窗口取剩余", status: "waiting_ca",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: until(2 * time.Hour),
			wantRemaining: 2 * time.Hour, wantSeconds: 7200, wantRetryable: true,
		},
		{
			name: "waiting_ca CA 退避已到期即可重试", status: "waiting_ca",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: ago(time.Minute),
			wantRemaining: 0, wantSeconds: 0, wantRetryable: true,
		},
		{
			name: "waiting_ca CA 退避剩余不足一秒仍下发 1", status: "waiting_ca",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: until(100 * time.Millisecond),
			wantRemaining: 100 * time.Millisecond, wantSeconds: 1, wantRetryable: true,
		},
		{
			name: "waiting_ca CA 退避整 90 秒下发 90", status: "waiting_ca",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: until(90 * time.Second),
			wantRemaining: 90 * time.Second, wantSeconds: 90, wantRetryable: true,
		},
		{
			name: "waiting_ca CA 退避 90.4 秒向上取整", status: "waiting_ca",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: until(90*time.Second + 400*time.Millisecond),
			wantRemaining: 90*time.Second + 400*time.Millisecond, wantSeconds: 91, wantRetryable: true,
		},
		{
			name: "waiting_ca CA 退避 90.9 秒向上取整", status: "waiting_ca",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: until(90*time.Second + 900*time.Millisecond),
			wantRemaining: 90*time.Second + 900*time.Millisecond, wantSeconds: 91, wantRetryable: true,
		},
		{
			name: "failed 冷却窗口内按 updated_at 扣减", status: "failed",
			updatedAt: ago(4 * time.Minute), createdAt: ago(30 * time.Minute), caAvailableAt: missing,
			wantRemaining: time.Minute, wantSeconds: 60, wantRetryable: true,
		},
		{
			name: "failed 剩余 59.4 秒向上取整", status: "failed",
			updatedAt: ago(4*time.Minute + 600*time.Millisecond), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 59*time.Second + 400*time.Millisecond, wantSeconds: 60, wantRetryable: true,
		},
		{
			name: "failed 剩余不足一秒仍下发 1", status: "failed",
			updatedAt: ago(5*time.Minute - 100*time.Millisecond), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 100 * time.Millisecond, wantSeconds: 1, wantRetryable: true,
		},
		{
			name: "failed 剩余整 5 秒下发 5", status: "failed",
			updatedAt: ago(4*time.Minute + 55*time.Second), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 5 * time.Second, wantSeconds: 5, wantRetryable: true,
		},
		{
			name: "failed 冷却已到期", status: "failed",
			updatedAt: ago(5 * time.Minute), createdAt: ago(5 * time.Minute), caAvailableAt: missing,
			wantRemaining: 0, wantSeconds: 0, wantRetryable: true,
		},
		{
			name: "queued 冷却窗口内按 updated_at 扣减", status: "queued",
			updatedAt: ago(14 * time.Minute), createdAt: ago(14 * time.Minute), caAvailableAt: missing,
			wantRemaining: time.Minute, wantSeconds: 60, wantRetryable: true,
		},
		{
			name: "queued 剩余 59.5 秒向上取整", status: "queued",
			updatedAt: ago(14*time.Minute + 500*time.Millisecond), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 59*time.Second + 500*time.Millisecond, wantSeconds: 60, wantRetryable: true,
		},
		{
			name: "queued 剩余不足一秒仍下发 1", status: "queued",
			updatedAt: ago(14*time.Minute + 59*time.Second + 500*time.Millisecond), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 500 * time.Millisecond, wantSeconds: 1, wantRetryable: true,
		},
		{
			name: "queued 冷却已到期", status: "queued",
			updatedAt: ago(16 * time.Minute), createdAt: ago(16 * time.Minute), caAvailableAt: missing,
			wantRemaining: 0, wantSeconds: 0, wantRetryable: true,
		},
		{
			name: "issued 无通用冷却", status: "issued",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 0, wantSeconds: 0, wantRetryable: true,
		},
		{
			name: "updated_at 缺失回退 created_at", status: "failed",
			updatedAt: missing, createdAt: ago(3 * time.Minute), caAvailableAt: missing,
			wantRemaining: 2 * time.Minute, wantSeconds: 120, wantRetryable: true,
		},
		{
			name: "两列时间都缺失按刚更新计满窗口", status: "queued",
			updatedAt: missing, createdAt: missing, caAvailableAt: missing,
			wantRemaining: 15 * time.Minute, wantSeconds: 900, wantRetryable: true,
		},
		{
			name: "disabled 永久不可重试", status: "disabled",
			updatedAt: ago(0), createdAt: ago(0), caAvailableAt: missing,
			wantRemaining: 0, wantSeconds: 0, wantRetryable: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remaining, retryable := CertJobRetryRemaining(tc.status, tc.updatedAt, tc.createdAt, tc.caAvailableAt, now)
			if retryable != tc.wantRetryable {
				t.Fatalf("retryable=%v, want %v", retryable, tc.wantRetryable)
			}
			if remaining != tc.wantRemaining {
				t.Fatalf("remaining=%v, want %v", remaining, tc.wantRemaining)
			}
			seconds, ok := CertJobRetryRemainingSeconds(tc.status, tc.updatedAt, tc.createdAt, tc.caAvailableAt, now)
			if ok != tc.wantRetryable {
				t.Fatalf("seconds ok=%v, want %v", ok, tc.wantRetryable)
			}
			if !ok {
				return
			}
			if seconds != tc.wantSeconds {
				t.Fatalf("seconds=%d, want %d（下发口径=剩余时长向上取整，不足 1s 下发 1）", seconds, tc.wantSeconds)
			}
		})
	}
}

// 同一行在时间流逝后下发的秒数必须递减：这钉住「此刻剩余秒」而不是静态窗口。
func TestCertJobRetryRemainingSeconds_decreasesWithTime(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	updatedAt := sql.NullTime{Time: now, Valid: true}
	var missing sql.NullTime

	first, ok := CertJobRetryRemainingSeconds("queued", updatedAt, missing, missing, now)
	if !ok || first != 900 {
		t.Fatalf("刚更新 queued 剩余=%d ok=%v, want 900", first, ok)
	}
	later, ok := CertJobRetryRemainingSeconds("queued", updatedAt, missing, missing, now.Add(10*time.Minute))
	if !ok || later != 300 {
		t.Fatalf("10 分钟后 queued 剩余=%d ok=%v, want 300", later, ok)
	}
	expired, ok := CertJobRetryRemainingSeconds("queued", updatedAt, missing, missing, now.Add(15*time.Minute))
	if !ok || expired != 0 {
		t.Fatalf("到期后 queued 剩余=%d ok=%v, want 0（现在可重试）", expired, ok)
	}
	// 剩余不足 1 秒仍下发 1：0 的公开语义是「现在即可重试」。
	tail, ok := CertJobRetryRemainingSeconds("failed", updatedAt, missing, missing, now.Add(5*time.Minute-time.Millisecond))
	if !ok || tail != 1 {
		t.Fatalf("剩余不足 1 秒下发=%d ok=%v, want 1", tail, ok)
	}
}

// 非证书状态族永不返回剩余秒（ok=false），消费方据此下发 null 而非
// 「0=现在可重试」——永久不可重试与无冷却必须可区分。
func TestCertJobRetryRemainingSeconds_disabledIsNotZeroCooldown(t *testing.T) {
	now := time.Now()
	if seconds, ok := CertJobRetryRemainingSeconds("disabled", sql.NullTime{}, sql.NullTime{}, sql.NullTime{}, now); ok {
		t.Fatalf("disabled 不得以冷却秒数表达（seconds=%d, ok=true）", seconds)
	}
}
