package services

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// 续签窗口的「寿命-窗口」盲区：证书实际寿命 L 只比配置窗口 W 大一点点时
// （CA 按天/小时签发，L ∈ (W, W+最小节奏]），首次入队发生在剩余 ≤ W，下一次
// 入队间隔退化为 L−W——W=88 天 + CA 实际签发 88.5 天时 L−W=12h，每轮扫描都会
// 整轮重签，5 次/周即触发 CA 重复证书限流（签发失败后自动续签链终止）。
// 扫描侧按真实寿命把窗口收敛到「可执行窗口」：W 无法在 L 下执行时退到保护区，
// 只在到期前 7 天内续签（节奏 L−7 天），且库值不被改写。
func TestCheckExpiration_lifetimeJustAboveWindowDoesNotRenewDaily(t *testing.T) {
	now := time.Now()
	// CA 实际签发 88.5 天（W=89 的旧契约值读侧按安全上限 88 生效）→ L−W=12h。
	const lifetime = 88*24*time.Hour + 12*time.Hour
	cases := []struct {
		name      string
		age       time.Duration
		wantRenew bool
	}{
		{"13h after issuance", 13 * time.Hour, false},
		{"25h after issuance (previous daily re-entry)", 25 * time.Hour, false},
		{"45d into 88.5d lifetime", 45 * 24 * time.Hour, false},
		{"remaining 7.5d outside protection zone", 81 * 24 * time.Hour, false},
		{"remaining 6.5d inside protection zone", 82 * 24 * time.Hour, true},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			// 旧版本遗留的 89 天：库值原样保留，读侧按安全上限 88 天生效。
			setRenewalDays(t, database, CertRenewalLifetimeDays-1)
			notBefore := now.Add(-tc.age)
			suffix := strconv.Itoa(index)
			seedRenewalWindowJob(t, database, "lb_blind_"+suffix, "blind-"+suffix+".example.com",
				notBefore, notBefore.Add(lifetime))

			jobs, skipped, err := NewCertificateService().CheckExpiration(context.Background())
			if err != nil {
				t.Fatalf("check expiration: %v", err)
			}
			if skipped != 0 {
				t.Fatalf("scan skipped=%d, want 0", skipped)
			}
			if got := len(jobs) == 1; got != tc.wantRenew {
				t.Fatalf("candidates=%d, want renew=%v（L=88.5d、W=88d、age=%s）", len(jobs), tc.wantRenew, tc.age)
			}
		})
	}
}

// 单源：配置窗口 + 证书实际寿命 → 本轮可执行窗口。
func TestCertRenewalWindowForLifetime_table(t *testing.T) {
	const day = 24 * time.Hour
	cases := []struct {
		name     string
		window   time.Duration
		lifetime time.Duration
		want     time.Duration
	}{
		// 正常配置：窗口留足最小节奏，原样执行（零行为变化）。
		{"90d lifetime 30d window", 30 * day, 90 * day, 30 * day},
		{"90d lifetime 60d window", 60 * day, 90 * day, 60 * day},
		{"90d lifetime 83d window", 83 * day, 90 * day, 83 * day},
		// 盲区：L 只比 W 大一点 → 退到保护区。
		{"88.5d lifetime 88d window", 88 * day, 88*day + 12*time.Hour, certRenewalGuaranteedGrace},
		{"90d lifetime 88d window (safe max)", 88 * day, 90 * day, certRenewalGuaranteedGrace},
		{"80d lifetime 88d window (covers lifetime)", 88 * day, 80 * day, certRenewalGuaranteedGrace},
		{"20d lifetime 30d window (covers lifetime)", 30 * day, 20 * day, certRenewalGuaranteedGrace},
		{"85d lifetime 84d window", 84 * day, 85 * day, certRenewalGuaranteedGrace},
		// 短寿命证书：最小节奏按半寿命收敛，保护区不超过寿命本身。
		{"10d lifetime 30d window", 30 * day, 10 * day, 5 * day},
		{"5d lifetime 30d window", 30 * day, 5 * day, 5 * day / 2},
		{"14d lifetime 30d window", 30 * day, 14 * day, certRenewalGuaranteedGrace},
		// 未知寿命/零窗口：保持既有语义（窗口门由上游契约兜底）。
		{"unknown lifetime", 30 * day, 0, 30 * day},
		{"zero window", 0, 90 * day, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := certRenewalWindowForLifetime(tc.window, tc.lifetime)
			if got != tc.want {
				t.Fatalf("effective window=%s, want %s (window=%s lifetime=%s)", got, tc.want, tc.window, tc.lifetime)
			}
			// 不变量：窗口被收敛时，相邻两次自动续签的间隔（L−eff）必须 ≥ 最小节奏，
			// 否则仍会每日/亚日级重签。
			if got != tc.window && tc.lifetime > 0 {
				minCadence := certRenewalGuaranteedGrace
				if half := tc.lifetime / 2; half < minCadence {
					minCadence = half
				}
				if cadence := tc.lifetime - got; cadence < minCadence {
					t.Fatalf("cadence=%s < minCadence=%s（收敛后仍会密集重签）", cadence, minCadence)
				}
			}
		})
	}
}
