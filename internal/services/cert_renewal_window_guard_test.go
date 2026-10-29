package services

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func setRenewalDays(t *testing.T, database *sql.DB, days int) {
	t.Helper()
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=? WHERE id=1", days); err != nil {
		t.Fatalf("set renewal days: %v", err)
	}
}

func seedRenewalWindowJob(t *testing.T, database *sql.DB, ruleID, domain string, notBefore, notAfter time.Time) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'window', ?, 'http', 8080, 1, 1, 'acme_dns')`, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	certPEM, keyPEM := certificatePairForDomains(t, notBefore, notAfter, domain)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id)
		VALUES (?, ?, 'issued', ?, ?, ?, 1)`, ruleID, domain, certPEM, keyPEM, notAfter.UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("seed job: %v", err)
	}
}

// 配置窗口在证书实际寿命下不可执行时（days*24h > NotAfter-NotBefore − 7 天）不得
// 每轮重签：此时「选中证书 NotAfter 晚于 now+窗口」的去抖门在成功签发后几乎恒假，
// 6h 扫描会把签下的证书反复入队；CA 重复证书限流后任务落 failed（只能手动重试），
// 约一个寿命周期后证书到期、TLS 中断。写侧/导入已收敛到安全上限
// （CertRenewalDaysMax），但 CA 实际签发的寿命可能短于规划值，因此扫描侧再用
// certRenewalWindowForLifetime 按真实寿命收敛到保护区，且剩余 ≤ 7 天必须放行续签。
func TestCheckExpiration_skipsRenewalWindowCoveringCertificateLifetime(t *testing.T) {
	now := time.Now()

	t.Run("max window covering shorter certificate lifetime", func(t *testing.T) {
		_, database := newClusterTestService(t)
		// 90 是旧契约值，读侧按安全上限 88 生效；证书实际寿命 88 天
		// （CA 缩短寿命）→ 窗口覆盖寿命，刚签发也不得再入队。
		setRenewalDays(t, database, CertRenewalLifetimeDays)
		seedRenewalWindowJob(t, database, "lb_window_90", "window90.example.com",
			now.Add(-time.Hour), now.Add(88*24*time.Hour-time.Hour))

		jobs, _, err := NewCertificateService().CheckExpiration(context.Background())
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("candidates=%d, want 0（窗口覆盖整张寿命，刚签发不得再入队）", len(jobs))
		}
	})

	t.Run("20 day lifetime with 30 day window", func(t *testing.T) {
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 30)
		seedRenewalWindowJob(t, database, "lb_window_30", "window30.example.com",
			now.Add(-time.Hour), now.Add(19*24*time.Hour))

		jobs, _, err := NewCertificateService().CheckExpiration(context.Background())
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("candidates=%d, want 0（30 天窗口 ≥ 20 天寿命）", len(jobs))
		}
	})

	t.Run("protection zone still renews", func(t *testing.T) {
		// 同一「窗口 ≥ 寿命」配置，但证书只剩 1 天：必须放行，避免配置越界
		// 演变成证书到期中断。
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 30)
		seedRenewalWindowJob(t, database, "lb_window_protect", "windowprotect.example.com",
			now.Add(-19*24*time.Hour), now.Add(24*time.Hour))

		jobs, _, err := NewCertificateService().CheckExpiration(context.Background())
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 1 {
			t.Fatalf("candidates=%d, want 1（剩余 ≤7 天保护区必须续签）", len(jobs))
		}
	})

	// 保护区边界是排他的：剩余恰 7 天不放行（否则边界上每轮都会重签），
	// 不足 7 天才放行。只测「剩 24h / 剩 19d」无法发现边界改成 >= 的回归。
	t.Run("grace boundary is exclusive", func(t *testing.T) {
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 90)
		notAfter := now.Add(certRenewalGuaranteedGrace + time.Hour)
		// 寿命 80 天 < 生效窗口 88 天 ⇒ 配置窗口不可执行、收敛到保护区；剩余
		// 7 天 + 1h 在保护区之外必须跳过（边界排他）。寿命取 90 天同样是不可
		// 执行配置，但会让「剩余」与寿命的关系不同，测不到本判据的边界值。
		seedRenewalWindowJob(t, database, "lb_window_grace_in", "windowgracein.example.com",
			notAfter.Add(-80*24*time.Hour), notAfter)

		jobs, _, err := NewCertificateService().CheckExpiration(context.Background())
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("candidates=%d, want 0（剩余 7 天 + 1h 仍在保护区之外）", len(jobs))
		}
	})

	t.Run("grace boundary inside renews", func(t *testing.T) {
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 90)
		notAfter := now.Add(certRenewalGuaranteedGrace - time.Hour)
		seedRenewalWindowJob(t, database, "lb_window_grace_out", "windowgraceout.example.com",
			notAfter.Add(-90*24*time.Hour), notAfter)

		jobs, _, err := NewCertificateService().CheckExpiration(context.Background())
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 1 {
			t.Fatalf("candidates=%d, want 1（剩余 7 天 - 1h 已进入保护区）", len(jobs))
		}
	})
}
