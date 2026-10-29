package services

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 续签窗口接近证书寿命（90 天寿命下 ≥ 89 天，即「寿命-24h」）时，窗口门与
// 成功侧迟滞数学等价：证书一签发就落进窗口，每轮扫描整轮重签 → CA 重复证书
// 限流 → 任务 failed → 约一个寿命后证书到期中断。治理单源=安全上限
// CertRenewalDaysMax：写侧拒绝、导入钳制、读侧按上限生效（库值不静默改写）。

func TestGetCertRenewalDays_clampsLegacyWindowAboveSafeMax(t *testing.T) {
	_, database := newClusterTestService(t)
	buf := captureApplicationLogs(t)

	// 存量/旧备份遗留的越界窗口：库值原样保留，但本轮生效窗口收敛到安全上限
	// 并显性 error 留痕（不得静默改写存量配置）。
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=89 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if got := GetCertRenewalDays(); got != CertRenewalDaysMax {
		t.Fatalf("cert_renewal_days=89: GetCertRenewalDays()=%d, want %d（安全上限）", got, CertRenewalDaysMax)
	}
	logged := buf.String()
	if !strings.Contains(logged, "89") || !strings.Contains(logged, "ERROR") || !strings.Contains(logged, "cert_renewal_days") {
		t.Fatalf("cert_renewal_days=89: log=%q, want error 级留痕（值 + 字段名）", logged)
	}
	var stored int
	if err := database.QueryRow("SELECT cert_renewal_days FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 89 {
		t.Fatalf("stored=%d, want 89（读侧不得改写存量库值）", stored)
	}

	// 90（写侧旧上界）同样收敛；安全上限本身与更低值原样生效且不告警。
	for _, tc := range []struct {
		stored   int
		want     int
		wantWarn bool
	}{
		{90, CertRenewalDaysMax, true},
		{CertRenewalDaysMax, CertRenewalDaysMax, false},
		{60, 60, false},
	} {
		if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=? WHERE id=1", tc.stored); err != nil {
			t.Fatal(err)
		}
		buf.Reset()
		if got := GetCertRenewalDays(); got != tc.want {
			t.Fatalf("cert_renewal_days=%d: GetCertRenewalDays()=%d, want %d", tc.stored, got, tc.want)
		}
		if warned := strings.Contains(buf.String(), "ERROR"); warned != tc.wantWarn {
			t.Fatalf("cert_renewal_days=%d: warned=%v, want %v (log=%q)", tc.stored, warned, tc.wantWarn, buf.String())
		}
	}
}

// 引擎级行为验证：存量 89 天窗口下，签发 25h 后剩余 88.5 天的证书不得被选中
// （旧实现按 89 天窗口选中 → 日级重签）；进入保护区（剩余 ≤ 7 天）的证书照常
// 续签——收敛是窗口门的事，不得把自动续签变成永久跳过。
func TestCheckExpiration_legacyWindowAboveSafeMaxDoesNotChurnDaily(t *testing.T) {
	_, database := newClusterTestService(t)
	now := time.Now()
	seed := func(ruleID string, notBefore, notAfter time.Time) int64 {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,'http','example.com',8443,1,1,'acme_dns')`, ruleID, ruleID); err != nil {
			t.Fatalf("seed rule %s: %v", ruleID, err)
		}
		certPEM, keyPEM := certificatePairForDomains(t, notBefore, notAfter, "example.com")
		result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,expires_at,updated_at)
			VALUES (?,'example.com','issued',0,?,?,?,datetime('now','-25 hours'))`, ruleID, certPEM, keyPEM,
			notAfter.UTC().Format("2006-01-02 15:04:05"))
		if err != nil {
			t.Fatalf("seed job %s: %v", ruleID, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=89 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// A：25h 前签发、剩余 88.5 天——旧 89 天窗口下会与其等价重签。
	// 收敛后可执行窗口是保护区：剩余 88.5 天远在保护区之外，不得入队。
	idA := seed("lb_hi_window", now.Add(-25*time.Hour), now.Add(88*24*time.Hour+12*time.Hour))
	// B：剩余 6 天（寿命 90 天 > 上限窗口）——已进保护区，必须照常进入续签候选
	// （收敛不得把自动续签变成永久跳过）。
	idB := seed("lb_normal_window", now.Add(-90*24*time.Hour+6*24*time.Hour), now.Add(6*24*time.Hour))
	if _, err := database.Exec("UPDATE cert_jobs SET updated_at=datetime('now','-72 hours') WHERE id=?", idB); err != nil {
		t.Fatal(err)
	}

	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	jobs, _, err := service.CheckExpiration(context.Background())
	if err != nil {
		t.Fatalf("check expiration: %v", err)
	}
	selected := map[int64]bool{}
	for _, job := range jobs {
		selected[int64(job.ID)] = true
	}
	if selected[idA] {
		t.Fatalf("job %d（剩余 88.5 天，窗口受限于 %d 天）被选中——存量越界窗口仍会日级重签", idA, CertRenewalDaysMax)
	}
	if !selected[idB] {
		t.Fatalf("job %d（剩余 6 天）未被选中——保护区内续签不得被阻断", idB)
	}
}
