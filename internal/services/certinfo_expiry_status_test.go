package services

// U06-F03（第 78 轮）：证书到期状态判定单源。修复前 certinfo 列表用截断天数
// `<=`、任务列表（handlers/certjobs.go）用完整时长 `<= days*24h`——同一证书
// 在 30 天阈值 + 1 分钟处两处结论分叉（列表 expiring / 任务 valid）。
// 本族钉住 CertificateExpiryStatus 的天粒度单源，并逐消费点核对一致。

import (
	"log"
	"strings"
	"testing"
	"time"
)

// Given 同一 now 与 30 天阈值。
// When 按阈值前 1 分钟 / 恰好 / 阈值后 1 分钟 / 阈值后 1 天 / 已过期 1 小时求状态。
// Then 天粒度单源给出全表一致结论（+1m 仍为 expiring——与 certinfo 原口径一致，
// 而不是任务列表按纳秒比较的 valid）。
func TestCertificateExpiryStatus_dayGranularityBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	const threshold = 30
	cases := []struct {
		name       string
		offset     time.Duration
		wantStatus string
		wantDays   int
	}{
		{name: "threshold-1m", offset: 30*24*time.Hour - time.Minute, wantStatus: "expiring", wantDays: 29},
		{name: "exactly-threshold", offset: 30 * 24 * time.Hour, wantStatus: "expiring", wantDays: 30},
		{name: "threshold+1m", offset: 30*24*time.Hour + time.Minute, wantStatus: "expiring", wantDays: 30},
		{name: "threshold+1d", offset: 31 * 24 * time.Hour, wantStatus: "valid", wantDays: 31},
		{name: "expired-1h", offset: -time.Hour, wantStatus: "expired", wantDays: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notAfter := now.Add(tc.offset)
			if got := CertificateExpiryStatus(notAfter, now, threshold); got != tc.wantStatus {
				t.Fatalf("CertificateExpiryStatus(offset=%v)=%q, want %q", tc.offset, got, tc.wantStatus)
			}
			if got := CertDaysRemaining(notAfter, now); got != tc.wantDays {
				t.Fatalf("CertDaysRemaining(offset=%v)=%d, want %d", tc.offset, got, tc.wantDays)
			}
		})
	}
}

// Given 真实 PEM 证书（NotAfter 落在各边界）。
// When FormatRuleCertInfo 生成展示信息。
// Then Status/DaysRemaining 与单源逐项一致（certinfo 消费点）。
func TestFormatRuleCertInfo_matchesCertificateExpiryStatus(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	const threshold = 30
	for _, offset := range []time.Duration{
		30*24*time.Hour - time.Minute,
		30 * 24 * time.Hour,
		30*24*time.Hour + time.Minute,
		31 * 24 * time.Hour,
		-time.Hour,
	} {
		certPEM, _ := expiredShapeCertAndKey(t, "single-source.test", now.Add(offset))
		info := FormatRuleCertInfo(certPEM, "manual", "single-source.test", "", threshold, now)
		want := CertificateExpiryStatus(now.Add(offset), now, threshold)
		if info.Status != want {
			t.Fatalf("offset=%v: FormatRuleCertInfo status=%q, want %q (单源)", offset, info.Status, want)
		}
		if info.DaysRemaining != CertDaysRemaining(now.Add(offset), now) {
			t.Fatalf("offset=%v: days=%d, want %d", offset, info.DaysRemaining, CertDaysRemaining(now.Add(offset), now))
		}
	}
}

// Given 一张 30 天 + 1 分钟到期的手动证书（阈值 30 天）。
// When 手动巡检（checkManualCertExpiration）执行。
// Then 按天粒度判为临期（与单源一致），计入 expiring 而非 valid。
func TestCheckManualCertExpiration_matchesCertificateExpiryStatus(t *testing.T) {
	_, database := newClusterTestService(t)
	certPEM, _ := expiredShapeCertAndKey(t, "manual-single-source.test", time.Now().Add(30*24*time.Hour+time.Minute))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert) VALUES ('lb_manual_single','manual-single','manual-single.test','http',8080,1,1,'manual',?)`, certPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=30 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	resetCertificateServiceForTest(t)

	NewCertificateService().checkManualCertExpiration()

	if !strings.Contains(buf.String(), "TLS Certificate Check: 0 expired, 1 expiring within 30 days") {
		t.Fatalf("log=%q, want 30 天 +1 分钟按天粒度判为临期（与单源一致）", buf.String())
	}
}
