package services

import (
	"log"
	"strings"
	"testing"
	"time"
)

// CERT44-5（第 44 轮审计）：checkManualCertExpiration 读到的 cert_expiry_days
// 为 0/负值时必须回退 30 天（与 certinfo.go GetCertExpiryThreshold 同形态），
// 否则阈值退化后「即将过期」告警静默失效。
func TestCERT44_5_checkManualCertExpiration_floorsNonPositiveWarnDays(t *testing.T) {
	_, database := newClusterTestService(t)
	// Given：一张 20 天后过期的手动证书（0 < 20 <= 30，阈值是否回退决定其是否计入）
	certPEM, _ := expiredShapeCertAndKey(t, "manual44.test", time.Now().Add(20*24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert) VALUES ('lb_manual44','manual44','manual44.test','http',8080,1,1,'manual',?)`, certPEM); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	for _, days := range []int{0, -5} {
		buf.Reset()
		if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=? WHERE id=1", days); err != nil {
			t.Fatal(err)
		}

		// When
		NewCertificateService().checkManualCertExpiration()

		// Then：阈值回退 30 天，20 天后过期的证书计入即将过期
		if !strings.Contains(buf.String(), "TLS Certificate Check: 0 expired, 1 expiring within 30 days") {
			t.Fatalf("cert_expiry_days=%d log=%q, want 阈值回退 30 天并计入 1 个即将过期", days, buf.String())
		}
	}

	// 回归形状：正常配置值原样生效
	buf.Reset()
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=45 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	NewCertificateService().checkManualCertExpiration()
	if !strings.Contains(buf.String(), "TLS Certificate Check: 0 expired, 1 expiring within 45 days") {
		t.Fatalf("cert_expiry_days=45 log=%q, want 45 天阈值生效", buf.String())
	}
}
