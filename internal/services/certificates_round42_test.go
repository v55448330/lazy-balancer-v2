package services

import (
	"context"
	"log"
	"strings"
	"testing"
)

// CERT42-5（第 42 轮审计）：三处续签天数读取（启动恢复/续签巡检/首发失败重试）
// 读库失败降级默认值时必须与 certissuer.go 同口径补降级告警——否则配置读取
// 退化（锁/IO 错误）静默落到 30 天默认，无任何可观测痕迹。
func TestCertificateRenewalDays_logsWarningOnReadFailure(t *testing.T) {
	// Given a broken global_config read（表被改名，读取必失败）
	_, database := newClusterTestService(t)
	if _, err := database.Exec("ALTER TABLE global_config RENAME TO global_config_round42_bak"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec("ALTER TABLE global_config_round42_bak RENAME TO global_config"); err != nil {
			t.Errorf("restore global_config: %v", err)
		}
	})
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When the three renewal-days readers run with the broken read
	service := NewCertificateService()
	_ = service.CheckExpiration()
	_ = service.checkFailedFirstIssuance(3)
	if err := requeueNonTerminalCertJobs(context.Background(), nil); err != nil {
		t.Fatalf("requeueNonTerminalCertJobs: %v", err)
	}

	// Then each degraded read logged the certissuer-pattern warning（默认 30 天行为不变）
	if got := strings.Count(buf.String(), "read cert_renewal_days failed"); got != 3 {
		t.Fatalf("warning count=%d, want 3（三处读取各告警一次）\nlog:\n%s", got, buf.String())
	}
}
