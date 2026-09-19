package services

import (
	"testing"
	"time"
)

// CERT41-3:同一证书同日同档位重复扫描只告警一次(10min 扫描周期不再刷屏)。
func TestManualCertExpiryAlertGate_sameDaySameLevelSuppressed(t *testing.T) {
	// Given
	gate := newManualCertExpiryAlertGate()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.Local)

	// When/Then
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpiringSoon, now) {
		t.Fatal("first alert of the day must fire")
	}
	if gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpiringSoon, now.Add(10*time.Minute)) {
		t.Fatal("same cert same day same level must be suppressed")
	}
}

// CERT41-3:状态加深(临期→已过期)当日可再告——新档位是新事件。
func TestManualCertExpiryAlertGate_levelDeepeningRealertsSameDay(t *testing.T) {
	// Given
	gate := newManualCertExpiryAlertGate()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.Local)
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpiringSoon, now) {
		t.Fatal("first alert must fire")
	}

	// When/Then
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpired, now.Add(30*time.Minute)) {
		t.Fatal("deepened level (expiring→expired) must re-alert same day")
	}
	// 已报过期的同日临期档不再回退重告
	if gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpiringSoon, now.Add(40*time.Minute)) {
		t.Fatal("shallower level after deeper alert must stay suppressed same day")
	}
}

// CERT41-3:跨日重新告警(每日最多每档一次)。
func TestManualCertExpiryAlertGate_nextDayRealerts(t *testing.T) {
	// Given
	gate := newManualCertExpiryAlertGate()
	day1 := time.Date(2026, 9, 19, 23, 50, 0, 0, time.Local)
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpired, day1) {
		t.Fatal("first alert must fire")
	}

	// When/Then
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpired, day1.Add(20*time.Minute)) {
		t.Fatal("next calendar day must re-alert")
	}
}

// CERT41-3:按证书 ID 独立记忆,互不影响。
func TestManualCertExpiryAlertGate_perCertIndependent(t *testing.T) {
	// Given
	gate := newManualCertExpiryAlertGate()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.Local)

	// When/Then
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpiringSoon, now) {
		t.Fatal("cert A first alert must fire")
	}
	if !gate.shouldAlert("lb_cert_b", manualCertExpiryLevelExpiringSoon, now) {
		t.Fatal("cert B must alert independently")
	}
	if gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpiringSoon, now.Add(10*time.Minute)) {
		t.Fatal("cert A second alert must be suppressed")
	}
}

// CERT41-3:nil 门禁(测试直构 CertificateService 未初始化字段)防御性放行,
// 保持告警不丢失。
func TestManualCertExpiryAlertGate_nilGateAllows(t *testing.T) {
	// Given
	var gate *manualCertExpiryAlertGate

	// When/Then
	if !gate.shouldAlert("lb_cert_a", manualCertExpiryLevelExpired, time.Now()) {
		t.Fatal("nil gate must allow alerts (no suppression without state)")
	}
}
