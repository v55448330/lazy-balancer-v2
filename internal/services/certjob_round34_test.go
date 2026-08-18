package services

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
)

// TestTruncateJobMessage 验证 F-R34-3 共享截断 helper：1KB 上限 + UTF-8 边界回退。
func TestTruncateJobMessage(t *testing.T) {
	if got := truncateJobMessage("short message"); got != "short message" {
		t.Fatalf("truncateJobMessage(short)=%q, want passthrough", got)
	}
	if got := truncateJobMessage(strings.Repeat("x", 2048)); len(got) != maxJobMessageBytes || !utf8.ValidString(got) {
		t.Fatalf("truncateJobMessage(ascii) len=%d valid=%v, want %d bytes valid UTF-8", len(got), utf8.ValidString(got), maxJobMessageBytes)
	}
	// 1500 字节中文：截断点落在 3 字节字符中间，必须回退到合法边界（341×3=1023）。
	got := truncateJobMessage(strings.Repeat("中", 500))
	if len(got) != 1023 || !utf8.ValidString(got) {
		t.Fatalf("truncateJobMessage(multibyte) len=%d valid=%v, want 1023 bytes valid UTF-8", len(got), utf8.ValidString(got))
	}
}

// TestFailJobTruncatesMessage 验证长 CA 错误详情经 failJob 写入 cert_jobs.message
// 时有界（F-R34-3 写入点之一）。
func TestFailJobTruncatesMessage(t *testing.T) {
	jobID, _ := seedCertificateJob(t, "queued")
	longDetail := strings.Repeat("中", 400) + strings.Repeat("detail:", 300)

	failJob(jobID, longDetail)

	var message string
	if err := db.DB.QueryRow("SELECT message FROM cert_jobs WHERE id=?", jobID).Scan(&message); err != nil {
		t.Fatalf("read failed job message: %v", err)
	}
	if len(message) > maxJobMessageBytes || !utf8.ValidString(message) {
		t.Fatalf("cert_jobs.message len=%d valid=%v, want <=%d valid UTF-8", len(message), utf8.ValidString(message), maxJobMessageBytes)
	}
	if !strings.Contains(message, strings.Repeat("中", 100)) {
		t.Fatalf("failed job message lost the CA detail prefix: %.120s...", message)
	}
}

// TestDeploymentFailedTruncatesMessage 验证长部署错误经 deploymentFailed 写入
// cert_jobs.message 时有界（F-R34-3 写入点之一）。
func TestDeploymentFailedTruncatesMessage(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	issuer := NewCertIssuer(func() error { return errors.New("reload failed") })
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}
	longDetail := strings.Repeat("中", 400) + strings.Repeat("deploy-error:", 300)

	_ = issuer.deploymentFailed(jobID, material, longDetail, errors.New("reload failed"))

	var message string
	if err := db.DB.QueryRow("SELECT message FROM cert_jobs WHERE id=?", jobID).Scan(&message); err != nil {
		t.Fatalf("read deployment-failed job message: %v", err)
	}
	if len(message) > maxJobMessageBytes || !utf8.ValidString(message) {
		t.Fatalf("cert_jobs.message len=%d valid=%v, want <=%d valid UTF-8", len(message), utf8.ValidString(message), maxJobMessageBytes)
	}
	if !strings.HasPrefix(message, "部署失败 [attempt=1/10]:") {
		t.Fatalf("deployment-failed message lost attempt prefix: %.120s...", message)
	}
}
