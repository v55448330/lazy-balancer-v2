package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func testCertificatePEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func seedCertificateJob(t *testing.T, status string) (int, string) {
	t.Helper()
	_, database := newClusterTestService(t)
	ruleID := "lb_issue_test"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES (?, 'issue test', 'http', 8080, 1)`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?, 'example.com', ?, 1)`, ruleID, status)
	if err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate job ID: %v", err)
	}
	return int(jobID), ruleID
}

func TestCertIssuer_deployIssuedCertificate_keeps_nonterminal_state_when_reload_fails(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	issuer := NewCertIssuer(func() error { return errors.New("reload failed") })
	retries := 0
	issuer.deploymentRetry = func(gotJobID int, got issuedCertificate, _ time.Duration) {
		if gotJobID != jobID || got.ruleID != ruleID {
			t.Fatalf("retry job=(%d,%q), want (%d,%q)", gotJobID, got.ruleID, jobID, ruleID)
		}
		retries++
	}
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	// When
	err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

	// Then
	if err == nil {
		t.Fatal("deployment succeeded despite reload failure")
	}
	var status, certPEM, keyPEM string
	var version int
	if err := db.DB.QueryRow("SELECT status, COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id=?", jobID).Scan(&status, &certPEM, &keyPEM); err != nil {
		t.Fatalf("read failed job: %v", err)
	}
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if status != "downloaded" || certPEM != "new-cert" || keyPEM != "new-key" || version != 0 || retries != 1 {
		t.Fatalf("job=(%q,%q,%q) version=%d retries=%d, want downloaded persisted material, no version bump, one retry", status, certPEM, keyPEM, version, retries)
	}
}

func TestCertIssuer_deployIssuedCertificate_finalizes_post_cleanup_state(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "cleanup_dns")
	useTemporaryCertDir(t)
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	// When
	err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

	// Then
	if err != nil {
		t.Fatalf("deploy issued certificate: %v", err)
	}
	var status string
	var version int
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read issued job: %v", err)
	}
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if status != "issued" || version != 1 || reloads != 1 {
		t.Fatalf("status=%q version=%d reloads=%d, want issued, 1, 1", status, version, reloads)
	}
}

func TestCertIssuer_deployIssuedCertificate_restores_files_when_job_disabled_before_finalize(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	if err := WriteCertFiles(ruleID, "old-cert", "old-key"); err != nil {
		t.Fatalf("write previous certificate pair: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		if reloads == 1 {
			_, err := db.DB.Exec("UPDATE cert_jobs SET status='disabled' WHERE id=?", jobID)
			return err
		}
		return nil
	})
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	// When
	err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

	// Then
	if err == nil {
		t.Fatal("deployment finalized after the job was disabled")
	}
	certPath, keyPath := CertFilePaths(ruleID)
	certPEM, certErr := os.ReadFile(certPath)
	if certErr != nil {
		t.Fatalf("read restored cert: %v", certErr)
	}
	keyPEM, keyErr := os.ReadFile(keyPath)
	if keyErr != nil {
		t.Fatalf("read restored key: %v", keyErr)
	}
	var status string
	var version int
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read disabled job: %v", err)
	}
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if string(certPEM) != "old-cert" || string(keyPEM) != "old-key" || status != "disabled" || version != 0 || reloads != 2 {
		t.Fatalf("files=(%q,%q) status=%q version=%d reloads=%d", certPEM, keyPEM, status, version, reloads)
	}
}

func TestCertIssuer_Issue_fast_path_returns_reload_error_and_keeps_downloaded(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "issued")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='key', ca_provider_id=1 WHERE id=?", certPEM, jobID); err != nil {
		t.Fatalf("seed issued material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=1 WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("seed rule CA provider: %v", err)
	}
	issuer := NewCertIssuer(func() error { return errors.New("reload failed") })
	retries := 0
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) { retries++ }

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: 1})

	// Then
	if err == nil {
		t.Fatal("fast path reported success despite reload failure")
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read fast-path job: %v", err)
	}
	if status != "downloaded" || retries != 1 {
		t.Fatalf("fast-path job status=%q retries=%d, want downloaded and one retry", status, retries)
	}
}

func TestCertIssuer_deploymentFailed_backs_off_and_stops_after_max_attempts(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	issuer := NewCertIssuer(nil)
	var delays []time.Duration
	var retryMaterial issuedCertificate
	issuer.deploymentRetry = func(_ int, material issuedCertificate, delay time.Duration) {
		delays = append(delays, delay)
		retryMaterial = material
	}
	material := issuedCertificate{ruleID: ruleID, providerID: 1}

	// When
	for attempt := range maxCertificateDeploymentAttempts {
		_ = issuer.deploymentFailed(jobID, material, "reload failed", errors.New("reload failed"))
		if attempt+1 < maxCertificateDeploymentAttempts {
			if _, err := db.DB.Exec("UPDATE cert_jobs SET message='检测到已签发的有效证书，直接重新部署文件' WHERE id=?", jobID); err != nil {
				t.Fatalf("overwrite deployment progress: %v", err)
			}
			material = retryMaterial
		}
	}

	// Then
	wantDelays := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		32 * time.Second, 64 * time.Second, 128 * time.Second, 256 * time.Second,
	}
	if len(delays) != len(wantDelays) {
		t.Fatalf("scheduled retries=%d, want %d", len(delays), len(wantDelays))
	}
	for i := range wantDelays {
		if delays[i] != wantDelays[i] {
			t.Fatalf("retry %d delay=%v, want %v", i+1, delays[i], wantDelays[i])
		}
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read deployment retry status: %v", err)
	}
	if status != "failed" {
		t.Fatalf("deployment retry status=%q, want failed", status)
	}
}

func TestCertificateDeploymentBackoff_caps_at_five_minutes(t *testing.T) {
	if got := certificateDeploymentBackoff(20); got != 5*time.Minute {
		t.Fatalf("deployment backoff=%v, want 5m", got)
	}
}
