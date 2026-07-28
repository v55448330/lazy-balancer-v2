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
	if status == "issued" || certPEM != "new-cert" || keyPEM != "new-key" || version != 0 {
		t.Fatalf("job=(%q,%q,%q) version=%d, want non-issued persisted material without version bump", status, certPEM, keyPEM, version)
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

func TestCertIssuer_Issue_fast_path_returns_reload_error_and_marks_job_failed(t *testing.T) {
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
	if status != "failed" {
		t.Fatalf("fast-path job status=%q, want failed", status)
	}
}
