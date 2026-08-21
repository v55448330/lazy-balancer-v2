package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
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
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'issue test', 'example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
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
	// R57 A-#1 起再调度为异步（go deploymentRetry）——断言必须经 channel 等待
	// 回调到达，裸读计数器既是顺序竞态也是数据竞态（全量并发下偶发 flake）。
	retried := make(chan struct{}, 1)
	issuer.deploymentRetry = func(gotJobID int, got issuedCertificate, _ time.Duration) {
		if gotJobID != jobID || got.ruleID != ruleID {
			t.Fatalf("retry job=(%d,%q), want (%d,%q)", gotJobID, got.ruleID, jobID, ruleID)
		}
		retried <- struct{}{}
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
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("deployment retry was never rescheduled (async goroutine missing)")
	}
	var status, certPEM, keyPEM, deploymentAvailableAfter string
	var deploymentAttempts int
	var version int
	if err := db.DB.QueryRow("SELECT status, COALESCE(cert_pem,''), COALESCE(key_pem,''), deployment_attempts, COALESCE(deployment_available_after,'') FROM cert_jobs WHERE id=?", jobID).Scan(&status, &certPEM, &keyPEM, &deploymentAttempts, &deploymentAvailableAfter); err != nil {
		t.Fatalf("read failed job: %v", err)
	}
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if status != "downloaded" || certPEM != "new-cert" || keyPEM != "new-key" || deploymentAttempts != 1 || deploymentAvailableAfter == "" || version != 0 {
		t.Fatalf("job=(%q,%q,%q) deployment_attempts=%d available_after=%q version=%d", status, certPEM, keyPEM, deploymentAttempts, deploymentAvailableAfter, version)
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
	installCertJobVersionTrigger(t)

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

func TestConfirmCertificateDeployment_accepts_equivalent_normalized_domain_set(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec("UPDATE lb_rules SET domain='WWW.Example.com, example.com' WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("set dual-domain rule: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET domain='example.com,www.example.com' WHERE id=?", jobID); err != nil {
		t.Fatalf("set canonical job domains: %v", err)
	}

	// When
	err := confirmCertificateDeployment(context.Background(), jobID, issuedCertificate{ruleID: ruleID}, false)

	// Then
	if err != nil {
		t.Fatalf("confirm equivalent domain set: %v", err)
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

func TestCertIssuer_deployIssuedCertificate_skips_rollback_when_cas_loser_files_match_winner(t *testing.T) {
	// R56 N-1(b)：并发部署回调（在途回调 × Resume/Unblock 补扫重试）部署同
	// jobID 同一份证书时，双方 WriteCertFiles 内容相同，终态 CAS 先到者提交
	// issued、后到者进冲突分支——其部署前快照可能早于胜者写入（旧证书），无
	// 条件恢复会把磁盘回退到旧证书，而 DB='issued'+新 PEM、Caddy 服务新证书，
	// 三方静默分叉（reconcileMissingCertFiles 只在文件缺失时重建，不比对内容，
	// 分叉持续到下次续签）。磁盘已是目标证书时必须跳过快照恢复，仅保留
	// failJob 归因（issued 为终态，failJob no-op）。
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	if err := WriteCertFiles(ruleID, "old-cert", "old-key"); err != nil {
		t.Fatalf("write old certificate pair: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		if reloads == 1 {
			// 模拟并发胜者：本回调（败者）重载期间已提交终态 issued
			_, err := db.DB.Exec("UPDATE cert_jobs SET status='issued' WHERE id=?", jobID)
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

	// Then：CAS 败者报错，但磁盘保持胜者成果（新证书）、无回滚重载、行保持 issued
	if err == nil {
		t.Fatal("CAS-losing deployment unexpectedly succeeded")
	}
	certPath, keyPath := CertFilePaths(ruleID)
	gotCert, certErr := os.ReadFile(certPath)
	gotKey, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		t.Fatalf("read deployed files: cert=%v key=%v", certErr, keyErr)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if string(gotCert) != "new-cert" || string(gotKey) != "new-key" || status != "issued" || reloads != 1 {
		t.Fatalf("files=(%q,%q) status=%q reloads=%d, want 胜者成果保留 (new-cert,new-key) issued 1（不得回滚胜者写入）",
			gotCert, gotKey, status, reloads)
	}
}

func TestCertIssuer_deployIssuedCertificate_restores_when_disk_differs_from_own_material(t *testing.T) {
	// R56 N-1(b) 对照：终态 CAS 冲突但磁盘内容与本回调部署的证书不同（并发
	// 新化身写入了另一份证书）时，快照恢复语义必须保持不变——回滚到本回调
	// 部署前快照并重新重载。
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	if err := WriteCertFiles(ruleID, "old-cert", "old-key"); err != nil {
		t.Fatalf("write old certificate pair: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		if reloads == 1 {
			if _, err := db.DB.Exec("UPDATE cert_jobs SET status='issued' WHERE id=?", jobID); err != nil {
				return err
			}
			// 并发新化身写入不同的证书内容
			return WriteCertFiles(ruleID, "winner-cert", "winner-key")
		}
		return nil
	})
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "loser-cert", keyPEM: "loser-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	// When
	err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

	// Then：内容不匹配 → 恢复部署前快照（旧证书）+ 回滚重载
	if err == nil {
		t.Fatal("CAS-losing deployment unexpectedly succeeded")
	}
	certPath, keyPath := CertFilePaths(ruleID)
	gotCert, certErr := os.ReadFile(certPath)
	gotKey, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		t.Fatalf("read restored files: cert=%v key=%v", certErr, keyErr)
	}
	if string(gotCert) != "old-cert" || string(gotKey) != "old-key" || reloads != 2 {
		t.Fatalf("files=(%q,%q) reloads=%d, want 快照恢复 (old-cert,old-key) 且部署+回滚各重载一次",
			gotCert, gotKey, reloads)
	}
}

func TestCertIssuer_Issue_preflight_rate_limit_enters_waiting_ca(t *testing.T) {
	// Given：CA 预检连通性测试被 429 限流
	jobID, ruleID := seedCertificateJob(t, "queued")
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		default:
			response.Header().Set("Retry-After", "1")
			response.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	result, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('Rate Limited CA','letsencrypt',?,'{}',1,0,1)`, serverURL+"/directory")
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='admin@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed ACME email: %v", err)
	}
	issuer := NewCertIssuer(func() error { return nil }, t.TempDir())

	// When
	issueErr := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: int(providerID)})

	// Then：预检 429 走限流冷却，而非直接失败
	var rateLimitErr *CAProviderRateLimitError
	if !errors.As(issueErr, &rateLimitErr) {
		t.Fatalf("preflight error=%v, want CA rate limit", issueErr)
	}
	handleQueueExecutionError(jobID, issueErr)
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "waiting_ca" {
		t.Fatalf("job status=%q, want waiting_ca", status)
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
	// R57 A-#1 起再调度异步——channel 等待替代裸计数器（消顺序/数据竞态）。
	retried := make(chan struct{}, 1)
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) { retried <- struct{}{} }

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: 1})

	// Then
	if err == nil {
		t.Fatal("fast path reported success despite reload failure")
	}
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("fast-path retry was never rescheduled (async goroutine missing)")
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read fast-path job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("fast-path job status=%q, want downloaded", status)
	}
}

func TestCertIssuer_Issue_queued_valid_certificate_runs_CA_flow(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "queued")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const providerID = 999
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='old-key', ca_provider_id=? WHERE id=?", certPEM, providerID, jobID); err != nil {
		t.Fatalf("seed queued certificate material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id=?", providerID, ruleID); err != nil {
		t.Fatalf("seed rule CA provider: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID})

	// Then
	if !errors.Is(err, ErrCAProviderNotFound) {
		t.Fatalf("queued issuance error=%v, want CA provider lookup failure", err)
	}
	if reloads != 0 {
		t.Fatalf("queued issuance reloaded Caddy %d times, want 0", reloads)
	}
}

func TestCertIssuer_Issue_downloaded_valid_certificate_uses_fast_path(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const providerID = 999
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key', ca_provider_id=? WHERE id=?", certPEM, providerID, jobID); err != nil {
		t.Fatalf("seed downloaded certificate material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id=?", providerID, ruleID); err != nil {
		t.Fatalf("seed rule CA provider: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID})

	// Then
	if err != nil {
		t.Fatalf("redeploy downloaded certificate: %v", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read redeployed certificate job: %v", err)
	}
	if status != "issued" || reloads != 1 {
		t.Fatalf("redeployed job status=%q reloads=%d, want issued and 1", status, reloads)
	}
}

func TestCertIssuer_Issue_fast_path_skips_redeploy_when_deployed_cert_matches(t *testing.T) {
	// Given：规则跟随默认 CA（ca_provider_id=0），已部署证书与任务证书内容一致
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const providerID = 7
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES (?, 'Default CA', 'letsencrypt', 'https://acme.example/directory', '{}', 1, 0, 1)`, providerID); err != nil {
		t.Fatalf("seed default CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET default_ca_provider_id=? WHERE id=1", providerID); err != nil {
		t.Fatalf("set default CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key', ca_provider_id=? WHERE id=?", certPEM, providerID, jobID); err != nil {
		t.Fatalf("seed downloaded certificate material: %v", err)
	}
	certPath, _ := CertFilePaths(ruleID)
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write deployed certificate file: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID})

	// Then：无需重新部署，也不触发 Caddy 重载
	if err != nil {
		t.Fatalf("issue with deployed certificate match: %v", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read fast-path job: %v", err)
	}
	deployed, readErr := os.ReadFile(certPath)
	if readErr != nil {
		t.Fatalf("read deployed certificate file: %v", readErr)
	}
	if status != "issued" || reloads != 0 || string(deployed) != certPEM {
		t.Fatalf("job status=%q reloads=%d file-unchanged=%v, want issued, 0, true", status, reloads, string(deployed) == certPEM)
	}
}

func TestCertIssuer_Issue_fast_path_redeploys_when_deployed_cert_differs(t *testing.T) {
	// Given：已部署证书内容与任务证书不同，走原有重新部署路径
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const providerID = 999
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key', ca_provider_id=? WHERE id=?", certPEM, providerID, jobID); err != nil {
		t.Fatalf("seed downloaded certificate material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id=?", providerID, ruleID); err != nil {
		t.Fatalf("seed rule CA provider: %v", err)
	}
	certPath, _ := CertFilePaths(ruleID)
	if err := os.WriteFile(certPath, []byte("stale-deployed-cert"), 0644); err != nil {
		t.Fatalf("write stale deployed certificate: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID})

	// Then
	if err != nil {
		t.Fatalf("redeploy downloaded certificate: %v", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read redeployed certificate job: %v", err)
	}
	deployed, readErr := os.ReadFile(certPath)
	if readErr != nil {
		t.Fatalf("read deployed certificate file: %v", readErr)
	}
	if status != "issued" || reloads != 1 || string(deployed) != certPEM {
		t.Fatalf("job status=%q reloads=%d deployed-match=%v, want issued, 1, true", status, reloads, string(deployed) == certPEM)
	}
}

func TestCertIssuer_Issue_fast_path_skips_when_provider_changed(t *testing.T) {
	// Given：规则明确切换了 CA 提供商（888），任务仍持有旧提供商（999）证书，须走完整签发
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const oldProviderID = 999
	const newProviderID = 888
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key', ca_provider_id=? WHERE id=?", certPEM, oldProviderID, jobID); err != nil {
		t.Fatalf("seed downloaded certificate material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id=?", newProviderID, ruleID); err != nil {
		t.Fatalf("seed rule CA provider: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: oldProviderID})

	// Then：落入完整签发流程，因旧提供商已不存在而在 CA 预检处失败
	if !errors.Is(err, ErrCAProviderNotFound) {
		t.Fatalf("issuance error=%v, want CA provider lookup failure", err)
	}
	if reloads != 0 {
		t.Fatalf("provider-changed issuance reloaded Caddy %d times, want 0", reloads)
	}
}

func TestCAQueueManager_CancelJobsForRule_waits_for_fast_path_rollback(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "issued")
	useTemporaryCertDir(t)
	if err := WriteCertFiles(ruleID, "old-cert", "old-key"); err != nil {
		t.Fatalf("write old certificate: %v", err)
	}
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='new-key', ca_provider_id=1 WHERE id=?", certPEM, jobID); err != nil {
		t.Fatalf("seed issued material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=1 WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("seed rule provider: %v", err)
	}
	reloadEntered := make(chan struct{})
	releaseReload := make(chan struct{})
	var reloadOnce sync.Once
	issuer := NewCertIssuer(func() error {
		reloadOnce.Do(func() {
			close(reloadEntered)
			<-releaseReload
		})
		return nil
	})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.executeFn = func(ctx context.Context, item queueItem, provider models.CAProvider) error {
		return issuer.Issue(ctx, item.jobID, item.ruleID, item.domains, provider)
	}
	queue.enqueue(queueItem{jobID: jobID, ruleID: ruleID, domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(queue.ctx)
	queue.mu.Unlock()
	if !ok {
		t.Fatal("fast-path execution was not prepared")
	}
	go queue.execute(execution)
	<-reloadEntered
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}
	cancelDone := make(chan struct{})
	go func() {
		if err := manager.CancelJobsForRule(context.Background(), ruleID); err != nil {
			t.Errorf("cancel rule jobs: %v", err)
		}
		close(cancelDone)
	}()
	<-execution.ctx.Done()
	select {
	case <-cancelDone:
		t.Fatal("rule cancellation returned before fast-path deployment exited")
	default:
	}
	close(releaseReload)
	<-cancelDone
	if _, err := db.DB.Exec("DELETE FROM cert_jobs WHERE id=?", jobID); err != nil {
		t.Fatalf("delete certificate job: %v", err)
	}

	certPath, keyPath := CertFilePaths(ruleID)
	gotCert, certErr := os.ReadFile(certPath)
	gotKey, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		t.Fatalf("read rolled-back files: cert=%v key=%v", certErr, keyErr)
	}
	if string(gotCert) != "old-cert" || string(gotKey) != "old-key" {
		t.Fatalf("files after cancellation=(%q,%q), want old pair", gotCert, gotKey)
	}
}

func TestCertIssuer_deploymentFailed_backs_off_and_stops_after_max_attempts(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	issuer := NewCertIssuer(nil)
	// R59 A-1：deploymentFailed 的再调度是异步 go deploymentRetry（R57 A-#1），
	// 回调内裸写切片与 R58 已修的两处同型竞态——channel 收集 + 有界等待。
	type retryCall struct {
		material issuedCertificate
		delay    time.Duration
	}
	retries := make(chan retryCall, maxCertificateDeploymentAttempts)
	issuer.deploymentRetry = func(_ int, material issuedCertificate, delay time.Duration) {
		retries <- retryCall{material: material, delay: delay}
	}

	// When：连续打满退避上限，attempt 从 DB 重算（deploymentFailed 同步维护）。
	for range maxCertificateDeploymentAttempts {
		_ = issuer.deploymentFailed(jobID, issuedCertificate{ruleID: ruleID, providerID: 1}, "reload failed", errors.New("reload failed"))
	}

	// Then：收满 9 次再调度（5s 上限，顺序即投递顺序=退避顺序）。
	wantDelays := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		32 * time.Second, 64 * time.Second, 128 * time.Second, 256 * time.Second,
	}
	var delays []time.Duration
	var lastMaterial issuedCertificate
	for range wantDelays {
		select {
		case call := <-retries:
			delays = append(delays, call.delay)
			lastMaterial = call.material
		case <-time.After(5 * time.Second):
			t.Fatalf("scheduled retries=%d, want %d (async goroutine stalled)", len(delays), len(wantDelays))
		}
	}
	for i := range wantDelays {
		if delays[i] != wantDelays[i] {
			t.Fatalf("retry %d delay=%v, want %v", i+1, delays[i], wantDelays[i])
		}
	}
	if lastMaterial.ruleID != ruleID {
		t.Fatalf("retry material ruleID=%q, want %q", lastMaterial.ruleID, ruleID)
	}
	// channel 应已收空（无多余再调度）。
	select {
	case extra := <-retries:
		t.Fatalf("unexpected extra retry: %+v", extra)
	default:
	}
	var status string
	var attempts int
	if err := db.DB.QueryRow("SELECT status, deployment_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read deployment retry status: %v", err)
	}
	if status != "failed" || attempts != maxCertificateDeploymentAttempts {
		t.Fatalf("deployment retry status=%q attempts=%d, want failed and %d", status, attempts, maxCertificateDeploymentAttempts)
	}
}

func TestCertificateService_recoverCertJobs_preserves_deployment_retry_state(t *testing.T) {
	// Given
	jobID, _ := seedCertificateJob(t, "downloaded")
	available := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem='cert', key_pem='key', deployment_attempts=4, deployment_available_after=? WHERE id=?", available.Format("2006-01-02 15:04:05"), jobID); err != nil {
		t.Fatalf("seed deployment retry state: %v", err)
	}
	service := NewCertificateService()
	var gotAttempt int
	var gotDelay time.Duration
	service.deploymentRetry = func(_ int, material issuedCertificate, delay time.Duration) {
		gotAttempt = material.deploymentAttempt
		gotDelay = delay
	}

	// When
	service.recoverCertJobs(context.Background())

	// Then
	var status string
	var attempts int
	if err := db.DB.QueryRow("SELECT status, deployment_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read recovered deployment job: %v", err)
	}
	if status != "downloaded" || attempts != 4 || gotAttempt != 4 {
		t.Fatalf("recovered job status=%q attempts=%d scheduled_attempt=%d", status, attempts, gotAttempt)
	}
	if gotDelay < 59*time.Minute || gotDelay > time.Hour {
		t.Fatalf("recovered deployment delay=%v, want persisted delay near one hour", gotDelay)
	}
}

func TestCertificateDeploymentRetry_succeeds_when_provider_deleted(t *testing.T) {
	// Given
	jobID, _ := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	const providerID = 999
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='persisted-cert', key_pem='persisted-key', expires_at=datetime('now','+90 days'), ca_provider_id=? WHERE id=?`, providerID, jobID); err != nil {
		t.Fatalf("seed downloaded certificate: %v", err)
	}
	if _, err := db.DB.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("delete CA providers: %v", err)
	}
	reloads := 0

	// When
	err := retryCertificateDeployment(context.Background(), jobID, func() error {
		reloads++
		return nil
	})

	// Then
	if err != nil {
		t.Fatalf("retry downloaded certificate deployment: %v", err)
	}
	var status string
	var gotProviderID int
	if err := db.DB.QueryRow("SELECT status, ca_provider_id FROM cert_jobs WHERE id=?", jobID).Scan(&status, &gotProviderID); err != nil {
		t.Fatalf("read deployed certificate job: %v", err)
	}
	if status != "issued" || gotProviderID != providerID || reloads != 1 {
		t.Fatalf("job status=%q provider=%d reloads=%d, want issued with provider %d and one reload", status, gotProviderID, reloads, providerID)
	}
}

func TestRetryCertificateDeployment_accepts_cleanup_dns_status(t *testing.T) {
	// Given：任务停留在 cleanup_dns 且持有证书材料，部署重试必须能加载并推进到 issued
	jobID, _ := seedCertificateJob(t, "cleanup_dns")
	useTemporaryCertDir(t)
	const providerID = 999
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='persisted-cert', key_pem='persisted-key', expires_at=datetime('now','+90 days'), ca_provider_id=? WHERE id=?`, providerID, jobID); err != nil {
		t.Fatalf("seed cleanup_dns certificate: %v", err)
	}
	reloads := 0

	// When
	err := retryCertificateDeployment(context.Background(), jobID, func() error {
		reloads++
		return nil
	})

	// Then
	if err != nil {
		t.Fatalf("retry cleanup_dns certificate deployment: %v", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read deployed certificate job: %v", err)
	}
	if status != "issued" || reloads != 1 {
		t.Fatalf("job status=%q reloads=%d, want issued and one reload", status, reloads)
	}
}

func TestRetryCertificateDeployment_cleanup_dns_job_fails_after_max_attempts(t *testing.T) {
	// Given：长时间停留在 cleanup_dns 的任务，部署反复失败，重试到上限后必须落为 failed
	jobID, _ := seedCertificateJob(t, "cleanup_dns")
	useTemporaryCertDir(t)
	const providerID = 999
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='persisted-cert', key_pem='persisted-key', expires_at=datetime('now','+90 days'), ca_provider_id=?, deployment_attempts=? WHERE id=?`, providerID, maxCertificateDeploymentAttempts-1, jobID); err != nil {
		t.Fatalf("seed cleanup_dns certificate at last deployment attempt: %v", err)
	}

	// When
	err := retryCertificateDeployment(context.Background(), jobID, func() error {
		return errors.New("reload failed")
	})

	// Then
	if err == nil {
		t.Fatal("deployment succeeded despite reload failure")
	}
	var status string
	var attempts int
	if err := db.DB.QueryRow("SELECT status, deployment_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read failed cleanup_dns job: %v", err)
	}
	if status != "failed" || attempts != maxCertificateDeploymentAttempts {
		t.Fatalf("job status=%q attempts=%d, want failed with %d attempts", status, attempts, maxCertificateDeploymentAttempts)
	}
}

func installCertJobVersionTrigger(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`CREATE TRIGGER test_cluster_version_cert_jobs_update
		AFTER UPDATE OF rule_id, cert_pem, key_pem, expires_at ON cert_jobs
		WHEN (SELECT is_master FROM global_config WHERE id=1)=1
		BEGIN UPDATE global_config SET cluster_version=cluster_version+1 WHERE id=1; END`); err != nil {
		t.Fatalf("install certificate job version trigger: %v", err)
	}
}

func TestCertificateDeploymentBackoff_caps_at_five_minutes(t *testing.T) {
	if got := certificateDeploymentBackoff(20); got != 5*time.Minute {
		t.Fatalf("deployment backoff=%v, want 5m", got)
	}
}

func TestCertIssuer_deployIssuedCertificate_serializes_rollback_by_rule(t *testing.T) {
	// Given
	oldJobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	if err := WriteCertFiles(ruleID, "base-cert", "base-key"); err != nil {
		t.Fatalf("write base certificate: %v", err)
	}
	oldReloadEntered := make(chan struct{})
	releaseOldReload := make(chan struct{})
	oldIssuer := NewCertIssuer(func() error {
		close(oldReloadEntered)
		<-releaseOldReload
		return errors.New("old reload failed")
	})
	newReloadEntered := make(chan struct{})
	newIssuer := NewCertIssuer(func() error {
		close(newReloadEntered)
		return nil
	})
	oldDone := make(chan error, 1)
	newDone := make(chan error, 1)
	go func() {
		oldDone <- oldIssuer.deployIssuedCertificate(context.Background(), oldJobID, issuedCertificate{ruleID: ruleID, certPEM: "old-cert", keyPEM: "old-key", notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1})
	}()
	<-oldReloadEntered
	if _, err := db.DB.Exec("UPDATE lb_rules SET domain='www.example.com' WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("advance rule domain: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?, 'www.example.com', 'downloaded', 1)`, ruleID)
	if err != nil {
		t.Fatalf("seed newer job: %v", err)
	}
	newJobID64, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read newer job ID: %v", err)
	}
	newJobID := int(newJobID64)
	go func() {
		newDone <- newIssuer.deployIssuedCertificate(context.Background(), newJobID, issuedCertificate{ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key", notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1})
	}()

	// When
	timer := time.NewTimer(100 * time.Millisecond)
	newEnteredBeforeRollback := false
	select {
	case <-newReloadEntered:
		newEnteredBeforeRollback = true
	case <-timer.C:
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	close(releaseOldReload)

	// Then
	if err := <-oldDone; err == nil {
		t.Fatal("old deployment unexpectedly succeeded")
	}
	if err := <-newDone; err != nil {
		t.Fatalf("new deployment failed: %v", err)
	}
	if newEnteredBeforeRollback {
		t.Fatal("new deployment reached reload before the old deployment rolled back")
	}
	certPath, keyPath := CertFilePaths(ruleID)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read final cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read final key: %v", err)
	}
	if string(certPEM) != "new-cert" || string(keyPEM) != "new-key" {
		t.Fatalf("final certificate=(%q,%q), want newer pair", certPEM, keyPEM)
	}
}
