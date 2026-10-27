package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"

	xacme "golang.org/x/crypto/acme"
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

// testCertJobSeq 给本包种子任务分配高位 ID：异步部署重试 goroutine 可能
// 越过测试边界，若新库因 db.Initialize 重用 id=1，前一个用例的重试会改写
// 本用例的行（随机顺序门实证：第 3 次退避读到的 attempt 已多 1）。
var testCertJobSeq atomic.Int64

func nextTestCertJobID() int64 {
	return 900000 + testCertJobSeq.Add(1)
}

func seedCertificateJob(t *testing.T, status string) (int, string) {
	t.Helper()
	_, database := newClusterTestService(t)
	ruleID := "lb_issue_test"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'issue test', 'example.com', 'http', 8080, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	jobIDValue := nextTestCertJobID()
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (?, ?, 'example.com', ?, 1)`, jobIDValue, ruleID, status); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	return int(jobIDValue), ruleID
}

func TestCertIssuer_deployIssuedCertificate_keeps_nonterminal_state_when_reload_fails(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	issuer := NewCertIssuer(func() error { return errors.New("reload failed") })
	// 自此再调度为异步（go deploymentRetry）——断言必须经 channel 等待
	// 回调到达，裸读计数器既是顺序竞态也是数据竞态（全量并发下偶发 flake）。
	type retryCall struct {
		jobID  int
		ruleID string
	}
	retried := make(chan retryCall, 1)
	issuer.deploymentRetry = func(gotJobID int, got issuedCertificate, _ time.Duration) error {
		retried <- retryCall{jobID: gotJobID, ruleID: got.ruleID}
		return nil
	}
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}
	installCertJobVersionTrigger(t)

	// When
	err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

	// Then
	if err == nil {
		t.Fatal("deployment succeeded despite reload failure")
	}
	select {
	case got := <-retried:
		if got.jobID != jobID || got.ruleID != ruleID {
			t.Fatalf("retry job=(%d,%q), want (%d,%q)", got.jobID, got.ruleID, jobID, ruleID)
		}
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
	if status != "downloaded" || certPEM != "new-cert" || keyPEM != "new-key" || deploymentAttempts != 1 || deploymentAvailableAfter == "" || version != 1 {
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

// 落盘前四道 fail-closed 门（规则启用 / 主节点角色 / 任务与规则域名一致 /
// 状态可部署）各自必须有负例：任一门被放宽（例如去掉 SQL 的 enabled=1 或
// is_master 条件、去掉域名比对、把状态集合扩大），部署链会把证书写到已禁用
// 规则或从节点的磁盘上，与主节点渲染面分叉。
func TestConfirmCertificateDeployment_rejects_roleDisabledDomainAndStatusGates(t *testing.T) {
	cases := map[string]struct {
		status    string
		prepare   func(t *testing.T, jobID int, ruleID string)
		wantNoRow bool
		wantText  string
	}{
		"rule disabled": {
			status: "downloaded",
			prepare: func(t *testing.T, _ int, ruleID string) {
				if _, err := db.DB.Exec("UPDATE lb_rules SET enabled=0 WHERE caddy_id=?", ruleID); err != nil {
					t.Fatalf("disable rule: %v", err)
				}
			},
			wantNoRow: true,
		},
		"slave node": {
			status: "downloaded",
			prepare: func(t *testing.T, _ int, _ string) {
				if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
					t.Fatalf("demote node: %v", err)
				}
			},
			wantNoRow: true,
		},
		"job domains diverged from rule": {
			status: "downloaded",
			prepare: func(t *testing.T, jobID int, _ string) {
				if _, err := db.DB.Exec("UPDATE cert_jobs SET domain='other.example.com' WHERE id=?", jobID); err != nil {
					t.Fatalf("diverge job domains: %v", err)
				}
			},
			wantText: "no longer match rule",
		},
		"status queued is not deployable": {
			status:   "queued",
			prepare:  func(*testing.T, int, string) {},
			wantText: "no longer deployable",
		},
		"status issued is not deployable for new material": {
			status:   "issued",
			prepare:  func(*testing.T, int, string) {},
			wantText: "no longer deployable",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			jobID, ruleID := seedCertificateJob(t, tc.status)
			tc.prepare(t, jobID, ruleID)

			err := confirmCertificateDeployment(context.Background(), jobID, issuedCertificate{ruleID: ruleID}, false)

			if err == nil {
				t.Fatal("confirmCertificateDeployment accepted a deployment the gate must reject")
			}
			if tc.wantNoRow && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("error=%v, want sql.ErrNoRows（规则/角色门由 JOIN 条件把关）", err)
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error=%v, want contains %q", err, tc.wantText)
			}
		})
	}
}

// 门拒绝时不得触碰磁盘：已禁用规则的证书目录必须保持上一次部署内容。
func TestCertIssuer_deployIssuedCertificate_disabledRuleKeepsDiskUnchanged(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	if err := WriteCertFiles(ruleID, "old-cert", "old-key"); err != nil {
		t.Fatalf("write previous certificate pair: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET enabled=0 WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("disable rule: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error { reloads++; return nil })
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	err := issuer.deployIssuedCertificate(context.Background(), jobID, material)

	if err == nil {
		t.Fatal("部署必须被已禁用规则拒绝")
	}
	certPath, keyPath := CertFilePaths(ruleID)
	if data, readErr := os.ReadFile(certPath); readErr != nil || string(data) != "old-cert" {
		t.Fatalf("cert file=%q err=%v, want 上一次部署内容（旧 %q）", string(data), readErr, "old-cert")
	}
	if data, readErr := os.ReadFile(keyPath); readErr != nil || string(data) != "old-key" {
		t.Fatalf("key file=%q err=%v, want 上一次部署内容（旧 %q）", string(data), readErr, "old-key")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0（被拒的部署不得触发 Caddy 重载）", reloads)
	}
}

// 快速路径的年龄门：库内材料已进入续签窗口（NotAfter 距现在 < cert_renewal_days）
// 时必须回落完整签发——否则任务被反复「重部署旧证书」，证书临期却不换新，
// 到期后 HTTPS 中断，而续签扫描仍认为链路正常（任务状态被重部署刷新）。
func TestCertIssuer_Issue_fastPathSkipsMaterialInsideRenewalWindow(t *testing.T) {
	// Given：downloaded 任务的材料只剩 1 天有效期（默认续签窗口 30 天）
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	// 指向本机不可达目录的专用提供商：完整签发在预检即失败，且不触碰真实 CA
	// （播种的默认提供商是真实 ZeroSSL/Let's Encrypt 端点）。
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "no acme here", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	result, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('unreachable CA','letsencrypt',?,'{}',1,0,1)`, server.URL+"/directory")
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id=?", providerID, ruleID); err != nil {
		t.Fatalf("bind rule CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET ca_provider_id=? WHERE id=?", providerID, jobID); err != nil {
		t.Fatalf("bind job CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='admin@example.com' WHERE id=1"); err != nil {
		t.Fatalf("seed ACME email: %v", err)
	}
	now := time.Now()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-2*time.Hour), now.Add(24*time.Hour), "example.com")
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem=? WHERE id=?", certPEM, keyPEM, jobID); err != nil {
		t.Fatalf("seed expiring material: %v", err)
	}
	issuer := NewCertIssuer(func() error { return nil })
	redeployed := make(chan struct{}, 1)
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error {
		redeployed <- struct{}{}
		return nil
	}

	// When：完整签发进入 CA 预检并以失败告终
	err = issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: int(providerID)})

	// Then：必须走 CA 签发链，而不是重部署临期材料
	if err == nil {
		t.Fatal("续签窗口内的材料必须回落完整签发（快速路径会重部署旧证书并返回 nil）")
	}
	select {
	case <-redeployed:
		t.Fatal("续签窗口内的材料不得登记部署重试")
	default:
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（完整签发在 CA 预检失败）", status)
	}
	logData, readErr := os.ReadFile(CertJobLogPath(ruleID))
	if readErr != nil {
		t.Fatalf("read cert job log: %v", readErr)
	}
	if !strings.Contains(string(logData), "测试 CA 提供商") {
		t.Fatalf("job log=%q, want 完整签发链的预检记录", string(logData))
	}
	if strings.Contains(string(logData), "重新部署") {
		t.Fatalf("job log=%q, 快速路径重部署不应出现在续签窗口分支", string(logData))
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
	installCertJobVersionTrigger(t)

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
	if string(certPEM) != "old-cert" || string(keyPEM) != "old-key" || status != "disabled" || version != 2 || reloads != 2 {
		t.Fatalf("files=(%q,%q) status=%q version=%d reloads=%d", certPEM, keyPEM, status, version, reloads)
	}
}

func TestCertIssuer_deployIssuedCertificate_skips_rollback_when_cas_loser_files_match_winner(t *testing.T) {
	// 并发部署回调（在途回调 × Resume/Unblock 补扫重试）部署同
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
	// 对照：终态 CAS 冲突但磁盘内容与本回调部署的证书不同（并发
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
	// 自此再调度异步——channel 等待替代裸计数器（消顺序/数据竞态）。
	retried := make(chan struct{}, 1)
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error { retried <- struct{}{}; return nil }

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
	// 快速路径同时比对私钥文件——部署态必须 cert+key 双文件
	// 都与任务材料一致才算「无需重新部署」。
	certPath, keyPath := CertFilePaths(ruleID)
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write deployed certificate file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("persisted-key"), 0600); err != nil {
		t.Fatalf("write deployed key file: %v", err)
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

// 规则与任务两侧都是「跟随默认 CA」（ca_provider_id=0）时，任务行未固化解析
// 结果（补偿重排队/导入回插/集群恢复可留下 0）。两侧必须经同一默认解析后比较：
// 此前规则侧解析为具体 ID、任务侧保持 0，被判为「提供商已切换」而白跑一次
// 完整 ACME 重签（CA 订单 + DNS 挑战），已签发材料却被丢弃。
func TestCertIssuer_Issue_fast_path_treats_both_follow_default_as_same_provider(t *testing.T) {
	// Given：默认 CA 指向一个必然连接失败的本地端口——若误走完整签发会立刻报错
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const providerID = 7
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES (?, 'Default CA', 'letsencrypt', 'http://127.0.0.1:1/directory', '{}', 1, 0, 1)`, providerID); err != nil {
		t.Fatalf("seed default CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET default_ca_provider_id=? WHERE id=1", providerID); err != nil {
		t.Fatalf("set default CA provider: %v", err)
	}
	// 两侧都跟随默认：规则与任务行均为 0。
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=0 WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("reset rule CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key', ca_provider_id=0 WHERE id=?", certPEM, jobID); err != nil {
		t.Fatalf("seed downloaded certificate material: %v", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write deployed certificate file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("persisted-key"), 0600); err != nil {
		t.Fatalf("write deployed key file: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: providerID})

	// Then：走「已部署且材料一致」快速路径，不重签不重载
	if err != nil {
		t.Fatalf("issue with both sides following default CA: %v", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read fast-path job: %v", err)
	}
	if status != "issued" || reloads != 0 {
		t.Fatalf("job status=%q reloads=%d, want issued and 0（两侧 0 应视为同一默认提供商）", status, reloads)
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

func TestCertIssuer_deploymentFailed_doesNotDowngradeOutsideDeployableLifecycle(t *testing.T) {
	for _, status := range []string{"issued", "failed", "disabled", "creating_order"} {
		t.Run(status, func(t *testing.T) {
			jobID, ruleID := seedCertificateJob(t, status)
			if _, err := db.DB.Exec(`UPDATE cert_jobs SET deployment_attempts=2 WHERE id=?`, jobID); err != nil {
				t.Fatal(err)
			}
			issuer := NewCertIssuer(nil)
			issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error {
				t.Error("non-deployable job must not schedule a retry")
				return nil
			}

			_ = issuer.deploymentFailed(jobID, issuedCertificate{ruleID: ruleID, providerID: 1}, "late deployment failure", errors.New("late failure"))

			var gotStatus string
			var attempts int
			if err := db.DB.QueryRow(`SELECT status,deployment_attempts FROM cert_jobs WHERE id=?`, jobID).Scan(&gotStatus, &attempts); err != nil {
				t.Fatal(err)
			}
			if gotStatus != status || attempts != 2 {
				t.Fatalf("late failure changed job to status=%q attempts=%d, want %q/2", gotStatus, attempts, status)
			}
		})
	}
}

func TestRetryCertificateDeployment_missingExpiryRecoversFromCertificatePEM(t *testing.T) {
	jobID, _ := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPEM := testCertificatePEM(t, notAfter)
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem=?,key_pem='stored-key',expires_at=NULL WHERE id=?`, certPEM, jobID); err != nil {
		t.Fatal(err)
	}

	if err := retryCertificateDeployment(context.Background(), jobID, nil); err != nil {
		t.Fatalf("retry imported downloaded job without expires_at: %v", err)
	}
	var status string
	var expiresAt string
	if err := db.DB.QueryRow(`SELECT status,COALESCE(expires_at,'') FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &expiresAt); err != nil {
		t.Fatal(err)
	}
	if status != "issued" || expiresAt == "" {
		t.Fatalf("recovered job status=%q expires_at=%q, want issued with backfilled expiry", status, expiresAt)
	}
}

func TestRetryCertificateDeployment_missingExpiryRejectsMalformedPEM(t *testing.T) {
	jobID, _ := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='not-a-certificate',key_pem='stored-key',expires_at=NULL WHERE id=?`, jobID); err != nil {
		t.Fatal(err)
	}
	if err := retryCertificateDeployment(context.Background(), jobID, nil); err == nil {
		t.Fatal("malformed certificate without expires_at must fail visibly")
	}
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" {
		t.Fatalf("malformed material changed status to %q, want downloaded", status)
	}
}

func TestCertIssuer_deploymentFailed_backs_off_then_slowRetriesAtMaxAttempts(t *testing.T) {
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	issuer := NewCertIssuer(nil)
	// deploymentFailed 的再调度是异步 go deploymentRetry，
	// 回调内裸写切片与已修的两处同型竞态——channel 收集 + 有界等待。
	type retryCall struct {
		material issuedCertificate
		delay    time.Duration
	}
	retries := make(chan retryCall, maxCertificateDeploymentAttempts)
	issuer.deploymentRetry = func(_ int, material issuedCertificate, delay time.Duration) error {
		retries <- retryCall{material: material, delay: delay}
		return nil
	}

	// When：连续打满退避上限，attempt 从 DB 重算（deploymentFailed 同步维护）。
	for range maxCertificateDeploymentAttempts {
		_ = issuer.deploymentFailed(jobID, issuedCertificate{ruleID: ruleID, providerID: 1}, "reload failed", errors.New("reload failed"))
	}

	// Then：每次失败都再调度——前 9 次按 1s→256s 退避，第 10 次封顶后转
	// 30 分钟慢速重试（不落 failed，材料保留、磁盘恢复后自动收敛）。
	wantDelays := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		32 * time.Second, 64 * time.Second, 128 * time.Second, 256 * time.Second,
		30 * time.Minute,
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
	var status, message string
	var attempts int
	if err := db.DB.QueryRow("SELECT status, COALESCE(message,''), deployment_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message, &attempts); err != nil {
		t.Fatalf("read deployment retry status: %v", err)
	}
	if status != "downloaded" || attempts != maxCertificateDeploymentAttempts {
		t.Fatalf("deployment retry status=%q attempts=%d, want downloaded (slow retry) and %d", status, attempts, maxCertificateDeploymentAttempts)
	}
	if !strings.Contains(message, "慢速重试") {
		t.Fatalf("message=%q at cap, want slow-retry disclosure", message)
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
	resetCertificateServiceForTest(t)
	var gotAttempt int
	var gotDelay time.Duration
	service.deploymentRetry = func(_ int, material issuedCertificate, delay time.Duration) error {
		gotAttempt = material.deploymentAttempt
		gotDelay = delay
		return nil
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

func TestRetryCertificateDeployment_cleanup_dns_job_slowRetriesAtMaxAttempts(t *testing.T) {
	// Given：长时间停留在 cleanup_dns 的任务，部署反复失败——封顶后保留可部署态
	// （落 failed 会把材料/磁盘分叉变成无自动通道的搁浅）
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
	var available sql.NullTime
	if err := db.DB.QueryRow("SELECT status, deployment_attempts, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts, &available); err != nil {
		t.Fatalf("read capped cleanup_dns job: %v", err)
	}
	if status != "downloaded" || attempts != maxCertificateDeploymentAttempts {
		t.Fatalf("job status=%q attempts=%d, want downloaded (slow retry) with %d attempts", status, attempts, maxCertificateDeploymentAttempts)
	}
	if !available.Valid || time.Until(available.Time) < 20*time.Minute {
		t.Fatalf("deployment_available_after=%v, want ~30m slow-retry window", available)
	}
}

// installCertJobVersionTrigger 安装与生产同语义的 cert_jobs 版本触发器
// （镜像 middleware 的 cluster_version_cert_jobs_update）：主节点守卫 +
// 成员条件（非 disabled 且材料齐全且未过期）+ 语义列值真实变化守卫 +
// disabled 双向例外。
//
// services 测试库不安装生产触发器（由 middleware 装配），此前的合成版本只按
// 列名触发、无值变化守卫：断言「失败/回滚不推进版本」在簿记列抖动时假绿，
// 而材料真实变化时的 bump 又无法区分。断言必须跑在与生产同形的语义上。
func installCertJobVersionTrigger(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`CREATE TRIGGER test_cluster_version_cert_jobs_update
		AFTER UPDATE OF rule_id, domain, status, cert_pem, key_pem, expires_at, ca_provider_id, renewal_attempts, ca_available_after, last_error_code, created_at, updated_at ON cert_jobs
		WHEN (SELECT COALESCE(is_master,1) FROM global_config WHERE id=1)=1
		 AND (
			(OLD.status<>'disabled' AND COALESCE(OLD.cert_pem,'')<>'' AND COALESCE(OLD.key_pem,'')<>'' AND datetime(OLD.expires_at)>datetime('now'))
			OR (NEW.status<>'disabled' AND COALESCE(NEW.cert_pem,'')<>'' AND COALESCE(NEW.key_pem,'')<>'' AND datetime(NEW.expires_at)>datetime('now'))
		 )
		 AND (
			OLD.rule_id IS NOT NEW.rule_id
			OR OLD.domain IS NOT NEW.domain
			OR OLD.cert_pem IS NOT NEW.cert_pem
			OR OLD.key_pem IS NOT NEW.key_pem
			OR OLD.expires_at IS NOT NEW.expires_at
			OR OLD.ca_provider_id IS NOT NEW.ca_provider_id
			OR (OLD.status<>'disabled' AND NEW.status='disabled')
			OR (OLD.status='disabled' AND NEW.status<>'disabled')
		 )
		BEGIN UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1; END`); err != nil {
		t.Fatalf("install certificate job version trigger: %v", err)
	}
}

// 簿记列抖动（message/attempts/available_after/updated_at）不得推进
// cluster_version：这些列在每次签发的阶段写里反复变化，bump 会让 304 门
// 失效、从节点反复全量重放。材料列的真实变化则必须 bump（从端要看到新证书）。
func TestClusterVersion_certJobBookkeepingDoesNotBump(t *testing.T) {
	jobID, _ := seedCertificateJob(t, "downloaded")
	installCertJobVersionTrigger(t)
	expiresAt := time.Now().UTC().Add(90 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='cert-a', key_pem='key-a', expires_at=? WHERE id=?`, expiresAt, jobID); err != nil {
		t.Fatalf("seed certificate material: %v", err)
	}
	var version int
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if version != 1 {
		t.Fatalf("材料落库后 version=%d, want 1", version)
	}

	// When：仅簿记列变化
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET message='等待排队签发', deployment_attempts=3, deployment_available_after=datetime('now'), updated_at=datetime('now') WHERE id=?`, jobID); err != nil {
		t.Fatalf("bump bookkeeping columns: %v", err)
	}

	// Then：版本不变
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if version != 1 {
		t.Fatalf("簿记列抖动使 version=%d, want 1（仅语义列变化才推进）", version)
	}

	// 对照：材料变化必须推进
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='cert-b' WHERE id=?`, jobID); err != nil {
		t.Fatalf("update certificate material: %v", err)
	}
	if err := db.DB.QueryRow("SELECT cluster_version FROM global_config WHERE id=1").Scan(&version); err != nil {
		t.Fatalf("read cluster version: %v", err)
	}
	if version != 2 {
		t.Fatalf("材料变化后 version=%d, want 2", version)
	}
}

func TestCertIssuer_Issue_fastPathMaterialReadFailure_defersDeployment(t *testing.T) {
	// 快速路径读材料失败（瞬时 DB 故障）不得静默回落完整签发——那会白烧一张
	// 新 CA 订单，而库里材料可能完好。必须走部署重试语义：任务保持部署
	// 生命周期 + 退避窗口 + 登记重试，且不重写材料列。
	// Given
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	issuer := NewCertIssuer(func() error { return nil })
	retried := make(chan struct{}, 1)
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error { retried <- struct{}{}; return nil }
	oldReader := readFastPathIssuedMaterial
	readFastPathIssuedMaterial = func(context.Context, int) (string, string, error) {
		return "", "", errors.New("injected material read failure")
	}
	t.Cleanup(func() { readFastPathIssuedMaterial = oldReader })

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: 1})

	// Then：部署重试错误族（不是 CA 签发失败），任务未被推进到签发态
	var deploymentErr *certificateDeploymentError
	if !errors.As(err, &deploymentErr) {
		t.Fatalf("issue error=%v, want certificateDeploymentError（读失败须走部署重试而非全签）", err)
	}
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("读失败后未登记部署重试")
	}
	var status string
	var attempts int
	var after sql.NullString
	if err := db.DB.QueryRow("SELECT status, COALESCE(deployment_attempts,0), deployment_available_after FROM cert_jobs WHERE id=?", jobID).
		Scan(&status, &attempts, &after); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（不得回落 creating_account 全签）", status)
	}
	if attempts != 1 || !after.Valid {
		t.Fatalf("deployment_attempts=%d window=%v, want 1 + 非空窗口", attempts, after.Valid)
	}
}

func TestCertificateDeploymentBackoff_ladderUpperBound(t *testing.T) {
	// 真实阶梯 = 1s×2^(attempt-1)，由循环守卫在跨过 5min 处停止加倍：
	// attempt 10 起为 512s（上界），attempt≥maxCertificateDeploymentAttempts
	// 时调用方改用 30min 慢速重试，阶梯值不再生效。
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{9, 256 * time.Second},
		{10, 512 * time.Second},
		{20, 512 * time.Second},
	}
	for _, tc := range cases {
		if got := certificateDeploymentBackoff(tc.attempt); got != tc.want {
			t.Fatalf("certificateDeploymentBackoff(%d)=%v, want %v", tc.attempt, got, tc.want)
		}
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
	// 未打桩的 deploymentRetry=scheduleCertificateDeploymentRetry 会注册真实
	// 定时器（首个 1s 退避即可在用例退出后触发、写跨用例的 DB/磁盘状态）。
	oldIssuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error { return nil }
	newReloadEntered := make(chan struct{})
	newIssuer := NewCertIssuer(func() error {
		close(newReloadEntered)
		return nil
	})
	newIssuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error { return nil }
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

// 字符串回退不得把裸 "429" 子串当限流证据——acme/issuer.go:105
// 把域名嵌进错误文本（"present dns for %s: ..."），429.example.com 这类域名
// 会被误分类为 CA 限流（waiting_ca 冷却 1-3h 而非 failJob 30min 重试）。
// 真实 CA 429 由结构化 *acme.Error StatusCode==429 分支覆盖。
func TestDetectRateLimit_string_fallback_ignores_bare_429_substring(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "dns present error embedding 429-like domain", err: fmt.Errorf("present dns for 429.example.com: connection refused"), want: false},
		{name: "dns propagation error embedding 429-like domain", err: fmt.Errorf("recursive DNS propagation failed for _acme-challenge.429.example.com: record not visible on public resolvers"), want: false},
		{name: "authz url containing 429 path segment", err: fmt.Errorf("GET https://acme.example/authz/429/abc: server internal error"), want: false},
		{name: "rate limit wording", err: fmt.Errorf("dns api: rate limit exceeded"), want: true},
		{name: "too many wording", err: fmt.Errorf("too many requests for this week"), want: true},
		{name: "wrapped CAProviderRateLimitError text", err: fmt.Errorf("issue: %w", &CAProviderRateLimitError{RetryAfter: time.Minute, Reason: "upstream limited"}), want: true},
		{name: "structured acme 429", err: &xacme.Error{StatusCode: http.StatusTooManyRequests, ProblemType: "urn:ietf:params:acme:error:rateLimited"}, want: true},
		{name: "structured acme non-429", err: &xacme.Error{StatusCode: http.StatusBadRequest, ProblemType: "urn:ietf:params:acme:error:malformed"}, want: false},
		{name: "unrelated error", err: errors.New("connection refused"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			got := detectRateLimit(tc.err)

			// Then
			if (got != nil) != tc.want {
				t.Fatalf("detectRateLimit(%v) classified rateLimit=%v, want %v", tc.err, got != nil, tc.want)
			}
		})
	}
}

// CA 429 提示分支封顶 3h。
func TestComputeBackoff_retryAfterClampedTo3h(t *testing.T) {
	if got := computeBackoff(1, 24*time.Hour); got != 3*time.Hour {
		t.Fatalf("computeBackoff(1, 24h)=%v, want 3h (clamped)", got)
	}
	if got := computeBackoff(1, time.Hour); got != time.Hour {
		t.Fatalf("computeBackoff(1, 1h)=%v, want 1h (under cap)", got)
	}
	if got := computeBackoff(1, 0); got != time.Hour {
		t.Fatalf("computeBackoff(1, 0)=%v, want 1h (ladder)", got)
	}
	if got := computeBackoff(2, 0); got != 2*time.Hour {
		t.Fatalf("computeBackoff(2, 0)=%v, want 2h (ladder)", got)
	}
}

// 注释承诺剥「句点或逗号」而 TrimRight 只剥句点
// ——逗号结尾的 "retry after 3600s," 此前落入解析失败被整段丢弃。
func TestExtractRetryAfterFromError_stripsTrailingCommaAndPeriod(t *testing.T) {
	if d := extractRetryAfterFromError("rate limited, retry after 3600s,"); d != 3600*time.Second {
		t.Fatalf("comma-suffixed seconds=%v, want 3600s", d)
	}
	if d := extractRetryAfterFromError("rate limited. retry after 3600s."); d != 3600*time.Second {
		t.Fatalf("period-suffixed seconds=%v, want 3600s", d)
	}
}

// 部署失败必须在 certjob-*.log 留一条 ERROR 业务行（attempt+
// 原因）——此前部署链 grep WriteCertJobLog 零命中，磁盘日志只剩签发阶段，
// 排障需反查 DB；重载/写文件/CAS 冲突等附带失败补 WARN 行，不改变签发结果。
func TestDeploymentFailed_writesCertJobLogWithAttemptAndReason(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	issuer := NewCertIssuer(nil)
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	// When：首次部署失败（attempt=1/10）
	if err := issuer.deploymentFailed(jobID, material, "重载 Caddy 失败: boom", errors.New("boom")); err == nil {
		t.Fatal("deploymentFailed returned nil error")
	}

	// Then：job 日志含 ERROR 行（阶段/attempt/原因）
	data, err := os.ReadFile(CertJobLogPath(ruleID))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	logText := string(data)
	for _, want := range []string{"[ERROR]", "deployment_failed", "attempt=1/10", "重载 Caddy 失败: boom"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("cert job log missing %q:\n%s", want, logText)
		}
	}
}

// 封顶形态：第 10 次部署失败保留可部署态（慢速重试），日志行
// 同样带 attempt=10/10 与慢速重试说明。
func TestDeploymentFailed_entersSlowRetryAtMaxAttempts(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec("UPDATE cert_jobs SET deployment_attempts=9 WHERE id=?", jobID); err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	issuer := NewCertIssuer(nil)
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	_ = issuer.deploymentFailed(jobID, material, "重载 Caddy 失败: boom", errors.New("boom"))

	data, err := os.ReadFile(CertJobLogPath(ruleID))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	if !strings.Contains(string(data), "attempt=10/10") {
		t.Fatalf("cert job log missing capped attempt=10/10:\n%s", data)
	}
	if !strings.Contains(string(data), "慢速重试") {
		t.Fatalf("cert job log missing slow-retry disclosure:\n%s", data)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("job status=%q, want downloaded (material retained for slow retry)", status)
	}
}

// 封顶后的慢速重试会继续累加计数器（真实值落库，重试链依赖它），但展示值
// 必须钳制在上限内——`[attempt=57/10]` 会让用户以为「超出配额却仍在重试」。
func TestDeploymentFailed_capsDisplayedAttemptWhileCounterKeepsGrowing(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	const actualAttempts = maxCertificateDeploymentAttempts*5 + 6
	if _, err := db.DB.Exec("UPDATE cert_jobs SET deployment_attempts=? WHERE id=?", actualAttempts, jobID); err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	issuer := NewCertIssuer(nil)
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	_ = issuer.deploymentFailed(jobID, material, "重载 Caddy 失败: boom", errors.New("boom"))

	data, err := os.ReadFile(CertJobLogPath(ruleID))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	logText := string(data)
	if !strings.Contains(logText, "attempt=10/10") {
		t.Fatalf("cert job log missing capped display attempt=10/10:\n%s", logText)
	}
	if strings.Contains(logText, "attempt=57/10") {
		t.Fatalf("cert job log leaks out-of-range attempt ratio:\n%s", logText)
	}

	var message string
	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(message,''), COALESCE(deployment_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&message, &attempts); err != nil {
		t.Fatalf("read job row: %v", err)
	}
	if attempts != actualAttempts+1 {
		t.Fatalf("deployment_attempts=%d, want %d（真实计数不得被展示钳制影响）", attempts, actualAttempts+1)
	}
	if strings.Contains(message, "attempt=57/10") || !strings.Contains(message, "attempt=10/10") {
		t.Fatalf("job message=%q, want capped attempt ratio", message)
	}
	if !strings.Contains(message, "慢速重试") {
		t.Fatalf("job message=%q, want slow-retry disclosure", message)
	}
}

// 状态回写失败（CAS 冲突/DB 故障）不得静默——补 WARN 行留痕，返回值仍
// 是部署失败（签发结果不变）。
func TestDeploymentFailed_warnsWhenStatusWritebackFails(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec(`CREATE TRIGGER force_cert_job_update_fail BEFORE UPDATE ON cert_jobs BEGIN SELECT RAISE(ABORT, 'forced'); END;`); err != nil {
		t.Fatalf("create fail trigger: %v", err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS force_cert_job_update_fail") })
	issuer := NewCertIssuer(nil)
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}

	if err := issuer.deploymentFailed(jobID, material, "重载 Caddy 失败: boom", errors.New("boom")); err == nil {
		t.Fatal("deploymentFailed returned nil error")
	}

	data, err := os.ReadFile(CertJobLogPath(ruleID))
	if err != nil {
		t.Fatalf("read cert job log: %v", err)
	}
	if !strings.Contains(string(data), "[WARN]") || !strings.Contains(string(data), "deployment_status_update_failed") {
		t.Fatalf("status writeback failure not surfaced as WARN:\n%s", data)
	}
}

func TestRetryCertificateDeploymentNow_tracksServiceLifecycle(t *testing.T) {
	// Given：运行中的证书服务接受立即部署重排。
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.retryDeployment = func(context.Context, int) error { return nil }
	if err := RetryCertificateDeploymentNow(41, "lb_retry_lifecycle"); err != nil {
		t.Fatalf("running certificate service rejected deployment retry: %v", err)
	}

	// When：服务停止后再触发同一入口。
	service.Stop()

	// Then：必须明确拒绝，不得把 stopping 分支的静默丢弃报告为已调度。
	if err := RetryCertificateDeploymentNow(42, "lb_retry_lifecycle"); !errors.Is(err, ErrCertificateQueueInactive) {
		t.Fatalf("stopped service retry error=%v, want ErrCertificateQueueInactive", err)
	}
}

func TestRetryCertificateDeploymentNow_reportsBusyCallback(t *testing.T) {
	// Given：服务运行中，但同任务的上一次部署回调尚未在取消等待内退出。
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	service.cancelWaitTimeout = 20 * time.Millisecond
	entry := &deploymentTimer{done: make(chan struct{}), ruleID: "lb_retry_busy"}
	entry.ctx, entry.cancel = context.WithCancel(service.ctx)
	service.deploymentCallbacks[42] = map[*deploymentTimer]struct{}{entry: {}}
	t.Cleanup(func() { close(entry.done) })

	// When
	err := RetryCertificateDeploymentNow(42, "lb_retry_busy")

	// Then：必须与「服务已停止」区分，避免把回调忙误报为任务停止。
	if !errors.Is(err, ErrCertificateDeploymentRetryBusy) {
		t.Fatalf("retry error=%v, want ErrCertificateDeploymentRetryBusy", err)
	}
}

func TestCAQueue_execute_roleInterruptionRequeuesWithoutRenewalAttempts(t *testing.T) {
	// Given：签发执行体经生产错误包装返回角色中断，任务已有 2 次续签尝试。
	jobID, ruleID := seedCertificateJob(t, "downloading")
	if _, err := db.DB.Exec("UPDATE cert_jobs SET renewal_attempts=2 WHERE id=?", jobID); err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("demote node: %v", err)
	}
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.executeFn = func(ctx context.Context, _ queueItem, _ models.CAProvider) error {
		return fmt.Errorf("execute issuance: %w", checkCertificateIssuanceRole(ctx))
	}
	queue.enqueue(queueItem{jobID: jobID, ruleID: ruleID, domains: "example.com"})
	queue.mu.Lock()
	execution, ok := queue.prepareExecutionLocked(context.Background())
	queue.mu.Unlock()
	if !ok {
		t.Fatal("role interruption execution was not prepared")
	}

	// When
	queue.execute(execution)

	// Then：经真实 execute→handleQueueExecutionError 链路仍不消耗预算。
	var status string
	var attempts int
	if err := db.DB.QueryRow("SELECT status,renewal_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read executed job: %v", err)
	}
	if status != "queued" || attempts != 2 {
		t.Fatalf("job status=%q attempts=%d, want queued/2", status, attempts)
	}
}

func TestHandleQueueExecutionError_roleInterruptionDoesNotConsumeRenewalAttempts(t *testing.T) {
	for _, tc := range []struct {
		name string
		// plainFailure：非角色错误的对照分支——同一张表必须真实调用
		// handleQueueExecutionError 走 failJob，否则「master 未变化不消耗预算」
		// 的一半语义（普通失败照常 failed + 预算+1）无人覆盖。
		plainFailure  bool
		status        string
		prepare       func(*testing.T)
		wantRoleError bool
		wantStatus    string
		wantAttempts  int
	}{
		{name: "master unchanged routes to plain CA failure", plainFailure: true, status: "downloading", prepare: func(*testing.T) {}, wantStatus: "failed", wantAttempts: 3},
		{name: "slave transition requeues", status: "downloading", prepare: func(t *testing.T) {
			if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
				t.Fatalf("demote node: %v", err)
			}
		}, wantRoleError: true, wantStatus: "queued", wantAttempts: 2},
		{name: "role read failure requeues", status: "downloading", prepare: func(t *testing.T) {
			if _, err := db.DB.Exec("DELETE FROM global_config WHERE id=1"); err != nil {
				t.Fatalf("remove role row: %v", err)
			}
		}, wantRoleError: true, wantStatus: "queued", wantAttempts: 2},
		{name: "disabled job remains disabled", status: "disabled", prepare: func(t *testing.T) {
			if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
				t.Fatalf("demote node: %v", err)
			}
		}, wantRoleError: true, wantStatus: "disabled", wantAttempts: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given：角色检查发生在 CA 已签发之后，既有预算为 2。
			jobID, _ := seedCertificateJob(t, tc.status)
			if _, err := db.DB.Exec("UPDATE cert_jobs SET renewal_attempts=2 WHERE id=?", jobID); err != nil {
				t.Fatalf("seed renewal attempts: %v", err)
			}
			tc.prepare(t)
			if tc.plainFailure {
				// 对照分支：普通（非角色）失败必须落 failed 并消耗一次预算。
				handleQueueExecutionError(jobID, errors.New("普通 CA 失败"))
			} else {
				roleErr := checkCertificateIssuanceRole(context.Background())
				if !tc.wantRoleError {
					if roleErr != nil {
						t.Fatalf("master role check failed: %v", roleErr)
					}
					return
				}
				var typedRoleErr *certificateRoleError
				if !errors.As(roleErr, &typedRoleErr) {
					t.Fatalf("role error=%v, want certificateRoleError", roleErr)
				}
				// When：队列按执行错误分类（含包装层）。
				handleQueueExecutionError(jobID, fmt.Errorf("execute: %w", roleErr))
			}

			// Then：生命周期中断不得进入 CA failed 终态或消耗预算；普通失败照常。
			var status string
			var attempts int
			if err := db.DB.QueryRow("SELECT status,renewal_attempts FROM cert_jobs WHERE id=?", jobID).Scan(&status, &attempts); err != nil {
				t.Fatalf("read job after role interruption: %v", err)
			}
			if status != tc.wantStatus || attempts != tc.wantAttempts {
				t.Fatalf("job status=%q attempts=%d, want %q/%d", status, attempts, tc.wantStatus, tc.wantAttempts)
			}
		})
	}
}

// ---- 回归钉 ----

func TestParseRetryAfter_non_positive_seconds_zeroes(t *testing.T) {
	for _, header := range []string{"-5", "0"} {
		if got := parseRetryAfter(header); got != 0 {
			t.Fatalf("parseRetryAfter(%q)=%v, want 0（契约：非正值归零）", header, got)
		}
	}
}

func TestExtractRetryAfterFromError_parses_go_time_string(t *testing.T) {
	// 注释文档化的 Go time.Time.String() 形态必须命中（此前该分支永不命中，
	// 退化为自有阶梯 1–3h）。
	target := time.Now().Add(90 * time.Minute)
	text := "rate limit exceeded, retry after " + target.Format("2006-01-02 15:04:05 -0700 MST")
	got := extractRetryAfterFromError(text)
	if got <= 0 {
		t.Fatalf("extractRetryAfterFromError(%q)=%v, want >0", text, got)
	}
	if got > 91*time.Minute || got < 88*time.Minute {
		t.Fatalf("extractRetryAfterFromError=%v, want ≈90m", got)
	}
}

// ZeroSSL 签发链每次签发不得重复注册 ACME 账户——预检
// （testCAProvider）已完成 RegisterAccount 的 client 必须被签发复用，
// Issuer 跳过重复注册。钉：/account POST 恰好 1 次（旧实现=2 次）。
func TestCertIssuer_Issue_zerosslRegistersAccountOnce(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "queued")
	var serverURL string
	var accountPosts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/account":
			accountPosts.Add(1)
			response.Header().Set("Location", serverURL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"status":"valid"}`))
		default:
			// 订单及以后一律 429：签发在预检后尽早停，聚焦注册次数断言。
			response.Header().Set("Retry-After", "1")
			response.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	result, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('ZeroSSL','zerossl',?, '{"eab_kid":"kid","eab_hmac_key":"a2jtMUD2Qzl6T0dIQXdNcQ"}',1,0,1)`, serverURL+"/directory")
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
	// DNS 凭据必须就位，否则签发在「未选择可用的 DNS 提供商」提前失败，
	// 到不了第二次注册（断言面假绿）。
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'dns','dnspod','{"mode":"tencent","secret_id":"id","secret_key":"key"}',1)`); err != nil {
		t.Fatalf("seed DNS config: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=1 WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("bind DNS config: %v", err)
	}
	issuer := NewCertIssuer(func() error { return nil }, t.TempDir())

	var provider models.CAProvider
	if err := scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=?", providerID), &provider); err != nil {
		t.Fatalf("load CA provider: %v", err)
	}
	issueErr := issuer.Issue(context.Background(), jobID, ruleID, "example.com", provider)
	if issueErr == nil {
		t.Fatal("issuance must stop at the 429 order endpoint")
	}
	if got := accountPosts.Load(); got != 1 {
		t.Fatalf("ACME /account POSTs=%d, want 1（预检注册后签发复用同 client，不重复注册）", got)
	}
}

// issued 形态的材料读失败：任务已部署完成，不在 deploymentFailed 的 from 集合
// ——旧实现走该链只会 CAS 失败并留下「部署失败状态回写失败」噪音，日志还谎称
// 「转部署重试」。必须保持 issued（不重签、不改状态）并如实说明接管通道。
func TestCertIssuer_Issue_fastPathMaterialReadFailure_issuedStaysIssued(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "issued")
	useTemporaryCertDir(t)
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	issuer := NewCertIssuer(func() error { return nil })
	retried := make(chan struct{}, 1)
	issuer.deploymentRetry = func(int, issuedCertificate, time.Duration) error { retried <- struct{}{}; return nil }
	oldReader := readFastPathIssuedMaterial
	readFastPathIssuedMaterial = func(context.Context, int) (string, string, error) {
		return "", "", errors.New("injected material read failure")
	}
	t.Cleanup(func() { readFastPathIssuedMaterial = oldReader })

	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: 1})

	var deploymentErr *certificateDeploymentError
	if !errors.As(err, &deploymentErr) {
		t.Fatalf("issue error=%v, want certificateDeploymentError（不得回落全签）", err)
	}
	select {
	case <-retried:
		t.Fatal("issued 形态不得登记部署重试（deploymentFailed 的 from 集合不含 issued）")
	case <-time.After(50 * time.Millisecond):
	}
	var status string
	var attempts int
	var after sql.NullString
	if err := db.DB.QueryRow("SELECT status, COALESCE(deployment_attempts,0), deployment_available_after FROM cert_jobs WHERE id=?", jobID).
		Scan(&status, &attempts, &after); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "issued" || attempts != 0 || after.Valid {
		t.Fatalf("status=%q attempts=%d window=%v, want issued/0/空（保持已部署终态）", status, attempts, after.Valid)
	}
	logData, readErr := os.ReadFile(CertJobLogPath(ruleID))
	if readErr != nil {
		t.Fatalf("读取证书任务日志 %s: %v", CertJobLogPath(ruleID), readErr)
	}
	if !strings.Contains(string(logData), "保持 issued") {
		t.Fatalf("任务日志未如实说明接管通道: %q", string(logData))
	}
}

// 手动证书未来生效：保持 valid 枚举（前端无 not_yet_valid 分支），但必须在
// Error 字段显性说明——否则卡片显示 valid + 很大的剩余天数，而客户端在
// NotBefore 前拒绝该证书。
func TestFormatRuleCertInfo_notYetValidReportsNote(t *testing.T) {
	now := time.Now()
	certPEM, _ := certificatePairForDomains(t, now.Add(48*time.Hour), now.Add(90*24*time.Hour), "future.example.test")
	info := FormatRuleCertInfo(certPEM, "manual", "future.example.test", "", 30, now)
	if info.Status != "valid" {
		t.Fatalf("status=%q, want valid（枚举不扩展，避免前端契约变更）", info.Status)
	}
	if !strings.Contains(info.Error, "尚未生效") {
		t.Fatalf("error=%q, want 尚未生效说明", info.Error)
	}
	// 对照：已生效证书不得带该提示。
	pastPEM, _ := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "active.example.test")
	if info := FormatRuleCertInfo(pastPEM, "manual", "active.example.test", "", 30, now); info.Error != "" {
		t.Fatalf("已生效证书 error=%q, want 空", info.Error)
	}
}
