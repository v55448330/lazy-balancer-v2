package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// testCertificatePEMWithWindow 生成指定生效窗口的自签测试证书。
func testCertificatePEMWithWindow(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// 未来时钟证书：部署照常完成，但 NotBefore > now 时必须「证书尚未生效」
// 告警留痕（RecordAuditLog），并登记一次 NotBefore+余量时刻的延迟重载
// （复用证书服务既有定时器族，不新建调度器）。
func TestCertIssuer_deployIssuedCertificate_flagsFutureNotBefore(t *testing.T) {
	// Given：一小时后才生效的证书材料
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	issuer := NewCertIssuer(func() error { return nil })
	notBefore := time.Now().Add(time.Hour)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	material := issuedCertificate{
		ruleID:     ruleID,
		certPEM:    testCertificatePEMWithWindow(t, notBefore, notAfter),
		keyPEM:     "new-key",
		notAfter:   notAfter,
		providerID: 1,
	}
	scheduled := make(chan time.Duration, 1)
	oldScheduler := notBeforeReloadScheduler
	notBeforeReloadScheduler = func(gotJobID int, gotRuleID string, delay time.Duration) {
		if gotJobID != jobID || gotRuleID != ruleID {
			t.Errorf("reload schedule target=(%d,%q), want (%d,%q)", gotJobID, gotRuleID, jobID, ruleID)
		}
		scheduled <- delay
	}
	t.Cleanup(func() { notBeforeReloadScheduler = oldScheduler })

	// When
	if err := issuer.deployIssuedCertificate(context.Background(), jobID, material); err != nil {
		t.Fatalf("deploy issued certificate: %v", err)
	}

	// Then：登记了一次生效点+余量后的延迟重载（余量 1 分钟口径）
	select {
	case delay := <-scheduled:
		if delay < 59*time.Minute || delay > 62*time.Minute {
			t.Fatalf("reload delay=%v, want NotBefore+余量（约 61 分钟）", delay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("未来时钟证书未登记生效后延迟重载")
	}
	// And：审计留痕「证书尚未生效」
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='警告' AND resource='证书任务' AND detail LIKE '%尚未生效%'`).Scan(&n); err != nil {
		t.Fatalf("count not-before audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("not-before audit rows=%d, want 1", n)
	}
}

// 对照形态：NotBefore 已过的正常证书部署不得告警、不得登记延迟重载。
func TestCertIssuer_deployIssuedCertificate_quietWhenNotBeforePast(t *testing.T) {
	// Given：已生效证书材料
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	issuer := NewCertIssuer(func() error { return nil })
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	material := issuedCertificate{
		ruleID:     ruleID,
		certPEM:    testCertificatePEMWithWindow(t, time.Now().Add(-time.Hour), notAfter),
		keyPEM:     "new-key",
		notAfter:   notAfter,
		providerID: 1,
	}
	scheduled := make(chan time.Duration, 1)
	oldScheduler := notBeforeReloadScheduler
	notBeforeReloadScheduler = func(_ int, _ string, delay time.Duration) { scheduled <- delay }
	t.Cleanup(func() { notBeforeReloadScheduler = oldScheduler })

	// When
	if err := issuer.deployIssuedCertificate(context.Background(), jobID, material); err != nil {
		t.Fatalf("deploy issued certificate: %v", err)
	}

	// Then
	// 同步可观测：deployIssuedCertificate 在返回路径上同步调用
	// noteFutureNotBefore → notBeforeReloadScheduler（本用例的桩是缓冲通道的
	// 直接发送），调用已在本协程内完成；返回后不存在「还没被调度」的可能——
	// 固定观测窗只会白等 200ms。
	select {
	case delay := <-scheduled:
		t.Fatalf("已生效证书登记了延迟重载（delay=%v），want 不登记", delay)
	default:
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='警告' AND resource='证书任务' AND detail LIKE '%尚未生效%'`).Scan(&n); err != nil {
		t.Fatalf("count not-before audit: %v", err)
	}
	if n != 0 {
		t.Fatalf("not-before audit rows=%d, want 0（已生效证书不得误报）", n)
	}
}

// 延迟重载回调钉测：登记 → 到时 → 自取 CaddyOpLock → 调 reloader。
// reloader 为 InLock 语义（InitCAQueueManager 契约），回调在部署临界区外
// 触发，未取锁的重载会与部署/配置写并发。
func TestScheduleDelayedReload_firesReloadUnderCaddyOpLock(t *testing.T) {
	oldManager := caQueueManager
	probe := make(chan bool, 1)
	caQueueManager = &CAQueueManager{
		queues:       make(map[int]*caQueue),
		blockedRules: make(map[string]map[RuleBlockToken]struct{}),
		reloader: func() error {
			held := !CaddyOpLock.TryLock()
			if !held {
				CaddyOpLock.Unlock()
			}
			probe <- held
			return nil
		},
	}
	t.Cleanup(func() { caQueueManager = oldManager })

	service := NewCertificateService()
	t.Cleanup(service.Stop)
	service.scheduleDelayedReload(123, "lb_delayed_reload", 10*time.Millisecond)

	select {
	case held := <-probe:
		if !held {
			t.Fatal("延迟重载调用 reloader 时未持 CaddyOpLock（InLock 契约破裂）")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("延迟重载回调未在到期后触发")
	}
}

// 快速重部署路径（Issue 快速路径 → redeployDownloadedInLock）的两个成功出口也
// 必须登记生效点重载：首次部署写盘后失败、随后由补扫/手动重试收敛时，若证书
// NotBefore 在未来，缺登记就让「生效点补充重载」这条收敛路径断链。
func TestCertIssuer_Issue_fastPathFutureNotBeforeRegistersDelayedReload(t *testing.T) {
	cases := []struct {
		name string
		// predeploy=true 命中「文件已一致，无需重新部署」出口，false 命中重写盘出口。
		predeploy bool
	}{
		{name: "文件已一致的出口", predeploy: true},
		{name: "重新写盘的出口", predeploy: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given：downloaded 任务材料两小时后才生效（且远离续签窗口）。
			// 规则显式绑定与任务相同的提供商：快速路径的「提供商未切换」判定按
			// 解析后的 ID 比较，跟随默认时依赖播种默认值，容易随夹具漂移。
			jobID, ruleID := seedCertificateJob(t, "downloaded")
			useTemporaryCertDir(t)
			if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=1 WHERE caddy_id=?", ruleID); err != nil {
				t.Fatalf("bind rule CA provider: %v", err)
			}
			notBefore := time.Now().Add(2 * time.Hour)
			notAfter := notBefore.Add(90 * 24 * time.Hour)
			certPEM := testCertificatePEMWithWindow(t, notBefore, notAfter)
			const keyPEM = "key-pem"
			// expires_at 留 NULL：快速重部署的两个成功出口都必须按材料回填，
			// 否则同一张证在任务行是「无到期」，聚合端（cluster_report 以
			// expires_at 为门）与续期扫描两套口径分叉。
			if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem=?, expires_at=NULL WHERE id=?", certPEM, keyPEM, jobID); err != nil {
				t.Fatalf("seed job material: %v", err)
			}
			if tc.predeploy {
				if err := WriteCertFiles(ruleID, certPEM, keyPEM); err != nil {
					t.Fatalf("predeploy files: %v", err)
				}
			}
			scheduled := make(chan time.Duration, 1)
			oldScheduler := notBeforeReloadScheduler
			notBeforeReloadScheduler = func(gotJobID int, gotRuleID string, delay time.Duration) {
				if gotJobID != jobID || gotRuleID != ruleID {
					t.Errorf("reload schedule target=(%d,%q), want (%d,%q)", gotJobID, gotRuleID, jobID, ruleID)
				}
				scheduled <- delay
			}
			t.Cleanup(func() { notBeforeReloadScheduler = oldScheduler })
			issuer := NewCertIssuer(func() error { return nil })

			// When
			if err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: 1}); err != nil {
				t.Fatalf("issue via fast path: %v", err)
			}

			// Then：登记时刻≈NotBefore+余量
			select {
			case delay := <-scheduled:
				if delay < time.Hour || delay > 3*time.Hour {
					t.Fatalf("delay=%v, want ≈NotBefore+余量（约 1h59m）", delay)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("快速重部署成功出口未登记生效后延迟重载")
			}
			// And：expires_at 已按材料回填（与 NotAfter 一致，秒级误差内）。
			var expiresAt sql.NullTime
			if err := db.DB.QueryRow("SELECT expires_at FROM cert_jobs WHERE id=?", jobID).Scan(&expiresAt); err != nil {
				t.Fatalf("read backfilled expires_at: %v", err)
			}
			if !expiresAt.Valid || expiresAt.Time.Sub(notAfter).Abs() > time.Minute {
				t.Fatalf("expires_at=%v valid=%v, want ≈%v（快速路径必须回填）", expiresAt.Time, expiresAt.Valid, notAfter)
			}
		})
	}
}
