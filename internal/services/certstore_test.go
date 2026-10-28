package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func useTemporaryCertDir(t *testing.T) string {
	t.Helper()
	oldCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = oldCertDir })
	return certDir
}

func TestRemoveCertFiles_waits_for_certificate_pair_lock(t *testing.T) {
	// Given
	dir := useTemporaryCertDir(t)
	certPath := filepath.Join(dir, "lb_locked.crt")
	keyPath := filepath.Join(dir, "lb_locked.key")
	if err := os.WriteFile(certPath, []byte("cert"), 0600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0600); err != nil {
		t.Fatalf("write key fixture: %v", err)
	}
	certWriteMu.Lock()
	// 失败路径（含 waitGoroutineBlockedOn 的 Fatal）同样必须解锁：残留持锁会
	// 让同包后续用例永久阻塞在 certWriteMu 上（全局锁污染跨用例传播）。
	locked := true
	releaseWriteLock := func() {
		if locked {
			locked = false
			certWriteMu.Unlock()
		}
	}
	t.Cleanup(releaseWriteLock)
	done := make(chan error, 1)
	go func() { done <- RemoveCertFiles("lb_locked") }()

	// When：删除协程必须**确定地**阻塞在 certWriteMu.RLock（阻塞点是
	// certstore.go 的 RLock），用协程栈作证据。「开协程 + 立刻 select-default」
	// 只证明「还没轮到这个协程」，把 RLock 删掉也照样绿。
	waitGoroutineBlockedOn(t, "TestRemoveCertFiles_waits_for_certificate_pair_lock", "sync.(*RWMutex).RLock")
	select {
	case err := <-done:
		releaseWriteLock()
		t.Fatalf("remove returned before lock release: %v", err)
	default:
	}
	releaseWriteLock()

	// Then
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("remove certificate files: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("锁释放后删除未完成（等待者未放行）")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("certificate still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("private key still exists or stat failed: %v", err)
	}
}

// waitGoroutineBlockedOn 等待（最多 5s）出现一个同时命中全部 markers 的
// goroutine 栈块。runtime.Stack 的每个 goroutine 块含其阻塞点帧，因此「协程已
// 推进到并阻塞在 X」是可断言的确定事实——用来替代「睡一会儿再断言尚未返回」的
// 时序猜测（后者在等待点被删掉/协程尚未被调度时同样绿）。
func waitGoroutineBlockedOn(t *testing.T, markers ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	// 每轮都要 dump 全部协程栈（stop-the-world），故按步退避：阻塞点通常在
	// 几微秒内出现，退避只影响极端慢机的等待开销。
	backoff := time.Millisecond
	for {
		stacks := dumpGoroutineStacks()
		for _, block := range strings.Split(stacks, "\n\n") {
			if containsAll(block, markers...) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("5s 内未观察到同时命中 %v 的阻塞协程（等待点可能不存在/未被推进）：\n%s", markers, stacks)
		}
		time.Sleep(backoff)
		if backoff < 20*time.Millisecond {
			backoff *= 2
		}
	}
}

func dumpGoroutineStacks() string {
	buf := make([]byte, 1<<20)
	for {
		if n := runtime.Stack(buf, true); n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

func TestRemoveCertFiles_returns_both_delete_errors(t *testing.T) {
	// Given
	dir := useTemporaryCertDir(t)
	for _, path := range []string{filepath.Join(dir, "lb_errors.crt"), filepath.Join(dir, "lb_errors.key")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatalf("create blocking directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0600); err != nil {
			t.Fatalf("write blocking child: %v", err)
		}
	}

	// When
	err := RemoveCertFiles("lb_errors")

	// Then
	if err == nil {
		t.Fatal("remove succeeded despite both paths being non-empty directories")
	}
	if !strings.Contains(err.Error(), "删除证书") || !strings.Contains(err.Error(), "删除私钥") {
		t.Fatalf("remove error did not preserve both failures: %v", err)
	}
}

func TestDeployLock_removes_entry_after_last_release(t *testing.T) {
	// Given
	certificateDeployLocks = refCountedLockTable{}

	// When
	unlock := DeployLock("lb_refcount")
	unlock()

	// Then
	if _, exists := certificateDeployLocks.locks.Load("lb_refcount"); exists {
		t.Fatal("deployment lock entry remained after its last holder released it")
	}
}

func TestDeployLock_serializes_waiters_and_keeps_entry_until_final_release(t *testing.T) {
	certificateDeployLocks = refCountedLockTable{}
	acquired := make(chan int)
	release := make(chan struct{})
	done := make(chan int)
	for id := 1; id <= 3; id++ {
		go func() {
			unlock := DeployLock("lb_serial")
			acquired <- id
			<-release
			unlock()
			done <- id
		}()
	}
	first := <-acquired
	// 忙等必须有截止：引用计数回收被改坏时，无界循环会把断言失败伪装成
	// 测试超时（CI 挂起）；类型断言带 ok 避免私有字段形态变更直接 panic。
	deadline := time.Now().Add(2 * time.Second)
	for {
		certificateDeployLocks.mu.Lock()
		value, exists := certificateDeployLocks.locks.Load("lb_serial")
		lock, ok := value.(*refCountedLock)
		registered := exists && ok && lock.refs == 3
		certificateDeployLocks.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deployment lock refs did not reach 3 within 2s（expected=%v ok=%v）", exists, ok)
		}
		runtime.Gosched()
	}
	release <- struct{}{}
	if released := <-done; released != first {
		t.Fatalf("released worker=%d, want first holder %d", released, first)
	}
	second := <-acquired
	if _, exists := certificateDeployLocks.locks.Load("lb_serial"); !exists {
		t.Fatal("deployment lock entry was deleted while a waiter held it")
	}
	release <- struct{}{}
	if released := <-done; released != second {
		t.Fatalf("released worker=%d, want second holder %d", released, second)
	}
	<-acquired
	if _, exists := certificateDeployLocks.locks.Load("lb_serial"); !exists {
		t.Fatal("deployment lock entry was deleted before the final release")
	}
	release <- struct{}{}
	<-done
	if _, exists := certificateDeployLocks.locks.Load("lb_serial"); exists {
		t.Fatal("deployment lock entry remained after final release")
	}
}

// 规则文件锁/部署锁/日志写锁共用 refCountedLockTable：条目必须在最后一个
// 持有者释放后回收（规则可反复创建/删除，只增不删的表会按历史规则总数无界
// 增长），且等待者在场时不得回收（否则同 key 会出现两把锁，per-rule 串行化
// 失效）。
func TestRefCountedLockTable_reclaimsOnlyAfterLastHolder(t *testing.T) {
	var table refCountedLockTable
	first := table.acquire("lb_refcounted")
	first.Lock()
	if _, exists := table.locks.Load("lb_refcounted"); !exists {
		t.Fatal("在途持锁时条目必须存在")
	}

	secondAcquired := make(chan *refCountedLock, 1)
	go func() {
		second := table.acquire("lb_refcounted")
		second.Lock()
		secondAcquired <- second
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		table.mu.Lock()
		refs := first.refs
		table.mu.Unlock()
		if refs == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待者未登记引用（refs=%d, want 2）", refs)
		}
		runtime.Gosched()
	}

	first.Unlock()
	if _, exists := table.locks.Load("lb_refcounted"); !exists {
		t.Fatal("等待者仍在阻塞，条目不得回收（否则同 key 会出现两把不同锁）")
	}
	second := <-secondAcquired
	if second != first {
		t.Fatal("等待者拿到了另一把锁：per-rule 串行化失效")
	}
	second.Unlock()
	if _, exists := table.locks.Load("lb_refcounted"); exists {
		t.Fatal("最后一个持有者释放后条目未回收（键空间随历史规则无界增长）")
	}
}

// 「查找/创建条目」与「引用登记」必须同属一个表级临界区：分开执行时，最后
// 一个持有者可在两步之间把条目从表里删除，迟到的获取者于是抱着已成孤儿的旧锁
// 加锁，而第三者已建出另一把新锁——同 key 同时被两把锁「保护」，per-rule
// 互斥失效（证书/私钥可交错写，部署快照可覆盖已提交的部署）。
func TestRefCountedLockTable_acquireNeverHandsOutStaleEntry(t *testing.T) {
	var table refCountedLockTable
	const key = "lb_stale_acquire"

	// Given：第一持有者持锁，第二获取者在此之前完成「取条目」。
	holder := table.acquire(key)
	holder.Lock()
	stale := table.acquire(key)
	if stale != holder {
		t.Fatal("acquire 返回了与表内条目不同的锁")
	}

	// When：第一持有者释放（旧实现此时 refs 归零 → 条目被回收），第三获取者
	// 随后取锁。
	holder.Unlock()
	fresh := table.acquire(key)

	// Then：已返回给调用方的条目不得被回收——第三获取者必须命中同一条目，
	// 否则同 key 存在两把并存的锁。
	if fresh != stale {
		t.Fatal("获取与引用登记非原子：同 key 出现两把并存的锁（per-rule 互斥失效）")
	}
	table.mu.Lock()
	_, exists := table.locks.Load(key)
	refs := stale.refs
	table.mu.Unlock()
	if !exists {
		t.Fatal("登记过引用的条目被回收")
	}
	if refs != 2 {
		t.Fatalf("两次 acquire 后 refs=%d, want 2", refs)
	}

	// 且两把「同一把」锁必须真实互斥：一方持锁期间另一方不得进入临界区。
	stale.Lock()
	acquired := make(chan struct{})
	go func() {
		fresh.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		t.Fatal("同 key 的两次获取同时进入临界区")
	case <-time.After(100 * time.Millisecond):
	}
	stale.Unlock()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("互斥释放后等待者未取得锁")
	}
	fresh.Unlock()

	if _, exists := table.locks.Load(key); exists {
		t.Fatal("最后一个持有者释放后条目未回收（键空间随历史规则无界增长）")
	}
}

func TestLockCertRuleFile_reclaimsEntryAfterRelease(t *testing.T) {
	const ruleID = "lb_reclaim_rule_file"
	lock := lockCertRuleFile(ruleID)
	lock.Lock()
	if _, exists := certRuleFileLocks.locks.Load(ruleID); !exists {
		t.Fatal("在途持锁时规则文件锁条目必须存在")
	}
	lock.Unlock()
	if _, exists := certRuleFileLocks.locks.Load(ruleID); exists {
		t.Fatal("规则文件锁条目未回收（键空间随历史规则无界增长）")
	}
}

func TestRestoreCertFiles_rolls_back_all_rules_when_later_restore_fails(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	for _, ruleID := range []string{"a-restored", "z-fails"} {
		certPath, keyPath := CertFilePaths(ruleID)
		if err := os.WriteFile(certPath, []byte(ruleID+"-current-cert"), 0644); err != nil {
			t.Fatalf("write current cert for %s: %v", ruleID, err)
		}
		if err := os.WriteFile(keyPath, []byte(ruleID+"-current-key"), 0600); err != nil {
			t.Fatalf("write current key for %s: %v", ruleID, err)
		}
	}
	_, failingKeyPath := CertFilePaths("z-fails")
	if err := os.Mkdir(failingKeyPath+".restore", 0700); err != nil {
		t.Fatalf("block key restore temporary path: %v", err)
	}
	snapshot := CertFilesSnapshot{
		"a-restored": {
			Cert: CertFileSnapshot{Data: []byte("a-snapshot-cert"), Mode: 0644, Exists: true},
			Key:  CertFileSnapshot{Data: []byte("a-snapshot-key"), Mode: 0600, Exists: true},
		},
		"z-fails": {
			Cert: CertFileSnapshot{Data: []byte("z-snapshot-cert"), Mode: 0644, Exists: true},
			Key:  CertFileSnapshot{Data: []byte("z-snapshot-key"), Mode: 0600, Exists: true},
		},
	}

	// When
	err := RestoreCertFiles(snapshot)

	// Then
	if err == nil {
		t.Fatal("restore succeeded despite blocked key restore")
	}
	for _, ruleID := range []string{"a-restored", "z-fails"} {
		certPath, keyPath := CertFilePaths(ruleID)
		cert, readErr := os.ReadFile(certPath)
		if readErr != nil {
			t.Fatalf("read rolled back cert for %s: %v", ruleID, readErr)
		}
		key, readErr := os.ReadFile(keyPath)
		if readErr != nil {
			t.Fatalf("read rolled back key for %s: %v", ruleID, readErr)
		}
		if string(cert) != ruleID+"-current-cert" || string(key) != ruleID+"-current-key" {
			t.Fatalf("%s pair after rollback=(%q,%q), want current pair", ruleID, cert, key)
		}
	}
}

func TestMaterializeCertPairs_skipsWrites_whenPairIsUnchanged(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	certPEM, keyPEM := matchingCertificatePair(t, "unchanged.example.test")
	material := CertMaterial{RuleID: "lb_unchanged", CertPEM: certPEM, KeyPEM: keyPEM}
	if _, err := MaterializeCertPairs([]CertMaterial{material}); err != nil {
		t.Fatalf("initial materialization: %v", err)
	}
	certPath, keyPath := CertFilePaths(material.RuleID)
	if err := os.Mkdir(certPath+".tmp", 0700); err != nil {
		t.Fatalf("block certificate temporary path: %v", err)
	}
	if err := os.Mkdir(keyPath+".tmp", 0700); err != nil {
		t.Fatalf("block key temporary path: %v", err)
	}

	// When
	snapshot, err := MaterializeCertPairs([]CertMaterial{material})

	// Then
	if err != nil {
		t.Fatalf("unchanged materialization attempted a write: %v", err)
	}
	if snapshot != nil {
		t.Fatalf("unchanged materialization snapshot=%#v, want nil", snapshot)
	}
}

func TestMaterializeCertPairs_restores_permissions_whenContentIsUnchanged(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	certPEM, keyPEM := matchingCertificatePair(t, "permissions.example.test")
	material := CertMaterial{RuleID: "lb_permissions", CertPEM: certPEM, KeyPEM: keyPEM}
	if _, err := MaterializeCertPairs([]CertMaterial{material}); err != nil {
		t.Fatalf("initial materialization: %v", err)
	}
	certPath, keyPath := CertFilePaths(material.RuleID)
	if err := os.Chmod(certPath, 0600); err != nil {
		t.Fatalf("tighten certificate permissions: %v", err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatalf("loosen private key permissions: %v", err)
	}

	// When
	_, err := MaterializeCertPairs([]CertMaterial{material})

	// Then
	if err != nil {
		t.Fatalf("rematerialize unchanged pair: %v", err)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat rematerialized certificate: %v", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat rematerialized private key: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 || keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("materialized modes=(%#o,%#o), want (0644,0600)", certInfo.Mode().Perm(), keyInfo.Mode().Perm())
	}
}

func TestMaterializeAllCertsFromDB_repairs_mismatched_downloaded_pair(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	wantCert, wantKey := matchingCertificatePair(t, "example.com")
	otherCert, _ := matchingCertificatePair(t, "other.example.com")
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_materialize','materialize','example.com','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,ca_provider_id)
		VALUES ('lb_materialize','example.com','downloaded',?,?,1)
	`, wantCert, wantKey); err != nil {
		t.Fatalf("seed downloaded certificate: %v", err)
	}
	certPath, keyPath := CertFilePaths("lb_materialize")
	if err := os.WriteFile(certPath, []byte(otherCert), 0644); err != nil {
		t.Fatalf("write mismatched certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(wantKey), 0600); err != nil {
		t.Fatalf("write mismatched private key: %v", err)
	}

	// When
	MaterializeAllCertsFromDB()

	// Then
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read materialized certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read materialized private key: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("materialized pair does not match: %v", err)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_materialize'").Scan(&status); err != nil {
		t.Fatalf("read materialized job status: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("materialized job status=%q, want downloaded", status)
	}
}

func TestReconcileMissingCertFiles_rebuilds_deleted_files(t *testing.T) {
	// Given：已签发 ACME 任务在 DB 中持有 cert_pem/key_pem，但磁盘文件缺失（模拟被清理）
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	wantCert, wantKey := matchingCertificatePair(t, "reconcile.example.com")
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_reconcile','reconcile','reconcile.example.com','http',8443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,ca_provider_id)
		VALUES ('lb_reconcile','reconcile.example.com','issued',?,?,1)
	`, wantCert, wantKey); err != nil {
		t.Fatalf("seed issued certificate: %v", err)
	}
	certPath, keyPath := CertFilePaths("lb_reconcile")
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("certificate file unexpectedly exists before reconcile")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key file unexpectedly exists before reconcile")
	}

	// When
	reconcileMissingCertFiles(context.Background(), db.DB)

	// Then
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read reconciled certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read reconciled private key: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("reconciled pair does not match: %v", err)
	}
}

func matchingCertificatePair(t *testing.T, domains ...string) (string, string) {
	t.Helper()
	if len(domains) == 0 {
		t.Fatal("certificate domains must not be empty")
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM)
}

// 物化查询多行规则——同 updated_at 秒级并列时
// 按 id DESC 取最新行,且域名适用性过滤(任务域≠规则当前域的行不物化)。
func TestMaterializeAllCertsFromDB_selectsLatestApplicableRow(t *testing.T) {
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	seedGenerationRule(t, database, "lb_multi_row", false)
	if _, err := database.Exec("UPDATE lb_rules SET enable_tls=1,tls_source='acme_dns' WHERE caddy_id='lb_multi_row'"); err != nil {
		t.Fatal(err)
	}
	newCert, newKey := matchingCertificatePair(t, "new.example.test")
	oldCert, oldKey := matchingCertificatePair(t, "old.example.test")
	sameTime := "2026-09-14 01:00:00"
	// id 小=旧域(不适用),id 大=新域(适用)——同 updated_at 秒级并列
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at) VALUES
		('lb_multi_row','old.example.test','issued',?,?,?),
		('lb_multi_row','new.example.test','issued',?,?,?)`,
		oldCert, oldKey, sameTime, newCert, newKey, sameTime); err != nil {
		t.Fatal(err)
	}
	// 规则当前域名=新域
	if _, err := database.Exec("UPDATE lb_rules SET domain='new.example.test' WHERE caddy_id='lb_multi_row'"); err != nil {
		t.Fatal(err)
	}

	// When
	MaterializeAllCertsFromDB()

	// Then: 物化的是新域证书(id DESC 最新+域名适用)
	certPath, _ := CertFilePaths("lb_multi_row")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cert not materialized: %v", err)
	}
	if string(data) != newCert {
		t.Fatalf("materialized cert is not the latest applicable row (want new.example.test cert)")
	}
}

// ---- 回归钉 ----

// 启动物化必须「先判适用性、后标记 seen」——最新行是
// 旧域（不适用）时不得短路较旧的适用行，否则整条规则不物化。
func TestMaterializeAllCertsFromDB_latest_inapplicable_row_does_not_shadow_older_applicable(t *testing.T) {
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	seedGenerationRule(t, database, "lb_shadow_row", false)
	if _, err := database.Exec("UPDATE lb_rules SET enable_tls=1,tls_source='acme_dns',domain='current.example.test' WHERE caddy_id='lb_shadow_row'"); err != nil {
		t.Fatal(err)
	}
	currentCert, currentKey := matchingCertificatePair(t, "current.example.test")
	staleCert, staleKey := matchingCertificatePair(t, "stale.example.test")
	// 最新行=旧域（不适用），较旧行=当前域（适用）
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at) VALUES
		('lb_shadow_row','current.example.test','issued',?,?,'2026-09-14 01:00:00'),
		('lb_shadow_row','stale.example.test','issued',?,?,'2026-09-14 02:00:00')`,
		currentCert, currentKey, staleCert, staleKey); err != nil {
		t.Fatal(err)
	}

	// When
	MaterializeAllCertsFromDB()

	// Then：物化的是较旧的适用行（当前域），最新不适用行不得遮蔽它
	certPath, _ := CertFilePaths("lb_shadow_row")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("applicable cert not materialized: %v", err)
	}
	if string(data) != currentCert {
		t.Fatalf("materialized cert is not the older applicable row (current.example.test)")
	}
}

// 零写（内容与权限已一致）不得计入「恢复」审计/任务日志——否则每次
// 启动都报「恢复 N 个」，真实恢复事件被稀释。
func TestMaterializeAllCertsFromDB_counts_only_actual_writes(t *testing.T) {
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_manual_count','manual-count','http',8080,1,1,'manual','','')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	certPEM, keyPEM := matchingCertificatePair(t, "manual.example.test")
	if _, err := database.Exec(`UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id='lb_manual_count'`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed manual cert: %v", err)
	}
	readRecoveries := func() int {
		var count int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='恢复' AND resource='证书文件'`).Scan(&count); err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return count
	}

	// When：首次物化真写入，第二次内容/权限一致=零写
	MaterializeAllCertsFromDB()
	afterFirst := readRecoveries()
	MaterializeAllCertsFromDB()
	afterSecond := readRecoveries()

	// Then
	if afterFirst != 1 {
		t.Fatalf("recovery audit rows=%d after first materialization, want 1", afterFirst)
	}
	if afterSecond != afterFirst {
		t.Fatalf("recovery audit rows=%d after no-op materialization, want unchanged %d（零写不得计为恢复）", afterSecond, afterFirst)
	}
}

// 写/删按规则并行：规则 A 的 per-rule 锁不得阻塞规则 B 的写入（全局互斥
// 时代 /load 渲染 N 条规则串行 N 组 fsync）；跨规则快照回滚
// （RestoreCertFiles）仍全局互斥——读锁在持时恢复必须等待。
func TestCertStore_perRuleWritesParallelGlobalRestoreExclusive(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	t.Cleanup(restore)

	// Given：规则 A 的 per-rule 锁被占用（模拟在途写/删）
	ruleLockA := lockCertRuleFile("lb_para_a")
	ruleLockA.Lock()
	defer ruleLockA.Unlock()

	// When/Then：规则 B 的写入照常完成（不被 A 阻塞）
	done := make(chan error, 1)
	go func() { done <- WriteCertFiles("lb_para_b", "cert-b", "key-b") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("concurrent write for unrelated rule: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("规则 B 写入被规则 A 的锁阻塞——per-rule 并行失效")
	}

	// When/Then：读锁在持时 Restore（写锁）必须等待；释放后放行
	certWriteMu.RLock()
	restoreDone := make(chan error, 1)
	go func() { restoreDone <- RestoreCertFiles(CertFilesSnapshot{}) }()
	select {
	case err := <-restoreDone:
		certWriteMu.RUnlock()
		t.Fatalf("跨规则回滚在并发文件操作进行中放行: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	certWriteMu.RUnlock()
	if err := <-restoreDone; err != nil {
		t.Fatalf("restore after lock release: %v", err)
	}
}
