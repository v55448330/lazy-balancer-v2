package services

import (
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
	"sync"
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
	done := make(chan error, 1)
	go func() { done <- RemoveCertFiles("lb_locked") }()

	// When
	select {
	case err := <-done:
		certWriteMu.Unlock()
		t.Fatalf("remove returned before lock release: %v", err)
	default:
	}
	certWriteMu.Unlock()

	// Then
	if err := <-done; err != nil {
		t.Fatalf("remove certificate files: %v", err)
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("certificate still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("private key still exists or stat failed: %v", err)
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
	certificateDeployLocks = sync.Map{}

	// When
	unlock := DeployLock("lb_refcount")
	unlock()

	// Then
	if _, exists := certificateDeployLocks.Load("lb_refcount"); exists {
		t.Fatal("deployment lock entry remained after its last holder released it")
	}
}

func TestDeployLock_serializes_waiters_and_keeps_entry_until_final_release(t *testing.T) {
	certificateDeployLocks = sync.Map{}
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
	for {
		certificateDeployLocksMu.Lock()
		value, exists := certificateDeployLocks.Load("lb_serial")
		registered := exists && value.(*certificateDeployLock).refs == 3
		certificateDeployLocksMu.Unlock()
		if registered {
			break
		}
		runtime.Gosched()
	}
	release <- struct{}{}
	if released := <-done; released != first {
		t.Fatalf("released worker=%d, want first holder %d", released, first)
	}
	second := <-acquired
	if _, exists := certificateDeployLocks.Load("lb_serial"); !exists {
		t.Fatal("deployment lock entry was deleted while a waiter held it")
	}
	release <- struct{}{}
	if released := <-done; released != second {
		t.Fatalf("released worker=%d, want second holder %d", released, second)
	}
	<-acquired
	if _, exists := certificateDeployLocks.Load("lb_serial"); !exists {
		t.Fatal("deployment lock entry was deleted before the final release")
	}
	release <- struct{}{}
	<-done
	if _, exists := certificateDeployLocks.Load("lb_serial"); exists {
		t.Fatal("deployment lock entry remained after final release")
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

func matchingCertificatePair(t *testing.T, domain string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
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
