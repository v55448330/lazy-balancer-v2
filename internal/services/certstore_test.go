package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestRestoreCertFiles_rolls_back_pair_when_key_restore_fails(t *testing.T) {
	// Given
	dir := useTemporaryCertDir(t)
	certPath := filepath.Join(dir, "lb_restore.crt")
	keyPath := filepath.Join(dir, "lb_restore.key")
	if err := os.WriteFile(certPath, []byte("current-cert"), 0644); err != nil {
		t.Fatalf("write current cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("current-key"), 0600); err != nil {
		t.Fatalf("write current key: %v", err)
	}
	if err := os.Mkdir(keyPath+".restore", 0700); err != nil {
		t.Fatalf("block key restore temporary path: %v", err)
	}
	snapshot := CertFilesSnapshot{
		"lb_restore": {
			Cert: CertFileSnapshot{Data: []byte("snapshot-cert"), Mode: 0644, Exists: true},
			Key:  CertFileSnapshot{Data: []byte("snapshot-key"), Mode: 0600, Exists: true},
		},
	}

	// When
	err := RestoreCertFiles(snapshot)

	// Then
	if err == nil {
		t.Fatal("restore succeeded despite blocked key restore")
	}
	cert, readErr := os.ReadFile(certPath)
	if readErr != nil {
		t.Fatalf("read rolled back cert: %v", readErr)
	}
	key, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		t.Fatalf("read rolled back key: %v", readErr)
	}
	if string(cert) != "current-cert" || string(key) != "current-key" {
		t.Fatalf("certificate pair after rollback=(%q,%q), want current pair", cert, key)
	}
}
