package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeAdminTLSChanged_detects_uploaded_certificate_rotation(t *testing.T) {
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "old-cert", Key: "old-key"})

	if !RuntimeAdminTLSChanged(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "new-cert", Key: "new-key"}) {
		t.Fatal("certificate content changed without changing admin TLS mode")
	}
}

func TestWriteAdminTLSCertPair_second_file_failure_restores_previous_pair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin_tls.crt")
	keyPath := filepath.Join(dir, "admin_tls.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed private key: %v", err)
	}
	if err := os.Mkdir(keyPath+".tmp", 0700); err != nil {
		t.Fatalf("block temporary private key write: %v", err)
	}

	if err := writeAdminTLSCertPair(certPath, keyPath, []byte("new-cert"), []byte("new-key")); err == nil {
		t.Fatal("second file write unexpectedly succeeded")
	}
	cert, certErr := os.ReadFile(certPath)
	key, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		t.Fatalf("read pair after rollback: cert=%v key=%v", certErr, keyErr)
	}
	if string(cert) != "old-cert" || string(key) != "old-key" {
		t.Fatalf("pair after rollback=(%q,%q), want previous pair", cert, key)
	}
}
