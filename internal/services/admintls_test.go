package services

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeAdminTLSChanged_detects_uploaded_certificate_rotation(t *testing.T) {
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "old-cert", Key: "old-key"})

	if !RuntimeAdminTLSChanged(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "new-cert", Key: "new-key"}) {
		t.Fatal("certificate content changed without changing admin TLS mode")
	}
}

// 存在但损坏的自签证书对必须自愈——读侧仅验「双文件
// 可读」不够，X509KeyPair 解析失败（截断/换位/垃圾内容）原样上抛会让启动
// 进入崩溃循环且面板无清除入口。先读后验：损坏对记 warn 并落既有重生成路径。
func TestSelfSignedCert_corrupt_pair_regenerates(t *testing.T) {
	// Given：两文件可读但不是合法 PEM 证书对
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin_tls.crt")
	keyPath := filepath.Join(dir, "admin_tls.key")
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0644); err != nil {
		t.Fatalf("seed corrupt certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-key"), 0600); err != nil {
		t.Fatalf("seed corrupt key: %v", err)
	}

	// When：默认（selfsigned）模式解析证书
	cert, err := AdminTLSConfig{}.ResolveCertificate(dir)
	if err != nil {
		t.Fatalf("resolve certificate with corrupt on-disk pair: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("regenerated certificate is incomplete")
	}

	// Then：磁盘对已被重生成（合法 PEM），且二次解析直接命中新对
	regenCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read regenerated certificate: %v", err)
	}
	regenKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read regenerated key: %v", err)
	}
	if string(regenCert) == "not-a-cert" || string(regenKey) == "not-a-key" {
		t.Fatal("corrupt pair still on disk — regeneration path did not run")
	}
	if _, err := tls.X509KeyPair(regenCert, regenKey); err != nil {
		t.Fatalf("regenerated pair does not parse: %v", err)
	}
	if _, err := (AdminTLSConfig{}).ResolveCertificate(dir); err != nil {
		t.Fatalf("second resolve after regeneration: %v", err)
	}
}

// 证书在场而私钥缺失必须留痕：静默重生成会以新密钥对覆盖既有 crt（已导入
// 浏览器/系统的信任失效），且日志无线索指向「私钥丢失」这一真实原因。
func TestSelfSignedCert_missingKeyWarnsAndRegenerates(t *testing.T) {
	// Given：目录只有证书文件，私钥不存在（卷只挂 crt / 人工删除）
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin_tls.crt")
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0644); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	logs := captureServiceLog(t)

	// When：selfsigned 模式解析证书
	cert, err := AdminTLSConfig{}.ResolveCertificate(dir)

	// Then：自愈仍成功，且日志点名「私钥不可读」+ 缺失形态
	if err != nil {
		t.Fatalf("resolve certificate: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("regenerated certificate is incomplete")
	}
	got := logs.String()
	if !strings.Contains(got, "私钥不可读") {
		t.Fatalf("私钥缺失必须留痕（当前日志无线索指向真实原因）: %q", got)
	}
	if !strings.Contains(got, "缺失=true") {
		t.Fatalf("日志必须区分「私钥缺失」与其它读失败形态: %q", got)
	}
}

// 指纹对 cert/key 无分隔拼接存在理论双解——
// cert="A",key="BC" 与 cert="AB",key="C" 同串同哈希，真实轮换会被误判为
// 未变化。钉住「边界组合必须产生不同指纹」。
func TestFingerprintAdminTLS_separates_cert_key_boundary(t *testing.T) {
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "A", Key: "BC"})

	if !RuntimeAdminTLSChanged(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "AB", Key: "C"}) {
		t.Fatal("different cert/key boundary split produced identical fingerprint")
	}
}

func TestWriteAdminTLSCertPair_keyRenameFailureRestoresPreviousCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "admin_tls.crt")
	keyPath := filepath.Join(dir, "admin_tls.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	// 非空目录作为私钥目标：两个临时文件均可写、证书 rename 已成功，只有私钥
	// rename 失败，从而真实进入 certstore 的证书补偿分支（无需生产测试缝）。
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatalf("seed private key target directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyPath, "keep"), []byte("block rename"), 0600); err != nil {
		t.Fatalf("make private key target non-empty: %v", err)
	}

	if err := writeAdminTLSCertPair(certPath, keyPath, []byte("new-cert"), []byte("new-key")); err == nil {
		t.Fatal("private key rename unexpectedly succeeded")
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate after rollback: %v", err)
	}
	if string(cert) != "old-cert" {
		t.Fatalf("certificate after key rename failure=%q, want previous certificate", cert)
	}
	if _, err := os.Stat(filepath.Join(keyPath, "keep")); err != nil {
		t.Fatalf("failed private key target must remain untouched: %v", err)
	}
}
