package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseConnectionStats_parses_linux_netstat_underscore_states(t *testing.T) {
	fixture := `Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 10.0.0.1:443           10.0.0.2:50000         ESTABLISHED
tcp        0      1 10.0.0.1:50001         10.0.0.2:443           SYN_SENT
tcp        0      0 10.0.0.1:443           10.0.0.2:50002         SYN_RECV
tcp        0      0 10.0.0.1:443           10.0.0.2:50003         FIN_WAIT1
tcp        0      0 10.0.0.1:443           10.0.0.2:50004         FIN_WAIT2
tcp        1      0 10.0.0.1:443           10.0.0.2:50005         CLOSE_WAIT
tcp        0      0 10.0.0.1:443           10.0.0.2:50006         CLOSING
tcp        0      0 10.0.0.1:443           10.0.0.2:50007         LAST_ACK
tcp        0      0 0.0.0.0:443            0.0.0.0:*               LISTEN
tcp        0      0 10.0.0.1:443           10.0.0.2:50008         TIME_WAIT`

	stats := parseConnectionStats(fixture)
	if stats.Established != 1 || stats.SynSent != 1 || stats.SynRecv != 1 || stats.FinWait1 != 1 ||
		stats.FinWait2 != 1 || stats.CloseWait != 1 || stats.Closing != 1 || stats.LastAck != 1 ||
		stats.Listening != 1 || stats.TimeWait != 1 || stats.Total != 9 {
		t.Fatalf("unexpected connection stats: %#v", stats)
	}
}

func TestParseNetDevTotals_sums_default_route_interface_only(t *testing.T) {
	withIsolatedGlobal(t)
	original := systemMetricsReadFile
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path == "/proc/net/route" {
			return []byte("Iface Destination Gateway Flags\nenp3s0 00000000 0100000A 0003\n"), nil
		}
		return original(path)
	}
	t.Cleanup(func() { systemMetricsReadFile = original })
	fixture := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0
  enp3s0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
   bond0: 3000 1 0 0 0 0 0 0 4000 1 0 0 0 0 0 0
 wlan0: 5000 1 0 0 0 0 0 0 6000 1 0 0 0 0 0 0
   br-app: 7000 1 0 0 0 0 0 0 8000 1 0 0 0 0 0 0`

	bytesIn, bytesOut, _, err := parseNetDevTotals(fixture)
	if err != nil {
		t.Fatalf("parse net dev fixture: %v", err)
	}
	if bytesIn != 1000 || bytesOut != 2000 {
		t.Fatalf("bytesIn=%d bytesOut=%d, want 1000/2000", bytesIn, bytesOut)
	}
}

func TestParseNetDevTotals_falls_back_to_physical_interfaces_when_no_default_route(t *testing.T) {
	withIsolatedGlobal(t)
	// Given：容器 netns 无默认路由（Docker Desktop 场景），仅有子网路由
	original := systemMetricsReadFile
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path == "/proc/net/route" {
			return []byte("Iface Destination Gateway Flags\nlo 0000007F 00000000 0001\neth0 0041A8C0 00000000 0001\n"), nil
		}
		return original(path)
	}
	t.Cleanup(func() { systemMetricsReadFile = original })
	fixture := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0
  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
 veth1234: 3000 1 0 0 0 0 0 0 4000 1 0 0 0 0 0 0
 docker0: 5000 1 0 0 0 0 0 0 6000 1 0 0 0 0 0 0
   br-abc: 7000 1 0 0 0 0 0 0 8000 1 0 0 0 0 0 0`

	// When
	bytesIn, bytesOut, _, err := parseNetDevTotals(fixture)

	// Then：只统计 eth0，虚拟叠加层不重复计入
	if err != nil {
		t.Fatalf("parse without default route: %v", err)
	}
	if bytesIn != 1000 || bytesOut != 2000 {
		t.Fatalf("bytesIn=%d bytesOut=%d, want 1000/2000 (eth0 only)", bytesIn, bytesOut)
	}
}

// 分项降级契约：内存采集失败只让 memory 从结果里缺席（Degraded 披露），
// 不得连带丢失磁盘/CPU——排障窗口里 CPU 单点故障曾让整卡数据消失。
func TestGetSystemMetrics_memoryFailureDegradesWithoutLosingOtherParts(t *testing.T) {
	withIsolatedGlobal(t)
	originalReadFile, originalDFCommand := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/meminfo":
			return nil, errors.New("permission denied")
		case "/proc/stat":
			return []byte("cpu 100 0 0 100 0\n"), nil
		default:
			return originalReadFile(path)
		}
	}
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'Filesystem 1B-blocks Used Available Use%% Mounted on\n/dev/x 1000 250 750 25%% /\n'")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDFCommand
	})

	metrics, err := getSystemMetrics()
	if err != nil {
		t.Fatalf("仅内存失败不得让整次采集失败: %v", err)
	}
	if !slices.Contains(metrics.Degraded, "memory") {
		t.Fatalf("degraded=%v, want 含 memory", metrics.Degraded)
	}
	if metrics.MemoryTotal != 0 || metrics.MemoryPercent != 0 {
		t.Fatalf("内存指标=%+v, want 零值（失败分项不伪造数据）", metrics)
	}
	if metrics.DiskTotal != 1000 || metrics.DiskUsed != 250 {
		t.Fatalf("磁盘指标=%d/%d, want 1000/250（内存失败不得连带丢失）", metrics.DiskTotal, metrics.DiskUsed)
	}
	for _, part := range metrics.Degraded {
		if part == "disk" {
			t.Fatalf("degraded=%v, 磁盘采集成功不得标记失败", metrics.Degraded)
		}
	}
}

// 磁盘解析失败同样只降级该项。
func TestGetSystemMetrics_diskFailureDegradesWithoutLosingOtherParts(t *testing.T) {
	withIsolatedGlobal(t)
	originalReadFile, originalDFCommand := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/meminfo":
			return []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), nil
		case "/proc/stat":
			return []byte("cpu 100 0 0 100 0\n"), nil
		default:
			return originalReadFile(path)
		}
	}
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf invalid")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDFCommand
	})

	metrics, err := getSystemMetrics()
	if err != nil {
		t.Fatalf("仅磁盘失败不得让整次采集失败: %v", err)
	}
	if !slices.Contains(metrics.Degraded, "disk") {
		t.Fatalf("degraded=%v, want 含 disk", metrics.Degraded)
	}
	if metrics.DiskTotal != 0 || metrics.DiskPercent != 0 {
		t.Fatalf("磁盘指标=%+v, want 零值（失败分项不伪造数据）", metrics)
	}
	if metrics.MemoryTotal == 0 {
		t.Fatalf("内存指标缺失：磁盘失败不得连带丢失 healthy 分项")
	}
	for _, part := range metrics.Degraded {
		if part == "memory" {
			t.Fatalf("degraded=%v, 内存采集成功不得标记失败", metrics.Degraded)
		}
	}
}

// 三项全失败才失败（此时确实无可展示数据）。
func TestGetSystemMetrics_allPartsFailingReturnsError(t *testing.T) {
	withIsolatedGlobal(t)
	originalReadFile, originalDFCommand := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(string) ([]byte, error) { return nil, errors.New("unavailable") }
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 3")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDFCommand
	})

	metrics, err := getSystemMetrics()
	if err == nil {
		t.Fatal("三项全失败必须返回 error（后端不得以全零冒充健康）")
	}
	if want := []string{"memory", "disk", "cpu", "pids"}; !slices.Equal(metrics.Degraded, want) {
		t.Fatalf("degraded=%v, want deterministic order %v", metrics.Degraded, want)
	}
	for _, fragment := range []string{"内存", "磁盘", "CPU"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error=%q, want 含 %q（逐项点名失败原因）", err.Error(), fragment)
		}
	}
}

func TestGetConnectionStats_returns_netstat_error(t *testing.T) {
	withIsolatedGlobal(t)
	original := netstatCommand
	resetConnectionStatsCacheForTest(t)
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 17")
	}
	t.Cleanup(func() { netstatCommand = original })
	_, err := getConnectionStats()
	if err == nil || !strings.Contains(err.Error(), "netstat -tan") {
		t.Fatalf("error=%v, want contextual netstat error", err)
	}
}

// generateTestCert creates a test certificate and key pair
func generateTestCert(domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	return generateTestCertWithNames(domain, []string{domain}, notBefore, notAfter)
}

// generateTestCertWithNames 生成 CN 与 SAN 可分离的证书。域名展示口径是
// 「SAN[0] 优先、CN 兜底」，夹具若把两者设成同值，删掉 SAN 覆盖分支也测不出，
// 故必须能构造 CN≠SAN（或只有 CN 无 SAN）的证书。
func generateTestCertWithNames(commonName string, dnsNames []string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	// Encode certificate to PEM
	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode key to PEM
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return string(certPEMBlock), string(keyPEMBlock), nil
}

// generateMismatchedCert creates a certificate with a different key
func generateMismatchedCert() (certPEM, keyPEM string, err error) {
	// Generate first key pair
	certPEM, _, err = generateTestCert("example.com", time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		return "", "", err
	}

	// Generate different key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	return certPEM, keyPEM, nil
}

// generateECDSACert creates an ECDSA certificate
func generateECDSACert(domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	return certPEM, keyPEM, nil
}

// generateEd25519Cert creates an Ed25519 certificate（内部 CA/自签
// 常用密钥类型，tls.X509KeyPair 与 Caddy 均支持）。
func generateEd25519Cert(domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return "", "", err
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	return certPEM, keyPEM, nil
}

func TestParseTLSCertificate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		certPEM     string
		keyPEM      string
		wantValid   bool
		wantDomain  string
		wantWarning bool
		wantErr     bool
		errContains string
	}{
		{
			name:      "empty cert and key",
			certPEM:   "",
			keyPEM:    "",
			wantValid: false,
			wantErr:   false,
		},
		{
			name:       "valid RSA certificate",
			wantValid:  true,
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:        "invalid cert PEM",
			certPEM:     "not a valid pem",
			keyPEM:      "not a valid key",
			wantErr:     true,
			errContains: "invalid certificate or key pair",
		},
		{
			name:        "expired certificate",
			wantValid:   true,
			wantDomain:  "expired.example.com",
			wantWarning: true,
			wantErr:     false,
		},
		{
			name:        "not yet valid certificate",
			wantValid:   true,
			wantDomain:  "future.example.com",
			wantWarning: true,
			wantErr:     false,
		},
		{
			// 只断言本包自有的错误文案（"invalid certificate
			// or key pair"），不钉 Go 标准库 crypto/tls 的措辞——小版本改写错误串
			// 不得误红，也不得让「配对检测坏了」与「引擎文案变了」混为一谈。
			name:        "mismatched cert and key",
			wantErr:     true,
			errContains: "invalid certificate or key pair",
		},
		{
			name:       "valid ECDSA certificate",
			wantValid:  true,
			wantDomain: "ecdsa.example.com",
			wantErr:    false,
		},
		{
			// Ed25519 手动证书此前被公钥类型白名单硬拒
			// （"unsupported public key type in certificate"）——面板比引擎更窄。
			name:       "valid Ed25519 certificate",
			wantValid:  true,
			wantDomain: "ed25519.example.com",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM := tt.certPEM
			keyPEM := tt.keyPEM
			var err error

			// Generate test certificates for specific test cases
			switch tt.name {
			case "valid RSA certificate":
				certPEM, keyPEM, err = generateTestCert("example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate test cert: %v", err)
				}
			case "expired certificate":
				certPEM, keyPEM, err = generateTestCert("expired.example.com", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate test cert: %v", err)
				}
			case "not yet valid certificate":
				certPEM, keyPEM, err = generateTestCert("future.example.com", now.Add(24*time.Hour), now.Add(48*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate test cert: %v", err)
				}
			case "mismatched cert and key":
				certPEM, keyPEM, err = generateMismatchedCert()
				if err != nil {
					t.Fatalf("failed to generate mismatched cert: %v", err)
				}
			case "valid ECDSA certificate":
				certPEM, keyPEM, err = generateECDSACert("ecdsa.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate ECDSA cert: %v", err)
				}
			case "valid Ed25519 certificate":
				certPEM, keyPEM, err = generateEd25519Cert("ed25519.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
				if err != nil {
					t.Fatalf("failed to generate Ed25519 cert: %v", err)
				}
			}

			info, err := parseTLSCertificate(certPEM, keyPEM)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseTLSCertificate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseTLSCertificate() error = %v, want containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("parseTLSCertificate() unexpected error = %v", err)
				return
			}

			if info == nil {
				t.Error("parseTLSCertificate() returned nil info")
				return
			}

			if info.Valid != tt.wantValid {
				t.Errorf("parseTLSCertificate() Valid = %v, want %v", info.Valid, tt.wantValid)
			}

			if tt.wantDomain != "" && info.Domain != tt.wantDomain {
				t.Errorf("parseTLSCertificate() Domain = %v, want %v", info.Domain, tt.wantDomain)
			}

			if tt.wantWarning && info.Warning == "" {
				t.Errorf("parseTLSCertificate() Warning = empty, want non-empty warning")
			}

			if !tt.wantWarning && info.Warning != "" {
				t.Errorf("parseTLSCertificate() Warning = %v, want empty", info.Warning)
			}
		})
	}
}

func TestParseTLSCertificate_ExtractsSANs(t *testing.T) {
	now := time.Now()
	// CN 与 SAN 必须不同值：同值时「SAN 优先」与「CN 兜底」两种实现都绿，
	// 该分支删掉也测不出来。
	const sanDomain = "san.example.com"
	certPEM, keyPEM, err := generateTestCertWithNames("cn-only.example.com", []string{sanDomain}, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	info, err := parseTLSCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseTLSCertificate() error = %v", err)
	}

	if info.Domain != sanDomain {
		t.Errorf("parseTLSCertificate() Domain = %v, want %v（SAN[0] 优先于 CN）", info.Domain, sanDomain)
	}
}

// 无 SAN 只有 CN 时回落 CN——覆盖「SAN 优先」的另一方向，保证两者都不丢。
func TestParseTLSCertificate_fallsBackToCommonNameWithoutSAN(t *testing.T) {
	now := time.Now()
	const cnDomain = "cn-fallback.example.com"
	certPEM, keyPEM, err := generateTestCertWithNames(cnDomain, nil, now.Add(-1*time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	info, err := parseTLSCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseTLSCertificate() error = %v", err)
	}

	if info.Domain != cnDomain {
		t.Errorf("parseTLSCertificate() Domain = %v, want %v（无 SAN 时回落 CN）", info.Domain, cnDomain)
	}
}

func TestParseTLSCertificate_DaysUntilExpiry(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := generateTestCert("days.example.com", now.Add(-1*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	info, err := parseTLSCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseTLSCertificate() error = %v", err)
	}

	// Should be approximately 7 days (might be 6 due to time elapsed during test)
	if info.DaysUntilExpiry < 5 || info.DaysUntilExpiry > 8 {
		t.Errorf("parseTLSCertificate() DaysUntilExpiry = %v, want approximately 7", info.DaysUntilExpiry)
	}
}

func TestParseTLSCertificate_keeps_empty_issuer_when_CN_and_organization_are_empty(t *testing.T) {
	// Given
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	// When
	info, err := parseTLSCertificate(certPEM, keyPEM)

	// Then
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if info.Issuer != "" {
		t.Fatalf("issuer=%q, want empty", info.Issuer)
	}
}

func TestValidateTLSCertificate(t *testing.T) {
	now := time.Now()

	t.Run("valid certificate", func(t *testing.T) {
		certPEM, keyPEM, err := generateTestCert("valid.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatalf("failed to generate test cert: %v", err)
		}

		if err := validateTLSCertificate(certPEM, keyPEM); err != nil {
			t.Errorf("validateTLSCertificate() error = %v", err)
		}
	})

	t.Run("empty certificate", func(t *testing.T) {
		if err := validateTLSCertificate("", ""); err != nil {
			t.Errorf("validateTLSCertificate() error = %v, want nil", err)
		}
	})

	t.Run("mismatched certificate", func(t *testing.T) {
		certPEM, keyPEM, err := generateMismatchedCert()
		if err != nil {
			t.Fatalf("failed to generate mismatched cert: %v", err)
		}

		if err := validateTLSCertificate(certPEM, keyPEM); err == nil {
			t.Error("validateTLSCertificate() error = nil, want error")
		}
	})
}

func TestParseDFOutput_uses_total_and_used_columns(t *testing.T) {
	output := "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/root 1000 750 250 75% /\n"
	total, used, ok := parseDFOutput(output)
	if !ok || total != 1000 || used != 750 {
		t.Fatalf("parseDFOutput()=(%d,%d,%v), want (1000,750,true)", total, used, ok)
	}
}

func TestParseCPUSnapshot_includes_idle_and_iowait(t *testing.T) {
	snapshot, ok := parseCPUSnapshot("cpu  10 20 30 40 5 6 7 8 0 0\ncpu0 1 2 3 4")
	if !ok || snapshot.total != 126 || snapshot.idle != 45 {
		t.Fatalf("parseCPUSnapshot()=%+v,%v, want total=126 idle=45", snapshot, ok)
	}
}

func TestGetCPUPercent_serializes_sample_read_with_baseline_update(t *testing.T) {
	withIsolatedGlobal(t)
	// 关闭采样窗口：本用例钉的是「采样读与基线更新串行」，需要每次调用都读样本。
	disableCPUSampleWindowForTest(t)
	// Given
	originalReader := systemMetricsReadFile
	lastCPUStats.mu.Lock()
	originalSnapshot, originalSampledAt, originalHasValue, originalPercent :=
		lastCPUStats.snapshot, lastCPUStats.sampledAt, lastCPUStats.hasValue, lastCPUStats.percent
	lastCPUStats.snapshot = cpuSnapshot{total: 100, idle: 50}
	lastCPUStats.mu.Unlock()
	t.Cleanup(func() {
		systemMetricsReadFile = originalReader
		lastCPUStats.mu.Lock()
		// 全字段复位（不只 snapshot）：getCPUPercent 同时推进 sampledAt/hasValue/
		// percent，只还原 snapshot 会在 suite 终态留下「有值基线」——固定声明序下
		// 被后续用例的 reset 掩盖，-shuffle 下判为全局态泄漏。
		lastCPUStats.snapshot, lastCPUStats.sampledAt, lastCPUStats.hasValue, lastCPUStats.percent =
			originalSnapshot, originalSampledAt, originalHasValue, originalPercent
		lastCPUStats.mu.Unlock()
	})
	firstRead := make(chan struct{})
	secondRead := make(chan struct{})
	releaseFirst := make(chan struct{})
	var callMu sync.Mutex
	callCount := 0
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path != "/proc/stat" {
			return nil, errors.New("unexpected path: " + path)
		}
		callMu.Lock()
		callCount++
		call := callCount
		callMu.Unlock()
		if call == 1 {
			close(firstRead)
			<-releaseFirst
			return []byte("cpu 100 0 0 100 0\n"), nil
		}
		close(secondRead)
		return []byte("cpu 200 0 0 200 0\n"), nil
	}
	errorsCh := make(chan error, 2)

	// When
	go func() {
		_, err := getCPUPercent()
		errorsCh <- err
	}()
	<-firstRead
	go func() {
		_, err := getCPUPercent()
		errorsCh <- err
	}()
	// 第二次采样在入口锁处阻塞（读+算+写基线整段持锁），只可能在
	// releaseFirst 之后才 close(secondRead)——原 select 的 secondRead 分支不可达，
	// 恒空转 100ms。此处直接释放即可；串行化由「持锁贯穿读样本」实现。
	close(releaseFirst)
	firstErr, secondErr := <-errorsCh, <-errorsCh

	// Then
	if firstErr != nil || secondErr != nil {
		t.Fatalf("interleaved CPU samples returned errors: %v, %v", firstErr, secondErr)
	}
	lastCPUStats.mu.Lock()
	finalSnapshot := lastCPUStats.snapshot
	lastCPUStats.mu.Unlock()
	if finalSnapshot.total != 400 || finalSnapshot.idle != 200 {
		t.Fatalf("final CPU snapshot=%+v, want newer total=400 idle=200", finalSnapshot)
	}
}

func TestGetCPUPercent_rebaselines_after_counter_rollback(t *testing.T) {
	withIsolatedGlobal(t)
	disableCPUSampleWindowForTest(t)
	// Given
	originalReader := systemMetricsReadFile
	lastCPUStats.mu.Lock()
	originalSnapshot, originalSampledAt, originalHasValue, originalPercent :=
		lastCPUStats.snapshot, lastCPUStats.sampledAt, lastCPUStats.hasValue, lastCPUStats.percent
	lastCPUStats.snapshot = cpuSnapshot{total: 100, idle: 50}
	lastCPUStats.mu.Unlock()
	samples := [][]byte{
		[]byte("cpu 20 0 0 20\n"),
		[]byte("cpu 50 0 0 30\n"),
	}
	call := 0
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path != "/proc/stat" {
			return nil, errors.New("unexpected path: " + path)
		}
		sample := samples[call]
		call++
		return sample, nil
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReader
		lastCPUStats.mu.Lock()
		// 同上：采样缓存的全部字段都要复位，否则 suite 终态残留有值基线。
		lastCPUStats.snapshot, lastCPUStats.sampledAt, lastCPUStats.hasValue, lastCPUStats.percent =
			originalSnapshot, originalSampledAt, originalHasValue, originalPercent
		lastCPUStats.mu.Unlock()
	})

	// When
	rollbackPercent, rollbackErr := getCPUPercent()
	nextPercent, nextErr := getCPUPercent()

	// Then
	if rollbackErr != nil || rollbackPercent != 0 {
		t.Fatalf("rollback sample percent=%v error=%v, want 0/nil", rollbackPercent, rollbackErr)
	}
	if nextErr != nil || nextPercent != 75 {
		t.Fatalf("post-rollback sample percent=%v error=%v, want 75/nil", nextPercent, nextErr)
	}
}

func TestGetRealtimeTraffic_serializes_sample_read_with_baseline_update(t *testing.T) {
	withIsolatedGlobal(t)
	// 关闭采样窗口：本用例钉的是「采样读与基线更新串行」，需要每次调用都读样本。
	disableNetSampleWindowForTest(t)
	// Given
	originalReader := systemMetricsReadFile
	lastNetStats.mu.Lock()
	originalBytesIn, originalBytesOut, originalTime := lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.time
	lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.time = 100, 200, time.Now().Add(-time.Second)
	lastNetStats.mu.Unlock()
	t.Cleanup(func() {
		systemMetricsReadFile = originalReader
		lastNetStats.mu.Lock()
		lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.time = originalBytesIn, originalBytesOut, originalTime
		lastNetStats.mu.Unlock()
	})
	firstRead := make(chan struct{})
	secondRead := make(chan struct{})
	releaseFirst := make(chan struct{})
	var callMu sync.Mutex
	callCount := 0
	netDevSamples := [][]byte{
		[]byte("Inter-| Receive | Transmit\neth0: 200 0 0 0 0 0 0 0 300 0 0 0 0 0 0 0\n"),
		[]byte("Inter-| Receive | Transmit\neth0: 400 0 0 0 0 0 0 0 600 0 0 0 0 0 0 0\n"),
	}
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path == "/proc/net/route" {
			return []byte("Iface Destination Gateway Flags\neth0 00000000 0100000A 0003\n"), nil
		}
		if path != "/proc/net/dev" {
			return nil, errors.New("unexpected path: " + path)
		}
		callMu.Lock()
		call := callCount
		callCount++
		callMu.Unlock()
		if call == 0 {
			close(firstRead)
			<-releaseFirst
		} else {
			close(secondRead)
		}
		return netDevSamples[call], nil
	}
	errorsCh := make(chan error, 2)

	// When
	go func() {
		_, err := getRealtimeTraffic()
		errorsCh <- err
	}()
	select {
	case <-firstRead:
	case <-time.After(time.Second):
		t.Fatal("realtime traffic sampler did not use the injectable system metrics reader")
	}
	go func() {
		_, err := getRealtimeTraffic()
		errorsCh <- err
	}()
	// 第二次采样在入口锁处阻塞（读+算+写基线整段持锁），只可能在
	// releaseFirst 之后才 close(secondRead)——原 select 的 secondRead 分支不可达，
	// 恒空转 100ms。此处直接释放即可；串行化由「持锁贯穿读样本」实现。
	close(releaseFirst)
	firstErr, secondErr := <-errorsCh, <-errorsCh

	// Then
	if firstErr != nil || secondErr != nil {
		t.Fatalf("interleaved network samples returned errors: %v, %v", firstErr, secondErr)
	}
	lastNetStats.mu.Lock()
	finalBytesIn, finalBytesOut := lastNetStats.bytesIn, lastNetStats.bytesOut
	lastNetStats.mu.Unlock()
	if finalBytesIn != 400 || finalBytesOut != 600 {
		t.Fatalf("final network snapshot=%d/%d, want newer 400/600", finalBytesIn, finalBytesOut)
	}
}

func TestGetRealtimeTraffic_rebaselines_after_counter_rollback(t *testing.T) {
	withIsolatedGlobal(t)
	disableNetSampleWindowForTest(t)
	// Given
	originalReader := systemMetricsReadFile
	lastNetStats.mu.Lock()
	originalBytesIn, originalBytesOut, originalTime := lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.time
	lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.time = 1000, 2000, time.Now().Add(-5*time.Second)
	lastNetStats.mu.Unlock()
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/dev":
			return []byte("Inter-| Receive | Transmit\neth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n"), nil
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\neth0 00000000 0100000A 0003\n"), nil
		default:
			return nil, errors.New("unexpected path: " + path)
		}
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReader
		lastNetStats.mu.Lock()
		lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.time = originalBytesIn, originalBytesOut, originalTime
		lastNetStats.mu.Unlock()
	})

	// When
	traffic, err := getRealtimeTraffic()

	// Then
	if err != nil {
		t.Fatalf("sample rollback traffic: %v", err)
	}
	if traffic.BytesIn != 0 || traffic.BytesOut != 0 {
		t.Fatalf("rollback traffic=%+v, want zero rates", traffic)
	}
	lastNetStats.mu.Lock()
	bytesIn, bytesOut := lastNetStats.bytesIn, lastNetStats.bytesOut
	lastNetStats.mu.Unlock()
	if bytesIn != 100 || bytesOut != 200 {
		t.Fatalf("network baseline=%d/%d, want 100/200", bytesIn, bytesOut)
	}
}

func TestParsePrometheusMetrics_does_not_double_count_requests_from_status_histogram(t *testing.T) {
	// Given
	body := strings.Join([]string{
		`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 9`,
		`caddy_http_request_duration_seconds_count{code="200",handler="reverse_proxy",host="example.com"} 9`,
	}, "\n")

	// When
	metrics, err := parsePrometheusMetrics(body)

	// Then
	if err != nil {
		t.Fatalf("parse metrics: %v", err)
	}
	if metrics.RequestsTotal != 9 || metrics.Status2xx != 9 {
		t.Fatalf("requestsTotal=%d status2xx=%d, want 9/9", metrics.RequestsTotal, metrics.Status2xx)
	}
}

func TestParseRuleMetricsFromPrometheus_normalizes_configured_hosts(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		listenPort int
		metricHost string
	}{
		{name: "custom HTTP port", domain: "example.com", listenPort: 8080, metricHost: "example.com:8080"},
		{name: "bracketed IPv6 with port", domain: "::1", listenPort: 8080, metricHost: "[::1]:8080"},
		{name: "bare IPv6", domain: "::1", listenPort: 8080, metricHost: "::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			body := `caddy_http_requests_total{handler="reverse_proxy",host="` + test.metricHost + `"} 5`

			// When
			metrics, err := parseRuleMetricsFromPrometheus(body, test.domain, test.listenPort, false)

			// Then
			if err != nil {
				t.Fatalf("parse rule metrics: %v", err)
			}
			if metrics["requests_total"] != int64(5) {
				t.Fatalf("requests_total=%v, want 5", metrics["requests_total"])
			}
		})
	}
}

// CPU 采样错误不得被 1s 采样窗口缓存成「正常的 0%」：错误轮之后的下一个请求
// 必须重新采样并继续报错（Degraded 不覆盖 cpu，0% 会被误读为负载骤降）。
func TestGetCPUPercent_errorIsNotCachedBySampleWindow(t *testing.T) {
	withIsolatedGlobal(t)
	oldWindow := cpuSampleWindow
	cpuSampleWindow = time.Minute
	t.Cleanup(func() { cpuSampleWindow = oldWindow })

	lastCPUStats.mu.Lock()
	oldSnapshot, oldSampledAt, oldHasValue, oldPercent := lastCPUStats.snapshot, lastCPUStats.sampledAt, lastCPUStats.hasValue, lastCPUStats.percent
	lastCPUStats.snapshot = cpuSnapshot{total: 1000, idle: 300}
	lastCPUStats.sampledAt = time.Now().Add(-5 * time.Minute)
	lastCPUStats.hasValue = true
	lastCPUStats.percent = 7
	lastCPUStats.mu.Unlock()
	t.Cleanup(func() {
		lastCPUStats.mu.Lock()
		lastCPUStats.snapshot, lastCPUStats.sampledAt, lastCPUStats.hasValue, lastCPUStats.percent = oldSnapshot, oldSampledAt, oldHasValue, oldPercent
		lastCPUStats.mu.Unlock()
	})

	// 两轮样本的 idle 增量都大于总量增量（个别字段计数回退的畸形样本）。
	samples := []string{
		"cpu  200 0 490 320 0 0 0 0 0 0\n",
		"cpu  200 0 470 350 0 0 0 0 0 0\n",
	}
	call := 0
	oldReadFile := systemMetricsReadFile
	systemMetricsReadFile = func(string) ([]byte, error) {
		s := samples[call]
		if call < len(samples)-1 {
			call++
		}
		return []byte(s), nil
	}
	t.Cleanup(func() { systemMetricsReadFile = oldReadFile })

	for round := 1; round <= len(samples); round++ {
		if _, err := getCPUPercent(); err == nil {
			t.Fatalf("第 %d 轮采样应报错（错误样本不得被采样窗口缓存成 0%%）", round)
		}
	}
}

// Prometheus 正文允许 NaN/±Inf，但样本值转 int64 对非有限值是实现相关的（会输出
// 荒谬负数计数）：非有限样本必须跳过；全部无效时与「无有效样本」同口径报错。
func TestParsePrometheusSamples_skipsNonFiniteValues(t *testing.T) {
	body := strings.Join([]string{
		"# HELP caddy_http_requests_total total",
		`caddy_http_requests_total{host="a"} 5`,
		"unused_gauge NaN",
		"unused_inf +Inf",
		"unused_neg_inf -Inf",
	}, "\n")
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		t.Fatalf("parsePrometheusSamples: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("samples=%+v, want 仅有限值样本", samples)
	}
	if samples[0].name != `caddy_http_requests_total{host="a"}` || samples[0].value != 5 {
		t.Fatalf("sample=%+v, want 有限值样本原样保留", samples[0])
	}
	if _, err := parsePrometheusSamples("unused_gauge NaN\n"); err == nil {
		t.Fatal("全部样本非有限值时应报错（与正文无有效样本同口径）")
	}
}

// 超长设备名让 df 折行时仍必须取到总量/已用列（此前固定取第 2 行把设备名当
// 数字列，磁盘分项整体降级）。
func TestParseDFOutput_toleratesWrappedDeviceName(t *testing.T) {
	wrapped := "Filesystem 1B-blocks Used Available Use% Mounted on\n" +
		"/dev/disk/by-uuid/0123456789abcdef0123456789abcdef\n" +
		"1000 750 250 75% /\n"
	if total, used, ok := parseDFOutput(wrapped); !ok || total != 1000 || used != 750 {
		t.Fatalf("parseDFOutput(wrapped)=(%d,%d,%v), want (1000,750,true)", total, used, ok)
	}
	if _, _, ok := parseDFOutput("Filesystem 1B-blocks Used Available Use% Mounted on\n"); ok {
		t.Fatal("无数据行时不得返回成功")
	}
}
