package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os/exec"
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

func TestParseNetDevTotals_sums_all_non_loopback_interfaces(t *testing.T) {
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

	bytesIn, bytesOut, err := parseNetDevTotals(fixture)
	if err != nil {
		t.Fatalf("parse net dev fixture: %v", err)
	}
	if bytesIn != 1000 || bytesOut != 2000 {
		t.Fatalf("bytesIn=%d bytesOut=%d, want 1000/2000", bytesIn, bytesOut)
	}
}

func TestParseNetDevTotals_falls_back_to_physical_interfaces_when_no_default_route(t *testing.T) {
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
	bytesIn, bytesOut, err := parseNetDevTotals(fixture)

	// Then：只统计 eth0，虚拟叠加层不重复计入
	if err != nil {
		t.Fatalf("parse without default route: %v", err)
	}
	if bytesIn != 1000 || bytesOut != 2000 {
		t.Fatalf("bytesIn=%d bytesOut=%d, want 1000/2000 (eth0 only)", bytesIn, bytesOut)
	}
}

func TestGetSystemMetrics_returns_error_when_meminfo_read_fails(t *testing.T) {
	original := systemMetricsReadFile
	systemMetricsReadFile = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
	t.Cleanup(func() { systemMetricsReadFile = original })

	metrics, err := getSystemMetrics()
	if err == nil || !strings.Contains(err.Error(), "读取系统内存指标失败") {
		t.Fatalf("metrics=%#v error=%v, want explicit memory error", metrics, err)
	}
}

func TestGetSystemMetrics_returns_error_when_df_output_is_invalid(t *testing.T) {
	originalReadFile, originalDFCommand := systemMetricsReadFile, systemMetricsDFCommand
	systemMetricsReadFile = func(string) ([]byte, error) {
		return []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), nil
	}
	systemMetricsDFCommand = func() *exec.Cmd { return exec.Command("sh", "-c", "printf invalid") }
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDFCommand
	})

	metrics, err := getSystemMetrics()
	if err == nil || !strings.Contains(err.Error(), "解析系统磁盘指标失败") {
		t.Fatalf("metrics=%#v error=%v, want explicit disk parse error", metrics, err)
	}
}

func TestGetConnectionStats_returns_netstat_error(t *testing.T) {
	original := netstatCommand
	netstatCommand = func() *exec.Cmd { return exec.Command("sh", "-c", "exit 17") }
	t.Cleanup(func() { netstatCommand = original })
	_, err := getConnectionStats()
	if err == nil || !strings.Contains(err.Error(), "netstat -tan") {
		t.Fatalf("error=%v, want contextual netstat error", err)
	}
}

// generateTestCert creates a test certificate and key pair
func generateTestCert(domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string, err error) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Create certificate template
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

	// Self-sign the certificate
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
			name:        "mismatched cert and key",
			wantErr:     true,
			errContains: "private key does not match public key",
		},
		{
			name:       "valid ECDSA certificate",
			wantValid:  true,
			wantDomain: "ecdsa.example.com",
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
	certPEM, keyPEM, err := generateTestCert("san.example.com", now.Add(-1*time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	info, err := parseTLSCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseTLSCertificate() error = %v", err)
	}

	if info.Domain != "san.example.com" {
		t.Errorf("parseTLSCertificate() Domain = %v, want san.example.com", info.Domain)
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
	// Given
	originalReader := systemMetricsReadFile
	lastCPUStats.mu.Lock()
	originalSnapshot := lastCPUStats.snapshot
	lastCPUStats.snapshot = cpuSnapshot{total: 100, idle: 50}
	lastCPUStats.mu.Unlock()
	t.Cleanup(func() {
		systemMetricsReadFile = originalReader
		lastCPUStats.mu.Lock()
		lastCPUStats.snapshot = originalSnapshot
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
	select {
	case <-secondRead:
		close(releaseFirst)
	case <-time.After(100 * time.Millisecond):
		close(releaseFirst)
	}
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

func TestGetRealtimeTraffic_serializes_sample_read_with_baseline_update(t *testing.T) {
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
	select {
	case <-secondRead:
		close(releaseFirst)
	case <-time.After(100 * time.Millisecond):
		close(releaseFirst)
	}
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
			metrics, err := parseRuleMetricsFromPrometheus(body, test.domain, test.listenPort, "http", false)

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
