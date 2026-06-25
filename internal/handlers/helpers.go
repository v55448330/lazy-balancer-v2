package handlers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

var startTime = time.Now()

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}


type CertificateInfo struct {
	Valid           bool   `json:"valid"`
	Domain          string `json:"domain"`
	Issuer          string `json:"issuer"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	Warning         string `json:"warning,omitempty"`
	Error           string `json:"error,omitempty"`
}

// validateTLSCertificate validates that the certificate and private key match
func validateTLSCertificate(certPEM, keyPEM string) error {
	_, err := parseTLSCertificate(certPEM, keyPEM)
	return err
}

// parseTLSCertificate parses certificate and returns info + error if invalid
func parseTLSCertificate(certPEM, keyPEM string) (*CertificateInfo, error) {
	info := &CertificateInfo{}

	if certPEM == "" || keyPEM == "" {
		return info, nil // Allow empty (will use auto cert or no TLS)
	}

	// Parse certificate
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid certificate or key pair: %w", err)
	}

	// Parse the certificate to check expiration
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract domain from Subject CN
	domain := ""
	if x509Cert.Subject.CommonName != "" {
		domain = x509Cert.Subject.CommonName
	}
	// Also check SANs
	if len(x509Cert.DNSNames) > 0 {
		domain = x509Cert.DNSNames[0]
	}

	// Extract issuer
	issuer := x509Cert.Issuer.CommonName
	if issuer == "" {
		issuer = x509Cert.Issuer.Organization[0]
	}

	info.Valid = true
	info.Domain = domain
	info.Issuer = issuer
	info.NotBefore = x509Cert.NotBefore.Format("2006-01-02")
	info.NotAfter = x509Cert.NotAfter.Format("2006-01-02")
	info.DaysUntilExpiry = int(x509Cert.NotAfter.Sub(time.Now()).Hours() / 24)

	// Check if certificate is expired - warning only
	if time.Now().After(x509Cert.NotAfter) {
		info.Warning = fmt.Sprintf("证书已过期 (过期时间: %s)", x509Cert.NotAfter.Format("2006-01-02"))
	}

	// Check if certificate is not yet valid - warning only
	if time.Now().Before(x509Cert.NotBefore) {
		info.Warning = fmt.Sprintf("证书尚未生效 (生效时间: %s)", x509Cert.NotBefore.Format("2006-01-02"))
	}

	// Extract public key from certificate
	var certPubKey interface{}
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		certPubKey = pub
	case *ecdsa.PublicKey:
		certPubKey = pub
	default:
		return nil, fmt.Errorf("unsupported public key type in certificate")
	}

	// Extract public key from private key
	var keyPubKey interface{}
	switch priv := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyPubKey = &priv.PublicKey
	case *ecdsa.PrivateKey:
		keyPubKey = &priv.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}

	// Compare public keys
	switch certPub := certPubKey.(type) {
	case *rsa.PublicKey:
		keyPub, ok := keyPubKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate and key public key types do not match")
		}
		if certPub.N.Cmp(keyPub.N) != 0 || certPub.E != keyPub.E {
			return nil, fmt.Errorf("certificate and private key do not match")
		}
	case *ecdsa.PublicKey:
		keyPub, ok := keyPubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate and key public key types do not match")
		}
		if certPub.X.Cmp(keyPub.X) != 0 || certPub.Y.Cmp(keyPub.Y) != 0 {
			return nil, fmt.Errorf("certificate and private key do not match")
		}
	}

	return info, nil
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}


func getHostname() string {
	cmd := exec.Command("hostname")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}


func getOSInfo() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		cmd := exec.Command("uname", "-s")
		output, err := cmd.Output()
		if err != nil {
			return "unknown"
		}
		return strings.TrimSpace(string(output))
	}
	lines := strings.Split(string(data), "\n")
	var prettyName, name string
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		}
	}
	if prettyName != "" {
		return prettyName
	}
	if name != "" {
		return name
	}
	return "Linux"
}


func getKernel() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}


func getArchitecture() string {
	cmd := exec.Command("arch")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}


func getNetworkIPs() map[string]string {
	ips := make(map[string]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				ips[iface.Name] = ip.String()
			}
		}
	}
	return ips
}


func getCaddyVersion() string {
	cmd := exec.Command("caddy", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	parts := strings.Fields(string(output))
	if len(parts) >= 1 {
		return strings.TrimPrefix(parts[0], "v")
	}
	return strings.TrimSpace(string(output))
}


func getUptime() int64 {
	return int64(time.Since(startTime).Seconds())
}


func getSystemMetrics() (models.SystemMetrics, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memoryTotal := m.TotalAlloc
	memoryUsed := m.Alloc

	vmStat, err := os.ReadFile("/proc/meminfo")
	var memTotal, memAvailable, diskUsed, diskTotal uint64
	if err == nil {
		lines := strings.Split(string(vmStat), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
					memTotal *= 1024
				}
			}
			if strings.HasPrefix(line, "MemAvailable:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
					memAvailable *= 1024
				}
			}
		}
		if memTotal > 0 && memAvailable > 0 {
			memoryTotal = memTotal
			memoryUsed = memTotal - memAvailable
		}
	}

	diskStat, err := os.Stat("/")
	if err == nil {
		diskTotal = uint64(diskStat.Size())
	}

	dfCmd := exec.Command("df", "-B1", "/")
	dfOutput, err := dfCmd.Output()
	if err == nil {
		lines := strings.Split(string(dfOutput), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				diskUsed, _ = strconv.ParseUint(fields[2], 10, 64)
				diskTotal, _ = strconv.ParseUint(fields[3], 10, 64)
			}
		}
	}

	cpuPercent := getCPUPercent()

	var memPercent float64
	if memoryTotal > 0 {
		memPercent = float64(memoryUsed) / float64(memoryTotal) * 100
	}
	var diskPercent float64
	if diskTotal > 0 {
		diskPercent = float64(diskUsed) / float64(diskTotal) * 100
	}

	return models.SystemMetrics{
		CPUPercent:    cpuPercent,
		MemoryTotal:   memoryTotal,
		MemoryUsed:    memoryUsed,
		MemoryPercent: memPercent,
		DiskTotal:     diskTotal,
		DiskUsed:      diskUsed,
		DiskPercent:   diskPercent,
	}, nil
}


func getCPUPercent() float64 {
	cmd := exec.Command("sh", "-c", "cat /proc/stat | head -1 | awk '{print ($2+$3+$4)/($2+$3+$4+$5)*100}'")
	output, err := cmd.Output()
	if err == nil {
		line := strings.TrimSpace(string(output))
		if val, err := strconv.ParseFloat(line, 64); err == nil {
			return val
		}
	}
	return 0
}


func getCPUFromProc() float64 {
	readFile := func(path string) []byte {
		data, _ := os.ReadFile(path)
		return data
	}

	prevStats := parseCPUStats(string(readFile("/proc/stat")))
	if prevStats == nil {
		cmd := exec.Command("sh", "-c", "cat /proc/stat | head -1")
		output, _ := cmd.Output()
		prevStats = parseCPUStats(string(output))
		if prevStats == nil {
			return 0
		}
	}
	time.Sleep(500 * time.Millisecond)
	currStats := parseCPUStats(string(readFile("/proc/stat")))
	if currStats == nil {
		return 0
	}

	prevTotal := prevStats.total()
	currTotal := currStats.total()
	if currTotal <= prevTotal {
		return 0
	}

	prevIdle := prevStats.idle + prevStats.iowait
	currIdle := currStats.idle + currStats.iowait
	idleDelta := currIdle - prevIdle
	totalDelta := currTotal - prevTotal

	if totalDelta == 0 {
		return 0
	}

	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100
}


type cpuStats struct {
	user, nice, system, idle, iowait, irq, softirq uint64
}

func (c *cpuStats) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq
}

func parseCPUStats(data string) *cpuStats {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				return nil
			}
			user, _ := strconv.ParseUint(fields[1], 10, 64)
			nice, _ := strconv.ParseUint(fields[2], 10, 64)
			system, _ := strconv.ParseUint(fields[3], 10, 64)
			idle, _ := strconv.ParseUint(fields[4], 10, 64)
			iowait, _ := strconv.ParseUint(fields[5], 10, 64)
			irq, _ := strconv.ParseUint(fields[6], 10, 64)
			softirq, _ := strconv.ParseUint(fields[7], 10, 64)
			return &cpuStats{user, nice, system, idle, iowait, irq, softirq}
		}
	}
	return nil
}


var lastNetStats struct {
	bytesIn  uint64
	bytesOut uint64
	time     time.Time
}

func getRealtimeTraffic() (models.RealtimeTraffic, error) {
	netStat, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return models.RealtimeTraffic{}, err
	}

	var totalBytesIn, totalBytesOut uint64
	lines := strings.Split(string(netStat), "\n")
	for _, line := range lines {
		if strings.Contains(line, "eth0") || strings.Contains(line, "ens") || strings.Contains(line, "docker0") {
			fields := strings.Fields(line)
			if len(fields) >= 11 {
				bytesIn, _ := strconv.ParseUint(fields[1], 10, 64)
				bytesOut, _ := strconv.ParseUint(fields[9], 10, 64)
				totalBytesIn += bytesIn
				totalBytesOut += bytesOut
			}
		}
	}

	now := time.Now()
	var rateIn, rateOut int64

	if !lastNetStats.time.IsZero() {
		elapsed := now.Sub(lastNetStats.time).Seconds()
		if elapsed > 0 {
			rateIn = int64(float64(totalBytesIn-lastNetStats.bytesIn) / elapsed)
			rateOut = int64(float64(totalBytesOut-lastNetStats.bytesOut) / elapsed)
			if rateIn < 0 {
				rateIn = 0
			}
			if rateOut < 0 {
				rateOut = 0
			}
		}
	}

	lastNetStats.bytesIn = totalBytesIn
	lastNetStats.bytesOut = totalBytesOut
	lastNetStats.time = now

	return models.RealtimeTraffic{
		BytesIn:  rateIn,
		BytesOut: rateOut,
	}, nil
}


func getConnectionStats() (models.ConnectionStats, error) {
	stats := models.ConnectionStats{}

	cmd := exec.Command("netstat", "-tan")
	output, err := cmd.Output()
	if err != nil {
		return stats, nil
	}

	lines := strings.Split(string(output), "\n")
	stateCounts := make(map[string]int64)

	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		if i == 0 && fields[0] == "Proto" {
			continue
		}

		state := fields[5]
		switch state {
		case "ESTABLISHED":
			stateCounts["established"]++
		case "SYN-SENT":
			stateCounts["syn_sent"]++
		case "SYN-RECV":
			stateCounts["syn_recv"]++
		case "FIN-WAIT1":
			stateCounts["fin_wait1"]++
		case "FIN-WAIT2":
			stateCounts["fin_wait2"]++
		case "CLOSE-WAIT":
			stateCounts["close_wait"]++
		case "CLOSING":
			stateCounts["closing"]++
		case "LAST-ACK":
			stateCounts["last_ack"]++
		case "LISTEN":
			stateCounts["listening"]++
		case "TIME-WAIT":
			stateCounts["time_wait"]++
		}
	}

	stats.Established = stateCounts["established"]
	stats.SynSent = stateCounts["syn_sent"]
	stats.SynRecv = stateCounts["syn_recv"]
	stats.FinWait1 = stateCounts["fin_wait1"]
	stats.FinWait2 = stateCounts["fin_wait2"]
	stats.CloseWait = stateCounts["close_wait"]
	stats.Closing = stateCounts["closing"]
	stats.LastAck = stateCounts["last_ack"]
	stats.Listening = stateCounts["listening"]
	stats.TimeWait = stateCounts["time_wait"]

	stats.Total = stats.Established + stats.SynSent + stats.SynRecv + stats.FinWait1 +
		stats.FinWait2 + stats.CloseWait + stats.Closing + stats.LastAck + stats.TimeWait

	return stats, nil
}


func parsePrometheusMetrics(body string) models.CaddyMetrics {
	m := models.CaddyMetrics{}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		value, _ := strconv.ParseFloat(fields[1], 64)
		switch {
		case strings.HasPrefix(name, "caddy_http_requests_total{"):
			v := int64(value)
			m.RequestsTotal += v
		case strings.HasPrefix(name, "caddy_http_request_duration_seconds_count{"):
			code := extractLabel(name, "code")
			v := int64(value)
			switch classifyStatusCode(code) {
			case "status_2xx":
				m.Status2xx += v
			case "status_3xx":
				m.Status3xx += v
			case "status_4xx":
				m.Status4xx += v
			case "status_5xx":
				m.Status5xx += v
			}
		case strings.HasPrefix(name, "caddy_http_requests_in_flight{"):
			m.RequestsInFlight += int64(value)
		case name == "go_goroutines":
			m.Goroutines = int64(value)
		}
		if strings.Contains(name, "caddy_http_request_size_bytes_sum") {
			m.BytesIn += int64(value)
		}
		if strings.Contains(name, "caddy_http_response_size_bytes_sum") {
			m.BytesOut += int64(value)
		}
	}
	return m
}


func parseHostMetrics(body string) []models.HostMetrics {
	hostMap := make(map[string]*models.HostMetrics)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		value, _ := strconv.ParseFloat(fields[1], 64)

		host := extractLabel(name, "host")
		if host == "" {
			continue
		}
		if _, ok := hostMap[host]; !ok {
			hostMap[host] = &models.HostMetrics{Host: host}
		}
		h := hostMap[host]

		switch {
		case strings.HasPrefix(name, "caddy_http_requests_total{"):
			v := int64(value)
			h.RequestsTotal += v
		case strings.HasPrefix(name, "caddy_http_request_duration_seconds_count{"):
			code := extractLabel(name, "code")
			v := int64(value)
			switch classifyStatusCode(code) {
			case "status_2xx":
				h.Status2xx += v
			case "status_3xx":
				h.Status3xx += v
			case "status_4xx":
				h.Status4xx += v
			case "status_5xx":
				h.Status5xx += v
			}
		case strings.HasPrefix(name, "caddy_http_requests_in_flight{"):
			h.RequestsInFlight += int64(value)
		case strings.Contains(name, "caddy_http_request_size_bytes_sum"):
			h.BytesIn += int64(value)
		case strings.Contains(name, "caddy_http_response_size_bytes_sum"):
			h.BytesOut += int64(value)
		}
	}
	result := make([]models.HostMetrics, 0, len(hostMap))
	for _, h := range hostMap {
		result = append(result, *h)
	}
	return result
}


func extractLabel(metricName string, label string) string {
	idx := strings.Index(metricName, label+`="`)
	if idx == -1 {
		return ""
	}
	start := idx + len(label) + 2
	end := strings.Index(metricName[start:], `"`)
	if end == -1 {
		return ""
	}
	return metricName[start : start+end]
}

func parseRuleMetricsFromPrometheus(body, domain string, listenPort int, protocol string, enableTLS bool) gin.H {
	result := emptyRuleMetrics()
	if domain == "" {
		return result
	}

	domains := strings.Split(domain, ",")
	hostSet := make(map[string]struct{})
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		hostSet[d] = struct{}{}
		if !strings.Contains(d, ":") {
			hostSet[d+":"+strconv.Itoa(listenPort)] = struct{}{}
			if enableTLS {
				hostSet[d+":443"] = struct{}{}
			} else if listenPort == 80 || listenPort == 0 {
				hostSet[d+":80"] = struct{}{}
			}
		}
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		value, _ := strconv.ParseFloat(fields[1], 64)

		host := extractLabel(name, "host")
		if host == "" {
			continue
		}
		if _, ok := hostSet[host]; !ok {
			continue
		}

		switch {
		case strings.HasPrefix(name, "caddy_http_requests_total{"):
			v := int64(value)
			result["requests_total"] = result["requests_total"].(int64) + v
		case strings.HasPrefix(name, "caddy_http_request_duration_seconds_count{"):
			code := extractLabel(name, "code")
			v := int64(value)
			bucket := classifyStatusCode(code)
			result[bucket] = result[bucket].(int64) + v
		case strings.HasPrefix(name, "caddy_http_requests_in_flight{"):
			result["requests_in_flight"] = result["requests_in_flight"].(int64) + int64(value)
		case strings.Contains(name, "caddy_http_request_size_bytes_sum"):
			result["bytes_in"] = result["bytes_in"].(int64) + int64(value)
		case strings.Contains(name, "caddy_http_response_size_bytes_sum"):
			result["bytes_out"] = result["bytes_out"].(int64) + int64(value)
		}
	}

	return result
}

func classifyStatusCode(code string) string {
	if code == "" {
		return "status_2xx"
	}
	prefix := code[:1]
	switch prefix {
	case "2":
		return "status_2xx"
	case "3":
		return "status_3xx"
	case "4":
		return "status_4xx"
	case "5":
		return "status_5xx"
	default:
		return "status_2xx"
	}
}

func emptyRuleMetrics() gin.H {
	return gin.H{
		"requests_total":     int64(0),
		"requests_in_flight": int64(0),
		"status_2xx":         int64(0),
		"status_3xx":         int64(0),
		"status_4xx":         int64(0),
		"status_5xx":         int64(0),
		"bytes_in":           int64(0),
		"bytes_out":          int64(0),
		"healthy":            false,
	}
}


func isValidHost(host string) bool {
	// Check if it's a valid IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return true
	}

	// Check if it's a valid domain name
	// Domain should not contain IP address-like patterns
	if len(host) > 253 {
		return false
	}

	// Basic domain validation - letters, numbers, dots, hyphens
	valid := true
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if part == "" {
			valid = false
			break
		}
		if len(part) > 63 {
			valid = false
			break
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
				valid = false
				break
			}
		}
		if !valid {
			break
		}
	}

	return valid
}


func isValidDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
		if len(part) > 63 {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
				return false
			}
		}
	}
	return true
}

