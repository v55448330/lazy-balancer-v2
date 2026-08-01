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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

var startTime = time.Now()

var systemMetricsReadFile = os.ReadFile
var systemMetricsDFCommand = func() *exec.Cmd { return exec.Command("df", "-B1", "/") }

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
	if issuer == "" && len(x509Cert.Issuer.Organization) > 0 {
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
	vmStat, err := systemMetricsReadFile("/proc/meminfo")
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("读取系统内存指标失败: %w", err)
	}
	memoryTotal, memoryUsed, err := parseMemInfo(string(vmStat))
	if err != nil {
		return models.SystemMetrics{}, err
	}

	dfCmd := systemMetricsDFCommand()
	dfOutput, err := dfCmd.Output()
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("读取系统磁盘指标失败: %w", err)
	}
	diskTotal, diskUsed, ok := parseDFOutput(string(dfOutput))
	if !ok {
		return models.SystemMetrics{}, fmt.Errorf("解析系统磁盘指标失败")
	}

	cpuPercent, err := getCPUPercent()
	if err != nil {
		return models.SystemMetrics{}, fmt.Errorf("读取系统 CPU 指标失败: %w", err)
	}

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

func parseMemInfo(input string) (uint64, uint64, error) {
	values := make(map[string]uint64, 2)
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("解析系统内存指标失败: %w", err)
		}
		values[fields[0]] = value * 1024
	}
	total, available := values["MemTotal:"], values["MemAvailable:"]
	if total == 0 || available > total {
		return 0, 0, fmt.Errorf("解析系统内存指标失败: MemTotal 或 MemAvailable 无效")
	}
	return total, total - available, nil
}

func getCPUPercent() (float64, error) {
	lastCPUStats.mu.Lock()
	defer lastCPUStats.mu.Unlock()

	stat, err := systemMetricsReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	current, ok := parseCPUSnapshot(string(stat))
	if !ok {
		return 0, fmt.Errorf("解析 /proc/stat 失败")
	}
	previous := lastCPUStats.snapshot
	if previous.total == 0 {
		lastCPUStats.snapshot = current
		return 0, nil
	}
	if current.total <= previous.total || current.idle < previous.idle {
		return 0, fmt.Errorf("CPU 计数器无效")
	}
	totalDelta := current.total - previous.total
	idleDelta := current.idle - previous.idle
	if idleDelta > totalDelta {
		return 0, fmt.Errorf("CPU 空闲计数器增量无效")
	}
	lastCPUStats.snapshot = current
	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100, nil
}

var lastNetStats struct {
	mu       sync.Mutex
	bytesIn  uint64
	bytesOut uint64
	time     time.Time
}

func getRealtimeTraffic() (models.RealtimeTraffic, error) {
	lastNetStats.mu.Lock()
	defer lastNetStats.mu.Unlock()

	netStat, err := systemMetricsReadFile("/proc/net/dev")
	if err != nil {
		return models.RealtimeTraffic{}, err
	}

	totalBytesIn, totalBytesOut, err := parseNetDevTotals(string(netStat))
	if err != nil {
		return models.RealtimeTraffic{}, err
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

func parseNetDevTotals(input string) (uint64, uint64, error) {
	route, err := systemMetricsReadFile("/proc/net/route")
	if err != nil {
		return 0, 0, fmt.Errorf("读取默认路由失败: %w", err)
	}
	if defaultInterface, err := parseDefaultRouteInterface(string(route)); err == nil {
		for _, line := range strings.Split(input, "\n") {
			name, counters, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(name) != defaultInterface {
				continue
			}
			fields := strings.Fields(counters)
			if len(fields) < 16 {
				return 0, 0, fmt.Errorf("解析网卡 %s 流量失败: 计数器字段不足", strings.TrimSpace(name))
			}
			bytesIn, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("解析网卡 %s 接收流量失败: %w", strings.TrimSpace(name), err)
			}
			bytesOut, err := strconv.ParseUint(fields[8], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("解析网卡 %s 发送流量失败: %w", strings.TrimSpace(name), err)
			}
			return bytesIn, bytesOut, nil
		}
		return 0, 0, fmt.Errorf("默认路由接口 %s 不存在于 /proc/net/dev", defaultInterface)
	}
	// 无默认路由（如容器 netns 只有子网路由）：统计物理类接口，排除 lo 与
	// 会重复计数的虚拟叠加层（veth/docker 网桥/br-*）
	var totalIn, totalOut uint64
	matched := false
	for _, line := range strings.Split(input, "\n") {
		name, counters, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(name)
		if iface == "" || iface == "lo" || strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "br-") {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) < 16 {
			continue
		}
		bytesIn, errIn := strconv.ParseUint(fields[0], 10, 64)
		bytesOut, errOut := strconv.ParseUint(fields[8], 10, 64)
		if errIn != nil || errOut != nil {
			continue
		}
		totalIn += bytesIn
		totalOut += bytesOut
		matched = true
	}
	if !matched {
		return 0, 0, fmt.Errorf("无法确定默认路由出口接口且无可用物理网卡")
	}
	return totalIn, totalOut, nil
}

func parseDefaultRouteInterface(input string) (string, error) {
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] != "Iface" && fields[1] == "00000000" {
			flags, err := strconv.ParseUint(fields[3], 16, 64)
			if err != nil {
				return "", fmt.Errorf("解析默认路由标志失败: %w", err)
			}
			if flags&1 != 0 {
				return fields[0], nil
			}
		}
	}
	return "", fmt.Errorf("无法确定默认路由出口接口")
}

type cpuSnapshot struct {
	total uint64
	idle  uint64
}

var lastCPUStats struct {
	mu       sync.Mutex
	snapshot cpuSnapshot
}

func parseCPUSnapshot(stat string) (cpuSnapshot, bool) {
	line, _, _ := strings.Cut(stat, "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSnapshot{}, false
	}
	var snapshot cpuSnapshot
	for index, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuSnapshot{}, false
		}
		if index < 8 {
			snapshot.total += value
		}
		if index == 3 || index == 4 {
			snapshot.idle += value
		}
	}
	return snapshot, snapshot.total > 0
}

func parseDFOutput(output string) (uint64, uint64, bool) {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return 0, 0, false
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return 0, 0, false
	}
	total, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	used, err := strconv.ParseUint(fields[2], 10, 64)
	return total, used, err == nil
}

func getConnectionStats() (models.ConnectionStats, error) {
	stats := models.ConnectionStats{}

	cmd := netstatCommand()
	output, err := cmd.Output()
	if err != nil {
		return stats, fmt.Errorf("execute netstat -tan: %w", err)
	}

	return parseConnectionStats(string(output)), nil
}

func parseConnectionStats(output string) models.ConnectionStats {
	stats := models.ConnectionStats{}
	lines := strings.Split(output, "\n")
	stateCounts := make(map[string]int64)

	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		if i == 0 && fields[0] == "Proto" {
			continue
		}

		state := strings.ReplaceAll(fields[5], "-", "_")
		switch state {
		case "ESTABLISHED":
			stateCounts["established"]++
		case "SYN_SENT":
			stateCounts["syn_sent"]++
		case "SYN_RECV":
			stateCounts["syn_recv"]++
		case "FIN_WAIT1":
			stateCounts["fin_wait1"]++
		case "FIN_WAIT2":
			stateCounts["fin_wait2"]++
		case "CLOSE_WAIT":
			stateCounts["close_wait"]++
		case "CLOSING":
			stateCounts["closing"]++
		case "LAST_ACK":
			stateCounts["last_ack"]++
		case "LISTEN":
			stateCounts["listening"]++
		case "TIME_WAIT":
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

	return stats
}

var netstatCommand = func() *exec.Cmd {
	return exec.Command("netstat", "-tan")
}

type prometheusSample struct {
	name  string
	value float64
}

func parsePrometheusSamples(body string) ([]prometheusSample, error) {
	var samples []prometheusSample
	for lineNumber, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("解析 Prometheus 第 %d 行样本值 %q 失败: %w", lineNumber+1, fields[1], err)
		}
		samples = append(samples, prometheusSample{name: fields[0], value: value})
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("Prometheus 正文不包含有效样本")
	}
	return samples, nil
}

func parsePrometheusMetrics(body string) (models.CaddyMetrics, error) {
	m := models.CaddyMetrics{}
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return m, err
	}
	for _, sample := range samples {
		name, value := sample.name, sample.value
		switch {
		case strings.HasPrefix(name, "caddy_http_requests_total{"):
			v := int64(value)
			m.RequestsTotal += v
		case strings.HasPrefix(name, "caddy_http_request_duration_seconds_count{"):
			code := extractLabel(name, "code")
			v := int64(value)
			switch bucket, _ := classifyStatusCode(code); bucket {
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
	return m, nil
}

func parseHostMetrics(body string) ([]models.HostMetrics, error) {
	hostMap := make(map[string]*models.HostMetrics)
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	for _, sample := range samples {
		name, value := sample.name, sample.value

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
			switch bucket, _ := classifyStatusCode(code); bucket {
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
	return result, nil
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

func parseTCPRuleMetricsFromPrometheus(body string, upstreams []models.Upstream) (gin.H, error) {
	result := emptyRuleMetrics()
	// TCP 没有健康信号来源，不输出 healthy 字段，前端显示为无数据
	delete(result, "healthy")

	upstreamSet := make(map[string]struct{})
	for _, u := range upstreams {
		if u.Enabled {
			upstreamSet[fmt.Sprintf("%s:%d", u.Host, u.Port)] = struct{}{}
		}
	}
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	if len(upstreamSet) == 0 {
		return result, nil
	}

	var connectionsTotal, activeConnections int64

	for _, sample := range samples {
		name, value := sample.name, sample.value

		upstream := extractLabel(name, "upstream")
		if upstream == "" {
			continue
		}
		if _, ok := upstreamSet[upstream]; !ok {
			continue
		}

		switch {
		case strings.HasPrefix(name, "caddy_layer4_proxy_connections_total{"),
			strings.HasPrefix(name, "caddy_layer4_proxy_connections_total "):
			connectionsTotal += int64(value)
		case strings.HasPrefix(name, "caddy_layer4_proxy_active_connections{"),
			strings.HasPrefix(name, "caddy_layer4_proxy_active_connections "):
			activeConnections += int64(value)
		}
	}

	result["requests_total"] = connectionsTotal
	result["requests_in_flight"] = activeConnections
	return result, nil
}

func parseRuleMetricsFromPrometheus(body, domain string, listenPort int, protocol string, enableTLS bool) (gin.H, error) {
	result := emptyRuleMetrics()
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	if domain == "" {
		return result, nil
	}

	domains := strings.Split(domain, ",")
	hostSet := make(map[string]struct{})
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		hostSet[d] = struct{}{}
		if host, _, err := net.SplitHostPort(d); err == nil {
			hostSet[host] = struct{}{}
		} else {
			hostSet[net.JoinHostPort(d, strconv.Itoa(listenPort))] = struct{}{}
			if enableTLS {
				hostSet[net.JoinHostPort(d, "443")] = struct{}{}
			} else if listenPort == 80 || listenPort == 0 {
				hostSet[net.JoinHostPort(d, "80")] = struct{}{}
			}
		}
	}

	for _, sample := range samples {
		name, value := sample.name, sample.value

		host := extractLabel(name, "host")
		if host == "" {
			continue
		}
		if _, ok := hostSet[host]; !ok {
			bareHost, _, err := net.SplitHostPort(host)
			if err != nil {
				continue
			}
			if _, ok := hostSet[bareHost]; !ok {
				continue
			}
		}

		switch {
		case strings.HasPrefix(name, "caddy_http_requests_total{"):
			v := int64(value)
			result["requests_total"] = result["requests_total"].(int64) + v
		case strings.HasPrefix(name, "caddy_http_request_duration_seconds_count{"):
			code := extractLabel(name, "code")
			v := int64(value)
			if bucket, ok := classifyStatusCode(code); ok {
				result[bucket] = result[bucket].(int64) + v
			}
		case strings.HasPrefix(name, "caddy_http_requests_in_flight{"):
			result["requests_in_flight"] = result["requests_in_flight"].(int64) + int64(value)
		case strings.Contains(name, "caddy_http_request_size_bytes_sum"):
			result["bytes_in"] = result["bytes_in"].(int64) + int64(value)
		case strings.Contains(name, "caddy_http_response_size_bytes_sum"):
			result["bytes_out"] = result["bytes_out"].(int64) + int64(value)
		}
	}

	return result, nil
}

func classifyStatusCode(code string) (string, bool) {
	if code == "" {
		return "", false
	}
	prefix := code[:1]
	switch prefix {
	case "2":
		return "status_2xx", true
	case "3":
		return "status_3xx", true
	case "4":
		return "status_4xx", true
	case "5":
		return "status_5xx", true
	default:
		return "", false
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
	domain = strings.ToLower(domain)
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
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
				return false
			}
		}
	}
	return true
}
