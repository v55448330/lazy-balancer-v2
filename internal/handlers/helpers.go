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
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

var startTime = time.Now()

var systemMetricsReadFile = os.ReadFile
var systemMetricsDFCommand = func() *exec.Cmd { return exec.Command("df", "-B1", "/") }

const systemSampleTTL = 5 * time.Second

var staticSystemInfo = struct {
	hostname, osInfo, kernel, architecture, caddyVersion string
}{
	hostname:     loadHostname(),
	osInfo:       loadOSInfo(),
	kernel:       loadCommandOutput("uname", "-r"),
	architecture: runtime.GOARCH,
	caddyVersion: loadCaddyVersion(),
}

var diskUsageCache struct {
	sync.Mutex
	total     uint64
	used      uint64
	expiresAt time.Time
}

var connectionStatsCache struct {
	sync.Mutex
	stats     models.ConnectionStats
	expiresAt time.Time
}

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

func loadHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getHostname() string { return staticSystemInfo.hostname }

func loadOSInfo() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return loadCommandOutput("uname", "-s")
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

func getOSInfo() string { return staticSystemInfo.osInfo }

func loadCommandOutput(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func getKernel() string       { return staticSystemInfo.kernel }
func getArchitecture() string { return staticSystemInfo.architecture }

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

func loadCaddyVersion() string {
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

func getCaddyVersion() string { return staticSystemInfo.caddyVersion }

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

	diskTotal, diskUsed, err := getCachedDiskUsage(time.Now())
	if err != nil {
		return models.SystemMetrics{}, err
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

func getCachedDiskUsage(now time.Time) (uint64, uint64, error) {
	diskUsageCache.Lock()
	defer diskUsageCache.Unlock()
	if now.Before(diskUsageCache.expiresAt) {
		return diskUsageCache.total, diskUsageCache.used, nil
	}
	dfOutput, err := systemMetricsDFCommand().Output()
	if err != nil {
		return 0, 0, fmt.Errorf("读取系统磁盘指标失败: %w", err)
	}
	total, used, ok := parseDFOutput(string(dfOutput))
	if !ok {
		return 0, 0, fmt.Errorf("解析系统磁盘指标失败")
	}
	diskUsageCache.total = total
	diskUsageCache.used = used
	diskUsageCache.expiresAt = now.Add(systemSampleTTL)
	return total, used, nil
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
	if current.total < previous.total || current.idle < previous.idle {
		lastCPUStats.snapshot = current
		return 0, nil
	}
	totalDelta := current.total - previous.total
	idleDelta := current.idle - previous.idle
	if idleDelta > totalDelta {
		return 0, fmt.Errorf("CPU 空闲计数器增量无效")
	}
	lastCPUStats.snapshot = current
	if totalDelta == 0 {
		return 0, nil
	}
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
		countersRolledBack := totalBytesIn < lastNetStats.bytesIn || totalBytesOut < lastNetStats.bytesOut
		if elapsed > 0 && !countersRolledBack {
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
	now := time.Now()
	connectionStatsCache.Lock()
	defer connectionStatsCache.Unlock()
	if now.Before(connectionStatsCache.expiresAt) {
		return connectionStatsCache.stats, nil
	}
	output, err := netstatCommand().Output()
	if err != nil {
		return models.ConnectionStats{}, fmt.Errorf("execute netstat -tan: %w", err)
	}
	connectionStatsCache.stats = parseConnectionStats(string(output))
	connectionStatsCache.expiresAt = now.Add(systemSampleTTL)
	return connectionStatsCache.stats, nil
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

type ruleMetricTarget struct {
	domain     string
	listenPort int
	enableTLS  bool
}

type ruleMetricsAggregate struct {
	requestsTotal    int64
	requestsInFlight int64
	status2xx        int64
	status3xx        int64
	status4xx        int64
	status5xx        int64
	bytesIn          int64
	bytesOut         int64
}

type prometheusMetricsIndex struct {
	global        ruleMetricsAggregate
	goroutines    int64
	hosts         map[string]*ruleMetricsAggregate
	httpHosts     map[string]*ruleMetricsAggregate
	httpBareHosts map[string]*ruleMetricsAggregate
	tcpUpstreams  map[string]*ruleMetricsAggregate
}

func buildPrometheusMetricsIndex(samples []prometheusSample) prometheusMetricsIndex {
	index := prometheusMetricsIndex{
		hosts:         make(map[string]*ruleMetricsAggregate),
		httpHosts:     make(map[string]*ruleMetricsAggregate),
		httpBareHosts: make(map[string]*ruleMetricsAggregate),
		tcpUpstreams:  make(map[string]*ruleMetricsAggregate),
	}
	for _, sample := range samples {
		index.addSample(sample)
	}
	return index
}

func (index prometheusMetricsIndex) globalMetrics() models.CaddyMetrics {
	return models.CaddyMetrics{
		RequestsTotal:    index.global.requestsTotal,
		RequestsInFlight: index.global.requestsInFlight,
		Status2xx:        index.global.status2xx,
		Status3xx:        index.global.status3xx,
		Status4xx:        index.global.status4xx,
		Status5xx:        index.global.status5xx,
		BytesIn:          index.global.bytesIn,
		BytesOut:         index.global.bytesOut,
		Goroutines:       index.goroutines,
	}
}

func (index prometheusMetricsIndex) hostMetrics() []models.HostMetrics {
	result := make([]models.HostMetrics, 0, len(index.hosts))
	for host, metrics := range index.hosts {
		result = append(result, models.HostMetrics{
			Host:             host,
			RequestsTotal:    metrics.requestsTotal,
			RequestsInFlight: metrics.requestsInFlight,
			Status2xx:        metrics.status2xx,
			Status3xx:        metrics.status3xx,
			Status4xx:        metrics.status4xx,
			Status5xx:        metrics.status5xx,
			BytesIn:          metrics.bytesIn,
			BytesOut:         metrics.bytesOut,
		})
	}
	return result
}

func (index prometheusMetricsIndex) ruleMetrics(target ruleMetricTarget) gin.H {
	if target.domain == "" {
		return emptyRuleMetrics()
	}
	hosts := ruleMetricHosts(target)
	var result ruleMetricsAggregate
	for host := range hosts {
		result.add(index.httpHosts[host])
		result.add(index.httpBareHosts[host])
	}
	for host := range hosts {
		bareHost, _, err := net.SplitHostPort(host)
		if err != nil {
			continue
		}
		if _, ok := hosts[bareHost]; ok {
			result.subtract(index.httpHosts[host])
		}
	}
	return result.ruleMetrics(true)
}

func (index prometheusMetricsIndex) tcpRuleMetrics(upstreams []models.Upstream) gin.H {
	var result ruleMetricsAggregate
	for _, upstream := range upstreams {
		if upstream.Enabled {
			result.add(index.tcpUpstreams[fmt.Sprintf("%s:%d", upstream.Host, upstream.Port)])
		}
	}
	return result.ruleMetrics(false)
}

func (metrics *ruleMetricsAggregate) add(other *ruleMetricsAggregate) {
	if other == nil {
		return
	}
	metrics.requestsTotal += other.requestsTotal
	metrics.requestsInFlight += other.requestsInFlight
	metrics.status2xx += other.status2xx
	metrics.status3xx += other.status3xx
	metrics.status4xx += other.status4xx
	metrics.status5xx += other.status5xx
	metrics.bytesIn += other.bytesIn
	metrics.bytesOut += other.bytesOut
}

func (metrics *ruleMetricsAggregate) observeHTTP(name string, value float64) {
	switch {
	case strings.HasPrefix(name, "caddy_http_requests_total{"):
		metrics.requestsTotal += int64(value)
	case strings.HasPrefix(name, "caddy_http_request_duration_seconds_count{"):
		v := int64(value)
		switch bucket, _ := classifyStatusCode(extractLabel(name, "code")); bucket {
		case "status_2xx":
			metrics.status2xx += v
		case "status_3xx":
			metrics.status3xx += v
		case "status_4xx":
			metrics.status4xx += v
		case "status_5xx":
			metrics.status5xx += v
		}
	case strings.HasPrefix(name, "caddy_http_requests_in_flight{"):
		metrics.requestsInFlight += int64(value)
	case strings.Contains(name, "caddy_http_request_size_bytes_sum"):
		metrics.bytesIn += int64(value)
	case strings.Contains(name, "caddy_http_response_size_bytes_sum"):
		metrics.bytesOut += int64(value)
	}
}

func (metrics *ruleMetricsAggregate) subtract(other *ruleMetricsAggregate) {
	if other == nil {
		return
	}
	metrics.requestsTotal -= other.requestsTotal
	metrics.requestsInFlight -= other.requestsInFlight
	metrics.status2xx -= other.status2xx
	metrics.status3xx -= other.status3xx
	metrics.status4xx -= other.status4xx
	metrics.status5xx -= other.status5xx
	metrics.bytesIn -= other.bytesIn
	metrics.bytesOut -= other.bytesOut
}

func (metrics ruleMetricsAggregate) ruleMetrics(includeHealthy bool) gin.H {
	result := gin.H{
		"requests_total":     metrics.requestsTotal,
		"requests_in_flight": metrics.requestsInFlight,
		"status_2xx":         metrics.status2xx,
		"status_3xx":         metrics.status3xx,
		"status_4xx":         metrics.status4xx,
		"status_5xx":         metrics.status5xx,
		"bytes_in":           metrics.bytesIn,
		"bytes_out":          metrics.bytesOut,
	}
	if includeHealthy {
		result["healthy"] = false
	}
	return result
}

func ruleMetricHosts(target ruleMetricTarget) map[string]struct{} {
	hosts := make(map[string]struct{})
	for _, domain := range strings.Split(target.domain, ",") {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		hosts[domain] = struct{}{}
		if host, _, err := net.SplitHostPort(domain); err == nil {
			hosts[host] = struct{}{}
			continue
		}
		hosts[net.JoinHostPort(domain, strconv.Itoa(target.listenPort))] = struct{}{}
		if target.enableTLS {
			hosts[net.JoinHostPort(domain, "443")] = struct{}{}
		} else if target.listenPort == 80 || target.listenPort == 0 {
			hosts[net.JoinHostPort(domain, "80")] = struct{}{}
		}
	}
	return hosts
}

func (index *prometheusMetricsIndex) addSample(sample prometheusSample) {
	name, value := sample.name, sample.value
	var metric ruleMetricsAggregate
	metric.observeHTTP(name, value)
	index.global.add(&metric)
	if name == "go_goroutines" {
		index.goroutines = int64(value)
	}

	if host := extractLabel(name, "host"); host != "" {
		index.aggregateFor(index.hosts, host).add(&metric)
		index.aggregateFor(index.httpHosts, host).add(&metric)
		if bareHost, _, err := net.SplitHostPort(host); err == nil {
			index.aggregateFor(index.httpBareHosts, bareHost).add(&metric)
		}
	}

	if upstream := extractLabel(name, "upstream"); upstream != "" {
		aggregate := index.aggregateFor(index.tcpUpstreams, upstream)
		switch {
		case strings.HasPrefix(name, "caddy_layer4_proxy_connections_total{"),
			strings.HasPrefix(name, "caddy_layer4_proxy_connections_total "):
			aggregate.requestsTotal += int64(value)
		case strings.HasPrefix(name, "caddy_layer4_proxy_active_connections{"),
			strings.HasPrefix(name, "caddy_layer4_proxy_active_connections "):
			aggregate.requestsInFlight += int64(value)
		}
	}
}

func (index *prometheusMetricsIndex) aggregateFor(aggregates map[string]*ruleMetricsAggregate, key string) *ruleMetricsAggregate {
	aggregate := aggregates[key]
	if aggregate == nil {
		aggregate = &ruleMetricsAggregate{}
		aggregates[key] = aggregate
	}
	return aggregate
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
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return models.CaddyMetrics{}, err
	}
	return parsePrometheusMetricsFromSamples(samples), nil
}

func parsePrometheusMetricsFromSamples(samples []prometheusSample) models.CaddyMetrics {
	return buildPrometheusMetricsIndex(samples).globalMetrics()
}

func parseHostMetrics(body string) ([]models.HostMetrics, error) {
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	return parseHostMetricsFromSamples(samples), nil
}

func parseHostMetricsFromSamples(samples []prometheusSample) []models.HostMetrics {
	return buildPrometheusMetricsIndex(samples).hostMetrics()
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
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	return parseTCPRuleMetricsFromSamples(samples, upstreams), nil
}

func parseTCPRuleMetricsFromSamples(samples []prometheusSample, upstreams []models.Upstream) gin.H {
	return buildPrometheusMetricsIndex(samples).tcpRuleMetrics(upstreams)
}

func parseRuleMetricsFromPrometheus(body, domain string, listenPort int, protocol string, enableTLS bool) (gin.H, error) {
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	return parseRuleMetricsFromSamples(samples, ruleMetricTarget{domain: domain, listenPort: listenPort, enableTLS: enableTLS}), nil
}

func parseRuleMetricsFromSamples(samples []prometheusSample, target ruleMetricTarget) gin.H {
	return buildPrometheusMetricsIndex(samples).ruleMetrics(target)
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
		isAlphaNumeric := func(c byte) bool {
			return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		}
		if !isAlphaNumeric(part[0]) || !isAlphaNumeric(part[len(part)-1]) {
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
