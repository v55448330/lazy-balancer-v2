package handlers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
		return info, nil // 允许为空：是否强制要求证书材料由调用方按 tls_source 校验
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
		if !certPub.Equal(keyPub) {
			return nil, fmt.Errorf("certificate and private key do not match")
		}
	}

	return info, nil
}

// tlsCertSystemRoots 链完整性校验的系统根来源——var 供测试注入测试 CA 根池
// (与 systemMetricsReadFile 同款测试隔离约定)。
var tlsCertSystemRoots = x509.SystemCertPool

// tlsCertificateWarnings(CERT41-4)对手动 TLS 证书做「不阻断」质量检查:
//  1. 链完整性——系统根 + PEM 内中间证书 x509.Verify,unknown authority 类
//     失败说明链可能不完整(浏览器/严格客户端将握手失败);
//  2. 域名覆盖——domain 非空且证书 DNSNames/CN 不覆盖(含通配符语义,
//     规则多域名逐枚校验)时提示不匹配。
//
// 纯警告不阻断:配对/解析合法性由 validateTLSCertificate 硬校验负责,此处
// 解析失败防御性返回 nil;无警告返回 nil。keyPEM 仅用于配对解析(契约与
// rules.go 消费侧对称)。
func tlsCertificateWarnings(certPEM, keyPEM, domain string) []string {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil
	}
	var warnings []string
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if intermediate, perr := x509.ParseCertificate(der); perr == nil {
			intermediates.AddCert(intermediate)
		}
	}
	roots, rerr := tlsCertSystemRoots()
	if rerr == nil {
		if _, verr := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); verr != nil {
			var unknownAuthority x509.UnknownAuthorityError
			if errors.As(verr, &unknownAuthority) {
				warnings = append(warnings, "证书链可能不完整，部分客户端将握手失败")
			}
		}
	}
	for _, name := range strings.Split(domain, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !tlsCertCoversDomain(leaf, name) {
			warnings = append(warnings, "证书域名与规则域名不匹配")
			break
		}
	}
	return warnings
}

// tlsCertCoversDomain 判定证书是否覆盖域名:优先标准 SAN 校验(Go 内建通配
// 语义),无 SAN 的老证书回退 CN 精确/单段通配匹配。比较小写化。
func tlsCertCoversDomain(cert *x509.Certificate, domain string) bool {
	if err := cert.VerifyHostname(domain); err == nil {
		return true
	}
	return tlsWildcardMatch(strings.ToLower(cert.Subject.CommonName), strings.ToLower(domain))
}

// tlsWildcardMatch 单段通配语义:*.example.com 覆盖恰好一级子域,不覆盖裸域
// 与二级以上子域;非通配模式精确匹配。
func tlsWildcardMatch(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == domain
	}
	suffix := pattern[1:]
	if !strings.HasSuffix(domain, suffix) {
		return false
	}
	label := domain[:len(domain)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
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
	ruleID     string // 2026-09-15:caddy_id 直接匹配(lb_rule_metrics 优先)
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
	// blockedByRule 是各规则安全拦截计数(lb_security_blocked_counter 插件,
	// lazybalancer_security_blocked_total{rule}——与 status_4xx 同源同抓取)。
	blockedByRule map[string]int64
	// ruleMetricsByRule 是各规则全量流量指标(lb_rule_metrics 插件,
	// 2026-09-15 用户裁定:caddy_id 直接匹配替代域名/host 匹配)。
	ruleMetricsByRule map[string]*ruleMetricsAggregate
}

func buildPrometheusMetricsIndex(samples []prometheusSample) prometheusMetricsIndex {
	index := prometheusMetricsIndex{
		hosts:             make(map[string]*ruleMetricsAggregate),
		httpHosts:         make(map[string]*ruleMetricsAggregate),
		httpBareHosts:     make(map[string]*ruleMetricsAggregate),
		tcpUpstreams:      make(map[string]*ruleMetricsAggregate),
		blockedByRule:     make(map[string]int64),
		ruleMetricsByRule: make(map[string]*ruleMetricsAggregate),
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
	// 2026-09-15 用户裁定:caddy_id 直接匹配(lb_rule_metrics)——优先;
	// 域名匹配兜底(未升级插件的形态/过渡期)。
	if target.ruleID != "" {
		// SR30-1(P4,第 30 轮审计):插件已升级(ruleMetricsByRule 全局非空)
		// 时本规则缺序列=零流量,返回空而非域名兜底(兜底在同裸域名多端口
		// 拓扑下跨规则串流量;兜底仅在插件未升级(全局空)时启用)。
		if len(index.ruleMetricsByRule) > 0 {
			if agg := index.ruleMetricsByRule[target.ruleID]; agg != nil {
				return agg.ruleMetrics(true)
			}
			return emptyRuleMetrics() // 本规则零流量(插件已升级,无序列)
		}
		if agg := index.ruleMetricsByRule[target.ruleID]; agg != nil {
			return agg.ruleMetrics(true)
		}
	}
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
	addresses := make(map[string]struct{}, len(upstreams))
	for _, upstream := range upstreams {
		if upstream.Enabled {
			addresses[net.JoinHostPort(upstream.Host, strconv.Itoa(upstream.Port))] = struct{}{}
		}
	}
	for address := range addresses {
		result.add(index.tcpUpstreams[address])
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
		switch bucket := classifyStatusCode(extractLabel(name, "code")); bucket {
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

	if rule := extractLabel(name, "rule"); rule != "" {
		if strings.HasPrefix(name, "lazybalancer_security_blocked_total{") {
			// SECLB30-2(P5,第 30 轮审计):blocked-only 样本不建 ruleMetricsByRule
			// 空聚合——否则过渡形态(插件未升级)下 ruleMetrics early return 空,
			// 架空域名兜底。blocked 仅记 blockedByRule。
			index.blockedByRule[rule] += int64(value)
			return
		}
		// lb_rule_metrics 全量流量指标归集(2026-09-15)
		agg := index.aggregateFor(index.ruleMetricsByRule, rule)
		switch {
		case strings.HasPrefix(name, "lazybalancer_requests_total{"):
			agg.requestsTotal += int64(value)
		case strings.HasPrefix(name, "lazybalancer_requests_in_flight{"):
			agg.requestsInFlight = int64(value)
		case strings.HasPrefix(name, "lazybalancer_request_status_total{"):
			switch extractLabel(name, "class") {
			case "2xx":
				agg.status2xx += int64(value)
			case "3xx":
				agg.status3xx += int64(value)
			case "4xx":
				agg.status4xx += int64(value)
			case "5xx":
				agg.status5xx += int64(value)
			}
		case strings.HasPrefix(name, "lazybalancer_bytes_total{"):
			switch extractLabel(name, "direction") {
			case "in":
				agg.bytesIn += int64(value)
			case "out":
				agg.bytesOut += int64(value)
			}
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

// extractLabel(LB40-6 精确键匹配):label 键必须以标签边界(逗号后/花括号后/
// 字符串起始)出现——子串匹配会把 x_host 误归集到 host,指标归因错乱。
func extractLabel(metricName string, label string) string {
	start := -1
	for _, boundary := range []string{"," + label + `="`, "{" + label + `="`} {
		if idx := strings.Index(metricName, boundary); idx >= 0 {
			start = idx + len(boundary)
			break
		}
	}
	if start < 0 && strings.HasPrefix(metricName, label+`="`) {
		start = len(label) + 2
	}
	if start < 0 {
		return ""
	}
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

// deductBlockedFrom4xx 从 4xx 计数扣除安全拦截并钳制 ≥0(第 28.6 轮 F6:
// Dashboard 与 GetRuleMetrics 两处逐字复制提为共享函数)。
func deductBlockedFrom4xx(metrics gin.H, blocked int64) {
	if s4, ok := metrics["status_4xx"].(int64); ok && blocked > 0 {
		if s4-blocked >= 0 {
			metrics["status_4xx"] = s4 - blocked
		} else {
			metrics["status_4xx"] = int64(0)
		}
	}
}

func parseRuleMetricsFromPrometheus(body, domain string, listenPort int, enableTLS bool, ruleCaddyID ...string) (gin.H, error) { // SR30-3:protocol 死参移除
	samples, err := parsePrometheusSamples(body)
	if err != nil {
		return nil, err
	}
	index := buildPrometheusMetricsIndex(samples)
	target := ruleMetricTarget{domain: domain, listenPort: listenPort, enableTLS: enableTLS}
	if len(ruleCaddyID) > 0 && ruleCaddyID[0] != "" {
		target.ruleID = ruleCaddyID[0]
	}
	result := index.ruleMetrics(target)
	// P4-2(第 28.5 轮审计):GET /metrics/rule/:caddy_id 与仪表盘同口径——
	// 加 blocked 并扣 4xx(钳制 ≥0);ruleCaddyID 为空时(TCP)跳过。
	if len(ruleCaddyID) > 0 && ruleCaddyID[0] != "" {
		blocked := index.blockedByRule[ruleCaddyID[0]]
		result["blocked"] = blocked
		deductBlockedFrom4xx(result, blocked)
	}
	return result, nil
}

func parseRuleMetricsFromSamples(samples []prometheusSample, target ruleMetricTarget) gin.H {
	return buildPrometheusMetricsIndex(samples).ruleMetrics(target)
}

func classifyStatusCode(code string) string {
	if code == "" {
		return ""
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
		return ""
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

	// 基础域名/主机名校验：字母、数字、连字符；标签首尾须为字母或数字（RFC 1123）。
	// 额外放行下划线 '_'：Docker Compose 服务名允许下划线（内嵌 DNS 可直接解析
	// my_backend 这类名称）。RFC 主机名确实禁止下划线，但此处校验的是上游地址，
	// 通常是容器服务名而非公网 DNS 主机名，故按 Docker 命名规则放宽。
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
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				valid = false
				break
			}
		}
		if !valid {
			break
		}
		if !isAlnumASCII(part[0]) || !isAlnumASCII(part[len(part)-1]) {
			valid = false
			break
		}
	}

	return valid
}

func isAlnumASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
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
			// SYS20-P5-6：删 c=='.'——part 来自 Split(domain, ".") 的产物，恒不含 '.'。
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
