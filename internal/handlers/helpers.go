package handlers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var startTime = time.Now()

var systemMetricsReadFile = os.ReadFile

// systemMetricsCommandTimeout 外部命令（df/netstat）单次执行超时上限：宿主
// 文件系统/网络栈卡住时，读路径不得无上限阻塞（老实现无 context，命令卡死即
// 等待者全部挂起）。
var systemMetricsCommandTimeout = 2 * time.Second

var systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
	// -P（POSIX 输出）保证「一行一文件系统」：非 POSIX 格式下超长设备名会
	// 独占一行，固定取第 2 行就把设备名当数字列，磁盘分项整体降级。
	return exec.CommandContext(ctx, "df", "-P", "-B1", "/")
}

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

// systemSampleNegativeTTL 外部命令失败的短负缓存窗口：df/netstat 挂起时，
// 每个轮询周期都重跑命令并等满超时（singleflight 只合并并发、不合并串行
// 轮询），读路径持续高延迟。失败短缓存到期即重试，与指标端点负缓存同型。
var systemSampleNegativeTTL = 2 * time.Second

var diskUsageCache struct {
	sync.Mutex
	total     uint64
	used      uint64
	expiresAt time.Time
	// 失败负缓存（窗口内直接返回同一错误，不再起子进程）。
	negativeUntil time.Time
	negativeErr   error
}

var connectionStatsCache struct {
	sync.Mutex
	stats     models.ConnectionStats
	expiresAt time.Time
	// 失败负缓存（同 diskUsageCache）。
	negativeUntil time.Time
	negativeErr   error
}

type CertificateInfo struct {
	Valid           bool   `json:"valid"`
	Domain          string `json:"domain"`
	Issuer          string `json:"issuer"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	Warning         string `json:"warning,omitempty"`
	// 原 Error 字段在本包零赋值点（恒空契约噪音），已删除
	// ——解析失败走 4xx message，前端自备错误通道。
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

	// Extract issuer（与证书卡/任务列表共用同一显示口径）
	issuer := services.CertificateIssuerDisplay(x509Cert)

	info.Valid = true
	info.Domain = domain
	info.Issuer = issuer
	// x509 时间为 UTC，直出会比配置时区少一天
	// （如 Asia/Shanghai 凌晨到期的证书显示前一天）——按配置时区渲染，
	// 与规则证书卡 formatDate 口径对齐。
	info.NotBefore = x509Cert.NotBefore.In(services.CurrentLocation()).Format("2006-01-02")
	info.NotAfter = x509Cert.NotAfter.In(services.CurrentLocation()).Format("2006-01-02")
	info.DaysUntilExpiry = services.CertDaysRemaining(x509Cert.NotAfter, time.Now())

	// Check if certificate is expired - warning only
	if time.Now().After(x509Cert.NotAfter) {
		info.Warning = fmt.Sprintf("证书已过期 (过期时间: %s)", x509Cert.NotAfter.In(services.CurrentLocation()).Format("2006-01-02"))
	}

	// Check if certificate is not yet valid - warning only
	if time.Now().Before(x509Cert.NotBefore) {
		info.Warning = fmt.Sprintf("证书尚未生效 (生效时间: %s)", x509Cert.NotBefore.In(services.CurrentLocation()).Format("2006-01-02"))
	}

	// 公钥等价比较：原实现按 *rsa.PublicKey/*ecdsa.PublicKey
	// 白名单分型——Ed25519（内部 CA/自签常用，tls.X509KeyPair 与 Caddy 均支持）
	// 被硬拒 400，面板支持面比引擎更窄。改为 crypto.Signer.Public() + PKIX 字节
	// 比较（同类型同参数编码恒等，跨类型/不同密钥恒不等），保留「类型不可用」
	// 与「不配对」两类错误文案。X509KeyPair 已先行拦截不配对形态，本段是引擎
	// 接受面内的纵深校验。
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type")
	}
	certKeyDER, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("unsupported public key type in certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("unsupported public key type in private key: %w", err)
	}
	if !bytes.Equal(certKeyDER, keyDER) {
		return nil, fmt.Errorf("certificate and private key do not match")
	}

	return info, nil
}

// tlsCertSystemRoots 链完整性校验的系统根来源——var 供测试注入测试 CA 根池
// (与 systemMetricsReadFile 同款测试隔离约定)。
var tlsCertSystemRoots = x509.SystemCertPool

// tlsCertificateWarnings对手动 TLS 证书做「不阻断」质量检查
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
	// 有效期同样以非阻断警告呈现——过期/未生效的自
	// 手动证书允许先落库后轮换（管理面板 TLS 上传仍硬拒），但保存/导入审计
	// 与响应 warnings 必须显式可见。此前 parseTLSCertificate 已算出 Warning，
	// 规则保存路径却丢弃未用。
	now := time.Now()
	if now.After(leaf.NotAfter) {
		warnings = append(warnings, "证书已过期 (过期时间: "+leaf.NotAfter.In(services.CurrentLocation()).Format("2006-01-02")+")")
	} else if now.Before(leaf.NotBefore) {
		warnings = append(warnings, "证书尚未生效 (生效时间: "+leaf.NotBefore.In(services.CurrentLocation()).Format("2006-01-02")+")")
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
// 语义);仅当证书完全没有 SAN（DNS/IP/Email/URI 均为空）时才回退 CN 精确/
// 单段通配匹配。有 SAN 的现代证书以 SAN 为准（RFC 6125），CN 回退
// 会抑制「SAN 不覆盖但 CN 恰好覆盖」的域名不匹配警告，而客户端仍握手失败。
// 比较小写化。
func tlsCertCoversDomain(cert *x509.Certificate, domain string) bool {
	if err := cert.VerifyHostname(domain); err == nil {
		return true
	}
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		return false
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

// dialOutboundIP 探测本机出口 IP（UDP dial 不写包，仅借路由决策读本地地址）。
// 探测失败或地址类型意外（原 unchecked type assertion）
// 回退 127.0.0.1 并返回 ok=false——单源实现，cluster_mode.go（需 ok 位做
// 审计点名）与系统信息展示共用。
//
// dialOutboundIPFn 是可注入的探测缝：被保护的失败分支（无默认路由的容器里
// ip_address 置空而非回显 127.0.0.1）只在该环境发生，而开发机/CI 恒有默认
// 路由——不注入就永不被自动化覆盖。生产恒为 netDialOutboundIP。
var dialOutboundIPFn = netDialOutboundIP

func dialOutboundIP() (string, bool) { return dialOutboundIPFn() }

func netDialOutboundIP() (string, bool) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1", false
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "127.0.0.1", false
	}
	return localAddr.IP.String(), true
}

// getOutboundIP 返回本机出口 IP；探测失败（无默认路由/受限网络）返回空串并
// 留痕——不得把回环地址当机器地址展示（排障窗口会把人引向错误方向）。
func getOutboundIP() string {
	ip, ok := dialOutboundIP()
	if !ok {
		services.LogConfigReadFailure("system-outbound-ip", errors.New("出口 IP 探测失败（无默认路由/受限网络），ip_address 置空"))
		return ""
	}
	services.LogConfigReadRecovered("system-outbound-ip")
	return ip
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
	// 与运行期 df/netstat 同口径：包初始化路径同样不得无界阻塞（外部二进制
	// 损坏/ PATH 指向阻塞脚本时，启动会在日志/端口就绪前挂死）。
	ctx, cancel := context.WithTimeout(context.Background(), systemMetricsCommandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).Output()
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
		// IPv4 优先（页面展示口径不变）；接口只有 IPv6（IPv6-only 主机/容器）
		// 时回落到全局单播 IPv6——否则该主机网络地址列表恒空。link-local
		// (fe80::/10) 不可路由，不展示。
		if ip := preferredInterfaceIP(addrs); ip != nil {
			ips[iface.Name] = ip.String()
		}
	}
	return ips
}

// preferredInterfaceIP 从接口地址中选出展示用地址：IPv4 优先；无 IPv4 时取
// 第一个非 link-local/未指定的 IPv6（IPv6-only 主机不再显示为空）。
func preferredInterfaceIP(addrs []net.Addr) net.IP {
	var ipv4, ipv6 net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			if ipv4 == nil {
				ipv4 = v4
			}
			continue
		}
		if ipv6 == nil && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			ipv6 = ip
		}
	}
	if ipv4 != nil {
		return ipv4
	}
	return ipv6
}

func loadCaddyVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), systemMetricsCommandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "caddy", "version").Output()
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

// getSystemMetrics 采集内存/磁盘/CPU——分项降级：任一项失败只把该项从结果中
// 移除并在 Degraded 中披露（留痕走状态转换单源），不再「全或无」（旧实现
// CPU 单点故障即让整卡内存/磁盘数据消失，排障窗口反而看不到健康维度）。
// 三项全部失败才返回错误（此时确实无可展示数据）。
func getSystemMetrics() (models.SystemMetrics, error) {
	failures := map[string]error{}
	order := []string{"memory", "disk", "cpu", "pids"}

	memoryTotal, memoryUsed := uint64(0), uint64(0)
	if vmStat, err := systemMetricsReadFile("/proc/meminfo"); err != nil {
		failures["memory"] = fmt.Errorf("读取系统内存指标失败: %w", err)
	} else if total, used, err := parseMemInfo(string(vmStat)); err != nil {
		failures["memory"] = err
	} else {
		memoryTotal, memoryUsed = total, used
	}

	diskTotal, diskUsed := uint64(0), uint64(0)
	if total, used, err := getCachedDiskUsage(time.Now()); err != nil {
		failures["disk"] = err
	} else {
		diskTotal, diskUsed = total, used
	}

	cpuPercent := float64(0)
	if percent, err := getCPUPercent(); err != nil {
		failures["cpu"] = fmt.Errorf("读取系统 CPU 指标失败: %w", err)
	} else {
		cpuPercent = percent
	}

	// 进程/线程配额：cgroup pids 是 fork 失败的直接原因层；ulimit -u
	// （RLIMIT_NPROC）作为二级提示，读取失败不影响 pids 展示。
	pidsCurrent, pidsMax, nprocLimit, pidsErr := readPidsUsage()
	if pidsErr != nil {
		failures["pids"] = pidsErr
	}

	// 分项留痕按状态转换去重（面板 5s 一轮轮询，不得每轮刷一条 warn）。
	var degraded []string
	var joined []error
	for _, part := range order {
		if err, failed := failures[part]; failed {
			degraded = append(degraded, part)
			joined = append(joined, err)
			services.LogConfigReadFailure("system-metrics-"+part, err)
			continue
		}
		services.LogConfigReadRecovered("system-metrics-" + part)
	}

	var memPercent float64
	if memoryTotal > 0 {
		memPercent = float64(memoryUsed) / float64(memoryTotal) * 100
	}
	var diskPercent float64
	if diskTotal > 0 {
		diskPercent = float64(diskUsed) / float64(diskTotal) * 100
	}
	// pids.max 为 "max"（无限）时 PidsMax=0：没有可展示的比例，保持 0。
	var pidsPercent float64
	if pidsMax > 0 {
		pidsPercent = float64(pidsCurrent) / float64(pidsMax) * 100
	}

	metrics := models.SystemMetrics{
		CPUPercent:    cpuPercent,
		MemoryTotal:   memoryTotal,
		MemoryUsed:    memoryUsed,
		MemoryPercent: memPercent,
		DiskTotal:     diskTotal,
		DiskUsed:      diskUsed,
		DiskPercent:   diskPercent,
		PidsCurrent:   pidsCurrent,
		PidsMax:       pidsMax,
		NprocLimit:    nprocLimit,
		PidsPercent:   pidsPercent,
		Degraded:      degraded,
	}
	if len(joined) == len(order) {
		return metrics, errors.Join(joined...)
	}
	return metrics, nil
}

// readPidsUsage 读取 cgroup pids 用量/上限（cgroup v2 优先，v1 回落）与
// RLIMIT_NPROC 软限。cgroup v2 与 v1 的落点不同：v2 在 /sys/fs/cgroup 根，
// v1 在 /sys/fs/cgroup/pids 子目录。读取失败按分项降级（pids），不影响
// 内存/磁盘/CPU 展示。
func readPidsUsage() (current, max, nproc int, err error) {
	current, max, err = readCgroupPids("/sys/fs/cgroup")
	if err != nil {
		current, max, err = readCgroupPids("/sys/fs/cgroup/pids")
	}
	if err != nil {
		return 0, 0, 0, fmt.Errorf("读取进程配额失败: %w", err)
	}
	return current, max, readNprocLimit(), nil
}

func readCgroupPids(dir string) (current, max int, err error) {
	currentRaw, err := systemMetricsReadFile(dir + "/pids.current")
	if err != nil {
		return 0, 0, err
	}
	maxRaw, err := systemMetricsReadFile(dir + "/pids.max")
	if err != nil {
		return 0, 0, err
	}
	if current, err = parsePidsCount(string(currentRaw)); err != nil {
		return 0, 0, err
	}
	if max, err = parsePidsLimit(string(maxRaw)); err != nil {
		return 0, 0, err
	}
	return current, max, nil
}

func parsePidsCount(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("pids.current 无效: %q", value)
	}
	return n, nil
}

// parsePidsLimit：cgroup v2 未设上限时文件内容为字面 "max"，统一归一为 0
// （消费方按「不限额」处理，不参与百分比计算）。
func parsePidsLimit(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "max" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("pids.max 无效: %q", value)
	}
	return n, nil
}

// readNprocLimit 解析 RLIMIT_NPROC 软限（ulimit -u）。按行首 "Max processes"
// 取第二列；"unlimited"/读取失败统一返回 0（二级提示，缺失不影响 pids 主值）。
func readNprocLimit() int {
	raw, err := systemMetricsReadFile("/proc/self/limits")
	if err != nil {
		return 0
	}
	return parseNprocLimit(string(raw))
}

func parseNprocLimit(raw string) int {
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "Max processes") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] == "unlimited" {
			return 0
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	return 0
}

// diskUsageGroup / connectionStatsGroup 合并并发刷新：同一刷新窗口内并发请求
// 等待同一趟外部命令，不各跑一遍。
var (
	diskUsageGroup       singleflight.Group
	connectionStatsGroup singleflight.Group
)

func getCachedDiskUsage(now time.Time) (uint64, uint64, error) {
	diskUsageCache.Lock()
	if now.Before(diskUsageCache.expiresAt) {
		total, used := diskUsageCache.total, diskUsageCache.used
		diskUsageCache.Unlock()
		return total, used, nil
	}
	if now.Before(diskUsageCache.negativeUntil) {
		err := diskUsageCache.negativeErr
		diskUsageCache.Unlock()
		return 0, 0, err
	}
	diskUsageCache.Unlock()
	// 外部命令在锁外执行（旧实现持锁 Output()：df 卡顿时连命中缓存的请求都
	// 被串行阻塞），并发 miss 经 single-flight 合并。
	value, err, _ := diskUsageGroup.Do("disk-usage", func() (any, error) {
		diskUsageCache.Lock()
		if time.Now().Before(diskUsageCache.expiresAt) {
			total, used := diskUsageCache.total, diskUsageCache.used
			diskUsageCache.Unlock()
			return [2]uint64{total, used}, nil
		}
		if time.Now().Before(diskUsageCache.negativeUntil) {
			err := diskUsageCache.negativeErr
			diskUsageCache.Unlock()
			return [2]uint64{}, err
		}
		diskUsageCache.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), systemMetricsCommandTimeout)
		defer cancel()
		dfOutput, err := systemMetricsDFCommand(ctx).Output()
		if err != nil {
			return [2]uint64{}, storeDiskUsageFailure(fmt.Errorf("读取系统磁盘指标失败: %w", err))
		}
		total, used, ok := parseDFOutput(string(dfOutput))
		if !ok {
			return [2]uint64{}, storeDiskUsageFailure(fmt.Errorf("解析系统磁盘指标失败"))
		}
		diskUsageCache.Lock()
		diskUsageCache.total, diskUsageCache.used = total, used
		diskUsageCache.expiresAt = time.Now().Add(systemSampleTTL)
		diskUsageCache.negativeUntil, diskUsageCache.negativeErr = time.Time{}, nil
		diskUsageCache.Unlock()
		return [2]uint64{total, used}, nil
	})
	if err != nil {
		return 0, 0, err
	}
	values, _ := value.([2]uint64)
	return values[0], values[1], nil
}

// storeDiskUsageFailure 写入失败短负缓存并原样返回错误（singleflight 的
// 等待者也必须拿到同一错误）。
func storeDiskUsageFailure(err error) error {
	diskUsageCache.Lock()
	diskUsageCache.negativeUntil = time.Now().Add(systemSampleNegativeTTL)
	diskUsageCache.negativeErr = err
	diskUsageCache.Unlock()
	return err
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
	total, hasTotal := values["MemTotal:"]
	available, hasAvailable := values["MemAvailable:"]
	if !hasTotal || total == 0 {
		return 0, 0, fmt.Errorf("缺少 MemTotal，无法计算内存使用")
	}
	// MemAvailable 缺失（内核 < 3.14 / 裁剪过的 meminfo）时必须报错走分项
	// 降级——按「可用=0」计算会输出恒 100% 使用率的伪造数据。
	if !hasAvailable {
		return 0, 0, fmt.Errorf("缺少 MemAvailable，无法计算内存使用")
	}
	if available > total {
		return 0, 0, fmt.Errorf("MemAvailable 大于 MemTotal，内存指标无效")
	}
	return total, total - available, nil
}

// cpuSampleWindow / netSampleWindow 采样窗口：窗口内的读取共享同一次采样与
// 同一速率（速率=固定窗口差分）。旧实现以「上一次 HTTP 请求」为基线——多页签
// 同时轮询或轮询周期变化时，A 客户端的请求会把 B 的基线拉近，算出尖峰或归零
// 的假速率，不能作运维判据。窗口值 ≤0 = 不缓存（测试隔离用）。
var (
	cpuSampleWindow = time.Second
	netSampleWindow = time.Second
)

func getCPUPercent() (float64, error) {
	lastCPUStats.mu.Lock()
	defer lastCPUStats.mu.Unlock()

	now := time.Now()
	if lastCPUStats.hasValue && cpuSampleWindow > 0 && now.Sub(lastCPUStats.sampledAt) < cpuSampleWindow {
		return lastCPUStats.percent, nil
	}

	stat, err := systemMetricsReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	current, ok := parseCPUSnapshot(string(stat))
	if !ok {
		return 0, fmt.Errorf("解析 /proc/stat 失败")
	}
	previous := lastCPUStats.snapshot
	lastCPUStats.snapshot = current
	lastCPUStats.sampledAt = now
	lastCPUStats.hasValue = true
	lastCPUStats.percent = 0
	if previous.total == 0 {
		return 0, nil
	}
	if current.total < previous.total || current.idle < previous.idle {
		return 0, nil
	}
	totalDelta := current.total - previous.total
	idleDelta := current.idle - previous.idle
	if idleDelta > totalDelta {
		// 错误样本不得留在采样缓存里冒充成功：本轮已写入的 hasValue 会让
		// 紧随其后的 1s 窗口内请求直接拿到 0,nil（Degraded 不含 cpu，面板
		// 会显示为「负载骤降」）。置失效让下一个请求立即重采样。
		lastCPUStats.hasValue = false
		return 0, fmt.Errorf("CPU 空闲计数器增量无效")
	}
	if totalDelta == 0 {
		return 0, nil
	}
	lastCPUStats.percent = float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	return lastCPUStats.percent, nil
}

var lastNetStats struct {
	mu       sync.Mutex
	bytesIn  uint64
	bytesOut uint64
	iface    string // 基线所属统计口径身份：默认路由接口名，或无默认路由时的聚合口径串；口径变化后新旧计数器不可比
	time     time.Time
	rateIn   int64
	rateOut  int64
	hasValue bool
}

func getRealtimeTraffic() (models.RealtimeTraffic, error) {
	lastNetStats.mu.Lock()
	defer lastNetStats.mu.Unlock()

	now := time.Now()
	if lastNetStats.hasValue && netSampleWindow > 0 && now.Sub(lastNetStats.time) < netSampleWindow {
		return models.RealtimeTraffic{BytesIn: lastNetStats.rateIn, BytesOut: lastNetStats.rateOut}, nil
	}

	netStat, err := systemMetricsReadFile("/proc/net/dev")
	if err != nil {
		return models.RealtimeTraffic{}, err
	}

	totalBytesIn, totalBytesOut, iface, err := parseNetDevTotals(string(netStat))
	if err != nil {
		return models.RealtimeTraffic{}, err
	}

	var rateIn, rateOut int64

	if !lastNetStats.time.IsZero() {
		elapsed := now.Sub(lastNetStats.time).Seconds()
		// 统计口径变化后新旧计数器不可比：默认路由切换（多网卡/容器重建/
		// 策略路由变更）、默认路由消失退回物理网卡聚合、聚合成员集变化。任一
		// 方向直接差分会把「新口径的历史总流量」当成本轮速率（数量级假峰值），
		// 身份串不等即重建基线（本轮速率 0）。
		ifaceChanged := lastNetStats.iface != iface
		countersRolledBack := totalBytesIn < lastNetStats.bytesIn || totalBytesOut < lastNetStats.bytesOut
		if ifaceChanged {
			services.Logf("info", "实时流量基线重建：统计口径 %s → %s（新旧计数器不可比，本轮速率归零）", describeNetIdentity(lastNetStats.iface), describeNetIdentity(iface))
		}
		if elapsed > 0 && !countersRolledBack && !ifaceChanged {
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
	lastNetStats.iface = iface
	lastNetStats.time = now
	lastNetStats.rateIn = rateIn
	lastNetStats.rateOut = rateOut
	lastNetStats.hasValue = true

	return models.RealtimeTraffic{
		BytesIn:  rateIn,
		BytesOut: rateOut,
	}, nil
}

// primeSystemSamplers 在包初始化时建立 CPU/实时流量基线：首个采集不再把
// 「尚无基线」静默显示为 0%（进程重启后首屏尤其明显——用户无法区分真的空闲
// 与仍在建基线）。基线读取失败（非 Linux/无 /proc）时保持未初始化，由首个
// 请求按原路径建基线。
func primeSystemSamplers() {
	now := time.Now()
	if stat, err := systemMetricsReadFile("/proc/stat"); err == nil {
		if snapshot, ok := parseCPUSnapshot(string(stat)); ok {
			lastCPUStats.mu.Lock()
			lastCPUStats.snapshot = snapshot
			lastCPUStats.sampledAt = now
			lastCPUStats.hasValue = true
			lastCPUStats.mu.Unlock()
		}
	}
	if netStat, err := systemMetricsReadFile("/proc/net/dev"); err == nil {
		if bytesIn, bytesOut, iface, err := parseNetDevTotals(string(netStat)); err == nil {
			lastNetStats.mu.Lock()
			lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = bytesIn, bytesOut, iface
			lastNetStats.time = now
			lastNetStats.hasValue = true
			lastNetStats.mu.Unlock()
		}
	}
}

func init() {
	primeSystemSamplers()
}

// netDevAggregateIdentityPrefix 标记「无默认路由时的物理网卡聚合」统计口径。
// 聚合口径同样需要可比较的身份：成员集变化（网卡下线/上线）会改变聚合总量
// 的含义，身份串随之变化才能触发基线重建。
const netDevAggregateIdentityPrefix = "aggregate:"

// describeNetIdentity 把统计口径身份串转成日志可读描述：默认路由接口名直出，
// 聚合口径列出参与聚合的物理网卡，尚无基线时如实标注。
func describeNetIdentity(identity string) string {
	if identity == "" {
		return "未知口径"
	}
	if names, ok := strings.CutPrefix(identity, netDevAggregateIdentityPrefix); ok {
		return "物理网卡聚合(" + names + ")"
	}
	return identity
}

// parseNetDevTotals 返回默认路由出口接口的累计收发字节与统计口径身份（身份
// 供读侧判定「基线是否仍属同一口径」）。无默认路由时统计物理类接口聚合并返回
// 显式聚合身份串（成员集有序拼接——行序抖动不得被当成口径变化）。
func parseNetDevTotals(input string) (uint64, uint64, string, error) {
	route, err := systemMetricsReadFile("/proc/net/route")
	if err != nil {
		return 0, 0, "", fmt.Errorf("读取默认路由失败: %w", err)
	}
	if defaultInterface, err := parseDefaultRouteInterface(string(route)); err == nil {
		for _, line := range strings.Split(input, "\n") {
			name, counters, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(name) != defaultInterface {
				continue
			}
			fields := strings.Fields(counters)
			if len(fields) < 16 {
				return 0, 0, "", fmt.Errorf("解析网卡 %s 流量失败: 计数器字段不足", strings.TrimSpace(name))
			}
			bytesIn, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				return 0, 0, "", fmt.Errorf("解析网卡 %s 接收流量失败: %w", strings.TrimSpace(name), err)
			}
			bytesOut, err := strconv.ParseUint(fields[8], 10, 64)
			if err != nil {
				return 0, 0, "", fmt.Errorf("解析网卡 %s 发送流量失败: %w", strings.TrimSpace(name), err)
			}
			return bytesIn, bytesOut, defaultInterface, nil
		}
		return 0, 0, "", fmt.Errorf("默认路由接口 %s 不存在于 /proc/net/dev", defaultInterface)
	}
	// 无默认路由（如容器 netns 只有子网路由）：统计物理类接口，排除 lo 与
	// 会重复计数的虚拟叠加层（veth/docker 网桥/br-*）
	var totalIn, totalOut uint64
	var members []string
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
		members = append(members, iface)
	}
	if len(members) == 0 {
		return 0, 0, "", fmt.Errorf("无法确定默认路由出口接口且无可用物理网卡")
	}
	sort.Strings(members)
	return totalIn, totalOut, netDevAggregateIdentityPrefix + strings.Join(members, ","), nil
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
	mu        sync.Mutex
	snapshot  cpuSnapshot
	percent   float64
	sampledAt time.Time
	hasValue  bool
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
	// 以挂载点列定位数据行（`df /` 的目标挂载点恒为 "/"）：非 POSIX 格式下
	// 超长设备名会独占一行，固定取第 2 行会把设备名当数字列；而只按「数字可
	// 解析」倒推，折行后的数字行会少一列（设备名在上一行）导致列错位。POSIX
	// (-P) 形态恒 6 列，折行形态为 5 列，按列数选择 total/used 下标。
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[len(fields)-1] != "/" {
			continue
		}
		totalIndex, usedIndex := 1, 2
		if len(fields) < 6 {
			totalIndex, usedIndex = 0, 1
		}
		total, err := strconv.ParseUint(fields[totalIndex], 10, 64)
		if err != nil {
			continue
		}
		used, err := strconv.ParseUint(fields[usedIndex], 10, 64)
		if err != nil {
			continue
		}
		return total, used, true
	}
	return 0, 0, false
}

func getConnectionStats() (models.ConnectionStats, error) {
	now := time.Now()
	connectionStatsCache.Lock()
	if now.Before(connectionStatsCache.expiresAt) {
		stats := connectionStatsCache.stats
		connectionStatsCache.Unlock()
		return stats, nil
	}
	if now.Before(connectionStatsCache.negativeUntil) {
		err := connectionStatsCache.negativeErr
		connectionStatsCache.Unlock()
		return models.ConnectionStats{}, err
	}
	connectionStatsCache.Unlock()
	// 外部命令在锁外执行且带超时、并发合并（旧实现持锁无超时执行
	// netstat：宿主网络栈卡住时所有并发请求串行挂起）。
	value, err, _ := connectionStatsGroup.Do("connection-stats", func() (any, error) {
		connectionStatsCache.Lock()
		if time.Now().Before(connectionStatsCache.expiresAt) {
			stats := connectionStatsCache.stats
			connectionStatsCache.Unlock()
			return stats, nil
		}
		if time.Now().Before(connectionStatsCache.negativeUntil) {
			err := connectionStatsCache.negativeErr
			connectionStatsCache.Unlock()
			return models.ConnectionStats{}, err
		}
		connectionStatsCache.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), systemMetricsCommandTimeout)
		defer cancel()
		output, err := netstatCommand(ctx).Output()
		if err != nil {
			failure := fmt.Errorf("execute netstat -tan: %w", err)
			connectionStatsCache.Lock()
			connectionStatsCache.negativeUntil = time.Now().Add(systemSampleNegativeTTL)
			connectionStatsCache.negativeErr = failure
			connectionStatsCache.Unlock()
			return models.ConnectionStats{}, failure
		}
		stats := parseConnectionStats(string(output))
		connectionStatsCache.Lock()
		connectionStatsCache.stats = stats
		connectionStatsCache.expiresAt = time.Now().Add(systemSampleTTL)
		connectionStatsCache.negativeUntil, connectionStatsCache.negativeErr = time.Time{}, nil
		connectionStatsCache.Unlock()
		return stats, nil
	})
	if err != nil {
		return models.ConnectionStats{}, err
	}
	stats, _ := value.(models.ConnectionStats)
	return stats, nil
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

var netstatCommand = func(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "netstat", "-tan")
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
		// 插件已升级(ruleMetricsByRule 全局非空)
		// 时本规则缺序列=零流量,返回空而非域名兜底(兜底在同裸域名多端口
		// 拓扑下跨规则串流量;兜底仅在插件未升级(全局空)时启用)。
		if len(index.ruleMetricsByRule) > 0 {
			if agg := index.ruleMetricsByRule[target.ruleID]; agg != nil {
				return agg.ruleMetrics()
			}
			return emptyRuleMetrics() // 本规则零流量(插件已升级,无序列)
		}
		// 插件未升级（map 全局为空）：无 rule 级序列可查，落空返回上层兜底
		// （此处曾有「空 map 查找」死分支，已删）。
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
	return result.ruleMetrics()
}

// tcpRuleMetrics 按上游地址归集 TCP 单规则指标
// caddy-l4 v0.1.2 的 L4 指标（caddy_layer4_proxy_connections_total /
// active_connections / upstream_healthy）标签仅 []string{"upstream"}
// （模块源码 modules/l4proxy/metrics.go:57-75 实证）——无 server/listener/
// rule 级标签，引擎层面无法按规则拆分。多条 TCP 规则共享同一上游地址时，
// 各规则看到的该上游连接数相同（跨规则合计值），UI（Dashboard 规则表
// 请求数/处理中列 tooltip）已向用户明示该口径；不硬造规则级标签。
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
	return result.ruleMetrics()
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
		switch bucket := classifyStatusCode(services.ExtractMetricLabel(name, "code")); bucket {
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
	case strings.HasPrefix(name, "caddy_http_request_size_bytes_sum"):
		metrics.bytesIn += int64(value)
	case strings.HasPrefix(name, "caddy_http_response_size_bytes_sum"):
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

// ruleMetrics 规则指标的统一键集（HTTP/TCP/空指标一致）。健康语义由
// /config/health 通道承载——此处曾有恒假 healthy 键（唯一写点、零读点），
// 外部消费者会把它当成真实健康状态。
func (metrics ruleMetricsAggregate) ruleMetrics() gin.H {
	return gin.H{
		"requests_total":     metrics.requestsTotal,
		"requests_in_flight": metrics.requestsInFlight,
		"status_2xx":         metrics.status2xx,
		"status_3xx":         metrics.status3xx,
		"status_4xx":         metrics.status4xx,
		"status_5xx":         metrics.status5xx,
		"bytes_in":           metrics.bytesIn,
		"bytes_out":          metrics.bytesOut,
	}
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

	if host := services.ExtractMetricLabel(name, "host"); host != "" {
		index.aggregateFor(index.hosts, host).add(&metric)
		index.aggregateFor(index.httpHosts, host).add(&metric)
		if bareHost, _, err := net.SplitHostPort(host); err == nil {
			index.aggregateFor(index.httpBareHosts, bareHost).add(&metric)
		}
	}

	if rule := services.ExtractMetricLabel(name, "rule"); rule != "" {
		if strings.HasPrefix(name, "lazybalancer_security_blocked_total{") {
			// blocked-only 样本不建 ruleMetricsByRule
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
			switch services.ExtractMetricLabel(name, "class") {
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
			switch services.ExtractMetricLabel(name, "direction") {
			case "in":
				agg.bytesIn += int64(value)
			case "out":
				agg.bytesOut += int64(value)
			}
		}
	}

	if upstream := services.ExtractMetricLabel(name, "upstream"); upstream != "" {
		aggregate := index.aggregateFor(index.tcpUpstreams, upstream)
		switch {
		case strings.HasPrefix(name, "caddy_layer4_proxy_connections_total{"):
			aggregate.requestsTotal += int64(value)
		case strings.HasPrefix(name, "caddy_layer4_proxy_active_connections{"):
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
		// geoip 透传路由无 reverse_proxy：同一请求先过它、再过主/路径路由，
		// 两条路由各自注入指标。本仓库的采集链按
		// services.IsGeoIPPassSeries 整行剔除，实时指标解析必须同口径
		// （共用同一判据），否则首页「总请求数/流量」在启用 GeoIP 的规则上
		// 恰好是真实值的两倍，且与同页采集链来源的速率卡互相矛盾。
		if services.IsGeoIPPassSeries(line) {
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
		// Prometheus 文本格式允许 NaN/±Inf，但消费侧把样本值转 int64——Go 规范
		// 下该转换对非有限值是实现相关的（arm64/amd64 得 -9.2e18），会以 HTTP
		// 200 输出荒谬的负数计数。非有限样本不参与聚合（与「正文无有效样本 →
		// 502」同口径：全部无效时仍报错）。
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
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

// 指标 label 抽取统一走 services.ExtractMetricLabel（LBS/
// 本包原 extractLabel 与 services extractMetricLabel 逐字重复，收敛为跨包单源）。

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

// deductBlockedFrom4xx 从 4xx 计数扣除安全拦截并钳制 ≥0(历史
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

func parseRuleMetricsFromPrometheus(body, domain string, listenPort int, enableTLS bool, ruleCaddyID ...string) (gin.H, error) { // protocol 死参移除
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
	// GET /metrics/rule/:caddy_id 与仪表盘同口径——
	// 加 blocked 并扣 4xx(钳制 ≥0);ruleCaddyID 为空时(TCP)跳过。
	if len(ruleCaddyID) > 0 && ruleCaddyID[0] != "" {
		blocked := index.blockedByRule[ruleCaddyID[0]]
		result["blocked"] = blocked
		deductBlockedFrom4xx(result, blocked)
	}
	return result, nil
}

// tailLogWindow 截断尾读日志窗口的首行残段（语义，
// 抽享——此前同一逻辑在 GetAppLogs/GetCaddyLogs 两份实现，历史只收敛了
// system.go，caddy.go 漏网）：startOffset 非零时窗口首字节可能落在某行中段
// （切在多字节 rune 中间时残段带无效字节，JSON 编码后以 U+FFFD 污染输出），
// 丢弃到下一 '\n' 为止；窗口内无 '\n' 则整窗是同一巨行的中段，返回空。
//
// 起点也可能恰为行首（调用方按 size-窗口 取任意字节偏移）：此时首行是完整行，
// 不得丢弃。边界只能回读 src 的 startOffset-1 字节判定（窗口数据自身看不出），
// 读不到时按行中段保守丢弃——宁丢一行残段，不输出半行。
func tailLogWindow(src io.ReaderAt, data []byte, startOffset int64) []byte {
	if startOffset <= 0 {
		return data
	}
	if src != nil {
		var prev [1]byte
		if _, err := src.ReadAt(prev[:], startOffset-1); err == nil && prev[0] == '\n' {
			return data
		}
	}
	if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
		return data[idx+1:]
	}
	return nil
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
	// 双源收敛：空值形状与 ruleMetricsAggregate 零值输出同源，禁手工维护两套键表。
	return ruleMetricsAggregate{}.ruleMetrics()
}

// allNumericLabels 报告点分串的每个标签是否都只由数字组成（999.1.1.1 形态）。
// 用于把「看似 IPv4 的非法地址」挡在含义更宽的主机名校验之外。
func allNumericLabels(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false
		}
		for _, c := range label {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isValidHost(host string) bool {
	// Check if it's a valid IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return true
	}

	// 全数字点分串（999.1.1.1、1.2.3.256、1.2.3.4.5）：net.ParseIP 已失败，
	// 下面的标签字母表校验会放行，但这类串只可能是想写 IP 的笔误——落库后
	// 渲染进上游地址 / 健康检查 Host 头 / 动态上游 DNS 解析，解析或探测静默
	// 失败（保存时零提示）。只拒绝「每个标签都纯数字」的点分形态，dns1.example.com
	// 一类含数字域名与单段数字主机名不受影响。
	if strings.Contains(host, ".") && allNumericLabels(host) {
		return false
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
			// 删 c=='.'——part 来自 Split(domain, ".") 的产物，恒不含 '.'。
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
