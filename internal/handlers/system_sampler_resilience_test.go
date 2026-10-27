package handlers

// 系统指标读路径的韧性契约：
//   - 启动期外部命令（uname/caddy version）与运行期 df/netstat 同口径超时；
//   - df/netstat 失败写短负缓存（串行轮询不再每轮各等满超时）；
//   - 实时流量基线携带接口身份（默认路由切换即重建基线，不产生假峰值）；
//   - 包初始化即建立 CPU/流量基线（首屏不再把「尚无基线」显示为 0）；
//   - 出口 IP 探测失败不把回环地址冒充机器地址；IPv6-only 接口可展示。

import (
	"context"
	"net"
	"os/exec"
	"testing"
	"time"
)

func TestLoadCommandOutput_timesOutInsteadOfBlockingStartup(t *testing.T) {
	withIsolatedGlobal(t)
	oldTimeout := systemMetricsCommandTimeout
	systemMetricsCommandTimeout = 40 * time.Millisecond
	t.Cleanup(func() { systemMetricsCommandTimeout = oldTimeout })

	start := time.Now()
	output := loadCommandOutput("sh", "-c", "sleep 5")
	elapsed := time.Since(start)
	if output != "unknown" {
		t.Fatalf("output=%q, want unknown（超时兜底）", output)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("等待 %v, want 受 %v 超时约束", elapsed, systemMetricsCommandTimeout)
	}
}

func TestGetCachedDiskUsage_failureNegativeCacheAvoidsRerun(t *testing.T) {
	withIsolatedGlobal(t)
	resetDiskUsageCacheForTest(t)
	oldCommand := systemMetricsDFCommand
	t.Cleanup(func() { systemMetricsDFCommand = oldCommand })
	calls := 0
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		calls++
		return exec.CommandContext(ctx, "false")
	}

	// Given 首次失败。
	if _, _, err := getCachedDiskUsage(time.Now()); err == nil {
		t.Fatal("df 失败必须返回错误")
	}
	// When 负缓存窗口内再次请求（串行轮询形态）。
	if _, _, err := getCachedDiskUsage(time.Now()); err == nil {
		t.Fatal("负缓存命中仍须返回失败")
	}
	// Then 不重起子进程。
	if calls != 1 {
		t.Fatalf("负缓存窗口内执行 df %d 次, want 1", calls)
	}

	// When 负缓存过期 → 立即重试。
	diskUsageCache.Lock()
	diskUsageCache.negativeUntil = time.Time{}
	diskUsageCache.Unlock()
	if _, _, err := getCachedDiskUsage(time.Now()); err == nil {
		t.Fatal("过期后仍须返回失败")
	}
	if calls != 2 {
		t.Fatalf("负缓存过期后累计执行 %d 次, want 2", calls)
	}
}

func TestGetConnectionStats_failureNegativeCacheAvoidsRerun(t *testing.T) {
	withIsolatedGlobal(t)
	resetConnectionStatsCacheForTest(t)
	oldCommand := netstatCommand
	t.Cleanup(func() { netstatCommand = oldCommand })
	calls := 0
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		calls++
		return exec.CommandContext(ctx, "false")
	}

	if _, err := getConnectionStats(); err == nil {
		t.Fatal("netstat 失败必须返回错误")
	}
	if _, err := getConnectionStats(); err == nil {
		t.Fatal("负缓存命中仍须返回失败")
	}
	if calls != 1 {
		t.Fatalf("负缓存窗口内执行 netstat %d 次, want 1", calls)
	}

	connectionStatsCache.Lock()
	connectionStatsCache.negativeUntil = time.Time{}
	connectionStatsCache.Unlock()
	if _, err := getConnectionStats(); err == nil {
		t.Fatal("过期后仍须返回失败")
	}
	if calls != 2 {
		t.Fatalf("负缓存过期后累计执行 %d 次, want 2", calls)
	}
}

func TestGetRealtimeTraffic_rebuildsBaselineWhenDefaultInterfaceChanges(t *testing.T) {
	withIsolatedGlobal(t)
	disableNetSampleWindowForTest(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\neth1 00000000 0100000A 0003\n"), nil
		case "/proc/net/dev":
			// 新接口计数器远大于旧接口基线（切换后直接差分＝数量级假峰值）。
			return []byte("Inter-| Receive | Transmit\neth1: 900000 0 0 0 0 0 0 0 800000 0 0 0 0 0 0 0\n"), nil
		}
		return original(path)
	}
	lastNetStats.mu.Lock()
	lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = 100, 200, "eth0"
	lastNetStats.time = time.Now().Add(-5 * time.Second)
	lastNetStats.hasValue = true
	lastNetStats.mu.Unlock()
	t.Cleanup(func() {
		lastNetStats.mu.Lock()
		lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = 0, 0, ""
		lastNetStats.time = time.Time{}
		lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
		lastNetStats.hasValue = false
		lastNetStats.mu.Unlock()
	})

	traffic, err := getRealtimeTraffic()
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if traffic.BytesIn != 0 || traffic.BytesOut != 0 {
		t.Fatalf("traffic=%+v, want 0/0（接口切换后重建基线，不做跨接口差分）", traffic)
	}
	lastNetStats.mu.Lock()
	iface := lastNetStats.iface
	lastNetStats.mu.Unlock()
	if iface != "eth1" {
		t.Fatalf("baseline iface=%q, want eth1（基线须更新为新接口）", iface)
	}
}

func TestPrimeSystemSamplers_firstReadIsRealNotZero(t *testing.T) {
	withIsolatedGlobal(t)
	disableCPUSampleWindowForTest(t)
	disableNetSampleWindowForTest(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	cpuReads, netReads := 0, 0
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/stat":
			cpuReads++
			if cpuReads == 1 {
				return []byte("cpu 100 0 0 100 0\n"), nil
			}
			return []byte("cpu 200 0 0 200 0\n"), nil
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\neth0 00000000 0100000A 0003\n"), nil
		case "/proc/net/dev":
			netReads++
			if netReads == 1 {
				return []byte("Inter-| Receive | Transmit\neth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"), nil
			}
			return []byte("Inter-| Receive | Transmit\neth0: 4000 0 0 0 0 0 0 0 8000 0 0 0 0 0 0 0\n"), nil
		}
		return original(path)
	}
	resetCPUSampleStateForTest(t)
	t.Cleanup(func() {
		lastNetStats.mu.Lock()
		lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = 0, 0, ""
		lastNetStats.time = time.Time{}
		lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
		lastNetStats.hasValue = false
		lastNetStats.mu.Unlock()
	})

	// 启动期建立基线（CPU 样本 1 / 网卡样本 1）。
	primeSystemSamplers()

	// When 首个请求采样：基线已存在 → 立即给出真实速率/占比，而非 0。
	percent, err := getCPUPercent()
	if err != nil {
		t.Fatalf("cpu err=%v", err)
	}
	if percent <= 0 {
		t.Fatalf("percent=%v, want >0（初始化基线后首轮即可算出真实占比）", percent)
	}
	traffic, err := getRealtimeTraffic()
	if err != nil {
		t.Fatalf("traffic err=%v", err)
	}
	if traffic.BytesIn <= 0 || traffic.BytesOut <= 0 {
		t.Fatalf("traffic=%+v, want 正速率（初始化基线后不再恒 0）", traffic)
	}
	if cpuReads != 2 || netReads != 2 {
		t.Fatalf("reads cpu=%d net=%d, want 2/2（基线 + 首请求各一次）", cpuReads, netReads)
	}
}

func TestPreferredInterfaceIP_prefersIPv4ThenGlobalIPv6(t *testing.T) {
	mustCIDR := func(s string) net.Addr {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("bad cidr %s: %v", s, err)
		}
		ipnet.IP = ip
		return ipnet
	}

	// IPv4 优先（即使 IPv6 先出现）。
	if ip := preferredInterfaceIP([]net.Addr{
		mustCIDR("2001:db8::5/64"),
		mustCIDR("192.0.2.10/24"),
	}); ip == nil || ip.String() != "192.0.2.10" {
		t.Fatalf("ip=%v, want 192.0.2.10（IPv4 优先）", ip)
	}
	// IPv6-only：回落到全局单播，跳过 link-local。
	if ip := preferredInterfaceIP([]net.Addr{
		mustCIDR("fe80::1/64"),
		mustCIDR("2001:db8::7/64"),
	}); ip == nil || ip.String() != "2001:db8::7" {
		t.Fatalf("ip=%v, want 2001:db8::7（IPv6-only 回落到全局单播）", ip)
	}
	// 只有 link-local → 不展示不可路由地址。
	if ip := preferredInterfaceIP([]net.Addr{mustCIDR("fe80::1/64")}); ip != nil {
		t.Fatalf("ip=%v, want nil（link-local 不展示）", ip)
	}
}

// 出口 IP 探测失败时 system info 不得把回环地址当机器地址展示。
// 用注入缝构造失败形态：无默认路由的容器才会自然发生，开发机/CI 恒有默认
// 路由——不注入则该保护分支零自动化覆盖（旧用例在有路由的机器上直接 Skip）。
func TestGetOutboundIP_emptyWhenProbeFails(t *testing.T) {
	old := dialOutboundIPFn
	t.Cleanup(func() { dialOutboundIPFn = old })

	dialOutboundIPFn = func() (string, bool) { return "127.0.0.1", false }
	if ip := getOutboundIP(); ip != "" {
		t.Fatalf("ip=%q, want 空串（探测失败不得回显 127.0.0.1）", ip)
	}

	// 回归形状：探测成功时原样返回探测值。
	dialOutboundIPFn = func() (string, bool) { return "192.0.2.10", true }
	if ip := getOutboundIP(); ip != "192.0.2.10" {
		t.Fatalf("ip=%q, want 192.0.2.10（成功路径不得被缝改变）", ip)
	}
}
