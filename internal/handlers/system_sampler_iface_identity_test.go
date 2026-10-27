package handlers

import (
	"strings"
	"testing"
	"time"
)

// seedLastNetStatsForTest 建立一条可比较的上一条采样基线（身份串由调用方给出）。
func seedLastNetStatsForTest(t *testing.T, bytesIn, bytesOut uint64, identity string) {
	t.Helper()
	lastNetStats.mu.Lock()
	lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = bytesIn, bytesOut, identity
	lastNetStats.time = time.Now().Add(-5 * time.Second)
	lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
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
}

// 默认路由消失（策略路由/网卡下线）后退回物理网卡聚合口径：基线身份从接口名
// 变成聚合值，新旧计数器不可比。旧判据要求新旧身份都非空，恰好漏掉「接口消失」
// 方向——聚合后的历史总流量被当成一轮速率（数量级假峰值）。
func TestGetRealtimeTraffic_rebaselinesWhenDefaultRouteDisappears(t *testing.T) {
	withIsolatedGlobal(t)
	disableNetSampleWindowForTest(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			// 无默认路由行：parseNetDevTotals 退回物理网卡聚合。
			return []byte("Iface Destination Gateway Flags\n"), nil
		case "/proc/net/dev":
			return []byte("Inter-| Receive | Transmit\neth0: 900000 0 0 0 0 0 0 0 800000 0 0 0 0 0 0 0\n"), nil
		}
		return original(path)
	}
	seedLastNetStatsForTest(t, 100, 200, "eth0")

	traffic, err := getRealtimeTraffic()
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if traffic.BytesIn != 0 || traffic.BytesOut != 0 {
		t.Fatalf("traffic=%+v, want 0/0（口径从默认路由接口变为聚合，不得做跨口径差分）", traffic)
	}
	lastNetStats.mu.Lock()
	identity := lastNetStats.iface
	lastNetStats.mu.Unlock()
	if identity == "" || !strings.Contains(identity, "eth0") {
		t.Fatalf("baseline identity=%q, want 显式聚合身份串且含成员 eth0", identity)
	}
}

// 反向：基线为聚合口径（无单一接口身份）时默认路由恢复，同样不可比。
func TestGetRealtimeTraffic_rebaselinesWhenDefaultRouteReturns(t *testing.T) {
	withIsolatedGlobal(t)
	disableNetSampleWindowForTest(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\neth0 00000000 0100000A 0003\n"), nil
		case "/proc/net/dev":
			return []byte("Inter-| Receive | Transmit\neth0: 900000 0 0 0 0 0 0 0 800000 0 0 0 0 0 0 0\n"), nil
		}
		return original(path)
	}
	seedLastNetStatsForTest(t, 100, 200, "")

	traffic, err := getRealtimeTraffic()
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if traffic.BytesIn != 0 || traffic.BytesOut != 0 {
		t.Fatalf("traffic=%+v, want 0/0（聚合口径 → 默认路由接口，计数器不可比）", traffic)
	}
	lastNetStats.mu.Lock()
	identity := lastNetStats.iface
	lastNetStats.mu.Unlock()
	if identity != "eth0" {
		t.Fatalf("baseline identity=%q, want eth0", identity)
	}
}

// 聚合口径内成员变化（网卡下线 + 新网卡上线）时，成员集合不同则聚合总量含义
// 不同：身份串必须随成员变化，否则跨成员集差分给出假峰值。
func TestGetRealtimeTraffic_aggregateIdentityTracksMembers(t *testing.T) {
	withIsolatedGlobal(t)
	disableNetSampleWindowForTest(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	current := "Inter-| Receive | Transmit\n" +
		"eth0: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n" +
		"eth1: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n"
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\n"), nil
		case "/proc/net/dev":
			return []byte(current), nil
		}
		return original(path)
	}
	lastNetStats.mu.Lock()
	lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = 0, 0, ""
	lastNetStats.time = time.Time{}
	lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
	lastNetStats.hasValue = false
	lastNetStats.mu.Unlock()
	t.Cleanup(func() {
		lastNetStats.mu.Lock()
		lastNetStats.bytesIn, lastNetStats.bytesOut, lastNetStats.iface = 0, 0, ""
		lastNetStats.time = time.Time{}
		lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
		lastNetStats.hasValue = false
		lastNetStats.mu.Unlock()
	})

	// 首轮建立聚合基线（eth0+eth1，速率 0）。
	if _, err := getRealtimeTraffic(); err != nil {
		t.Fatalf("首轮 err=%v", err)
	}
	// eth1 下线、eth2 上线且自带历史总流量：聚合总量增长，但成员集已变。
	current = "Inter-| Receive | Transmit\n" +
		"eth0: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n" +
		"eth2: 900000 0 0 0 0 0 0 0 800000 0 0 0 0 0 0 0\n"
	traffic, err := getRealtimeTraffic()
	if err != nil {
		t.Fatalf("二轮 err=%v", err)
	}
	if traffic.BytesIn != 0 || traffic.BytesOut != 0 {
		t.Fatalf("traffic=%+v, want 0/0（聚合成员集变化后不得跨集合差分）", traffic)
	}
}

// 聚合身份串须与 /proc/net/dev 行序无关：否则行序抖动会误触发基线重建。
func TestGetRealtimeTraffic_aggregateIdentityStableAcrossRowOrder(t *testing.T) {
	withIsolatedGlobal(t)
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	rowA := "eth0: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\neth1: 200 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n"
	rowB := "eth1: 200 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\neth0: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n"
	route := []byte("Iface Destination Gateway Flags\n")
	dev := []byte("Inter-| Receive | Transmit\n" + rowA)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return route, nil
		case "/proc/net/dev":
			return dev, nil
		}
		return original(path)
	}

	_, _, identityA, err := parseNetDevTotals(string(dev))
	if err != nil {
		t.Fatalf("identityA err=%v", err)
	}
	dev = []byte("Inter-| Receive | Transmit\n" + rowB)
	_, _, identityB, err := parseNetDevTotals(string(dev))
	if err != nil {
		t.Fatalf("identityB err=%v", err)
	}
	if identityA == "" || identityA != identityB {
		t.Fatalf("identityA=%q identityB=%q, want 相同的显式聚合身份串", identityA, identityB)
	}
}
