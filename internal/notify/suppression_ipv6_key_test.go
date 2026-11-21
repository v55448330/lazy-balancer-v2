package notify

// IPv6 抑制键归一钉：自动封禁 IPv6 条目是 /64 CIDR（名单值），CC 事件携带
// 裸地址——两侧不归一时级联抑制失配（已封禁 /64 内 CC 触发仍逐 IP 发通知）。
// 逐 IP 去抖保持原始地址粒度（同段不同地址是各自独立的攻击证据）。

import (
	"testing"
	"time"
)

func resetSuppressionStateForTest(t *testing.T) {
	t.Helper()
	suppressMu.Lock()
	oldArmed, oldCC := autobanArmed, ccLastPublished
	autobanArmed = map[string]time.Time{}
	ccLastPublished = map[string]time.Time{}
	suppressMu.Unlock()
	t.Cleanup(func() {
		suppressMu.Lock()
		autobanArmed, ccLastPublished = oldArmed, oldCC
		suppressMu.Unlock()
	})
}

func TestSuppressionKey_IPv6NormalizesToPrefix(t *testing.T) {
	same := []string{
		"2606:4700:abcd:1234::/64",
		"2606:4700:abcd:1234::1",
		"2606:4700:abcd:1234:dead:beef::99",
	}
	want := suppressionKey(same[0])
	if want != "2606:4700:abcd:1234::/64" {
		t.Fatalf("key=%q, want 2606:4700:abcd:1234::/64", want)
	}
	for _, ip := range same[1:] {
		if got := suppressionKey(ip); got != want {
			t.Fatalf("suppressionKey(%q)=%q, want %q（同 /64 必须同键）", ip, got, want)
		}
	}
	// 邻段与 IPv4 不被归一吞并。
	if got := suppressionKey("2606:4700:abcd:1235::1"); got == want {
		t.Fatalf("邻段被归一为同一键：%q", got)
	}
	if got := suppressionKey("198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("IPv4 key=%q, want 裸地址", got)
	}
}

// 已武装 /64 后，同段裸地址的 CC 触发必须被级联抑制（不进逐 IP 去抖表）；
// 邻段地址照常进入去抖表（对照证明抑制不是无条件）。
func TestPublishCCTriggered_suppressedBySameIPv6Prefix(t *testing.T) {
	resetSuppressionStateForTest(t)
	PublishAutobanTriggered("2606:4700:abcd:1234::/64", "命中：5 次/5 分钟，时长：1h")

	PublishCCTriggered("2606:4700:abcd:1234:dead::1", "rps_spike")
	suppressMu.Lock()
	_, suppressed := ccLastPublished["2606:4700:abcd:1234:dead::1"]
	armedKey := len(autobanArmed)
	suppressMu.Unlock()
	if suppressed {
		t.Fatal("同 /64 的 CC 触发未被级联抑制（抑制键与武装键失配）")
	}
	if armedKey != 1 {
		t.Fatalf("武装键应归一为 1 个 /64 键，实际 %d", armedKey)
	}

	// 对照：邻段地址不受抑制，进入逐 IP 去抖表。
	PublishCCTriggered("2606:4700:abcd:1235::1", "rps_spike")
	suppressMu.Lock()
	_, published := ccLastPublished["2606:4700:abcd:1235::1"]
	suppressMu.Unlock()
	if !published {
		t.Fatal("对照失败：邻段地址的 CC 触发应正常发出")
	}
}
