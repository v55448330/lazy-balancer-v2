package notify

// 级联抑制与逐 IP 去抖（进程内状态，重启即清——事实已在安全事件库，通知
// 只是 surfaced 面）。
//   - 级联抑制：autoban_triggered 已发出后，同 IP 的 cc_triggered 在抑制窗
//     （10 分钟）内不再发（CC 达标随后必被封禁，两条事件是同一事实的两面）。
//   - 逐 IP 去抖：cc_triggered 按 IP 去抖（同窗）——异常 IP 每请求都会产生
//     CC 事件，不去抖会灌满发布队列并挤掉 critical 事件。
// 发出方统一经 PublishAutobanTriggered / PublishCCTriggered，禁止绕过直发。

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// suppressionWindow 抑制/去抖共用窗口。
const suppressionWindow = 10 * time.Minute

var (
	suppressMu      sync.Mutex
	autobanArmed    = map[string]time.Time{} // 抑制键（IPv4 裸地址 / IPv6 /64）→ 自动封禁事件发出时刻
	ccLastPublished = map[string]time.Time{} // IP（原始地址）→ CC 事件上次发出时刻
	// 封禁风暴合并：5 分钟内第 5 个封禁起不再逐 IP 发，改为一条摘要。
	autobanBurstStart time.Time
	autobanBurstCount int
	autobanBurstIPs   []string
	autobanBurstSent  bool
)

// suppressionKey 归一抑制/去抖键：IPv6 按 /64 前缀归一，IPv4 保持裸地址。
// 自动封禁的 IPv6 条目是 /64 CIDR（名单值 "2001:db8::/64"），CC 事件携带的
// 是裸地址——不归一时武装键（CIDR）与查询键（裸地址）永不相等，同段 CC 触发
// 在已封禁后仍逐 IP 发通知（级联抑制失配，仅通知噪音）。IPv4 映射地址按
// IPv4 归一。
func suppressionKey(ip string) string {
	if prefix, err := netip.ParsePrefix(ip); err == nil {
		addr := prefix.Addr().Unmap()
		if !addr.Is6() {
			return addr.String()
		}
		p, err := addr.Prefix(64)
		if err != nil {
			return ip
		}
		return p.String()
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if !addr.Is6() {
		return addr.String()
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// PublishAutobanTriggered 发布自动封禁触发并武装同一抑制键（IPv6=/64 前缀，
// 与 CC 触发查询键同归一）的 CC 抑制窗。
// Fields 键序=模板参数序（目录 BodyFormat："IP（原因/口径）"）。
func PublishAutobanTriggered(ip, detail string) {
	now := time.Now()
	key := suppressionKey(ip)
	suppressMu.Lock()
	autobanArmed[key] = now
	pruneSuppressionLocked(now)
	suppressMu.Unlock()
	// 计入已开启的拦截聚合窗口（挑战/自动封禁是攻击规模的两项补充计数）。
	recordAutobanInWindow()
	if summary, suppress := recordAutobanBurst(ip, now); suppress {
		if summary != nil {
			Publish(*summary)
		}
		return
	}
	Publish(Event{Type: EvtAutobanTriggered, Fields: map[string]string{"1": ip, "2": detail}})
}

// recordAutobanBurst 5 分钟窗口封禁计数：第 5 个起合并为一条摘要并静默后续
// 单 IP 事件；窗口结束后重新计数。
func recordAutobanBurst(ip string, now time.Time) (*Event, bool) {
	suppressMu.Lock()
	defer suppressMu.Unlock()
	if autobanBurstStart.IsZero() || now.Sub(autobanBurstStart) >= blockedWindow {
		autobanBurstStart = now
		autobanBurstCount = 0
		autobanBurstIPs = nil
		autobanBurstSent = false
	}
	autobanBurstCount++
	autobanBurstIPs = append(autobanBurstIPs, ip)
	if len(autobanBurstIPs) > 5 {
		autobanBurstIPs = autobanBurstIPs[len(autobanBurstIPs)-5:]
	}
	if autobanBurstCount < 5 || autobanBurstSent {
		return nil, autobanBurstCount >= 5
	}
	autobanBurstSent = true
	span := blockedSpanLabel(now.Sub(autobanBurstStart))
	return &Event{
		Type: EvtAutobanSummary, Level: LevelWarn, Title: "封禁风暴",
		Body: fmt.Sprintf("%s内自动封禁 %d 个 IP（最近：%s）",
			span, autobanBurstCount, strings.Join(autobanBurstIPs, "、")),
		Fields: map[string]string{
			"1": span,
			"2": fmt.Sprint(autobanBurstCount),
			"3": strings.Join(autobanBurstIPs, "、"),
		},
	}, true
}

// PublishCCTriggered 发布 CC 防护触发：同 IP 处于 autoban 抑制窗或自身去抖窗
// 内时静默跳过。
func PublishCCTriggered(ip, reason string) {
	now := time.Now()
	// 级联抑制按归一键查（IPv6 /64：同段任一地址被封即抑制全段 CC 通知）；
	// 逐 IP 去抖仍按原始地址（同段不同地址是各自独立的攻击证据，不得互相
	// 吞掉通知）。
	armKey := suppressionKey(ip)
	suppressMu.Lock()
	if at, ok := autobanArmed[armKey]; ok && now.Sub(at) < suppressionWindow {
		suppressMu.Unlock()
		return
	}
	if at, ok := ccLastPublished[ip]; ok && now.Sub(at) < suppressionWindow {
		suppressMu.Unlock()
		return
	}
	ccLastPublished[ip] = now
	pruneSuppressionLocked(now)
	suppressMu.Unlock()
	Publish(Event{Type: EvtCCTriggered, Fields: map[string]string{"1": ip, "2": reason}})
}

// PublishAutobanExpired 发布自动封禁到期解封（逐 IP）。
func PublishAutobanExpired(ip string) {
	Publish(Event{Type: EvtAutobanExpired, Fields: map[string]string{"1": ip}})
}

// pruneSuppressionLocked 清理超窗条目（随写入懒清理，map 有界）。
func pruneSuppressionLocked(now time.Time) {
	for ip, at := range autobanArmed {
		if now.Sub(at) >= suppressionWindow {
			delete(autobanArmed, ip)
		}
	}
	for ip, at := range ccLastPublished {
		if now.Sub(at) >= suppressionWindow {
			delete(ccLastPublished, ip)
		}
	}
}
