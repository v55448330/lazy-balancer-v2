package notify

// 级联抑制与逐 IP 去抖（进程内状态，重启即清——事实已在安全事件库，通知
// 只是 surfaced 面）。
//   - 级联抑制：autoban_triggered 已发出后，同 IP 的 cc_triggered 在抑制窗
//     （10 分钟）内不再发（CC 达标随后必被封禁，两条事件是同一事实的两面）。
//   - 逐 IP 去抖：cc_triggered 按 IP 去抖（同窗）——异常 IP 每请求都会产生
//     CC 事件，不去抖会灌满发布队列并挤掉 critical 事件。
// 发出方统一经 PublishAutobanTriggered / PublishCCTriggered，禁止绕过直发。

import (
	"sync"
	"time"
)

// suppressionWindow 抑制/去抖共用窗口。
const suppressionWindow = 10 * time.Minute

var (
	suppressMu      sync.Mutex
	autobanArmed    = map[string]time.Time{} // IP → 自动封禁事件发出时刻
	ccLastPublished = map[string]time.Time{} // IP → CC 事件上次发出时刻
)

// PublishAutobanTriggered 发布自动封禁触发并武装同 IP 的 CC 抑制窗。
// Fields 键序=模板参数序（目录 BodyFormat："IP（原因/口径）"）。
func PublishAutobanTriggered(ip, detail string) {
	now := time.Now()
	suppressMu.Lock()
	autobanArmed[ip] = now
	pruneSuppressionLocked(now)
	suppressMu.Unlock()
	Publish(Event{Type: EvtAutobanTriggered, Fields: map[string]string{"1": ip, "2": detail}})
}

// PublishCCTriggered 发布 CC 防护触发：同 IP 处于 autoban 抑制窗或自身去抖窗
// 内时静默跳过。
func PublishCCTriggered(ip, reason string) {
	now := time.Now()
	suppressMu.Lock()
	if at, ok := autobanArmed[ip]; ok && now.Sub(at) < suppressionWindow {
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
