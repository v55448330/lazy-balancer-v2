package notify

// 事件聚合去抖（sec.blocked_aggregate）：首个拦截立即发布一条 info；
// 滚动窗口（默认 5 分钟，进程内状态）关闭时若累计 ≥ 升级阈值则追加一条
// warn/critical 聚合（N 次/TOP 规则）。窗口状态进程内，重启即新窗口
// （无正确性影响——事实已在安全事件库）。

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	blockedWindow     = 5 * time.Minute
	blockedWarnAt     = 50  // 窗口累计 ≥50 → warn（内置默认；可被 notify_settings 阈值覆盖）
	blockedCriticalAt = 200 // 窗口累计 ≥200 → critical（内置默认；可被 notify_settings 阈值覆盖）
)

type blockedWindowState struct {
	start   time.Time
	count   int
	topRule map[string]int
}

var (
	blockedMu        sync.Mutex
	blockedCurrent   *blockedWindowState
	blockedInitWheel sync.Once
	blockedFlushCh   chan struct{}
)

// RecordBlockedEvent 安全事件摄取拦截分支调用：计数+首条立即告警+窗口 flush。
// ruleName 为命中规则名（TOP 统计维度）。
func RecordBlockedEvent(ruleName string, publish func(Event)) {
	blockedInitWheel.Do(func() {
		blockedFlushCh = make(chan struct{})
		go blockedFlushLoop()
	})
	blockedMu.Lock()
	now := time.Now()
	if blockedCurrent == nil || now.Sub(blockedCurrent.start) >= blockedWindow {
		blockedCurrent = &blockedWindowState{start: now, topRule: map[string]int{}}
	}
	blockedCurrent.count++
	if ruleName != "" {
		blockedCurrent.topRule[ruleName]++
	}
	blockedMu.Unlock()

	// 首个拦截立即发布一条 info（及时性；后续进聚合）。
	if blockedCurrent.count == 1 {
		Publish(Event{
			Type: EvtBlockedAggregate, Level: LevelInfo,
			Title:  "拦截聚合",
			Body:   fmt.Sprintf("检测到拦截行为（%s），后续将按 %v 窗口聚合通报", ruleName, blockedWindow),
			Fields: map[string]string{"1": "5", "2": "1", "3": ruleName},
		})
	}
}

func blockedFlushLoop() {
	t := time.NewTicker(blockedWindow)
	defer t.Stop()
	for range t.C {
		select {
		case <-blockedFlushCh:
			return
		default:
		}
		flushBlockedWindow()
	}
}

func flushBlockedWindow() {
	blockedMu.Lock()
	w := blockedCurrent
	blockedCurrent = nil
	blockedMu.Unlock()
	if w == nil || w.count == 0 {
		return
	}
	level := LevelInfo
	warnAt, criticalAt := BlockedThresholds()
	if w.count >= criticalAt {
		level = LevelCritical
	} else if w.count >= warnAt {
		level = LevelWarn
	}
	top := topRules(w.topRule, 3)
	topStr := "无"
	for i, r := range top {
		if i > 0 {
			topStr += "、"
		}
		topStr += fmt.Sprintf("%s×%d", r.name, r.count)
	}
	Publish(Event{
		Type: EvtBlockedAggregate, Level: level,
		Title:  "拦截聚合",
		Body:   fmt.Sprintf("%d 分钟内拦截 %d 次（TOP 规则：%s）", int(blockedWindow.Minutes()), w.count, topStr),
		Fields: map[string]string{"1": fmt.Sprint(int(blockedWindow.Minutes())), "2": fmt.Sprint(w.count), "3": topStr},
	})
}

type ruleCount struct {
	name  string
	count int
}

func topRules(m map[string]int, n int) []ruleCount {
	out := make([]ruleCount, 0, len(m))
	for k, v := range m {
		out = append(out, ruleCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].count > out[j].count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}
