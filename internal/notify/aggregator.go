package notify

// 事件聚合去抖（sec.blocked_aggregate）：首个拦截立即发布一条 info；
// 滚动窗口（默认 5 分钟，进程内状态）关闭时只要有累计就发布一条汇总
// （任意非空窗口都发，不设静默下限）；汇总级别按累计数升级——≥warn 阈值
// 为 warn、≥critical 阈值为 critical，否则 info。窗口状态进程内，重启即
// 新窗口（无正确性影响——事实已在安全事件库）。

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
// ruleName 为命中规则名（TOP 统计维度）。发布恒走包级 Publish（无发布器注入
// 缝）——曾有的 publish 形参从未被使用，却让调用侧/测试误以为可以注入隔离的
// 发布器（传 no-op 仍会真实发布）。需要隔离断言时以包级总线状态为准。
func RecordBlockedEvent(ruleName string) {
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
	// 「是否本轮首条」必须在锁内判定并落局部变量：锁外再读 blockedCurrent
	// 会与 flush（置 nil）/窗口轮换竞争——nil 解引用 panic，或把轮换后窗口的
	// 非首条误当首条重发（-race 实证）。
	first := blockedCurrent.count == 1
	blockedMu.Unlock()

	// 首个拦截立即发布一条 info（及时性；后续进聚合）。
	if first {
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
	Publish(blockedAggregateEvent(w))
}

// blockedAggregateEvent 汇总事件（纯函数，便于钉测文案）。窗口跨度用实际
// time.Since(w.start)：全局 ticker 的相位与首个事件无关（窗口可能在 tick 前
// 几秒才开启），固定写「5 分钟内」会把几秒的爆发夸大成 5 分钟持续攻击
// （SEC154-P3-01）。
func blockedAggregateEvent(w *blockedWindowState) Event {
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
	span := blockedSpanLabel(time.Since(w.start))
	return Event{
		Type: EvtBlockedAggregate, Level: level,
		Title:  "拦截聚合",
		Body:   fmt.Sprintf("%s内拦截 %d 次（TOP 规则：%s）", span, w.count, topStr),
		Fields: map[string]string{"1": span, "2": fmt.Sprint(w.count), "3": topStr},
	}
}

// blockedSpanLabel 聚合窗口实际跨度的可读文案（<1 分钟按秒，其余按分钟；
// 非整分钟保留 1 位小数）。
func blockedSpanLabel(span time.Duration) string {
	if span < time.Minute {
		s := int(span.Round(time.Second) / time.Second)
		if s < 1 {
			s = 1
		}
		return fmt.Sprintf("%d 秒", s)
	}
	rounded := span.Round(10 * time.Second)
	if rounded%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(rounded/time.Minute))
	}
	return fmt.Sprintf("%.1f 分钟", rounded.Minutes())
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
