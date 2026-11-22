package notify

// 拦截聚合降噪（sec.blocked_aggregate）：滚动窗口（默认 5 分钟，进程内
// 状态）内，每个级别至多一条——首发恒 info（及时性），窗口累计跨过
// warn/critical 阈值时各补一条升级事件；窗口关闭时只在「仍有未发级别」时
// 补发（正常情况下不会发生，防御阈值在窗口末刻跨越的边沿）。单次拦截因此
// 只产生 1 条通知（旧实现首条 + 窗口摘要双发）。
//
// 聚合正文同时披露挑战数与自动封禁数：挑战（action=challenged）由摄取
// 主路径与 IPC 路径经 RecordChallengeEvent 计数；自动封禁在
// PublishAutobanTriggered 内累计。两者都只记入已开启的窗口（不单独开窗，
// 避免挑战流量把聚合变成逐请求通知）。
//
// 窗口状态进程内，重启即新窗口（无正确性影响——事实已在安全事件库）。

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

// blockedThresholdsFn 阈值来源（测试缝；生产=BlockedThresholds，读取
// notify_settings）。窗口开启时取一次——窗口内配置变更下一窗口生效，
// 避免每个拦截事件都查一次库。
var blockedThresholdsFn = BlockedThresholds

type blockedWindowState struct {
	start      time.Time
	count      int
	challenges int
	autobans   int
	topRule    map[string]int
	// warnAt/criticalAt 在窗口开启时快照（见 blockedThresholdsFn）。
	warnAt, criticalAt int
	// 已发布的级别（每级别至多一条）：info 恒随首条发出。
	infoSent, warnSent, criticalSent bool
}

var (
	blockedMu        sync.Mutex
	blockedCurrent   *blockedWindowState
	blockedInitWheel sync.Once
	blockedFlushCh   chan struct{}
)

// RecordBlockedEvent 安全事件摄取拦截分支调用：计数 + 按级别发布（首发
// info / 跨阈值升级各一条）。ruleName 为命中规则名（TOP 统计维度）。发布
// 恒走包级 Publish（无发布器注入缝）——需要隔离断言时以包级总线状态为准。
func RecordBlockedEvent(ruleName string) {
	for _, evt := range recordBlocked(ruleName) {
		Publish(evt)
	}
}

// recordBlocked 计数并返回本轮需要发布的事件（0-1 条；纯内存，便于单测
// 直接断言级别与文案而不依赖总线）。调用方负责发布。
func recordBlocked(ruleName string) []Event {
	blockedInitWheel.Do(func() {
		blockedFlushCh = make(chan struct{})
		go blockedFlushLoop()
	})
	blockedMu.Lock()
	defer blockedMu.Unlock()
	now := time.Now()
	if blockedCurrent == nil || now.Sub(blockedCurrent.start) >= blockedWindow {
		warnAt, criticalAt := blockedThresholdsFn()
		blockedCurrent = &blockedWindowState{
			start: now, topRule: map[string]int{},
			warnAt: warnAt, criticalAt: criticalAt,
		}
	}
	w := blockedCurrent
	w.count++
	if ruleName != "" {
		w.topRule[ruleName]++
	}
	switch {
	case w.count == 1:
		// 首发恒 info：阈值再低（如用户把 warn 配成 1）也不把首条直接升级，
		// 保证「首发 info + 升级各一条」的级别序列稳定。
		w.infoSent = true
		return []Event{blockedEventAtLevel(w, LevelInfo)}
	case w.criticalAt > 0 && w.count >= w.criticalAt && !w.criticalSent:
		w.criticalSent = true
		return []Event{blockedEventAtLevel(w, LevelCritical)}
	case w.warnAt > 0 && w.count >= w.warnAt && !w.warnSent:
		w.warnSent = true
		return []Event{blockedEventAtLevel(w, LevelWarn)}
	}
	return nil
}

// RecordChallengeEvent 摄取到 action=challenged 事件时调用（主路径与 IPC
// 路径）。只累加到已开启的聚合窗口：挑战流量本身不触发聚合通知（CC 触发
// 有独立事件与逐 IP 去抖）。
func RecordChallengeEvent() {
	blockedMu.Lock()
	if w := blockedCurrent; w != nil {
		w.challenges++
	}
	blockedMu.Unlock()
}

// recordAutobanInWindow 自动封禁计数（PublishAutobanTriggered 内调用）：
// 同样只累加到已开启窗口，不单独开窗。
func recordAutobanInWindow() {
	blockedMu.Lock()
	if w := blockedCurrent; w != nil {
		w.autobans++
	}
	blockedMu.Unlock()
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

// takeBlockedWindowEvent 取走当前窗口并返回需要补发的汇总事件（无=不发布）。
// 单次拦截窗口只有首发 info，flush 不再追加（降噪核心）；已发级别不重复。
func takeBlockedWindowEvent() *Event {
	blockedMu.Lock()
	w := blockedCurrent
	blockedCurrent = nil
	blockedMu.Unlock()
	if w == nil || w.count == 0 {
		return nil
	}
	level := blockedWindowLevel(w)
	switch level {
	case LevelCritical:
		if w.criticalSent {
			return nil
		}
	case LevelWarn:
		if w.warnSent {
			return nil
		}
	default:
		if w.infoSent {
			return nil
		}
	}
	evt := blockedEventAtLevel(w, level)
	return &evt
}

func flushBlockedWindow() {
	if evt := takeBlockedWindowEvent(); evt != nil {
		Publish(*evt)
	}
}

// blockedWindowLevel 窗口累计数对应的级别（阈值快照优先，缺省回落当前配置）。
func blockedWindowLevel(w *blockedWindowState) Level {
	warnAt, criticalAt := w.warnAt, w.criticalAt
	if warnAt <= 0 || criticalAt <= 0 {
		warnAt, criticalAt = blockedThresholdsFn()
	}
	if criticalAt > 0 && w.count >= criticalAt {
		return LevelCritical
	}
	if warnAt > 0 && w.count >= warnAt {
		return LevelWarn
	}
	return LevelInfo
}

// blockedAggregateEvent 汇总事件（纯函数，便于钉测文案）。窗口跨度用实际
// time.Since(w.start)：全局 ticker 的相位与首个事件无关（窗口可能在 tick 前
// 几秒才开启），固定写「5 分钟内」会把几秒的爆发夸大成 5 分钟持续攻击。
func blockedAggregateEvent(w *blockedWindowState) Event {
	return blockedEventAtLevel(w, blockedWindowLevel(w))
}

// blockedEventAtLevel 按指定级别构造聚合事件（Fields 序=目录模板参数序：
// 1 跨度 2 拦截 3 挑战 4 自动封禁 5 TOP 规则）。
func blockedEventAtLevel(w *blockedWindowState, level Level) Event {
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
		Title: "拦截聚合",
		Body: fmt.Sprintf("%s内拦截 %d 次 / 挑战 %d 次 / 自动封禁 %d 次（TOP 规则：%s）",
			span, w.count, w.challenges, w.autobans, topStr),
		Fields: map[string]string{
			"1": span,
			"2": fmt.Sprint(w.count),
			"3": fmt.Sprint(w.challenges),
			"4": fmt.Sprint(w.autobans),
			"5": topStr,
		},
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
