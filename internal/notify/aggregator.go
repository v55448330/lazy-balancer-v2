package notify

// 拦截聚合降噪（sec.blocked_aggregate）：滚动窗口（默认 5 分钟，进程内
// 状态）内，每个级别至多一条——低于最低阈值（默认 10 次）不通知；跨过
// 10/50/200 时分别补 info/warn/critical，窗口关闭时只补发未发级别。
// 单次扫描或零星拦截不再触发通知，避免绕过最低阈值。
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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	blockedWindow      = 5 * time.Minute
	blockedInfoAt      = 10  // 窗口累计 ≥10 → info（最低触发阈值；低于此不通知）
	blockedWarnAt      = 50  // 窗口累计 ≥50 → warn（内置默认；可被 notify_settings 阈值覆盖）
	blockedCriticalAt  = 200 // 窗口累计 ≥200 → critical（内置默认；可被 notify_settings 阈值覆盖）
	challengeSummaryAt = 50  // 挑战统计：5 分钟 ≥50 次才发摘要（事件本身默认关）

)

// MinBlockedWarnAt 拦截聚合 warn 阈值下限=info 起点。低于它时 warn 会在
// info 之前触发，同一窗口出现 warn→info 的级别倒序（配置/校验单源）。
const MinBlockedWarnAt = blockedInfoAt

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
	topIP      map[string]int
	topPath    map[string]int
	// infoAt 为最低触发阈值；warnAt/criticalAt 在窗口开启时快照。
	infoAt, warnAt, criticalAt int
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
func RecordBlockedEvent(ruleName, clientIP, path string) {
	for _, evt := range recordBlocked(ruleName, clientIP, path) {
		Publish(evt)
	}
}

// recordBlocked 计数并返回本轮需要发布的事件（0-1 条；纯内存，便于单测
// 直接断言级别与文案而不依赖总线）。调用方负责发布。
func recordBlocked(ruleName string, extra ...string) []Event {
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
			start: now, topRule: map[string]int{}, topIP: map[string]int{}, topPath: map[string]int{},
			infoAt: blockedInfoAt, warnAt: warnAt, criticalAt: criticalAt,
		}
	}
	w := blockedCurrent
	w.count++
	if ruleName != "" {
		w.topRule[ruleName]++
	}
	if len(extra) > 0 && extra[0] != "" {
		w.topIP[extra[0]]++
	}
	if len(extra) > 1 {
		path := extra[1]
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if path != "" {
			w.topPath[path]++
		}
	}
	switch {
	case w.criticalAt > 0 && w.count >= w.criticalAt && !w.criticalSent:
		w.criticalSent = true
		return []Event{blockedEventAtLevel(w, LevelCritical)}
	case w.warnAt > 0 && w.count >= w.warnAt && !w.warnSent:
		w.warnSent = true
		return []Event{blockedEventAtLevel(w, LevelWarn)}
	case w.infoAt > 0 && w.count >= w.infoAt && !w.infoSent:
		w.infoSent = true
		return []Event{blockedEventAtLevel(w, LevelInfo)}
	}
	return nil
}

// RecordChallengeEvent 摄取到 action=challenged 事件时调用（主路径与 IPC
// 路径）。累加到已开启的拦截聚合窗口，并单独累计挑战统计窗口（≥50 次才
// 发 sec.challenge_summary；该事件默认关，避免挑战流量逐请求通知）。
func RecordChallengeEvent(reason, ip string) {
	blockedMu.Lock()
	if w := blockedCurrent; w != nil {
		w.challenges++
	}
	blockedMu.Unlock()
	recordChallengeSummary(challengeReasonLabel(reason), ip)
}

// challengeReasonLabel 挑战原因展示标签归一：摄取两条路径分别传机器 ID
// （cc_rps_spike / human_failed / WAF 规则号）与展示名（规则名），直接计数会
// 让 TOP 原因同时出现两种形态。已知机器 token 映射中文标签，数字规则号加
// 「规则 」前缀，其余（已是展示名）原样透传。
func challengeReasonLabel(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if _, err := strconv.Atoi(reason); err == nil {
		return "规则 " + reason
	}
	if token, ok := strings.CutPrefix(reason, "cc_"); ok {
		if label := ccChallengeReasonLabel(token); label != "" {
			return label
		}
		return "CC 挑战"
	}
	switch reason {
	case "human_failed":
		return "人机验证失败"
	case "human_challenge":
		return "人机验证挑战"
	case "cc_rate_reject":
		return "限流拒绝"
	}
	return reason
}

// ccChallengeReasonLabel CC 触发原因 token → 中文标签（与自动封禁备注同一
// 词表；notify 包不得反向依赖 services，故在本包维护展示映射）。
func ccChallengeReasonLabel(token string) string {
	switch token {
	case "session_anomaly":
		return "会话异常"
	case "rps_spike":
		return "突刺"
	case "4xx_ratio":
		return "4xx激增"
	}
	return ""
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
	if w.count < w.infoAt && w.warnAt > w.count && w.criticalAt > w.count {
		return nil // 低于最低阈值：不补发
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
// 1 跨度 2 拦截 3 挑战 4 自动封禁 5 TOP 规则 6 TOP IP 7 TOP 路径）。
func blockedEventAtLevel(w *blockedWindowState, level Level) Event {
	topStr := topCounts(w.topRule, 3, "×")
	topIP := topCounts(w.topIP, 3, "×")
	topPath := topCounts(w.topPath, 3, "×")
	span := blockedSpanLabel(time.Since(w.start))
	return Event{
		Type: EvtBlockedAggregate, Level: level,
		Title: "拦截聚合",
		Body: fmt.Sprintf("%s内拦截 %d 次 / 挑战 %d 次 / 自动封禁 %d 次（TOP 规则：%s；TOP IP：%s；TOP 路径：%s）",
			span, w.count, w.challenges, w.autobans, topStr, topIP, topPath),
		Fields: map[string]string{
			"1": span,
			"2": fmt.Sprint(w.count),
			"3": fmt.Sprint(w.challenges),
			"4": fmt.Sprint(w.autobans),
			"5": topStr,
			"6": topIP,
			"7": topPath,
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

func topCounts(m map[string]int, n int, sep string) string {
	out := topRules(m, n)
	if len(out) == 0 {
		return "无"
	}
	parts := make([]string, 0, len(out))
	for _, r := range out {
		parts = append(parts, fmt.Sprintf("%s%s%d", r.name, sep, r.count))
	}
	return strings.Join(parts, "、")
}

func topRules(m map[string]int, n int) []ruleCount {
	out := make([]ruleCount, 0, len(m))
	for k, v := range m {
		out = append(out, ruleCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].name < out[j].name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ---- 挑战统计窗口（sec.challenge_summary；默认关） ----

type challengeWindowState struct {
	start     time.Time
	count     int
	topReason map[string]int
	topIP     map[string]int
}

var (
	challengeMu        sync.Mutex
	challengeCurrent   *challengeWindowState
	challengeInitWheel sync.Once
)

func recordChallengeSummary(reason, ip string) {
	challengeInitWheel.Do(func() { go challengeFlushLoop() })
	challengeMu.Lock()
	defer challengeMu.Unlock()
	now := time.Now()
	if challengeCurrent == nil || now.Sub(challengeCurrent.start) >= blockedWindow {
		challengeCurrent = &challengeWindowState{start: now, topReason: map[string]int{}, topIP: map[string]int{}}
	}
	w := challengeCurrent
	w.count++
	if reason != "" {
		w.topReason[reason]++
	}
	if ip != "" {
		w.topIP[ip]++
	}
}

func challengeFlushLoop() {
	t := time.NewTicker(blockedWindow)
	defer t.Stop()
	for range t.C {
		flushChallengeWindow()
	}
}

func flushChallengeWindow() {
	challengeMu.Lock()
	w := challengeCurrent
	challengeCurrent = nil
	challengeMu.Unlock()
	if w == nil || w.count < challengeSummaryAt {
		return
	}
	span := blockedSpanLabel(time.Since(w.start))
	Publish(Event{
		Type: EvtChallengeSummary, Level: LevelWarn,
		Title: "挑战统计",
		Body: fmt.Sprintf("%s内挑战 %d 次（TOP 原因：%s；TOP IP：%s）",
			span, w.count, topCounts(w.topReason, 3, "×"), topCounts(w.topIP, 3, "×")),
		Fields: map[string]string{
			"1": span,
			"2": fmt.Sprint(w.count),
			"3": topCounts(w.topReason, 3, "×"),
			"4": topCounts(w.topIP, 3, "×"),
		},
	})
}
