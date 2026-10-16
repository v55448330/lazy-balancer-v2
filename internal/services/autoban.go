// Package services 自动封禁（F73-A）：WAF 事件固定窗口计数 → 阈值判定 →
// 「自动封禁名单」条目 merge → 引用面收敛（投影热路径优先，2026-10-15：
// 资格门——被启用策略引用（含受信代理网段引用面，同日热路径化，原
// 「∧非受信代理网段引用」排除合取项已退役）——命中即零 /load，@ipListFast
// 匹配器 ≤1s stat 热感知；未命中/不可判定/未证实收敛回退全量重载，60s 节流
// 暂存合并）。
//
// 窗口语义（AU-5 显式声明）：固定窗口按事件到达对齐分桶（桶长=统计窗口），
// 桶满跨界即重置——不是物理滑动的平滑窗口。跨桶边界的短时突发可能被分散到
// 相邻两桶（单桶计数低估瞬时速率），相邻桶也可接力累计（被高估）；语义真值
// 以「同一桶内累计」为准，UI/API 文案统一称「固定窗口」。
//
// 数据流：security-events-ingestion 提交点（securityEventsProcessPass 每批
// Commit 后）喂 autobanObserveBatch（主节点+启用+口径+WAF 事件四重过滤）→
// 固定窗口计数器；autoban 任务（60s 循环、主节点；调度唯一前提=业务启用——
// PUT 保存联动启停，Descriptor 无 EnabledFn，Run 体首行业务门兜底）每轮
// 评估候选并执行「观察建议或名单 merge」。merge 读改写+收敛全程持
// CaddyOpLock（AU-1：与 handlers 名单写路径互斥；两个注入回调均为 InLock
// 变体，临界区内直呼不得自取锁）。
//
// 名单形态：预置 security_ip_lists 行（system=1，name=自动封禁名单，DB entries）。
// 条目扩展 created_at/expires_at（RFC 墙钟串、UTC 存储）——投影层
// （loadIPListEntriesVia）过滤已到期条目，到期即「自动解封」；手动条目
// （remark≠自动封禁）永不被任务挤出。删除条目即解封（2026-10-15 用户裁定：
// 删除后重新达标会被再次封禁，无解封冷却）。
package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

const (
	// AutobanTaskID 任务 ID（taskengine 注册/任务监控/日志文件名共用）。
	AutobanTaskID = "autoban"
	// AutobanPresetListName 预置名单行名（迁移种子同字面值，db_autoban_migration_test 锚定）。
	AutobanPresetListName = "自动封禁名单"
	// AutobanEntryRemark 自动条目标记：merge 挤出与「今日封禁数」统计的唯一判据。
	AutobanEntryRemark = "自动封禁"
	// AutobanManualUnbanRemark 手动追加条目的默认备注（地址列表页手动封禁）。
	AutobanManualUnbanRemark = "手动封禁"
	// AutobanAuditAction 封禁审计动作名（merge 写点与 AutobanBannedToday
	// 计数共用单源——两处字面量漂移会让今日封禁恒 0）。
	AutobanAuditAction = "自动封禁"

	// autobanReloadThrottle 重载节流窗口：全量重载回退路径至少间隔 60s 才真实
	// 重载，窗口内的回退请求暂存合并到下一轮（投影热路径免节流——节流对象恒为
	// 全量重载，见 autobanConvergeLocked Ruling）。
	autobanReloadThrottle = time.Minute
	// autobanSuggestionCap 观察建议保留上限（按计数降序截断）。
	autobanSuggestionCap = 200
)

// autobanTimeLayout 名单条目时间戳形态（UTC 墙钟串，前端 parseDateValue 按
// DB datetime 同款 +Z 规范化消费）。
const autobanTimeLayout = "2006-01-02 15:04:05"

// autobanMaxTrackedIPs 计数器键上限（超限丢新键并告警一次）——攻击洪峰下
// 计数器内存有界（10 万键 × ~50B ≈ 5MB 量级）。
var autobanMaxTrackedIPs = 100000

// AutobanListEntryCap 名单条目上限（与 handlers ipListMaxEntries 同值——
// handlers 侧有钉测锁定相等；merge 超限时挤最早到期的自动条目，仍不足按
// 容量截断新封并落「容量收敛」留痕）。2026-10-14 用户裁定设大值（500→2000）。
var AutobanListEntryCap = 2000

// AutobanDuration/Clock/Scope：配置枚举与时长换算。
var autobanDurations = map[string]time.Duration{
	"10m":       10 * time.Minute,
	"30m":       30 * time.Minute,
	"1h":        time.Hour,
	"6h":        6 * time.Hour,
	"12h":       12 * time.Hour,
	"24h":       24 * time.Hour,
	"permanent": 0, // 永久：expires_at 留空
}

func ValidAutobanDuration(s string) bool { _, ok := autobanDurations[s]; return ok }
func ValidAutobanScope(s string) bool    { return s == "blocked" || s == "logged" || s == "all" }

// AutobanDurationLabel 时长枚举的展示文案（前端配置弹框同款语义）。
func AutobanDurationLabel(s string) string {
	switch s {
	case "permanent":
		return "永久"
	case "10m":
		return "10 分钟"
	case "30m":
		return "30 分钟"
	case "6h":
		return "6 小时"
	case "12h":
		return "12 小时"
	case "24h":
		return "24 小时"
	case "1h":
		return "1 小时"
	default:
		return s
	}
}

// AutobanConfig 六项配置（GET/PUT /security/autoban 载荷与任务/计数器共用形态）。
type AutobanConfig struct {
	Enabled       bool   `json:"enabled"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	Duration      string `json:"duration"`
	Scope         string `json:"scope"`
	DryRun        bool   `json:"dry_run"`
}

// autobanNow 时钟缝（测试注入时间轴）。
var autobanNow = func() time.Time { return time.Now().UTC() }

// autobanIsMaster 主节点缝（生产=引擎角色；测试可覆写）。
var autobanIsMaster = func() bool {
	te := TaskEngine()
	return te != nil && te.IsMaster()
}

// AutobanIsMaster autoban 调度面节点角色（/status is_master 数据源；与 Run 体
// 业务门/喂入门同源——引擎角色，测试缝可覆写）。
func AutobanIsMaster() bool { return autobanIsMaster() }

// autobanRecheckEnabled AB-2 复查缝（生产=直读 AutobanEnabled；钉测注入
// 「首读 false 后、复查前」的 PUT enabled=1 + StartLoop 交错窗）。
var autobanRecheckEnabled = AutobanEnabled

// autobanReloader 全量重载回调（fail-safe 回退路径：热路径资格门未命中/
// 不可判定/刷新器未注册/未证实收敛时使用；AU-1 契约：在 CaddyOpLock 临界区
// 内被调用，必须为 InLock 变体——生产=GenerateAndApplyConfigForceInLock，
// 不得注入自取 CaddyOpLock 的 Force 变体）。
var autobanReloader func() error

// autobanProjectionRefresher 投影热路径回调（main.go 注入
// CaddyService.RefreshIPListProjectionsInLock，2026-10-15 用户裁定）：资格门
// 命中后的零 /load 收敛——按已提交 DB 视图全量渲染（投影文件为渲染副作用，
// 原子落盘新内容）后与运行配置结构级比对。返回 (ProjectionConverged,nil)=已
// 证实收敛（匹配器 ≤1s stat 热感知）；ProjectionNeedForce（本轮渲染物化了
// 证书文件，第 76 轮 CERT-1）/ProjectionFallback（发射面变化/运行配置不可读）
// 或渲染被拒——调用方回退 autobanReloader 全量重载（InLock 强制形态，宁可
// 一次重载，不欠引用方渲染收敛，同时满足 R72 W1-1）。InLock 变体（AU-1：
// merge 读改写+收敛同一 CaddyOpLock 临界区内直呼，不得自取锁）。
var autobanProjectionRefresher func() (IPListProjectionOutcome, error)

// SetAutobanReloader 注册全量重载回调（nil=清除，测试用）。
func SetAutobanReloader(fn func() error) { autobanReloader = fn }

// SetAutobanEnabled 写自动封禁业务开关并同步任务调度；禁用前执行与设置页
// 相同的收尾，再 StopLoop，避免名单变化滞留。
func SetAutobanEnabled(enabled bool) error {
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, updated_at=datetime('now') WHERE id=1`, enabled); err != nil {
		return err
	}
	if !enabled {
		AutobanDisableFlush()
	}
	syncTaskLoop(AutobanTaskID, enabled)
	return nil
}

// SetAutobanProjectionRefresher 注册投影热路径回调（nil=清除，测试用）。
func SetAutobanProjectionRefresher(fn func() (IPListProjectionOutcome, error)) {
	autobanProjectionRefresher = fn
}

// ---- 配置读写 ----

// GetAutobanConfig 读六项配置（COALESCE 兜底默认值——存量行/带外 NULL 行归一）。
func GetAutobanConfig() AutobanConfig {
	cfg := AutobanConfig{Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}
	if db.DB == nil {
		return cfg
	}
	var en, threshold, window, dry int
	var duration, scope string
	err := db.DB.QueryRow(`SELECT COALESCE(autoban_enabled,0), COALESCE(autoban_threshold,100), COALESCE(autoban_window_minutes,5),
		COALESCE(autoban_duration,'1h'), COALESCE(autoban_scope,'all'), COALESCE(autoban_dry_run,1)
		FROM global_config WHERE id=1`).Scan(&en, &threshold, &window, &duration, &scope, &dry)
	if err != nil {
		return cfg
	}
	cfg.Enabled = en == 1
	cfg.Threshold = threshold
	cfg.WindowMinutes = window
	cfg.Duration = duration
	cfg.Scope = scope
	cfg.DryRun = dry == 1
	return cfg
}

// ValidateAutobanConfig 写侧校验：阈值 1-10000、窗口 1-60 分钟、时长/口径枚举。
//
// F75C-4（第 75 轮审计·设计评审，显式声明）：六列配置的三条归一通道语义
// **有意分歧**，各自贴合通道处境，不做统一——
//   - 保存侧（本函数，PUT /security/autoban）：**拒绝**——面板表单是用户
//     直接意图，非法值响亮 400 让用户改输入；
//   - 导入侧（handlers.validateV2BackupAutobanConfig）：**钳制/归一**——
//     备份是历史快照，越界数值钳到同边界、缺省形态归缺省、非空非法枚举
//     响亮拒绝（整包 400，与保存侧枚举口径一致）；钳制留痕并入导入审计；
//   - 回填侧（db 包启动回填 defaultUpdates）：**复位默认**——带外改库污染
//     无用户在场，启动时静默收敛到治理默认（双锚钉测对齐），运行期窗口内
//     由消费侧护栏（RunAutobanCycle）拒绝执行兜底。
//
// 三通道边界单源：本函数与 ValidAutobanDuration/ValidAutobanScope（db 包
// 不反向依赖，SQL 字面量与迁移 DDL DEFAULT 同款双锚）。
func ValidateAutobanConfig(cfg AutobanConfig) error {
	if cfg.Threshold < 1 || cfg.Threshold > 10000 {
		return errors.New("阈值须在 1-10000 之间")
	}
	if cfg.WindowMinutes < 1 || cfg.WindowMinutes > 60 {
		return errors.New("统计窗口须在 1-60 分钟之间")
	}
	if !ValidAutobanDuration(cfg.Duration) {
		return errors.New("封禁时长取值无效")
	}
	if !ValidAutobanScope(cfg.Scope) {
		return errors.New("统计口径取值无效")
	}
	return nil
}

// SetAutobanConfig 写六项配置；窗口/口径变更时重置计数器（口径语义变了，
// 旧计数不可与新口径混算）。
func SetAutobanConfig(cfg AutobanConfig) error {
	if err := ValidateAutobanConfig(cfg); err != nil {
		return err
	}
	prev := GetAutobanConfig()
	en, dry := 0, 0
	if cfg.Enabled {
		en = 1
	}
	if cfg.DryRun {
		dry = 1
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=?, autoban_window_minutes=?, autoban_duration=?, autoban_scope=?, autoban_dry_run=? WHERE id=1`,
		en, cfg.Threshold, cfg.WindowMinutes, cfg.Duration, cfg.Scope, dry); err != nil {
		return err
	}
	if prev.WindowMinutes != cfg.WindowMinutes || prev.Scope != cfg.Scope {
		ResetAutobanCounters()
	}
	return nil
}

// AutobanEnabled 业务开关（EnabledFn 数据源，fail-closed：读库失败=已停止）。
func AutobanEnabled() bool {
	if db.DB == nil {
		return false
	}
	var en int
	if err := db.DB.QueryRow(`SELECT COALESCE(autoban_enabled,0) FROM global_config WHERE id=1`).Scan(&en); err != nil {
		return false
	}
	return en == 1
}

// ---- 计数器（固定窗口） ----

type autobanCounter struct {
	Count       int
	WindowStart time.Time
	// LastSeen 窗口内末次命中（feed 更新点记录；建议列表「首末时间」数据源）。
	LastSeen time.Time
	// Reached 本窗口内已达到过封禁阈值（计数分级日志的判据：threshold 行
	// 每 IP 每窗口恰一行；窗口过期清零时若为真落 expire 行）。
	Reached bool
}

// autobanFeedItem 摄取提交点的最小喂入形态。
type autobanFeedItem struct {
	IP            string
	Action        string
	RuleTriggered string
}

var autobanMu sync.Mutex

// autobanWindows 固定桶计数器（ip → 窗口计数/窗口起点）。
var autobanWindows = make(map[string]*autobanCounter)

// autobanSuggestions 上一轮观察建议（dry-run；/status 建议列表数据源）。
var autobanSuggestions []AutobanSuggestion

// autobanReloadPending/autobanLastReload 重载节流状态；autobanCapWarned 上限告警单次留痕。
var autobanReloadPending bool
var autobanLastReload time.Time
var autobanCapWarned bool

// ResetAutobanCounters 清空计数器（口径/窗口变更/测试用）：计数桶+上一轮观察
// 建议一并清空——建议是同一窗口口径下的观察输出，口径变更/名单全量替换后旧
// 建议对现状失真（P5 同款 ≤1 tick 展示残留，第 77 轮定性并入）。
func ResetAutobanCounters() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows = make(map[string]*autobanCounter)
	autobanSuggestions = nil
}

// autobanActionMatches 口径过滤：scope=blocked 只统计拦截，logged 只统计检测，
// all 全统计。
func autobanActionMatches(scope, action string) bool {
	switch scope {
	case "blocked":
		return action == "blocked"
	case "logged":
		return action == "logged"
	default:
		return action == "blocked" || action == "logged"
	}
}

// autobanObserveBatch 摄取提交点喂入（每批 Commit 后调用）。四重门：主节点 +
// 启用 + WAF 事件（rule_triggered 非空）+ 口径。任一门不过整批跳过；批内
// 逐条按口径过滤。
func autobanObserveBatch(items []autobanFeedItem) {
	if len(items) == 0 || !autobanIsMaster() || !AutobanEnabled() {
		return
	}
	// AU-2（第 74 轮）：热路径每批只读一次配置——整份 cfg 下传单事件路径
	//（scope/window/threshold），不再逐事件 SELECT（O(事件) 库查询）。
	cfg := GetAutobanConfig()
	for _, it := range items {
		autobanObserveEventScoped(cfg, it.IP, it.Action, it.RuleTriggered)
	}
}

// autobanObserveEvent 单事件喂入（测试缝 AU-4：生产摄取只走 autobanObserveBatch；
// 本函数仅供测试驱动单事件计数行为）。门：主节点+启用+口径+WAF 事件；配置当轮直读。
func autobanObserveEvent(ip, action, ruleTriggered string) {
	if !autobanIsMaster() || !AutobanEnabled() || ruleTriggered == "" {
		return
	}
	autobanObserveEventScoped(GetAutobanConfig(), ip, action, ruleTriggered)
}

func autobanObserveEventScoped(cfg AutobanConfig, ip, action, ruleTriggered string) {
	// 窗口无效（<=0，D2 消费侧护栏）跳过计数——不落写死兜底（旧 5 分钟
	// 兜底已删，第 74 轮 D2-③）。
	window := time.Duration(cfg.WindowMinutes) * time.Minute
	if ip == "" || ruleTriggered == "" || window <= 0 || !autobanActionMatches(cfg.Scope, action) {
		return
	}
	now := autobanNow()
	var capWarn, expiredReached, thresholdHit bool
	var thresholdCount, thresholdWindowMin int
	autobanMu.Lock()
	w, exists := autobanWindows[ip]
	if !exists {
		if len(autobanWindows) >= autobanMaxTrackedIPs {
			capWarn = !autobanCapWarned
			autobanCapWarned = true
		} else {
			w = &autobanCounter{}
			autobanWindows[ip] = w
		}
	}
	if w != nil {
		if w.WindowStart.IsZero() || now.Sub(w.WindowStart) >= window {
			// 窗口过期清零：曾达标 IP 落一行 expire（计数分级日志，非逐事件）。
			expiredReached = w.Reached
			w.Count = 0
			w.WindowStart = now
			w.Reached = false
		}
		w.Count++
		w.LastSeen = now
		// 首次达到阈值 → 恰一行 threshold（跨阈值后不再重复记）。
		if !w.Reached && cfg.Threshold > 0 && w.Count >= cfg.Threshold {
			w.Reached = true
			thresholdHit = true
			thresholdCount = w.Count
			thresholdWindowMin = cfg.WindowMinutes
		}
	}
	autobanMu.Unlock()
	if capWarn {
		Logf("warn", "自动封禁计数器达 %d 键上限，新 IP 不再计数（既有键不受影响）", autobanMaxTrackedIPs)
	}
	if expiredReached {
		TaskLogf(AutobanTaskID, "expire", "IP %s 计数窗口过期，清零", ip)
	}
	if thresholdHit {
		TaskLogf(AutobanTaskID, "threshold", "IP %s 达到封禁阈值（%d 次/%d 分钟）", ip, thresholdCount, thresholdWindowMin)
	}
}

// AutobanSuggestion 观察建议/候选形态。
type AutobanSuggestion struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
	// WindowStart/LastSeen 窗口内首次/末次命中（feed 更新点记录；/status
	// 建议列表「窗口内首末时间」数据源）。
	WindowStart time.Time `json:"window_start"`
	LastSeen    time.Time `json:"last_seen"`
	// Location 归属地展示文本（仅 /status 建议列表富化：handlers 侧
	// enrichIPLocation 单源装填；引擎候选/审计路径不消费，恒空串）。
	Location string `json:"ip_location"`
}

// autobanCandidates 评估候选：先评估后修剪（AB-1，第 75 轮）——过期桶若计数
// 已跨阈值（桶尾达标形态：最后采样在窗口尾、周期 tick 晚于窗口到期）必须并入
// 候选再删，否则该 IP 永不封禁；未跨阈值的过期桶照常修剪不产生候选。曾达标
// IP 的过期桶修剪时落一行 expire（与 Feed 路径同文案——窗口过期清零的唯一
// 两条发射面）。
func autobanCandidates(threshold int, window time.Duration) []AutobanSuggestion {
	now := autobanNow()
	var expiredReached []string
	autobanMu.Lock()
	var expiredCandidates []AutobanSuggestion
	for ip, w := range autobanWindows {
		if !w.WindowStart.IsZero() && now.Sub(w.WindowStart) >= window {
			// AB-1：先评估——过期桶已跨阈值的并入候选，再删桶。
			if w.Count >= threshold {
				expiredCandidates = append(expiredCandidates, AutobanSuggestion{IP: ip, Count: w.Count, WindowStart: w.WindowStart, LastSeen: w.LastSeen})
			}
			if w.Reached {
				expiredReached = append(expiredReached, ip)
			}
			delete(autobanWindows, ip)
		}
	}
	var out []AutobanSuggestion
	for ip, w := range autobanWindows {
		if w.Count >= threshold {
			out = append(out, AutobanSuggestion{IP: ip, Count: w.Count, WindowStart: w.WindowStart, LastSeen: w.LastSeen})
		}
	}
	out = append(out, expiredCandidates...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > autobanSuggestionCap {
		out = out[:autobanSuggestionCap]
	}
	autobanMu.Unlock()
	for _, ip := range expiredReached {
		TaskLogf(AutobanTaskID, "expire", "IP %s 计数窗口过期，清零", ip)
	}
	return out
}

// autobanSuggestionDisplayCap /status 建议列表展示上限（Count 降序 Top N——
// 仅展示截断：审计/TaskLogf 消费 candidates 全量，不受影响）。
const autobanSuggestionDisplayCap = 50

// AutobanSuggestions 上一轮观察建议（/status 建议列表数据源；未运行过=空）。
// 展示截断：按 Count 降序 Top 50（2026-10-15 用户裁定——dry-run 洪峰下
// 前端逐行渲染有界）。
func AutobanSuggestions() []AutobanSuggestion {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	out := append([]AutobanSuggestion(nil), autobanSuggestions...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > autobanSuggestionDisplayCap {
		out = out[:autobanSuggestionDisplayCap]
	}
	return out
}

func autobanSetSuggestions(s []AutobanSuggestion) {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanSuggestions = s
}

// AutobanForgetIPs 解封侧计数清零（第 76 轮 F2/AB-1，用户裁定「删除即解封」
// 语义闭环）：从预置名单移除条目（remove-ip 端点、预置名单差集全量保存两条
// 解封路径）时调用——不清桶则窗口内旧计数（Count≥threshold 未过期）让下一
// 轮 merge 在零新流量下立即重封，解封在 ≤1 tick 内被撤销。清桶只重置旧计数：
// 新流量重新计数、重新达标仍会再封（apidocs「IP 重新达标会被再次封禁」口径
// 不变）。两解封路径共用本单一入口（新增解封面不得旁路）。
func AutobanForgetIPs(ips []string) {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	for _, ip := range ips {
		if ip != "" {
			delete(autobanWindows, ip)
		}
	}
	// P5（第 77 轮）：同步清 autobanSuggestions 对应 IP——建议列表是上一轮
	// 观察快照，解封后仍展示该 IP 是 ≤1 tick 的展示残留（下一轮 Run 才重算
	// 覆盖）；按值剔除，保留其余 IP 建议。
	if len(autobanSuggestions) > 0 && len(ips) > 0 {
		gone := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			if ip != "" {
				gone[ip] = struct{}{}
			}
		}
		kept := autobanSuggestions[:0]
		for _, s := range autobanSuggestions {
			if _, drop := gone[s.IP]; !drop {
				kept = append(kept, s)
			}
		}
		autobanSuggestions = kept
	}
}

// AutobanSetSuggestionsForTest 直设建议暂存（handlers 层富化钉测用；nil=清空，
// 与 SetAutobanReloader 同款测试缝约定）。
func AutobanSetSuggestionsForTest(s []AutobanSuggestion) {
	autobanSetSuggestions(s)
}

// AutobanSeedCounterForTest 直填计数桶（handlers 层接线钉测用——绕过喂入门
// 主节点/启用/口径三重门，桶形态与 Feed 路径产出一致）。
func AutobanSeedCounterForTest(ip string, count, threshold int) {
	now := autobanNow()
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows[ip] = &autobanCounter{Count: count, WindowStart: now, LastSeen: now, Reached: threshold > 0 && count >= threshold}
}

// ---- 名单 merge ----

// autobanMergeOutcome 单轮 merge 结果（TaskLogf 摘要与审计数据源）。
type autobanMergeOutcome struct {
	ListID     int64
	Expired    []string // 到期自动解封的 IP
	Banned     []string // 本轮新封禁的 IP
	Evicted    int      // 超限挤出的自动条目数
	DroppedNew int      // 容量不足丢弃的新封数
	Total      int      // merge 后名单总条数
	Changed    bool
}

// parseAutobanEntryTime 解析条目时间戳（UTC 墙钟串）；畸形视为零值（调用方
// 按无时间处理——到期过滤只认可解析且 <= now 的值，畸形 expires_at 保留条目
// 不误删）。
func parseAutobanEntryTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	ts, err := time.ParseInLocation(autobanTimeLayout, s, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return ts
}

// autobanMergeEntries 单次 merge（纯 DB 侧，无重载/审计副作用——便于钉测）：
// 清到期 → 已在名单过滤 → 追加新封 → 超限挤最早到期自动条目 → 回写。
func autobanMergeEntries(cfg AutobanConfig, candidates []AutobanSuggestion) (autobanMergeOutcome, error) {
	var out autobanMergeOutcome
	if db.DB == nil {
		return out, errors.New("数据库未初始化")
	}
	now := autobanNow()
	nowStr := now.Format(autobanTimeLayout)
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&id); err != nil {
		return out, fmt.Errorf("预置名单「%s」不存在: %w", AutobanPresetListName, err)
	}
	out.ListID = id
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		return out, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return out, fmt.Errorf("预置名单条目解析失败: %w", err)
	}

	// 1) 清到期（到期即解封）；不可解析的 expires_at 保留（fail-open 不误删）。
	kept := make([]models.IPListEntry, 0, len(entries))
	inList := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if exp := parseAutobanEntryTime(e.ExpiresAt); !exp.IsZero() && !exp.After(now) {
			out.Expired = append(out.Expired, e.Value)
			out.Changed = true
			continue
		}
		kept = append(kept, e)
		inList[e.Value] = struct{}{}
	}

	// 2) 新封过滤：已在名单跳过；其余追加（permanent 不带 expires_at）。
	duration := autobanDurations[cfg.Duration]
	var toAdd []models.IPListEntry
	for _, c := range candidates {
		if c.IP == "" {
			continue
		}
		if _, exists := inList[c.IP]; exists {
			continue
		}
		entry := models.IPListEntry{Value: c.IP, Remark: AutobanEntryRemark, CreatedAt: nowStr}
		if duration > 0 {
			entry.ExpiresAt = now.Add(duration).Format(autobanTimeLayout)
		}
		toAdd = append(toAdd, entry)
		inList[c.IP] = struct{}{}
	}

	// 3) 容量收敛：先挤「最早到期的自动条目」（永久自动条目次之），手动条目
	//（remark≠自动封禁）不挤；仍不足丢弃剩余新封。
	evict := func() (models.IPListEntry, bool) {
		var victimIdx = -1
		var victimTime time.Time
		var victimPermanent bool
		for i, e := range kept {
			if e.Remark != AutobanEntryRemark {
				continue
			}
			exp := parseAutobanEntryTime(e.ExpiresAt)
			perm := exp.IsZero()
			if victimIdx == -1 {
				victimIdx, victimTime, victimPermanent = i, exp, perm
				continue
			}
			// 挤出序：有到期时间者按到期升序先挤；永久条目排在所有有到期者之后。
			switch {
			case !perm && victimPermanent:
				victimIdx, victimTime, victimPermanent = i, exp, perm
			case !perm && !victimPermanent && exp.Before(victimTime):
				victimIdx, victimTime, victimPermanent = i, exp, perm
			case perm && victimPermanent:
				// 两个永久条目：按 created_at 更早者先挤
				if cur := parseAutobanEntryTime(e.CreatedAt); !cur.IsZero() {
					if vk := parseAutobanEntryTime(kept[victimIdx].CreatedAt); vk.IsZero() || cur.Before(vk) {
						victimIdx = i
					}
				}
			}
		}
		if victimIdx == -1 {
			return models.IPListEntry{}, false
		}
		victim := kept[victimIdx]
		kept = append(kept[:victimIdx], kept[victimIdx+1:]...)
		return victim, true
	}
	for len(kept)+len(toAdd) > AutobanListEntryCap {
		if victim, ok := evict(); ok {
			out.Evicted++
			out.Changed = true
			_ = victim
			continue
		}
		// 自动条目已无可挤（kept 全手动或已清空）且总量仍超限：按容量截断
		// 新封（候选按计数降序，高计数优先保留），其余丢弃并计数入 DroppedNew
		//（容量收敛可观测：挤出/丢弃数随本轮 WARN 行与审计行落痕）。
		keep := AutobanListEntryCap - len(kept)
		if keep < 0 {
			keep = 0
		}
		out.DroppedNew = len(toAdd) - keep
		toAdd = toAdd[:keep]
		break
	}

	// 4) 落库（有变化时）。
	kept = append(kept, toAdd...)
	out.Total = len(kept)
	if len(toAdd) > 0 {
		out.Banned = make([]string, len(toAdd))
		for i, e := range toAdd {
			out.Banned[i] = e.Value
		}
		out.Changed = true
	}
	if !out.Changed {
		return out, nil
	}
	merged, err := json.Marshal(kept)
	if err != nil {
		return out, err
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=?, updated_by=0, updated_at=? WHERE id=?`, string(merged), nowStr, id); err != nil {
		return out, err
	}
	return out, nil
}

// ---- 重载节流 ----

// autobanReloadState 本轮收敛请求的终态（D4：摘要尾注与暂存标记一致——
// 失败时不得宣称「已触发」）。热路径收敛（HotApplied）是「已收敛」的零重载
// 形态，审计真实性：不落「重载」系统审计、尾注不宣称已重载。
type autobanReloadState int

const (
	autobanReloadNone       autobanReloadState = iota // 无名单变化，未请求收敛
	autobanReloadApplied                              // 已重载（全量链收敛）
	autobanReloadHotApplied                           // 投影热路径收敛（零重载，匹配器 ≤1s 热感知）
	autobanReloadDeferred                             // 节流窗口内，暂存至下一轮合并执行（仅全量重载回退路径）
	autobanReloadErrored                              // 全量重载失败（已留审计+置暂存再武装）
)

// autobanMarkReloadFailed 重载失败统一处置（D4，镜像 threat_reload_pending）：
// 系统重载审计留痕 + 置暂存再武装（下一轮 flush/重新启用后重试）。
func autobanMarkReloadFailed(reason string, err error) {
	recordSystemReloadAudit("autoban", err)
	autobanMu.Lock()
	autobanReloadPending = true
	autobanMu.Unlock()
	Logf("error", "自动封禁名单重载失败（%s，已置暂存待重试）: %v", reason, err)
}

// autobanListHotPathEligible 热路径资格门（与手动名单写路径同一查询核心
// 单源）：被启用策略引用（ip_acl_list_refs/ip_whitelist_refs）∪ 受信代理
// 网段引用（trusted_proxy_range_refs，tp.txt 投影消费）∪ CRS 排除
// scope=ip/list 条目的 ListRefs（p<id>-crsxc-N 投影消费）——引用面补全见
// ipListsReferencedByEnabledPolicyLabeled（第 76 轮 SEC-2）。查询/解析失败
// 按「被引用」处理（fail-closed——宁可回退一次全量重载，不欠引用方渲染
// 收敛）。
func autobanListHotPathEligible(listID int64) bool {
	if listID <= 0 {
		return false
	}
	return ipListsReferencedByEnabledPolicyLabeled("自动封禁", []int{int(listID)})
}

// autobanConvergeLocked 名单内容变化（merge 新封/清到期/容量挤出）后的生效
// 路径（热路径优先，2026-10-15 用户裁定）：
//   - 资格门命中 ∧ 投影刷新器已注册 → 投影热路径（零 /load，@ipListFast
//     匹配器 ≤1s stat 热感知）→ HotApplied；
//   - 资格未命中/不可判定/刷新器未注册/未证实收敛（发射面变化/运行配置不可
//     读/渲染被拒）→ 回退既有全量重载（autobanRequestReloadLocked 单源：
//     60s 节流+暂存+失败再武装语义原样）。
//
// 节流 Ruling：节流（60s 窗口+暂存合并+禁用豁免强制）的存在理由是压制全量
// /load 的成本与扰断，节流对象恒为「全量重载回退路径」。投影热路径是毫秒级
// 幂等操作（渲染+字节比对+投影文件原子落盘），无 Caddy 重载扰断，且收敛只
// 发生在 60s 任务周期/禁用收尾两个节拍上——天然限频无风暴可节流 → 热路径
// 免节流、不消费 autobanLastReload 记账（窗口会计专属全量重载，防后续回退
// 重载被热路径无谓推迟）。Applied/Deferred/Errored 三态原样保留给回退路径。
//
// 调用契约（AU-1）：调用方已持 CaddyOpLock（merge 读改写+收敛同一临界区），
// 本函数不得再取锁。
func autobanConvergeLocked(reason string, listID int64) autobanReloadState {
	if autobanProjectionRefresher != nil && autobanListHotPathEligible(listID) {
		hot, err := autobanProjectionRefresher()
		if err == nil && hot == ProjectionConverged {
			Logf("info", "自动封禁名单变化经投影热路径收敛（零 Caddy 重载，匹配器 ≤1s 热感知生效）")
			return autobanReloadHotApplied
		}
		// 未证实收敛/刷新被拒 → 回退 /load 收敛——宁可一次重载，不欠引用方
		// 渲染收敛（fail-safe 与威胁库收敛门同向）。NeedForce（本轮渲染物化
		// 了证书文件，第 76 轮 CERT-1）同样回退：回退回调为强制形态
		// （GenerateAndApplyConfigForceInLock），击穿 errSameConfig 让新证书
		// 进 Caddy 内存；Ruling：NeedForce 走既有 60s 节流暂存可接受——证书
		// 续期与封禁写撞车是小概率事件，收敛延迟上界=下一轮周期（60s）。
		Logf("info", "自动封禁投影热路径未证实收敛（发射面变化/证书物化或刷新失败），回退重载 Caddy 配置")
	}
	return autobanRequestReloadLocked(reason)
}

// autobanRequestReloadLocked 名单变化后请求全量重载（热路径回退路径）：距上次
// 真实重载 ≥60s 立即执行，否则置暂存（下一轮 Run 的 autobanFlushPendingReload
// 合并执行）。调用契约（AU-1）：调用方已持 CaddyOpLock（merge 读改写+收敛
// 同一临界区），注入回调为 InLock 变体——本函数不得再取 CaddyOpLock。
func autobanRequestReloadLocked(reason string) autobanReloadState {
	if autobanReloader == nil {
		return autobanReloadNone
	}
	autobanMu.Lock()
	now := autobanNow()
	if !autobanLastReload.IsZero() && now.Sub(autobanLastReload) < autobanReloadThrottle {
		autobanReloadPending = true
		autobanMu.Unlock()
		return autobanReloadDeferred
	}
	autobanLastReload = now
	autobanMu.Unlock()
	if err := autobanReloader(); err != nil {
		autobanMarkReloadFailed(reason, err)
		return autobanReloadErrored
	}
	recordSystemReloadAudit("autoban", nil)
	return autobanReloadApplied
}

// autobanFlushPendingReload Run 轮首调用：暂存重载在节流窗口外时合并执行
// （此处自取 CaddyOpLock——重载回调为 InLock 变体，须与 handler 写路径互斥）。
func autobanFlushPendingReload() {
	autobanMu.Lock()
	if !autobanReloadPending || autobanReloader == nil {
		autobanMu.Unlock()
		return
	}
	if !autobanLastReload.IsZero() && autobanNow().Sub(autobanLastReload) < autobanReloadThrottle {
		autobanMu.Unlock()
		return
	}
	autobanReloadPending = false
	autobanLastReload = autobanNow()
	autobanMu.Unlock()
	CaddyOpLock.Lock()
	err := autobanReloader()
	CaddyOpLock.Unlock()
	if err != nil {
		autobanMarkReloadFailed("暂存重载", err)
		return
	}
	recordSystemReloadAudit("autoban", nil)
}

// autobanForceFlushPendingReload 暂存重载的节流豁免收敛（仅禁用路径：此后
// 无下一轮 flush 点，禁用前暂存的变化必须立即落盘生效；常规路径走
// autobanFlushPendingReload 的节流约束）。
func autobanForceFlushPendingReload() {
	autobanMu.Lock()
	if !autobanReloadPending || autobanReloader == nil {
		autobanMu.Unlock()
		return
	}
	autobanReloadPending = false
	autobanLastReload = autobanNow()
	autobanMu.Unlock()
	CaddyOpLock.Lock()
	err := autobanReloader()
	CaddyOpLock.Unlock()
	if err != nil {
		autobanMarkReloadFailed("禁用收尾强制重载", err)
		return
	}
	recordSystemReloadAudit("autoban", nil)
}

// AutobanDisableFlush 禁用路径收尾（AU-8/D5，PUT 保存 enabled=false 后、
// StopLoop 前调用）：①到期自动条目清理一次（禁用后无循环清理点——最后一批
// 已到期条目立即解封并留「自动解封」审计）；②暂存重载强制收敛一次（绕过节流
// ——禁用前节流暂存的名单变化与本次清理变化必须落盘生效）。重载失败按 D4
// 留痕+保持暂存（重新启用后下一轮 flush 重试）。
func AutobanDisableFlush() {
	cfg := GetAutobanConfig()
	CaddyOpLock.Lock()
	out, err := autobanMergeEntries(cfg, nil)
	if err == nil && out.Changed {
		autobanAuditExpiredUnban(out.Expired)
		autobanConvergeLocked("自动封禁禁用收尾", out.ListID)
	}
	CaddyOpLock.Unlock()
	autobanForceFlushPendingReload()
}

// ---- Run 循环 ----

// RunAutobanCycle 单轮执行（引擎 autoban 任务体）：业务门（未启用=失败+重禁
// 调度）→ 配置护栏（无效=失败+自停）→ 修剪计数器 → 评估候选（dry-run 锁外；
// 正式模式并入下方 merge 的 CaddyOpLock 临界区，PM-2 第 77 轮）→ 观察建议或
// 名单 merge → 审计/重载/每轮摘要行。
//
// 业务门（2026-10-14 用户裁定）：本任务只能由「启用后按配置调度执行」——
// Descriptor 不设 EnabledFn（调度面无业务门，任务监控 enabled 列恒开，启停
// 语义全在调度开关+事件页业务开关），未启用期间的手动开调度/手动触发到
// Run 体首行拦下：落痕+落 failed 行+StopLoop 重禁调度，防未启用空转续跑。
// AB-2（第 75 轮）：StopLoop 前复查一次——首读 false 与停环之间存在
// 「PUT enabled=1 + StartLoop」交错窗，无条件停环会把并发重新启用的新调度
// 误杀（enabled=1 而调度停，无自动恢复）；复查仍 false 才停，复查转 true
// 视为已被并发启用、本轮按启用继续。残留窗收窄至复查与 StopLoop 之间，
// 彻底消除需引擎代际令牌（不在本修复范围）。
func RunAutobanCycle(rc taskengine.RunContext) error {
	if !AutobanEnabled() && !autobanRecheckEnabled() {
		if te := TaskEngine(); te != nil {
			te.StopLoop(AutobanTaskID)
		}
		TaskLogf(AutobanTaskID, "manual", "手动调度，执行失败：未启用")
		return errors.New("自动封禁未启用，已停止调度（请先在安全事件页配置中启用）")
	}
	cfg := GetAutobanConfig()
	// D2③（第 74 轮审计）：消费侧护栏——直读配置执行前显式校验（库值唯一真相
	// 铁律：无效值拒绝执行+显性报错，禁止静默兜底）。threshold<=0 会让
	// 「count>=threshold」把全量候选收进名单；duration 非法经 autobanDurations
	// 查表得 0 被当「永久」（候选全落永久封禁条目）；window<=0 让窗口失真。
	// 带外脏行由启动回填（db.go defaultUpdates 六列）在下次启动收敛；校验单源
	// 复用写侧 ValidateAutobanConfig（导入/写侧/消费侧三通道同一口径——通道
	// 语义差异见 ValidateAutobanConfig 注释，F75C-4）。
	// AB-3（第 75 轮 Ruling=自停）：无效配置是带外污染造成的**持续态**（保存
	// 侧与导入侧各自归一后不可再产生），每轮拒绝=无意义空转（约 1440 条
	// failed 行/天）——与业务门同构：留痕（WARN+failed 行）后 StopLoop；恢复
	// 路径=PUT 保存有效配置（校验过即联动 StartLoop）或重启（启动回填收敛）。
	if err := ValidateAutobanConfig(cfg); err != nil {
		TaskLogfWarn(AutobanTaskID, "config", "配置无效，已拒绝执行并停止调度：%v", err)
		if te := TaskEngine(); te != nil {
			te.StopLoop(AutobanTaskID)
		}
		return fmt.Errorf("自动封禁配置无效，已停止调度：%v（修正配置并保存后恢复；库值可能被带外写入污染，重启后启动回填将收敛）", err)
	}
	window := time.Duration(cfg.WindowMinutes) * time.Minute
	autobanFlushPendingReload()

	if cfg.DryRun {
		// 观察模式不写名单，无 TOCTOU 面——候选评估无需临界区。
		candidates := autobanCandidates(cfg.Threshold, window)
		autobanSetSuggestions(candidates)
		TaskLogf(AutobanTaskID, "cycle", "观察模式：计数 %d IP / 活跃 %d 个 IP / 达阈值 %d（阈值 %d 次/%d 分钟，口径 %s）",
			autobanTrackedCount(), autobanReachedCount(), len(candidates), cfg.Threshold, cfg.WindowMinutes, autobanScopeLabel(cfg.Scope))
		return nil
	}

	var candidates []AutobanSuggestion
	var out autobanMergeOutcome
	reloadState := autobanReloadNone
	// AU-1（第 74 轮）：merge 读改写+收敛并入同一 CaddyOpLock 临界区——与
	// handlers 名单写路径（AddIPToList/UpdateIPList 持 caddyOpMu=CaddyOpLock
	// 的读改写）交错会丢更新/复活条目；收敛回调（投影热路径/全量重载）均为
	// InLock 变体，临界区内直呼。
	// PM-2（第 77 轮）：候选评估（autobanCandidates，含 AB-1 过期桶先评估再删）
	// 同入本临界区——曾评估在锁外、merge 进锁用陈旧候选：handlers 解封（持
	// CaddyOpLock 的读改写+AutobanForgetIPs 清桶）落在「候选已评估」与「进锁
	// merge」之间时，本轮把刚解封的 IP 加回名单，解封被 ≤1 tick 撤销。评估入
	// 临界区后，解封清桶与本轮评估在锁上全序：解封先完成则候选为空（不回封），
	// 本轮先完成则解封写路径随后删条目（解封生效）。锁序安全：临界区内仅
	// autobanMu（叶锁，全仓无 autobanMu→CaddyOpLock 反向嵌套）。
	if err := func() error {
		CaddyOpLock.Lock()
		defer CaddyOpLock.Unlock()
		candidates = autobanCandidates(cfg.Threshold, window)
		o, err := autobanMergeEntries(cfg, candidates)
		if err != nil {
			return err
		}
		out = o
		if out.Changed {
			reloadState = autobanConvergeLocked("名单更新", out.ListID)
		}
		return nil
	}(); err != nil {
		return err
	}
	autobanSetSuggestions(nil)
	if out.Changed {
		// 审计逐 IP「自动封禁」+ 每批「到期自动解封」汇总（系统操作者）。
		for _, ip := range out.Banned {
			RecordAuditLog("system", AutobanAuditAction, "IP 地址列表",
				FormatAuditDetail("IP："+ip,
					fmt.Sprintf("命中：%d 次/%d 分钟", cfg.Threshold, cfg.WindowMinutes),
					"时长："+AutobanDurationLabel(cfg.Duration),
					AuditResultPart("success")), "")
		}
		autobanAuditExpiredUnban(out.Expired)
		if out.Evicted > 0 || out.DroppedNew > 0 {
			// 容量收敛可观测（2026-10-14 用户裁定）：发生挤出/丢弃的那轮落
			// WARN 级任务日志行（含计数）+ 系统操作者审计行。
			TaskLogfWarn(AutobanTaskID, "capacity", "自动封禁名单容量收敛：挤出 %d、丢弃 %d（上限 %d）",
				out.Evicted, out.DroppedNew, AutobanListEntryCap)
			RecordAuditLog("system", "容量收敛", "IP 地址列表",
				fmt.Sprintf("自动封禁容量收敛：挤出 %d、丢弃 %d（上限 %d）", out.Evicted, out.DroppedNew, AutobanListEntryCap), "")
		}
	}
	TaskLogf(AutobanTaskID, "cycle", "本轮：计数 %d IP / 活跃 %d 个 IP / 候选 %d / 新封 %d / 到期解封 %d / 名单 %d 条%s",
		autobanTrackedCount(), autobanReachedCount(), len(candidates), len(out.Banned), len(out.Expired), out.Total, reloadNote(out.Changed, reloadState))
	return nil
}

// autobanAuditExpiredUnban 到期自动解封审计（Run 轮与禁用收尾共用单一实现，
// 系统操作者归因）。
func autobanAuditExpiredUnban(ips []string) {
	if len(ips) == 0 {
		return
	}
	RecordAuditLog("system", "自动解封", "IP 地址列表",
		fmt.Sprintf("到期自动解封 %d 个 IP：%s", len(ips), strings.Join(ips, "、")), "")
}

func reloadNote(changed bool, state autobanReloadState) string {
	if !changed {
		return ""
	}
	switch state {
	case autobanReloadHotApplied:
		return "（投影热路径收敛，零重载）"
	case autobanReloadApplied:
		return "（已重载）"
	case autobanReloadDeferred:
		return "（重载暂存，下一轮合并执行）"
	case autobanReloadErrored:
		return "（重载失败，已留痕待重试）"
	default:
		return ""
	}
}

func autobanScopeLabel(scope string) string {
	switch scope {
	case "blocked":
		return "仅拦截"
	case "logged":
		return "仅检测"
	default:
		return "全部"
	}
}

func autobanTrackedCount() int {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	return len(autobanWindows)
}

// autobanReachedCount 当前窗口内已达到过封禁阈值的 IP 数（每轮摘要行
// 「活跃 M 个 IP」——与 threshold/expire 分级行同一集合口径）。
func autobanReachedCount() int {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	n := 0
	for _, w := range autobanWindows {
		if w.Reached {
			n++
		}
	}
	return n
}

// AutobanTrackedIPs 当前计数器键数（/status tracked_ips）。
func AutobanTrackedIPs() int { return autobanTrackedCount() }

// ---- Status 辅助 ----

// AutobanListEntries 预置名单条目与名单 ID（/status 名单条数与前端条目管理数据源）。
func AutobanListEntries() ([]models.IPListEntry, int64, error) {
	if db.DB == nil {
		return nil, 0, errors.New("数据库未初始化")
	}
	var id int64
	var raw string
	if err := db.DB.QueryRow(`SELECT id, COALESCE(entries,'[]') FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&id, &raw); err != nil {
		return nil, 0, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, id, err
	}
	return entries, id, nil
}

// autobanEntryExpired 条目到期判定（AB-4 第 75 轮：与渲染投影层
// loadIPListEntriesVia 的 F73-A 过滤共用单一判据——expires_at 可解析且
// <= now 视为已到期；空/畸形 expires_at 保留条目不误删）。
func autobanEntryExpired(e models.IPListEntry, now time.Time) bool {
	if e.ExpiresAt == "" {
		return false
	}
	exp := parseAutobanEntryTime(e.ExpiresAt)
	return !exp.IsZero() && !exp.After(now)
}

// AutobanActiveEntries 生效条目视图（AB-4 第 75 轮）：过滤已到期未清理条目
// ——/status list_entries 与渲染生效面同口径，Run 轮清理间隙不再虚高。
func AutobanActiveEntries(entries []models.IPListEntry) []models.IPListEntry {
	now := autobanNow()
	active := make([]models.IPListEntry, 0, len(entries))
	for _, e := range entries {
		if !autobanEntryExpired(e, now) {
			active = append(active, e)
		}
	}
	return active
}

// AutobanBannedToday 今日自动封禁数（事件性统计，2026-10-15 用户裁定）：
// 审计留痕中今天的「自动封禁」系统动作次数——与名单现状解耦，删除条目/
// 到期解封不回退今日计数，同 IP 重新封禁累计次数。数据源=audit_log
// （created_at UTC 墙钟串，action/created_at 双索引；默认保留 3 个月，
// 覆盖当日）；审计库未初始化/查询失败按 0（状态卡统计位容错）。
func AutobanBannedToday() int {
	if db.AuditDB == nil {
		return 0
	}
	loc := CurrentLocation()
	now := autobanNow().In(loc)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC().Format(autobanTimeLayout)
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND created_at >= ?`, AutobanAuditAction, dayStart).Scan(&n); err != nil {
		return 0
	}
	return n
}
