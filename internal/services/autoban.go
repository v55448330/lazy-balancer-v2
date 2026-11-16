// Package services 自动封禁：WAF 事件固定窗口计数 → 阈值判定 →
// 「自动封禁名单」条目 merge → 引用面收敛（投影热路径优先，2026-10-15：
// 资格门——被启用策略引用（含受信代理网段引用面，同日热路径化，原
// 「∧非受信代理网段引用」排除合取项已退役）——命中即零 /load，@ipListFast
// 匹配器 ≤1s stat 热感知；未命中/不可判定/未证实收敛回退全量重载，60s 节流
// 暂存合并）。
//
// 窗口语义：固定窗口按事件到达对齐分桶（桶长=统计窗口），
// 桶满跨界即重置——不是物理滑动的平滑窗口。跨桶边界的短时突发可能被分散到
// 相邻两桶（单桶计数低估瞬时速率），相邻桶也可接力累计（被高估）；语义真值
// 以「同一桶内累计」为准，UI/API 文案统一称「固定窗口」。
//
// 数据流：security-events-ingestion 提交点（securityEventsProcessPass 每批
// Commit 后）喂 autobanObserveBatch（主节点+启用+口径+WAF 阶段 3 事件五重
// 过滤）→
// 固定窗口计数器；autoban 任务（60s 循环、主节点；调度唯一前提=业务启用——
// PUT 保存联动启停，Descriptor 无 EnabledFn，Run 体首行业务门兜底）每轮
// 评估候选并执行「观察建议或名单 merge」。merge 读改写+收敛全程持
// CaddyOpLock（与 handlers 名单写路径互斥；两个注入回调均为 InLock
// 变体，临界区内直呼不得自取锁）。
//
// 名单形态：预置 security_ip_lists 行（system=1，name=自动封禁名单，DB entries）。
// 条目扩展 created_at/expires_at（RFC 墙钟串、UTC 存储）——投影层
// （loadIPListEntriesVia）过滤已到期条目，到期即「自动解封」；手动条目
// （remark≠自动封禁）永不被任务挤出。删除条目即解封（2026-10-15 用户裁定：
// 删除后重新达标会被再次封禁，无解封冷却）。
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

const (
	// AutobanTaskID 任务 ID（taskengine 注册/任务监控/日志文件名共用）。
	AutobanTaskID = "autoban"
	// AutobanFeedTaskID 自动封禁计数的唯一喂入源（安全事件采集 daemon，
	// 与 taskengine 注册 ID 同源（securityEventsIngestionTaskID）——摄取批次
	// 提交后 autobanObserveBatch 喂入；健康联动见 AutobanFeedHealth）。
	AutobanFeedTaskID = securityEventsIngestionTaskID
	// AutobanPresetListName 预置名单行名（迁移种子同字面值，db_autoban_migration_test 锚定）。
	AutobanPresetListName = "自动封禁名单"
	// autobanPresetListDescription 预置行描述（db 播种文案同字面值；描述禁改，
	// 运行期自愈补建时须与播种一致）。
	autobanPresetListDescription = "自动封禁命中 IP（自动封禁任务维护；可手动追加或删除条目）"
	// autobanEntryRemark 自动条目标记：merge 挤出与「今日封禁数」统计的唯一
	// 判据。仅包内消费（跨包不得引用——地址列表页手动封禁/解封判定用
	// AutobanManualUnbanRemark），导出会让读者误以为是跨包契约。
	autobanEntryRemark = "自动封禁"
	// AutobanManualUnbanRemark 手动追加条目的默认备注（地址列表页手动封禁）。
	AutobanManualUnbanRemark = "手动封禁"
	// AutobanAuditAction 封禁审计动作名（merge 写点与 AutobanBannedToday
	// 计数共用单源——两处字面量漂移会让今日封禁恒 0）。
	AutobanAuditAction = "自动封禁"
	// autobanAuditSummaryPrefix 是单轮汇总行 detail 的机器可读前缀：前缀后紧跟
	// 被省略的逐条记录数（形如「汇总：其余 300 个 IP 省略逐条记录（本轮共 800 个
	// IP，逐条上限 500；…）」）。AutobanBannedToday 按「逐 IP 行各 1 + 汇总行
	// 省略数」相加补齐单轮逐条上限丢掉的部分——汇总文案可改说明段，但不得改变
	// 「前缀 + 省略数」这个开头。
	autobanAuditSummaryPrefix = "汇总：其余 "

	// autobanReloadThrottle 重载节流窗口：全量重载回退路径至少间隔 60s 才真实
	// 重载，窗口内的回退请求暂存合并到下一轮（投影热路径免节流——节流对象恒为
	// 全量重载，见 autobanConvergeLocked Ruling）。
	autobanReloadThrottle = time.Minute
	// autobanSuggestionCap 观察建议保留上限（按计数降序截断）。
	//
	// 保留用途：这是「暂存量」而非展示口径——展示层由 AutobanSuggestions
	// 再截 Top 50（autobanSuggestionDisplayCap，2026-10-15 用户裁定），本层
	// 在两者之间给解封剔除（AutobanForgetIPs 逐条扫描）与暂存内存一个有界
	// 上限；正式 merge 不经过本层（评估全量消费）。已知观测边界：dry-run
	// TaskLog 的「达阈值 N」计数取截断后长度，>200 洪峰时该值为 200 且无
	// 「+N 省略」注记——截断本身在任何可达输出都不可观测（展示恒 ≤50），
	// 排障时以 /status 的 tracked/reached 计数为准，勿以建议条数反推洪峰量。
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

// autobanAuditPerRoundCap 单轮逐 IP「自动封禁」审计行上限。逐 IP 留痕是
// 可追溯性裁定（2026-09-14/15 审计可见性强化链）的默认形态，正常规模不
// 触发；（首次启用/容量刚释放时）单轮 2000 个 IP 同时达标会一次写 2000 行
// 审计——审计库按 3 个月保留，洪峰下写放大与体积不可控。超限时保留前 N 条
// 逐 IP 行并补一条汇总行（点名总数与省略数）；完整名单始终以预置 IP 列表
// 为准。今日封禁计数不依赖逐 IP 行数：汇总行携带本轮总数，AutobanBannedToday
// 按「逐 IP 行 + 汇总总数」相加，省略部分不会从统计里消失。
var autobanAuditPerRoundCap = 500

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

// AutobanEscalation* 累犯渐进升级档位：off=固定时长（现行行为，默认）；
// standard=首次配置时长→二次 24h→三次+永久；aggressive=首次配置时长→
// 二次+永久。累犯按封禁身份键（autobanIdentityKey）记账于 autoban_recidivism。
const (
	AutobanEscalationOff        = "off"
	AutobanEscalationStandard   = "standard"
	AutobanEscalationAggressive = "aggressive"
)

var autobanEscalations = map[string]bool{
	AutobanEscalationOff:        true,
	AutobanEscalationStandard:   true,
	AutobanEscalationAggressive: true,
}

// ValidAutobanEscalation 升级档位枚举校验（写侧/导入/消费侧三通道同口径单源）。
func ValidAutobanEscalation(s string) bool { return autobanEscalations[s] }

// AutobanEscalationOrOff 把缺省形态（空串=旧客户端/旧调用方未携带该字段）
// 归一为 off；显式值原样返回（非法值交由 ValidateAutobanConfig 拒绝）。
// 写侧入口（PUT 绑定/SetAutobanConfig）共用本单源，保证「缺省=off」口径
// 不在两处漂移。
func AutobanEscalationOrOff(s string) string {
	if s == "" {
		return AutobanEscalationOff
	}
	return s
}

// 证据分层计数模式（classic=四口径等权存量语义；evidence=确证/嫌疑双累加器）。
const (
	AutobanCountingClassic  = "classic"
	AutobanCountingEvidence = "evidence"
)

var autobanCountingModes = map[string]bool{
	AutobanCountingClassic:  true,
	AutobanCountingEvidence: true,
}

// ValidAutobanCountingMode 计数模式枚举校验（写侧/导入/消费侧三通道同口径）。
func ValidAutobanCountingMode(s string) bool { return autobanCountingModes[s] }

// AutobanCountingModeOrClassic 把缺省形态（空串=旧客户端未携带）归一 classic；
// 显式值原样返回（非法值交 ValidateAutobanConfig 拒绝）。
func AutobanCountingModeOrClassic(s string) string {
	if s == "" {
		return AutobanCountingClassic
	}
	return s
}

// 嫌疑倍率域 [2,20]（1 会退化等权、上限防嫌疑通道虚设）与确证打底枚举
// {0.2,0.4,0.6}（离散档避免自由小数配置面）。
const (
	AutobanSuspicionMultiplierMin = 2
	AutobanSuspicionMultiplierMax = 20
)

// AutobanSuspicionMultiplierOrDefault 缺省形态（0=旧客户端未携带）归一默认；
// 默认值直绑 db 治理常量（DDL DEFAULT/启动回填/读侧 COALESCE 同一单源，
// 禁止私抄字面量副本）；显式越界交 ValidateAutobanConfig 拒绝。
func AutobanSuspicionMultiplierOrDefault(n int) int {
	if n == 0 {
		return db.DefaultAutobanSuspicionMultiplier
	}
	return n
}

// AutobanConfirmFloorRatioOrDefault 缺省形态（空串）归一默认（直绑 db 治理
// 常量，与倍率同口径单源）。
func AutobanConfirmFloorRatioOrDefault(s string) string {
	if s == "" {
		return db.DefaultAutobanConfirmFloorRatio
	}
	return s
}

var autobanConfirmFloorRatios = map[string]bool{"0.2": true, "0.4": true, "0.6": true}

// ValidAutobanConfirmFloorRatio 打底比例枚举校验。
func ValidAutobanConfirmFloorRatio(s string) bool { return autobanConfirmFloorRatios[s] }

// autobanConfirmFloorPermille 把打底比例枚举解析为千分比整数（避免浮点）：
// "0.2"→200,"0.4"→400,"0.6"→600。非法值返回 0（调用方须先校验）。
func autobanConfirmFloorPermille(s string) int {
	switch s {
	case "0.2":
		return 200
	case "0.4":
		return 400
	case "0.6":
		return 600
	}
	return 0
}

// autobanScopeIsConfirmed 报告口径维度是否属攻击确证组（blocked/challenge_failed）；
// logged/challenge_issued 属嫌疑组。证据分层计数分组单源。
func autobanScopeIsConfirmed(dim string) bool {
	return dim == AutobanScopeBlocked || dim == AutobanScopeChallengeFailed
}

// autobanEvidenceFloor 确证打底门槛 = ceil(T1 × 打底比例)（千分比整数避免浮点）。
// T1>=1 且比例>0 时 floor>=1——纯嫌疑（确证 0）永不达标。
func autobanEvidenceFloor(threshold int, floorRatio string) int {
	permille := autobanConfirmFloorPermille(floorRatio)
	return (threshold*permille + 999) / 1000
}

// autobanEvidenceReached 证据分层达标判定：
// 确证 >= T1（快通道）OR（确证 >= 打底 AND 确证+嫌疑 >= T1×倍率）。
func autobanEvidenceReached(confirmed, suspicion, threshold, multiplier int, floorRatio string) bool {
	if threshold <= 0 {
		return false
	}
	if confirmed >= threshold {
		return true
	}
	floor := autobanEvidenceFloor(threshold, floorRatio)
	t2 := threshold * multiplier
	return confirmed >= floor && confirmed+suspicion >= t2
}

// 自动封禁统计口径四维度（2026-11-13 用户裁定：单选改多选）。scope 存逗号
// 分隔集合；挑战发放/失败拆为独立维度（证据强度不同），count_human_failed
// 开关退役（语义并入 challenge_failed）。
const (
	AutobanScopeBlocked         = "blocked"
	AutobanScopeLogged          = "logged"
	AutobanScopeChallengeIssued = "challenge_issued"
	AutobanScopeChallengeFailed = "challenge_failed"
)

var autobanScopeDimensions = map[string]bool{
	AutobanScopeBlocked:         true,
	AutobanScopeLogged:          true,
	AutobanScopeChallengeIssued: true,
	AutobanScopeChallengeFailed: true,
}

// AutobanScopeSet 解析逗号分隔口径集合为成员表（去空白；非法/重复成员由
// ValidAutobanScope 在写侧拒绝，本函数只做解析）。
func AutobanScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, part := range strings.Split(scope, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			set[part] = true
		}
	}
	return set
}

// ValidAutobanScope 口径集合校验：非空、成员均为四维度之一、无重复。
func ValidAutobanScope(s string) bool {
	parts := strings.Split(s, ",")
	seen := make(map[string]bool, len(parts))
	count := 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || !autobanScopeDimensions[part] || seen[part] {
			return false
		}
		seen[part] = true
		count++
	}
	return count > 0
}

// MigrateLegacyAutobanScope 把旧单值口径（blocked/logged/all）+ count_human_failed
// 开关映射为新四维集合（2026-11-13 用户裁定）。已是新集合形态原样返回；
// 非法值（非旧单值也非新集合）原样返回，交由写侧/导入校验响亮拒绝——
// 迁移不得把损坏值伪装成合法默认。映射：blocked→blocked；logged→logged；
// all→blocked,logged（开关开再追加 challenge_failed）。供 db 启动迁移与备份导入共用单源。
func MigrateLegacyAutobanScope(scope string, countHumanFailed bool) string {
	if ValidAutobanScope(scope) {
		return scope
	}
	switch strings.TrimSpace(scope) {
	case "blocked":
		return AutobanScopeBlocked
	case "logged":
		return AutobanScopeLogged
	case "all":
		if countHumanFailed {
			return AutobanScopeBlocked + "," + AutobanScopeLogged + "," + AutobanScopeChallengeFailed
		}
		return AutobanScopeBlocked + "," + AutobanScopeLogged
	default:
		return scope // 非法值原样返回，校验拒绝
	}
}

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

// AutobanConfig 十项配置（GET/PUT /security/autoban 载荷与任务/计数器共用形态）。
// Scope 为逗号分隔口径集合（blocked/logged/challenge_issued/challenge_failed，
// 2026-11-13 用户裁定多选）；count_human_failed 开关退役，语义并入 challenge_failed。
// Escalation 为累犯渐进升级档位（off/standard/aggressive，默认 off）。
type AutobanConfig struct {
	Enabled       bool   `json:"enabled"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	Duration      string `json:"duration"`
	Scope         string `json:"scope"`
	DryRun        bool   `json:"dry_run"`
	Escalation    string `json:"escalation"`
	// 证据分层计数：classic=四口径等权（默认，存量语义）；evidence=确证/嫌疑
	// 双累加器 + 打底门槛。倍率/打底仅在 evidence 下参与判定。
	CountingMode        string `json:"counting_mode"`
	SuspicionMultiplier int    `json:"suspicion_multiplier"`
	ConfirmFloorRatio   string `json:"confirm_floor_ratio"`
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

// autobanRecheckEnabled 复查缝（生产=直读 AutobanEnabled；钉测注入
// 「首读 false 后、复查前」的 PUT enabled=1 + StartLoop 交错窗）。
var autobanRecheckEnabled = AutobanEnabled

// autobanReloader 全量重载回调（fail-safe 回退路径：热路径资格门未命中/
// 不可判定/刷新器未注册/未证实收敛时使用；契约：在 CaddyOpLock 临界区
// 内被调用，必须为 InLock 变体——生产=GenerateAndApplyConfigForceInLock，
// 不得注入自取 CaddyOpLock 的 Force 变体）。
var autobanReloader func() error

// autobanProjectionRefresher 投影热路径回调（main.go 注入
// CaddyService.RefreshIPListProjectionsInLock，2026-10-15 用户裁定）：资格门
// 命中后的零 /load 收敛——按已提交 DB 视图全量渲染（投影文件为渲染副作用，
// 原子落盘新内容）后与运行配置结构级比对。返回 (ProjectionConverged,nil)=已
// 证实收敛（匹配器 ≤1s stat 热感知）；ProjectionNeedForce（本轮渲染物化了
// 证书文件）/ProjectionFallback（发射面变化/运行配置不可读）
// 或渲染被拒——调用方回退 autobanReloader 全量重载（InLock 强制形态，宁可
// 一次重载，不欠引用方渲染收敛，同时满足）。InLock 变体
// merge 读改写+收敛同一 CaddyOpLock 临界区内直呼，不得自取锁）。
var autobanProjectionRefresher func() (IPListProjectionOutcome, error)

// SetAutobanReloader 注册全量重载回调（nil=清除，测试用）。
func SetAutobanReloader(fn func() error) { autobanReloader = fn }

// SetAutobanProjectionRefresher 注册投影热路径回调（nil=清除，测试用）。
func SetAutobanProjectionRefresher(fn func() (IPListProjectionOutcome, error)) {
	autobanProjectionRefresher = fn
}

// ---- 配置读写 ----

// AutobanConfigQuerier 是十列读取的最小依赖面（库句柄或已开启的事务）。
// 事务形态是备份导入的必需用法：导入在写事务内比对「导入前」运行值，
// 事务外读 live 会与已开启的写事务争同一连接（单连接池下自锁）。
type AutobanConfigQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ReadAutobanConfigFrom 在调用方给定的视图上读十列（COALESCE 仅归一存量
// NULL；读失败显性返回错误）。GetAutobanConfig 与导入侧共用本单源——
// 两份手写 SELECT 的列/COALESCE 默认值漂移会让导入侧比对出假的「配置变化」。
func ReadAutobanConfigFrom(ctx context.Context, q AutobanConfigQuerier) (AutobanConfig, error) {
	var en, threshold, window, dry, mult int
	var duration, scope, escalation, mode, floor string
	err := q.QueryRowContext(ctx, `SELECT COALESCE(autoban_enabled,?), COALESCE(autoban_threshold,?),
		COALESCE(autoban_window_minutes,?), COALESCE(autoban_duration,?), COALESCE(autoban_scope,?), COALESCE(autoban_dry_run,?), COALESCE(autoban_escalation,?),
		COALESCE(autoban_counting_mode,?), COALESCE(autoban_suspicion_multiplier,?), COALESCE(autoban_confirm_floor_ratio,?)
		FROM global_config WHERE id=1`,
		db.DefaultAutobanEnabled, db.DefaultAutobanThreshold, db.DefaultAutobanWindowMinutes,
		db.DefaultAutobanDuration, db.DefaultAutobanScope, db.DefaultAutobanDryRun, db.DefaultAutobanEscalation,
		db.DefaultAutobanCountingMode, db.DefaultAutobanSuspicionMultiplier, db.DefaultAutobanConfirmFloorRatio).Scan(
		&en, &threshold, &window, &duration, &scope, &dry, &escalation, &mode, &mult, &floor)
	if err != nil {
		return AutobanConfig{}, err
	}
	return AutobanConfig{
		Enabled:             en == 1,
		Threshold:           threshold,
		WindowMinutes:       window,
		Duration:            duration,
		Scope:               scope,
		DryRun:              dry == 1,
		Escalation:          escalation,
		CountingMode:        mode,
		SuspicionMultiplier: mult,
		ConfirmFloorRatio:   floor,
	}, nil
}

// GetAutobanConfig 读十项配置（COALESCE 仅归一存量 NULL；读失败显性返回错误）。
func GetAutobanConfig() (AutobanConfig, error) {
	cfg := AutobanConfig{
		Threshold:           db.DefaultAutobanThreshold,
		WindowMinutes:       db.DefaultAutobanWindowMinutes,
		Duration:            db.DefaultAutobanDuration,
		Scope:               db.DefaultAutobanScope,
		DryRun:              db.DefaultAutobanDryRun == 1,
		Escalation:          db.DefaultAutobanEscalation,
		CountingMode:        db.DefaultAutobanCountingMode,
		SuspicionMultiplier: db.DefaultAutobanSuspicionMultiplier,
		ConfirmFloorRatio:   db.DefaultAutobanConfirmFloorRatio,
	}
	if db.DB == nil {
		return cfg, errors.New("自动封禁配置数据库未装配")
	}
	read, err := ReadAutobanConfigFrom(context.Background(), db.DB)
	if err != nil {
		return cfg, err
	}
	return read, nil
}

// ValidateAutobanConfig 写侧校验：阈值 1-10000、窗口 1-60 分钟、时长/口径/升级枚举。
//
// 历史设计评审（显式声明）：十列配置的三条归一通道语义
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
// 三通道边界单源：本函数与 ValidAutobanDuration/ValidAutobanScope/
// ValidAutobanEscalation（db 包不反向依赖，SQL 字面量与迁移 DDL DEFAULT 同款双锚）。
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
	if !ValidAutobanEscalation(cfg.Escalation) {
		return errors.New("累犯升级取值无效")
	}
	// 证据分层三字段：缺省形态（空模式/0 倍率/空比例=旧调用方未携带）在
	// 校验内归一默认——直调 Validate 的部分配置（既有测试/内部构造）不因
	// 新字段缺省而误拒；显式非法值仍响亮拒绝。写侧入口另先归一（幂等）。
	mode := AutobanCountingModeOrClassic(cfg.CountingMode)
	mult := AutobanSuspicionMultiplierOrDefault(cfg.SuspicionMultiplier)
	floor := AutobanConfirmFloorRatioOrDefault(cfg.ConfirmFloorRatio)
	if !ValidAutobanCountingMode(mode) {
		return errors.New("计数模式取值无效")
	}
	if mult < AutobanSuspicionMultiplierMin || mult > AutobanSuspicionMultiplierMax {
		return fmt.Errorf("嫌疑累计倍率须在 %d-%d 之间", AutobanSuspicionMultiplierMin, AutobanSuspicionMultiplierMax)
	}
	if !ValidAutobanConfirmFloorRatio(floor) {
		return errors.New("确证打底比例取值无效")
	}
	return nil
}

// SetAutobanConfig 写十项配置；窗口/口径变更时重置计数器（口径语义
// 变了，旧计数不可与新口径混算）。禁用（enabled=false）同样清空计数桶与观察
// 建议——停用期无喂入，陈旧计数不得在重新启用后立即封禁（见下方调用点注释）。
// Escalation 缺省（空串=旧客户端/旧调用方未携带该字段）归一为 off——保持
// 固定时长现行行为；显式非法值仍由 ValidateAutobanConfig 响亮拒绝。
func SetAutobanConfig(cfg AutobanConfig) error {
	cfg.Escalation = AutobanEscalationOrOff(cfg.Escalation)
	cfg.CountingMode = AutobanCountingModeOrClassic(cfg.CountingMode)
	cfg.SuspicionMultiplier = AutobanSuspicionMultiplierOrDefault(cfg.SuspicionMultiplier)
	cfg.ConfirmFloorRatio = AutobanConfirmFloorRatioOrDefault(cfg.ConfirmFloorRatio)
	if err := ValidateAutobanConfig(cfg); err != nil {
		return err
	}
	prev, err := GetAutobanConfig()
	if err != nil {
		return fmt.Errorf("读取自动封禁配置失败: %w", err)
	}
	en, dry := 0, 0
	if cfg.Enabled {
		en = 1
	}
	if cfg.DryRun {
		dry = 1
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=?, autoban_window_minutes=?, autoban_duration=?, autoban_scope=?, autoban_dry_run=?, autoban_escalation=?, autoban_counting_mode=?, autoban_suspicion_multiplier=?, autoban_confirm_floor_ratio=? WHERE id=1`,
		en, cfg.Threshold, cfg.WindowMinutes, cfg.Duration, cfg.Scope, dry, cfg.Escalation,
		cfg.CountingMode, cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio); err != nil {
		return err
	}
	// 运行期收敛（清桶/重算 Reached/禁用收尾/调度联动）与备份导入提交后
	// 共用同一单源——十列有第二条写入路径（导入/还原的通用
	// `UPDATE global_config`），各自内联判断会让不变量在导入面静默失效。
	ReconcileAutobanRuntimeAfterConfigReplace(prev, cfg)
	return nil
}

// autobanConfigReplaceEffects 是「十列配置已被替换」后的运行期收敛判定。
// 单源：ReconcileAutobanRuntimeAfterConfigReplace 的动作与
// AutobanConfigReplaceEffectNote 的文案共用本判定（判定与文案漂移会让
// 「响应说清了桶」与「实际清桶」分叉）。
type autobanConfigReplaceEffects struct {
	// resetCounters：口径/窗口变更 → 旧计数不可与新口径混算。
	resetCounters bool
	// recomputeReached：阈值变更 → 重算「已达阈值」读口径。
	recomputeReached bool
	// disableFlush：新配置为禁用 → 到期条目解封收尾 + 清桶。判据是
	// 「保存后处于停用态」而非「真实翻转」：停用期保存/导入同样必须清掉已到期
	// 条目（否则过期条目会一直挂在名单里），这是既有契约。
	// 「已停用再保存」与「真实翻转」的区别只体现在用户可读说明上：仅真实翻转
	// 才声称「已执行禁用收尾」（见 AutobanConfigReplaceEffectNote 的
	// disableFlushTransition）。
	disableFlush bool
	// disableFlushTransition：本次保存是 enabled→disabled 的真实翻转（用于文案，
	// 不复用为动作门——动作门必须覆盖停用期保存）。
	disableFlushTransition bool
	// loopToggled：启用态翻转 → 调度随之启停。
	loopToggled bool
}

func autobanConfigReplaceEffectsOf(old, new AutobanConfig) autobanConfigReplaceEffects {
	effect := autobanConfigReplaceEffects{
		resetCounters: old.WindowMinutes != new.WindowMinutes || old.Scope != new.Scope ||
			old.CountingMode != new.CountingMode ||
			old.SuspicionMultiplier != new.SuspicionMultiplier ||
			old.ConfirmFloorRatio != new.ConfirmFloorRatio,
		recomputeReached:       old.Threshold != new.Threshold,
		disableFlush:           !new.Enabled,
		disableFlushTransition: old.Enabled && !new.Enabled,
		loopToggled:            old.Enabled != new.Enabled,
	}
	return effect
}

// ReconcileAutobanRuntimeAfterConfigReplace 在「十列自动封禁配置已被替换」之后
// 收敛运行期状态（单源：PUT 保存 / 备份导入-还原提交后）。old/new 分别为
// 替换前后的运行值；调用方只需保证替换已完成（本函数不写库）。
//
// 前置条件：调用方**未持** CaddyOpLock——禁用收尾会自取（非重入锁，已在
// Caddy 临界区内调用必须在释放锁之后再调本函数）。
//
// 动作语义：
//   - 口径（scope）/统计窗口变更 → 清空固定窗口计数桶与观察建议：
//     旧计数按新口径不可混算（口径过滤集合变了、桶长也变了）；
//   - 仅阈值变更 → 保留计数桶（窗口内证据不丢），只重算 Reached：该标记是
//     按「feed 当时阈值」单向置真的读口径，不重算会让 /status「达阈值 M 个」
//     与过期摘要滞后到下一个窗口（调低阈值后已达标 IP 仍不计入，调高短期
//     多报）；封禁候选评估本就用实时 Count>=threshold，不受该标记影响；
//   - 禁用 → 先做到期清理（保留「自动解封」语义），再清空整表计数桶：禁用
//     期间无喂入，陈旧桶会跨越任意长度的停用期，停用数天/数周后重新启用会
//     以旧计数立即封禁并从这里重算封禁起点/时长；
//   - 启用态 → 调度联动（应用值在锁内按库实态读取，本参数仅作读失败回退）。
func ReconcileAutobanRuntimeAfterConfigReplace(old, new AutobanConfig) {
	effect := autobanConfigReplaceEffectsOf(old, new)
	if effect.resetCounters {
		ResetAutobanCounters()
	} else if effect.recomputeReached {
		autobanRecomputeReached(new)
	}
	if effect.disableFlush {
		AutobanDisableFlush()
		ResetAutobanCounters()
	}
	// 调度应用走与业务驱动整轮对齐共用的互斥（避免「库新/loop 旧」交错）。
	applyBusinessTaskLoop(AutobanTaskID, new.Enabled)
}

// AutobanConfigReplaceEffectNote 返回「替换十列后运行期收敛动作」的用户可读
// 说明（导入/还原响应的 warnings 与成功审计单源）；无收敛动作（十列相同，
// 或仅时长/观察模式变化）时返回空串。
func AutobanConfigReplaceEffectNote(old, new AutobanConfig) string {
	effect := autobanConfigReplaceEffectsOf(old, new)
	parts := []string{}
	if effect.resetCounters {
		parts = append(parts, fmt.Sprintf("统计窗口/口径由 %d 分钟/%s 改为 %d 分钟/%s，已清空自动封禁统计计数（旧计数不适用于新口径）",
			old.WindowMinutes, old.Scope, new.WindowMinutes, new.Scope))
	} else if effect.recomputeReached {
		parts = append(parts, fmt.Sprintf("封禁阈值由 %d 改为 %d，已按新阈值重算统计达标标记", old.Threshold, new.Threshold))
	}
	if effect.disableFlushTransition {
		parts = append(parts, "自动封禁已停用，已执行禁用收尾（到期条目解封、统计计数清空）")
	} else if effect.disableFlush {
		parts = append(parts, "自动封禁处于停用态，已清理到期条目并清空统计计数")
	} else if effect.loopToggled {
		parts = append(parts, "自动封禁已启用，调度已按新配置开启")
	}
	if len(parts) == 0 {
		return ""
	}
	return "自动封禁配置变更：" + strings.Join(parts, "；")
}

// AutobanEnabled 业务开关（EnabledFn 数据源，fail-closed：读库失败=已停止）。
func AutobanEnabled() bool {
	enabled, known := autobanEnabledState()
	return known && enabled
}

// autobanEnabledState 业务开关三态读取：known=false 表示启用状态不可判定
// （DB 不可读/瞬断）。调度面（EnabledFn）用 AutobanEnabled 的二态 fail-closed
// 口径；Run 体业务门必须区分「确认未启用」与「不可判定」——后者按失败落定
// 且不得停环（瞬时读错误不得把已启用的任务永久停调度），与角色读取
// （updateRunRole 三态）同口径。
//
// 读失败必须留痕（与 AutoBackupEnabledState/globalTaskAutoUpdateState 单源
// 状态转换同口径）：此前静默 fail-closed 让「库故障」与「用户关闭」在调度面
// 完全同形（零执行、零失败行、零日志）。
func autobanEnabledState() (enabled, known bool) {
	d := db.GetDB()
	if d == nil {
		return false, false
	}
	var en int
	if err := d.QueryRow(`SELECT COALESCE(autoban_enabled,0) FROM global_config WHERE id=1`).Scan(&en); err != nil {
		logScheduleReadFailure("schedule-read-autoban-enabled", err)
		return false, false
	}
	logScheduleReadRecovered("schedule-read-autoban-enabled")
	return en == 1, true
}

// ---- 计数器（固定窗口） ----

type autobanCounter struct {
	Count       int
	WindowStart time.Time
	// LastSeen 窗口内末次命中（feed 更新点记录；建议列表「首末时间」数据源）。
	LastSeen time.Time
	// Reached 本窗口内已达到过封禁阈值（窗口过期清零时用于 expire 汇总行
	// 的「达阈值」明细与 /status 的达阈值 IP 计数；热路径喂入不写任何分级
	// 日志——每轮只有 Run 的汇总行「活跃 M 个 IP」）。
	Reached bool
	// Reasons 窗口内按触发原因类别计数（有限键集=autobanBanReasonOrder，
	// 非无界增长）——候选主原因归因数据源，窗口滚动随 Count 一并清零。
	Reasons map[string]int
	// Confirmed/Suspicion 证据分层双累加器（仅 evidence 模式写入）：
	// 确证=blocked+challenge_failed；嫌疑=logged+challenge_issued。
	// Count 恒等于二者之和（排序/展示复用）；classic 模式二者恒 0。
	Confirmed int
	Suspicion int
}

// autobanBanReasonOrder 原因类别固定优先序（平局裁决：人机>会话异常>CC
// 拦截>CRS>自定义，拦截>检测>挑战）——候选主原因取窗口内计数最多类别，
// 平局按此序。键集即桶 Reasons 的有限键域；新增类别须同步 autobanBanReason 分类。
var autobanBanReasonOrder = []string{
	"人机验证失败", "人机验证挑战",
	"会话异常", "突刺", "4xx激增", "限流拒绝",
	"CRS拦截", "CRS检测",
	"自定义规则拦截", "自定义规则检测",
}

// autobanBanReason 把喂入事件的 action×rule_triggered 归类为封禁原因文本
// （名单条目备注消费）。值域=喂入点实际可达形态（阶段 3 族门内：人机两态
// + CRS/自定义 × blocked/logged；人机通道豁免族门的 blocked×cc_rate_reject
// =限流拒绝）；未知形态返回空串（merge 降级占位符）。
// 备注是存储层数据非 UI 词条，中文常量直存（与「事件处置」「手动封禁」同口径）。
func autobanBanReason(action, ruleTriggered string) string {
	switch {
	case action == "challenged" && ruleTriggered == "human_failed":
		return "人机验证失败"
	case action == "challenged" && ruleTriggered == "human_challenge":
		return "人机验证挑战"
	case action == "challenged" && strings.HasPrefix(ruleTriggered, "cc_"):
		return AutobanCCTriggerReasonLabel(strings.TrimPrefix(ruleTriggered, "cc_"))
	case action == "blocked" && ruleTriggered == "cc_rate_reject":
		// CC reject（429）经人机通道喂 blocked 口径（族门豁免）——归因
		// 「限流拒绝」，与事件 rule_msg「限流拒绝（429）」同族语义。
		return "限流拒绝"
	case securityEventsRuleIsCRSFamily(ruleTriggered):
		if action == "blocked" {
			return "CRS拦截"
		}
		if action == "logged" {
			return "CRS检测"
		}
	case securityEventsRuleIsCustomFamily(ruleTriggered):
		if action == "blocked" {
			return "自定义规则拦截"
		}
		if action == "logged" {
			return "自定义规则检测"
		}
	}
	return ""
}

// AutobanCCTriggerReasonLabel CC 触发原因 token → 中文标签单源（lbhuman
// evalCC 的 Reason 值域：rps_spike/4xx_ratio/session_anomaly）。条目备注
// 与事件 rule_msg 共用；未知 token 返回空串（不污染归因）。
func AutobanCCTriggerReasonLabel(reason string) string {
	switch reason {
	case "session_anomaly":
		return "会话异常"
	case "rps_spike":
		return "突刺"
	case "4xx_ratio":
		return "4xx激增"
	}
	return ""
}

// autobanDominantReason 窗口内主原因：计数最多类别，平局按固定优先序
// （autobanBanReasonOrder）；空桶返回空串。
func autobanDominantReason(reasons map[string]int) string {
	best, bestCount := "", 0
	for _, r := range autobanBanReasonOrder {
		if c := reasons[r]; c > bestCount {
			best, bestCount = r, c
		}
	}
	return best
}

// autobanEntryIsAutomatic 自动条目判据（merge 挤出/到期手动豁免单源）：
// 存量占位符「自动封禁」、原因词表形态、「累犯·」前缀形态均识别为自动
// 条目——备注升级为具体原因后判据不得把自动条目误判为手动（挤出/清理/
// 豁免错乱）。手动备注（「手动封禁」「事件处置」/自定义文本）不命中。
func autobanEntryIsAutomatic(e models.IPListEntry) bool {
	if e.Remark == autobanEntryRemark {
		return true
	}
	remark := strings.TrimPrefix(e.Remark, "累犯·")
	for _, r := range autobanBanReasonOrder {
		if remark == r {
			return true
		}
	}
	return false
}

// autobanFeedItem 摄取提交点的最小喂入形态。
type autobanFeedItem struct {
	IP            string
	Action        string
	RuleTriggered string
	At            time.Time
	// TrustExempt 表示该 logged 事件来自规则绑定的信任 IP（含 stage0 保留
	// 检测）。生产喂入侧按规则信任并集计算；direct test seam 恒 false。
	TrustExempt bool
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

// autobanFeedDegradedWarned 上一轮是否已就「喂入源停摆」告警（转换沿单次留痕，
// 防 60s 周期刷屏；恢复时记一次恢复行）。
var autobanFeedDegradedWarned bool

// AutobanFeedHealth 报告自动封禁数据源（安全事件采集 daemon）的健康状态
// 计数器唯一喂入点是摄取批次提交后的 autobanObserveBatch——该提交钩子由
// 「IPC 主路径」与「尾读/补采」两条通道共用。任务调度只拥有后者：任务停止
// 只暂停 spool 补采与审计日志轮转，实时 IPC 入库仍直接提交并继续喂入计数。
// 因此降级原因不得由任务态推断「计数停止增长」（把补采停止说成采集停止会
// 让用户按错误前提做容量/排障决策）。
//
// 判据（持久停摆才降级）：LoopOn=false 是用户显式停止与「异常自愈预算用尽后
// 停环」的共同终态（引擎 restartExhausted 同时置 LoopOn=false）；瞬时态
// （LoopOn=true 而 Run 正处于 1s/5s/30s 重拉退避）不报——自愈通道仍在。
// 判据单源=securityEventsIngestionTaskState（健康位复用同一函数，禁止在此
// 另写一份 Running/LoopOn 组合）。
// 引擎未装配/任务未注册=不判定（测试与装配早期，避免误报）。
//
// 调度态之外叠加摄取健康位：摄取循环对 tick 失败只记账不退出（LoopOn 恒
// true），metrics 库写失败/磁盘满等形态下补采停摆、待补采事件进不了库（也就
// 还没进计数器），而调度态一切正常——单看调度态是「健康位分裂」型静默失效。
// 摄取健康快照已含写侧降级折算；stalled 停等瞬态不入失败计数，不会误报。
func AutobanFeedHealth() (degraded bool, reason string) {
	task := securityEventsIngestionTaskState()
	switch {
	case task.State == "unknown":
		return false, ""
	case task.RestartExhausted:
		return true, "安全事件补采任务异常自愈预算已用尽并停止调度：spool 补采与审计日志轮转已暂停，实时 IPC 入库仍在运行（自动封禁计数仍会随实时事件增长）"
	case task.State == "stopped":
		return true, "安全事件补采任务调度已停止：spool 补采与审计日志轮转已暂停，实时 IPC 入库仍在运行（自动封禁计数仍会随实时事件增长）"
	}
	if st := SecurityEventsIngestionHealthSnapshot(); st.Observed && !st.Healthy {
		if st.LastError != "" {
			return true, "安全事件补采/审计日志轮转异常：待补采事件可能未入库，自动封禁计数可能偏少（实时 IPC 入库仍在运行；" + st.LastError + "）"
		}
		return true, "安全事件补采/审计日志轮转处于非健康状态（补采任务停止或写侧持续失败）：自动封禁计数可能偏少（实时 IPC 入库仍在运行）"
	}
	return false, ""
}

// autobanReportFeedHealth 喂入源健康的状态变化留痕（RunAutobanCycle 每轮调用）：
// 降级沿 Warn 一次、恢复沿 Info 一次。不自动拉起用户显式停止的任务（尊重调度
// 语义，只做可见性——见 AutobanFeedHealth）。
func autobanReportFeedHealth(degraded bool, reason string) {
	autobanMu.Lock()
	prev := autobanFeedDegradedWarned
	autobanFeedDegradedWarned = degraded
	autobanMu.Unlock()
	switch {
	case degraded && !prev:
		TaskLogfWarn(AutobanTaskID, "feed", "数据源异常：%s", reason)
	case !degraded && prev:
		TaskLogf(AutobanTaskID, "feed", "数据源已恢复：安全事件补采任务在调度中，spool 补采与审计日志轮转已恢复")
	}
}

// ResetAutobanCounters 清空计数器（口径/窗口变更/测试用）：计数桶+上一轮
// 观察建议一并清空——建议是同一窗口口径下的观察输出，口径变更/名单全量
// 替换后旧建议对现状失真（同款 ≤1 tick 展示残留，历史定性并入）。
func ResetAutobanCounters() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows = make(map[string]*autobanCounter)
	autobanSuggestions = nil
	autobanCapWarned = false
}

// HumanObserveItem 人机事件批量喂入的最小形态（IPC 提交点按批提交）。
// Kind=challenge|fail|pass。
type HumanObserveItem struct {
	IP   string
	Kind string
	// Reason CC 触发原因（session_anomaly/rps_spike/4xx_ratio；非 CC 触发空）——
	// 会话异常等 CC 触发的归因数据源（条目备注/事件详情）。
	Reason string
	At     time.Time
}

// ObserveHumanEvents 供人机事件 IPC 提交后按批喂入挑战证据（2026-11-13
// 用户裁定：发放/失败按各自维度成员资格计数，通过永不计）。仅主节点 +
// 自动封禁启用时计入；配置每批只读一次（与 autobanObserveBatch 同构——
// 逐事件 SELECT 是热路径 O(事件) 库查询）。挑战事件不受 WAF 阶段 3 族门
// 约束；pass 的维度为空，由 autobanObserveEventScopedAt 自然跳过。
func ObserveHumanEvents(items []HumanObserveItem) {
	if len(items) == 0 || !autobanIsMaster() {
		return
	}
	cfg, err := GetAutobanConfig()
	if err != nil || !cfg.Enabled {
		return
	}
	for _, it := range items {
		// CC reject 动作（429 限流拒绝）按「被拦截」口径喂 blocked 维度——
		// 429 确属拦截，与 WAF blocked 同组（evidence 模式计确证）。走人机
		// 事件传输通道但 action=blocked，rule token 用 cc_rate_reject 归因。
		if it.Kind == "rate_reject" {
			autobanObserveEventScopedAt(cfg, it.IP, "blocked", "cc_rate_reject", it.At)
			continue
		}
		ruleTriggered := "human_challenge"
		switch it.Kind {
		case "fail":
			ruleTriggered = "human_failed"
		case "pass":
			ruleTriggered = "human_pass"
		}
		// CC 触发放行事件改用 CC 原因 token（会话异常等归因）；失败/通过
		// 保持人机维度 token（失败是独立计数维度，不并入触发原因）。
		if it.Kind == "challenge" && it.Reason != "" {
			ruleTriggered = "cc_" + it.Reason
		}
		autobanObserveEventScopedAt(cfg, it.IP, "challenged", ruleTriggered, it.At)
	}
}

// autobanObserveBatch 摄取提交点喂入（每批 Commit 后调用）。五重门：主节点 +
// 启用 + WAF 事件（rule_triggered 非空）+ 口径 + 阶段 3 族。任一门不过整批
// 跳过；批内逐条按口径过滤。阶段 3 族门与逐事件门收敛在
// autobanObserveEventScopedAt——首喂、跨 pass 改判补喂、批量改判三条喂入
// 路径统一经此，判据单点维护。
func autobanObserveBatch(items []autobanFeedItem) {
	if len(items) == 0 || !autobanIsMaster() {
		return
	}
	// 热路径每批只读一次配置——整份 cfg 下传单事件路径
	//（scope/window/threshold），不再逐事件 SELECT（O(事件) 库查询）。
	// 启用门并入同一行读取（GetAutobanConfig 的 SELECT
	// 已含 autoban_enabled）——旧实现先 AutobanEnabled() 再 GetAutobanConfig()，
	// 每批多一次主库单行查询；读失败时本批不喂入（fail-closed 语义不变）。
	cfg, err := GetAutobanConfig()
	if err != nil || !cfg.Enabled {
		return
	}
	for _, it := range items {
		if it.TrustExempt {
			continue
		}
		autobanObserveEventScopedAt(cfg, it.IP, it.Action, it.RuleTriggered, it.At)
	}
}

// autobanStage3Eligible 报告事件是否属阶段 3（WAF 引擎）事件族——自动封禁
// 只消费 WAF 命中（2026-10-30 用户裁定）：CRS 段 [900000,1000000) ∪ 自定义
// 规则族（id+10000 发射段、本地合成段 ≥1000000、OR 分支高段）。为什么只收
// 阶段 3：阶段 1 预检（固定 id {2,3,4,5,7,8,12,14} 与 GeoIP 8xxxxx 三族）的
// 拦截是策略主动拒绝——IP 名单/地域/信任名单命中即断，不是攻击证据；计入会
// 让同一 IP 被重复累计、与既有拦截策略重复表达同一结论。段界全部复用事件归因
// 单源谓词 securityEventsRuleIsCustomFamily / securityEventsRuleIsCRSFamily
// （与 securityevents.go 归因口径同一事实源），禁止在此复写字面量段界；非数值
// token 一律不计。
func autobanStage3Eligible(ruleTriggered string) bool {
	return securityEventsRuleIsCustomFamily(ruleTriggered) || securityEventsRuleIsCRSFamily(ruleTriggered)
}

// autobanSourceEligible 只排除真实验证爬虫豁免事件（810xxx 豁免段）。该段已被
// autobanStage3Eligible 的阶段门整体排除，本门按 2026-10-30 用户裁定显式保留
// 为独立条款（「爬虫豁免规则仍不计」），不依赖阶段段界的巧合。
func autobanSourceEligible(ruleTriggered string) bool {
	return !securityEventsIsCrawlerExemptRule(ruleTriggered)
}

func autobanObserveEventScopedAt(cfg AutobanConfig, ip, action, ruleTriggered string, at time.Time) {
	// 廉价门控前置：身份/窗口不合法的事件直接丢弃，不做口径解析与族判定。
	if ip == "" || ruleTriggered == "" {
		return
	}
	// 保留地址硬排除（与攻击光流环入环门同一判据 IsReservedClientIP）：
	// 内网扫描器/监控源命中 CRS/自定义规则不是外网攻击证据，计入会把内网
	// 服务自动封禁（断内网访问）。三条喂入路径（WAF 首喂/改判补喂、人机
	// 批喂）统一经此门，判据单点维护。
	if IsReservedClientIP(ip) {
		return
	}
	// IPv6 按 /64 归一计数（隐私扩展地址在 /64 内轮换，逐地址建键永不达
	// 阈值且耗尽键上限）；封禁条目随之落 /64 CIDR——与 CC/cookie 检测粒度
	// 对齐。/64 波及整个用户前缀（同 /64 无辜主机连带），为 IPv6 标准封禁
	// 粒度，启用须知已披露。
	normalized := autobanNormalizeIP(ip)
	window := time.Duration(cfg.WindowMinutes) * time.Minute
	if window <= 0 {
		return
	}
	// 口径集合每事件只解析一次：WAF 事件与人机维度共用同一成员表
	//（此前 autobanActionMatches 二次解析同一 scope，热路径双倍字符串切分）。
	scopeSet := AutobanScopeSet(cfg.Scope)
	// dim 是事件的口径维度（WAF=action；人机=发放/失败映射）——evidence
	// 模式按 dim 分组累加确证/嫌疑。
	dim := action
	if action == "challenged" {
		// 人机事件：发放/失败按各自维度成员资格计数；通过永不计。
		dim = ""
		switch {
		case ruleTriggered == "human_challenge" || strings.HasPrefix(ruleTriggered, "cc_"):
			// CC 触发放行（cc_session_anomaly 等）属发放维度——与 human_challenge
			// 同口径计数，原因分类另走 autobanBanReason。
			dim = AutobanScopeChallengeIssued
		case ruleTriggered == "human_failed":
			dim = AutobanScopeChallengeFailed
		}
		if dim == "" || !scopeSet[dim] {
			return
		}
	} else if !scopeSet[action] || !autobanSourceEligible(ruleTriggered) {
		return
	} else if action != "blocked" || ruleTriggered != "cc_rate_reject" {
		// WAF 事件须过阶段 3 族门；CC reject（cc_rate_reject）是人机通道
		// 的拦截事件，不属 WAF 族但语义确属拦截，豁免族门（口径门仍生效）。
		if !autobanStage3Eligible(ruleTriggered) {
			return
		}
	}
	now := autobanNow()
	// 积压回放（摄取停摆恢复/轮转补采）不得按到达时间瞬时达标：早于当前
	// 窗口的事件不计数。
	if !at.IsZero() && now.Sub(at) > window {
		return
	}
	var capWarn bool
	autobanMu.Lock()
	w, exists := autobanWindows[normalized]
	if !exists {
		if len(autobanWindows) >= autobanMaxTrackedIPs {
			capWarn = !autobanCapWarned
			autobanCapWarned = true
		} else {
			w = &autobanCounter{}
			autobanWindows[normalized] = w
		}
	}
	if w != nil {
		if w.WindowStart.IsZero() || now.Sub(w.WindowStart) >= window {
			w.Count = 0
			w.Confirmed = 0
			w.Suspicion = 0
			w.WindowStart = now
			w.Reached = false
			w.Reasons = nil
		}
		w.Count++
		evidence := cfg.CountingMode == AutobanCountingEvidence
		if evidence {
			if autobanScopeIsConfirmed(dim) {
				w.Confirmed++
			} else {
				w.Suspicion++
			}
		}
		w.LastSeen = now
		if reason := autobanBanReason(action, ruleTriggered); reason != "" {
			if w.Reasons == nil {
				w.Reasons = make(map[string]int, len(autobanBanReasonOrder))
			}
			w.Reasons[reason]++
		}
		if !w.Reached {
			if evidence {
				w.Reached = autobanEvidenceReached(w.Confirmed, w.Suspicion, cfg.Threshold, cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio)
			} else if cfg.Threshold > 0 && w.Count >= cfg.Threshold {
				w.Reached = true
			}
		}
	}
	autobanMu.Unlock()
	if capWarn {
		Logf("warn", "自动封禁计数器达 %d 键上限，新 IP 不再计数（既有键不受影响）", autobanMaxTrackedIPs)
	}
}

// autobanNormalizeIP 是自动封禁的计数身份归一：IPv6 取 /64 前缀（隐私扩展
// 地址漂移不误判、同前缀轮换聚合计数），IPv4 与不可解析串原样。
// 与 lbhuman.normalizeIP（lbhuman/cookie.go，CC 检测/cookie 绑定同粒度）
// 语义等价：lbhuman 是依赖 Caddy 的独立插件模块，面板主模块不引入其依赖树，
// 此处为镜像实现——改一处必须同步另一处，语义等价由
// autoban_ipv6_granularity_test.go 的对拍钉测兜底。
func autobanNormalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}

// autobanIdentityKey 是自动封禁的身份键单源：计数桶键、merge 名单身份、
// 解封清桶与累犯表（autoban_recidivism.identity）恒经此函数归一，禁止旁路
// 第二份归一实现。恒为 autobanNormalizeIP（IPv6 /64 归一，IPv4/不可解析串
// 原样）。
func autobanIdentityKey(ip string) string {
	return autobanNormalizeIP(ip)
}

// autobanBanValue 把计数身份转成名单条目值：IPv6 /64 网络地址落 CIDR
// （名单/匹配器按前缀封禁整段），IPv4 与其余形态保持裸地址。候选 IP 恒经
// autobanIdentityKey 归一，此处只判「是否 /64 网络地址」，不再二次掩码。
func autobanBanValue(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	if !parsed.Equal(parsed.Mask(net.CIDRMask(64, 128))) {
		return ip
	}
	return ip + "/64"
}

// autobanEntryIdentity 把名单条目值归一为计数键身份：CIDR 取网络地址
// （/64 自动封禁条目 → 与喂入归一键同形），裸地址经 autobanIdentityKey
// 单源归一。merge 的「已在名单/刚到期」判定与解封清桶共用本函数，
// 保证条目值形态（裸地址/CIDR）不影响身份匹配。
func autobanEntryIdentity(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return autobanIdentityKey(prefix.Masked().Addr().String())
	}
	return autobanIdentityKey(value)
}

// AutobanEntryIdentity 把名单条目值/处置 IP 归一为计数键身份（公开包装，
// handlers 加名单中断路径消费——与 merge/解封清桶同键，禁止旁路第二份归一）。
func AutobanEntryIdentity(value string) string { return autobanEntryIdentity(value) }

// autobanIdentityBannedInView 在调用方给定视图上判定身份是否正被封禁
// （预置名单生效条目命中——限时未到期或永久）。与 enrichAutobanRecidivismRows
// 的 ban_status join 同口径（AutobanActiveEntries + autobanEntryIdentity 归一，
// IPv6 /64 CIDR↔裸身份键）。视图形态供守卫与删除同事务消费（BEGIN
// IMMEDIATE 写锁下读到的名单即删除时刻的名单，无 TOCTOU 窗口）；名单行
// 缺失按未封禁（只读判定不补建——与库句柄形态的 ensure 补建刻意分叉，
// 补建是写动作，不得混入守卫事务）。
func autobanIdentityBannedInView(ctx context.Context, q AutobanConfigQuerier, identity string) (bool, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return false, err
	}
	key := autobanEntryIdentity(identity)
	for _, e := range AutobanActiveEntries(entries) {
		if autobanEntryIdentity(e.Value) == key {
			return true, nil
		}
	}
	return false, nil
}

// AutobanIdentityActivelyBanned 判定身份是否正在被自动封禁（库句柄视图；
// handlers 单条移除守卫的事务形态见 DeleteAutobanRecidivismGuarded）。
func AutobanIdentityActivelyBanned(identity string) (bool, error) {
	if db.DB == nil {
		return false, errors.New("数据库未初始化")
	}
	return autobanIdentityBannedInView(context.Background(), db.DB, identity)
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
	// Reason 窗口内主触发原因（计数最多类别，平局按固定优先序）——merge
	// 写条目备注消费（「累犯·原因」/直接原因）；无 feed 详情的 direct seam
	// 恒空串（merge 降级占位符）。
	Reason string `json:"reason,omitempty"`
	// ConfirmedCount/SuspicionCount 证据分层双分数（evidence 模式投影；
	// classic 模式 confirmed=count、suspicion=0——旧前端读 count 不变）。
	ConfirmedCount int `json:"confirmed_count"`
	SuspicionCount int `json:"suspicion_count"`
}

// autobanCandidates 评估候选：先评估后修剪——过期桶若计数
// 已跨阈值（桶尾达标形态：最后采样在窗口尾、周期 tick 晚于窗口到期）必须并入
// 候选再删，否则该 IP 永不封禁；未跨阈值的过期桶照常修剪不产生候选。曾达标
// IP 的过期桶修剪时按轮汇总一条 expire（与 Feed 路径同语义——窗口过期清零的
// 唯一两条发射面）。
func autobanCandidates(cfg AutobanConfig, window time.Duration) []AutobanSuggestion {
	now := autobanNow()
	threshold := cfg.Threshold
	evidence := cfg.CountingMode == AutobanCountingEvidence
	// reached 判定单源：classic 等权 Count>=T1；evidence 双条件。
	reached := func(w *autobanCounter) bool {
		if evidence {
			return autobanEvidenceReached(w.Confirmed, w.Suspicion, threshold, cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio)
		}
		return threshold > 0 && w.Count >= threshold
	}
	suggestion := func(ip string, w *autobanCounter) AutobanSuggestion {
		s := AutobanSuggestion{IP: ip, Count: w.Count, WindowStart: w.WindowStart, LastSeen: w.LastSeen, Reason: autobanDominantReason(w.Reasons)}
		if evidence {
			s.ConfirmedCount, s.SuspicionCount = w.Confirmed, w.Suspicion
		} else {
			s.ConfirmedCount, s.SuspicionCount = w.Count, 0
		}
		return s
	}
	var expiredReached []string
	autobanMu.Lock()
	var expiredCandidates []AutobanSuggestion
	for ip, w := range autobanWindows {
		if !w.WindowStart.IsZero() && now.Sub(w.WindowStart) >= window {
			// 先评估——过期桶已跨阈值的并入候选，再删桶。
			if reached(w) {
				expiredCandidates = append(expiredCandidates, suggestion(ip, w))
			}
			if w.Reached {
				expiredReached = append(expiredReached, ip)
			}
			delete(autobanWindows, ip)
		}
	}
	var out []AutobanSuggestion
	for ip, w := range autobanWindows {
		if reached(w) {
			out = append(out, suggestion(ip, w))
		}
	}
	out = append(out, expiredCandidates...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	// 候选评估不做展示/建议上限截断——正式 merge 必须
	// 看到全部达标候选（旧实现复用 autobanSuggestionCap=200 截断候选项，
	// 第 201 个达标 IP 永远不会被封禁）；容量由 AutobanListEntryCap 收敛。
	// 观察模式在 autobanSetSuggestions 前单独截断（展示口径）。
	autobanMu.Unlock()
	if len(expiredReached) > 0 {
		// 洪峰下一轮可有数万过期 IP：按轮只写一条汇总，保留排序后的少量
		// 样本用于排障，避免逐 IP TaskLogf 淹没任务日志。
		sort.Strings(expiredReached)
		const sampleCap = 5
		sample := expiredReached
		if len(sample) > sampleCap {
			sample = sample[:sampleCap]
		}
		detail := "IP " + strings.Join(sample, "、")
		if rest := len(expiredReached) - len(sample); rest > 0 {
			detail += fmt.Sprintf(" 等，另有 %d 个", rest)
		}
		TaskLogf(AutobanTaskID, "expire", "%d 个 IP 计数窗口过期，清零（%s）", len(expiredReached), detail)
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
	// 空集也返回非 nil 空切片：JSON 序列化契约是数组（null 与前端/文档的
	// 数组契约不符），调用方不得各自补空切片——单源收在这里。
	out := append([]AutobanSuggestion{}, autobanSuggestions...)
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

// AutobanForgetIPs 解封侧计数清零（用户裁定「删除即解封」
// 语义闭环）：从预置名单移除条目（remove-ip 端点、预置名单差集全量保存两条
// 解封路径）时调用——不清桶则窗口内旧计数（Count≥threshold 未过期）让下一
// 轮 merge 在零新流量下立即重封，解封在 ≤1 tick 内被撤销。清桶只重置旧计数：
// 新流量重新计数、重新达标仍会再封（apidocs「IP 重新达标会被再次封禁」口径
// 不变）。两解封路径共用本单一入口（新增解封面不得旁路）。
func AutobanForgetIPs(ips []string) {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	// 解封值可能是 CIDR（IPv6 /64 自动条目）或裸地址：计数键恒为归一身份，
	// 两侧经 autobanEntryIdentity 同键删除，否则删 /64 条目不清桶 → 下一轮
	// 零新流量立即重封（「删除即解封」被撤销）。
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		identity := autobanEntryIdentity(ip)
		delete(autobanWindows, identity)
	}
	// 同步清 autobanSuggestions 对应 IP——建议列表是上一轮
	// 观察快照，解封后仍展示该 IP 是 ≤1 tick 的展示残留（下一轮 Run 才重算
	// 覆盖）；按值剔除，保留其余 IP 建议。
	if len(autobanSuggestions) > 0 && len(ips) > 0 {
		gone := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			if ip != "" {
				gone[autobanEntryIdentity(ip)] = struct{}{}
			}
		}
		kept := autobanSuggestions[:0]
		for _, s := range autobanSuggestions {
			if _, drop := gone[autobanEntryIdentity(s.IP)]; !drop {
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
	ListID  int64
	Expired []string // 到期解封的 IP（自动+手动条目全集，清桶口径按全集）
	// ExpiredManual 是 Expired 中 remark≠自动封禁（手动封禁）的子集：解封
	// 动作同样由系统执行，但审计文案若把人工封禁条目称「到期自动解封」会把
	// 来源说错（排障时无法区分自动/手动），故单列供审计分流。
	ExpiredManual []string
	Banned        []string // 本轮新封禁的 IP
	// BannedDurations 与 Banned 平行：逐新封的实际执法时长（累犯升档后可能
	// 不同于配置时长，0=永久）——逐 IP 审计按实际时长报告；容量丢弃的新封
	// 不在此列（未执法不审计）。空/短于 Banned=无 merge 详情的直调形态，
	// 审计回退配置时长。
	BannedDurations []time.Duration
	Evicted         int      // 超限挤出的自动条目数
	EvictedIPs      []string // 被挤出条目的 IP（挤出=解封同语义：调用方须随
	// Expired 一起清计数桶，否则旧计数仍 ≥ 阈值 → 下轮零新事件立即重封，
	// 形成「挤出→重封→再挤出」轮转；同时供容量收敛留痕点名身份）
	DroppedNew int // 容量不足丢弃的新封数
	// DroppedIPs 被容量截断丢弃的候选 IP（与 EvictedIPs 同口径：调用方须清
	// 其计数桶。不清则同一批攻击者每轮都重新达标、每 60s 轮重复落同一份容量
	// 审计+WARN，真实告警被自身噪音淹没；清桶后需在新窗口内重新累计，攻击
	// 流量会再次达标，容量释放后仍可正常封禁）。
	DroppedIPs []string
	Total      int // merge 后名单总条数
	Changed    bool
}

// autobanEntryTimeParses 条目时间解析调用计数（测试观测挤出路径的复杂度；
// 生产成本=每次解析一次原子加）。
var autobanEntryTimeParses atomic.Int64

// parseAutobanEntryTime 解析条目时间戳（UTC 墙钟串）；畸形视为零值（调用方
// 按无时间处理——到期过滤只认可解析且 <= now 的值，畸形 expires_at 保留条目
// 不误删）。
func parseAutobanEntryTime(s string) time.Time {
	autobanEntryTimeParses.Add(1)
	if s == "" {
		return time.Time{}
	}
	ts, err := time.ParseInLocation(autobanTimeLayout, s, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return ts
}

// ensureAutobanPresetListID 返回预置名单 id；system=1 行缺失时补建
// 与 db 播种同为 name+system=1 口径）。可达形态：旧备份导入全表替换后 system
// 名单种子不重播、旧版本可携带同名用户列表——仅 name 判定的播种会永久跳过
// 内置行，而 autoban 全部消费方要求 system=1。同名用户列表不合并、不删除。
//
// 补建统一走 db.EnsureSystemIPList（启动播种/导入重播共用实现）：OR IGNORE
// 幂等、描述按代码文案归一、同名用户列表留痕都在单源内完成——手写 INSERT
// 曾与播种在 category 字面量/描述来源/幂等性三处漂移。
func ensureAutobanPresetListID() (int64, error) {
	if db.DB == nil {
		return 0, errors.New("数据库未初始化")
	}
	var id int64
	err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	created, cerr := db.EnsureSystemIPList(db.DB, AutobanPresetListName, autobanPresetListDescription, "自动封禁")
	if cerr != nil {
		return 0, fmt.Errorf("补建预置名单「%s」: %w", AutobanPresetListName, cerr)
	}
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&id); err != nil {
		return 0, fmt.Errorf("预置名单「%s」补建后仍不可见: %w", AutobanPresetListName, err)
	}
	if created {
		Logf("warn", "自动封禁预置名单缺失，已自动补建 system=1 行（若存在同名用户列表请重命名以消除歧义）")
	}
	return id, nil
}

// autobanMergeEntries 单次 merge（纯 DB 侧，无重载/审计副作用——便于钉测）：
// 清到期 → 已在名单过滤 → 追加新封 → 超限挤最早到期自动条目 → 回写。
func autobanMergeEntries(cfg AutobanConfig, candidates []AutobanSuggestion) (autobanMergeOutcome, error) {
	var out autobanMergeOutcome
	if db.DB == nil {
		return out, errors.New("数据库未初始化")
	}
	// 零值/未知升级形态按 off 消费（与写侧枚举校验同口径）：配置结构体
	// 零值不携带 Escalation 的调用方保持固定时长现行行为，不产生累犯记账。
	if !ValidAutobanEscalation(cfg.Escalation) {
		cfg.Escalation = AutobanEscalationOff
	}
	// 永久时长下升级无意义（首封即顶格，无升级空间）：UI 切 permanent 已把
	// escalation 归 off；消费侧兜底——绕过 UI 直 PUT / 带外库值同样按 off 消费，
	// 不产生累犯记账。
	if cfg.Duration == "permanent" {
		cfg.Escalation = AutobanEscalationOff
	}
	now := autobanNow()
	nowStr := now.Format(autobanTimeLayout)
	id, err := ensureAutobanPresetListID()
	if err != nil {
		return out, err
	}
	out.ListID = id
	// 读改写包进单一事务：集群 apply/导入可能在两步之间整表替换该行，
	// 无事务时陈旧快照会覆盖刚同步的名单（RowsAffected=0 还会被当成成功）。
	tx, err := db.DB.Begin()
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	var raw string
	if err := tx.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		return out, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return out, fmt.Errorf("预置名单条目解析失败: %w", err)
	}

	// 1) 清到期（到期即解封）；不可解析的 expires_at 保留（fail-open 不误删）。
	kept := make([]models.IPListEntry, 0, len(entries))
	inList := make(map[string]struct{}, len(entries))
	expiredThisRound := make(map[string]struct{})
	for _, e := range entries {
		if exp := parseAutobanEntryTime(e.ExpiresAt); !exp.IsZero() && !exp.After(now) {
			out.Expired = append(out.Expired, e.Value)
			if !autobanEntryIsAutomatic(e) {
				out.ExpiredManual = append(out.ExpiredManual, e.Value)
			}
			expiredThisRound[autobanEntryIdentity(e.Value)] = struct{}{}
			out.Changed = true
			continue
		}
		kept = append(kept, e)
		inList[autobanEntryIdentity(e.Value)] = struct{}{}
	}

	// 2) 新封过滤：已在名单跳过；其余追加（permanent 不带 expires_at）。
	// 本轮刚到期解封的 IP 不得在同一轮被计数桶立即重封
	// （window>duration 时计数仍跨阈值 → 封禁被延长到约 window+duration 并
	// 产生成对的「自动解封/自动封禁」审计）；计数桶由 RunAutobanCycle 随后
	// 清空，新流量重新计数/达标仍会再封（与手动解封同语义）。
	duration := autobanDurations[cfg.Duration]
	var toAdd []models.IPListEntry
	// bannedOffenses 与 toAdd 平行：衰减后的本次累计次数（升级后可能不同于
	// 原记账），落库后累犯记账用（容量丢弃的新封不记账）。逐新封的实际执法
	// 时长随 out.BannedDurations 传出（审计消费，与 toAdd 同容量截断口径）。
	var bannedOffenses []int
	for _, c := range candidates {
		if c.IP == "" {
			continue
		}
		// 名单身份与计数身份同键：条目值可能是 CIDR（IPv6 /64 自动封禁），
		// 候选恒为归一后的计数键——两侧都经 autobanEntryIdentity 归一，
		// 否则「已在名单/刚到期」判定对 /64 条目恒失配（重复追加/同轮重封）。
		identity := autobanEntryIdentity(c.IP)
		if _, justExpired := expiredThisRound[identity]; justExpired {
			continue
		}
		if _, exists := inList[identity]; exists {
			continue
		}
		// 累犯渐进升级：off=固定配置时长；standard/aggressive 按累犯次数
		// 升档（读在事务内，记账在落库后同事务——名单与累犯原子一致）。
		banDuration := duration
		offense := 0
		if cfg.Escalation != AutobanEscalationOff {
			d, n, err := autobanEscalatedDuration(tx, cfg, identity, now)
			if err != nil {
				return out, err
			}
			banDuration, offense = d, n
		}
		// 备注=具体触发原因（用户裁定）：累犯升档（offense>1 且升级开启）
		// 冠「累犯·」前缀；首封/关闭档直接原因；无原因降级占位符（存量形态）。
		remark := c.Reason
		if remark == "" {
			remark = autobanEntryRemark
		} else if offense > 1 {
			remark = "累犯·" + remark
		}
		entry := models.IPListEntry{Value: autobanBanValue(c.IP), Remark: remark, CreatedAt: nowStr}
		if banDuration > 0 {
			entry.ExpiresAt = now.Add(banDuration).Format(autobanTimeLayout)
		}
		toAdd = append(toAdd, entry)
		out.BannedDurations = append(out.BannedDurations, banDuration)
		bannedOffenses = append(bannedOffenses, offense)
		inList[identity] = struct{}{}
	}

	// 3) 容量收敛：先挤「最早到期的自动条目」（永久自动条目次之），手动条目
	//（remark≠自动封禁）不挤；仍不足丢弃剩余新封。
	// 挤出序**一次预计算**：此前每挤出一个都全表扫描 + 逐条重新解析时间戳
	// （O(n²) 解析、O(n²) 比较），名单接近容量上限时一轮可达数万次
	// time.Parse。预计算与逐次挑选的优先级逐字对齐：
	//   有到期时间者按到期升序先挤；永久条目排在所有有到期者之后；永久条目
	//   之间按 created_at 升序（不可解析 created_at 视为最后），同值按键序
	//   （先出现者先挤）——与旧实现的严格 Before 比较一致。
	type evictCandidate struct {
		idx     int
		exp     time.Time
		perm    bool
		created time.Time
	}
	evictQueue := make([]evictCandidate, 0, len(kept))
	for i, e := range kept {
		if !autobanEntryIsAutomatic(e) {
			continue
		}
		exp := parseAutobanEntryTime(e.ExpiresAt)
		evictQueue = append(evictQueue, evictCandidate{
			idx: i, exp: exp, perm: exp.IsZero(),
			created: parseAutobanEntryTime(e.CreatedAt),
		})
	}
	sort.SliceStable(evictQueue, func(a, b int) bool {
		x, y := evictQueue[a], evictQueue[b]
		if x.perm != y.perm {
			return !x.perm
		}
		if !x.perm {
			return x.exp.Before(y.exp)
		}
		xZero, yZero := x.created.IsZero(), y.created.IsZero()
		if xZero != yZero {
			return !xZero
		}
		if xZero {
			return false
		}
		return x.created.Before(y.created)
	})
	evictNext := 0
	evictedIdx := make([]bool, len(kept))
	evict := func() (models.IPListEntry, bool) {
		if evictNext >= len(evictQueue) {
			return models.IPListEntry{}, false
		}
		victim := kept[evictQueue[evictNext].idx]
		evictedIdx[evictQueue[evictNext].idx] = true
		evictNext++
		return victim, true
	}
	evictedCount := 0
	for len(kept)-evictedCount+len(toAdd) > AutobanListEntryCap {
		if victim, ok := evict(); ok {
			out.Evicted++
			evictedCount++
			out.EvictedIPs = append(out.EvictedIPs, victim.Value)
			out.Changed = true
			continue
		}
		// 自动条目已无可挤（kept 全手动或已清空）且总量仍超限：按容量截断
		// 新封（候选按计数降序，高计数优先保留），其余丢弃并计数入 DroppedNew
		//（容量收敛可观测：挤出/丢弃数随本轮 WARN 行与审计行落痕）。
		keep := AutobanListEntryCap - (len(kept) - evictedCount)
		if keep < 0 {
			keep = 0
		}
		out.DroppedNew = len(toAdd) - keep
		for _, dropped := range toAdd[keep:] {
			out.DroppedIPs = append(out.DroppedIPs, dropped.Value)
		}
		toAdd = toAdd[:keep]
		out.BannedDurations = out.BannedDurations[:keep]
		break
	}
	if evictedCount > 0 {
		// 原地压缩：保留未被挤出条目的相对顺序（与逐次删除的最终顺序一致）。
		write := 0
		for i, e := range kept {
			if evictedIdx[i] {
				continue
			}
			kept[write] = e
			write++
		}
		kept = kept[:write]
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
	res, err := tx.Exec(`UPDATE security_ip_lists SET entries=?, updated_by=0, updated_at=? WHERE id=?`, string(merged), nowStr, id)
	if err != nil {
		return out, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return out, err
	}
	if affected != 1 {
		return out, fmt.Errorf("预置名单行已被并发替换（rows=%d），本轮封禁未落库", affected)
	}
	// 累犯记账与名单落库同事务：只计真实新封（容量丢弃的不记）。
	// offense_count 直存「衰减后的本次累计次数」——衰减必须随再犯落库，
	// 否则每次读都重新衰减、永不收敛（防永久标签失效）。
	if cfg.Escalation != AutobanEscalationOff {
		for i, e := range toAdd {
			label := autobanEscalationDurationLabel(out.BannedDurations[i])
			if _, err := tx.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(identity) DO UPDATE SET
					offense_count=excluded.offense_count, last_ban_at=excluded.last_ban_at, escalated_duration=excluded.escalated_duration`,
				autobanEntryIdentity(e.Value), bannedOffenses[i], nowStr, label); err != nil {
				return out, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

// ---- 累犯渐进升级 ----

// autobanRecidivismDecay 累犯衰减窗口：距上次封禁超过该时长无再犯，
// offense_count 降一级（防永久标签——改过自新的身份不被历史永久钉死）。
// 默认 30 天；测试缝可覆写（生产可配点）。
var autobanRecidivismDecay = 30 * 24 * time.Hour

// autobanEscalationDurationLabel 执法时长的枚举标签（累犯表 escalated_duration
// 留痕用，与 autobanDurations 键同形）；0=永久。
func autobanEscalationDurationLabel(d time.Duration) string {
	if d <= 0 {
		return "permanent"
	}
	for label, dur := range autobanDurations {
		if dur == d {
			return label
		}
	}
	return d.String()
}

// autobanEscalatedDuration 按累犯历史计算本次执法时长与累计次数（读在调用方
// 事务视图内）：先衰减——last_ban_at 距今超过 autobanRecidivismDecay 无再犯
// 则历史清零（防永久标签：守法满一个窗口的身份按首次档重新开始；若只降一级
// 再 +1，净计数不变，档位永不回落，衰减形同虚设）；窗口内再犯则历史累加。
// 再按档位映射——standard：1 次=配置时长、2 次=24h、3 次+=永久；aggressive：
// 1 次=配置时长、2 次+=永久。返回的 offense=本次累计次数（衰减后），由调用方
// 在名单落库后同事务直存；本函数只读不写。
func autobanEscalatedDuration(tx *sql.Tx, cfg AutobanConfig, identity string, now time.Time) (time.Duration, int, error) {
	var count int
	var lastBan string
	err := tx.QueryRow(`SELECT offense_count, last_ban_at FROM autoban_recidivism WHERE identity=?`, identity).Scan(&count, &lastBan)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, 0, err
	}
	if err == nil && autobanRecidivismDecay > 0 {
		if last := parseAutobanEntryTime(lastBan); !last.IsZero() && now.Sub(last) > autobanRecidivismDecay {
			count = 0
		}
	}
	offense := count + 1
	var d time.Duration
	switch cfg.Escalation {
	case AutobanEscalationStandard:
		switch {
		case offense <= 1:
			d = autobanDurations[cfg.Duration]
		case offense == 2:
			d = 24 * time.Hour
		default:
			d = 0
		}
	case AutobanEscalationAggressive:
		if offense <= 1 {
			d = autobanDurations[cfg.Duration]
		} else {
			d = 0
		}
	default:
		d = autobanDurations[cfg.Duration]
	}
	return d, offense, nil
}

// autobanPruneDecayedRecidivism 物理清理衰减行（RunAutobanCycle 每轮调用，
// 防表无限增长）：last_ban_at 距今超过 autobanRecidivismDecay 的身份行删除。
// 与读时衰减（autobanEscalatedDuration 清零重算）同窗口口径——读时衰减只
// 在再犯时生效，长期不再犯的身份行会永久滞留；物理清理补齐收敛。边界同读时
// 判据（严格 > decay，恰在窗口边界保留）；空 last_ban_at 不清理。墙钟串与
// 存储同格式（autobanTimeLayout），字典序=时间序；写侧恒落该格式。
// decay<=0（衰减禁用）不清理。
// DELETE 触发器 bump cluster_version，从端下一同步周期整表收敛。
func autobanPruneDecayedRecidivism(now time.Time) {
	if autobanRecidivismDecay <= 0 {
		return
	}
	d := db.GetDB()
	if d == nil {
		return
	}
	cutoff := now.Add(-autobanRecidivismDecay).Format(autobanTimeLayout)
	if _, err := d.Exec(`DELETE FROM autoban_recidivism WHERE last_ban_at <> '' AND last_ban_at < ?`, cutoff); err != nil {
		TaskLogfWarn(AutobanTaskID, "cycle", "累犯衰减行清理失败（本轮跳过，下轮重试）: %v", err)
	}
}

// ---- 重载节流 ----

// autobanReloadState 本轮收敛请求的终态（摘要尾注与暂存标记一致——
// 失败时不得宣称「已触发」）。热路径收敛（HotApplied）是「已收敛」的零重载
// 形态，审计真实性：不落「重载」系统审计、尾注不宣称已重载。
type autobanReloadState int

const (
	autobanReloadNone         autobanReloadState = iota // 无名单变化，未请求收敛
	autobanReloadApplied                                // 已重载（全量链收敛）
	autobanReloadHotApplied                             // 投影热路径收敛（零重载，匹配器 ≤1s 热感知）
	autobanReloadUnreferenced                           // 名单无发射面引用，零重载
	autobanReloadDeferred                               // 节流窗口内，暂存至下一轮合并执行（仅全量重载回退路径）
	autobanReloadErrored                                // 全量重载失败（已留审计+置暂存再武装）
)

// autobanMarkReloadFailed 重载失败统一处置（镜像 threat_reload_pending）
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
// ipListsReferencedByEnabledPolicyLabeled。查询/解析失败
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
// 调用契约：调用方已持 CaddyOpLock（merge 读改写+收敛同一临界区），
// 本函数不得再取锁。
func autobanConvergeLocked(reason string, listID int64) autobanReloadState {
	if !autobanListHotPathEligible(listID) {
		// 查询/解析失败在资格门内按被引用处理，因此 false 是确定的
		// 无引用：没有任何发射面消费该名单，DB 更新无需 /load 或投影重写。
		Logf("info", "自动封禁名单未被任何启用策略、受信代理或 CRS 排除引用，跳过收敛重载")
		return autobanReloadUnreferenced
	}
	if autobanProjectionRefresher != nil {
		hot, err := autobanProjectionRefresher()
		if err == nil && hot == ProjectionConverged {
			Logf("info", "自动封禁名单变化经投影热路径收敛（零 Caddy 重载，匹配器 ≤1s 热感知生效）")
			return autobanReloadHotApplied
		}
		// 未证实收敛/刷新被拒 → 回退 /load 收敛——宁可一次重载，不欠引用方
		// 渲染收敛（fail-safe 与威胁库收敛门同向）。NeedForce（本轮渲染物化
		// 了证书文件）同样回退：回退回调为强制形态
		// （GenerateAndApplyConfigForceInLock），击穿 errSameConfig 让新证书
		// 进 Caddy 内存；Ruling：NeedForce 走既有 60s 节流暂存可接受——证书
		// 续期与封禁写撞车是小概率事件，收敛延迟上界=下一轮周期（60s）。
		Logf("info", "自动封禁投影热路径未证实收敛（发射面变化/证书物化或刷新失败），回退重载 Caddy 配置")
	}
	return autobanRequestReloadLocked(reason)
}

// autobanRequestReloadLocked 名单变化后请求全量重载（热路径回退路径）：距上次
// 真实重载 ≥60s 立即执行，否则置暂存（下一轮 Run 的 autobanFlushPendingReload
// 合并执行）。调用契约：调用方已持 CaddyOpLock（merge 读改写+收敛
// 同一临界区），注入回调为 InLock 变体——本函数不得再取 CaddyOpLock。
func autobanRequestReloadLocked(reason string) autobanReloadState {
	if autobanReloader == nil {
		TaskLogfWarn(AutobanTaskID, "reloading", "重载回调未注册，跳过名单收敛（引用方由下次配置变更收敛）")
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

// autobanFlushPendingReload 执行暂存重载。常规轮 force=false，遵守节流窗口；
// 禁用收尾 force=true，绕过节流（此后无下一轮 flush 点）。此处自取
// CaddyOpLock——重载回调为 InLock 变体，须与 handler 写路径互斥。
func autobanFlushPendingReload(force bool) {
	autobanMu.Lock()
	if !autobanReloadPending || autobanReloader == nil {
		autobanMu.Unlock()
		return
	}
	if !force && !autobanLastReload.IsZero() && autobanNow().Sub(autobanLastReload) < autobanReloadThrottle {
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
		reason := "暂存重载"
		if force {
			reason = "禁用收尾强制重载"
		}
		autobanMarkReloadFailed(reason, err)
		return
	}
	recordSystemReloadAudit("autoban", nil)
}

// autobanApplyMergeOutcomeLocked 是 Run 与禁用收尾共用的 merge 收尾：清理
// 到期/挤出条目的计数桶，再按名单变化收敛引用方。调用方已持 CaddyOpLock。
// observe 用于禁用收尾保持原有「容量留痕+解封审计先于收敛」顺序；Run 的
// 容量留痕与逐 IP 审计仍在锁外角色复核后执行。
func autobanApplyMergeOutcomeLocked(reason string, out autobanMergeOutcome, observe func()) autobanReloadState {
	AutobanForgetIPs(out.Expired)
	AutobanForgetIPs(out.EvictedIPs)
	// 容量丢弃与挤出一并处：丢弃=本轮不封，计数桶不清则同一批候选每轮都重新
	// 达标，重复落容量审计/WARN（且名单内容不变时 Changed=false，留痕纯噪音）。
	AutobanForgetIPs(out.DroppedIPs)
	if observe != nil {
		observe()
	}
	if out.Changed {
		return autobanConvergeLocked(reason, out.ListID)
	}
	return autobanReloadNone
}

// AutobanDisableFlush 禁用路径收尾（PUT 保存 enabled=false 后、
// StopLoop 前调用）：①到期自动条目清理一次（禁用后无循环清理点——最后一批
// 已到期条目立即解封并留「自动解封」审计）；②已到期条目的计数桶同步清空
// （到期自动解封与手动解封同语义，——否则
// 窗口内重新启用且零新流量时，旧计数仍 ≥ 阈值会立即重封刚解封的 IP）；
// ③暂存重载强制收敛一次（绕过节流——禁用前节流暂存的名单变化与本次清理
// 变化必须落盘生效）。重载失败按留痕+保持暂存（重新启用后下一轮 flush
// 重试）。
func AutobanDisableFlush() {
	cfg, err := GetAutobanConfig()
	if err != nil {
		Logf("error", "自动封禁禁用收尾读取配置失败: %v", err)
		return
	}
	CaddyOpLock.Lock()
	out, err := autobanMergeEntries(cfg, nil)
	if err != nil {
		msg := fmt.Sprintf("禁用收尾到期条目清理失败: %v", err)
		Logf("error", "自动封禁%s", msg)
		RecordAuditLog("system", "写入失败", "自动封禁", FormatAuditDetail(msg, AuditResultPart("failed")), "")
	} else {
		autobanApplyMergeOutcomeLocked("自动封禁禁用收尾", out, func() {
			// 禁用收尾 candidates=nil 仍可触发挤出；容量与解封审计保持先于收敛。
			autobanReportCapacityOutcome("（禁用收尾）", out)
			if out.Changed {
				autobanAuditExpiredUnban(out.Expired, out.ExpiredManual)
			}
		})
	}
	CaddyOpLock.Unlock()
	autobanFlushPendingReload(true)
}

// ---- Run 循环 ----

// RunAutobanCycle 单轮执行（引擎 autoban 任务体）：业务门（未启用=失败+重禁
// 调度）→ 配置护栏（无效=失败+自停）→ 修剪计数器 → 评估候选（dry-run 锁外；
// 正式模式并入下方 merge 的 CaddyOpLock 临界区）→ 观察建议或
// 名单 merge → 审计/重载/每轮摘要行。
//
// 业务门（2026-10-14 用户裁定）：本任务只能由「启用后按配置调度执行」——
// Descriptor 不设 EnabledFn（调度面无业务门；TaskMeta.Enabled 已删除，任务
// 监控只认 loop_on，启停语义全在调度开关+事件页业务开关），未启用期间的手动
// 开调度/手动触发到 Run 体首行拦下：落痕+落 failed 行+StopLoop 重禁调度，防
// 未启用空转续跑。
// StopLoop 前复查一次——首读 false 与停环之间存在
// 「PUT enabled=1 + StartLoop」交错窗，无条件停环会把并发重新启用的新调度
// 误杀（enabled=1 而调度停，无自动恢复）；复查仍 false 才停，复查转 true
// 视为已被并发启用、本轮按启用继续。残留窗收窄至复查与 StopLoop 之间，
// 彻底消除需引擎代际令牌（不在本修复范围）。
func RunAutobanCycle(rc taskengine.RunContext) error {
	// demote/停止会在 SetRole 取消 ctx；autoban 必须消费 ctx 并复核角色，
	// 否则在途轮次仍会写主库名单（与 threat/CRS 同族）。
	if rc.Ctx != nil {
		select {
		case <-rc.Ctx.Done():
			return taskengine.ErrTaskSkipped
		default:
		}
	}
	if isMaster, known := updateRunRole(); !known {
		// 角色读取失败（DB 瞬断/脏行）≠从节点——按失败返回（task_runs/任务
		// 监控可见），不得静默跳过（二态复核把 DB 故障当从节点）。
		TaskLogfWarn(AutobanTaskID, "failed", "角色读取失败，无法判定本节点是否主节点，本轮自动封禁未执行")
		return errors.New("角色读取失败，无法判定本节点是否主节点")
	} else if !isMaster {
		return taskengine.ErrTaskSkipped
	}
	// 启用状态不可判定（DB 瞬断/关闭期）≠ 未启用：本轮按失败返回（失败行+
	// WARN 可见），**不停环**——读错误恢复后自动恢复执行；只有成功读到
	// enabled=0 才停止调度。
	if enabled, known := autobanEnabledState(); !known {
		TaskLogfWarn(AutobanTaskID, "failed", "读取启用状态失败（数据库暂不可读），本轮自动封禁未执行，调度保持运行")
		return errors.New("读取自动封禁启用状态失败，本轮未执行（数据库暂不可读，调度保持运行）")
	} else if !enabled && !autobanRecheckEnabled() {
		if te := TaskEngine(); te != nil {
			te.StopLoop(AutobanTaskID)
		}
		// 文案按 trigger 二元化：auto 轮（周期 tick）不写「手动调度」——
		// 日志按字面归因触发来源，混写会让排障误判有人点了手动触发。
		if rc.Trigger == "manual" {
			TaskLogf(AutobanTaskID, "manual", "手动调度，执行失败：未启用")
		} else {
			TaskLogf(AutobanTaskID, "auto", "定时调度，执行失败：未启用")
		}
		return errors.New("自动封禁未启用，已停止调度（请先在安全事件页配置中启用）")
	}
	cfg, err := GetAutobanConfig()
	if err != nil {
		TaskLogfWarn(AutobanTaskID, "failed", "读取自动封禁配置失败，本轮未执行: %v", err)
		return fmt.Errorf("读取自动封禁配置失败: %w", err)
	}
	// 消费侧护栏——直读配置执行前显式校验（库值唯一真相
	// 铁律：无效值拒绝执行+显性报错，禁止静默兜底）。threshold<=0 会让
	// 「count>=threshold」把全量候选收进名单；duration 非法经 autobanDurations
	// 查表得 0 被当「永久」（候选全落永久封禁条目）；window<=0 让窗口失真。
	// 带外脏行由启动回填（db.go defaultUpdates 六列）在下次启动收敛；校验单源
	// 复用写侧 ValidateAutobanConfig（导入/写侧/消费侧三通道同一口径——通道
	// 语义差异见 ValidateAutobanConfig 注释）。
	// 无效配置是带外污染造成的**持续态**（保存
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
	autobanFlushPendingReload(false)
	// 累犯表物理衰减清理（每轮；dry-run 观察轮同样执行——表增长与模式无关）。
	autobanPruneDecayedRecidivism(autobanNow())

	// 喂入源健康联动。计数唯一喂入点是被停掉的
	// 安全事件采集时，本任务仍会每轮 success 记「计数 0 IP」——自动封禁静默
	// 失效。此处只做可见性：状态变化沿 Warn/Info 各一次 + 每轮摘要追加停摆
	// 注记（+ /security/autoban/status 的 feed_degraded/reason）。不自动拉起
	// 用户显式停止的任务（尊重调度语义）。
	feedDegraded, feedReason := AutobanFeedHealth()
	autobanReportFeedHealth(feedDegraded, feedReason)
	feedNote := ""
	if feedDegraded {
		feedNote = "；数据源停摆：" + feedReason
	}

	if cfg.DryRun {
		// 观察模式不写名单，无 TOCTOU 面——候选评估无需临界区。展示/建议
		// 口径在此截断（评估层不截断，正式 merge 消费全量）。
		candidates := autobanCandidates(cfg, window)
		if len(candidates) > autobanSuggestionCap {
			candidates = candidates[:autobanSuggestionCap]
		}
		autobanSetSuggestions(candidates)
		TaskLogf(AutobanTaskID, "cycle", "观察模式：计数 %d IP / 活跃 %d 个 IP / 达阈值 %d（%s，口径 %s）%s",
			autobanTrackedCount(), autobanReachedCount(), len(candidates), autobanHitDetail(cfg), AutobanScopeLabel(cfg.Scope), feedNote)
		return nil
	}

	// 成功写路径前复核（与威胁/爬虫族同一写门 updateRunWriteGate）：入口角色
	// 门到 merge 写库之间的降级窗口——从节点 merge 会写主库名单（只读不变量）。
	// 已降级→ErrTaskSkipped（不写不收敛）；不可判定→失败落定（任务可见）；
	// 手动取消→ctx.Err。
	if gerr := updateRunWriteGate(rc.Ctx); gerr != nil {
		if errors.Is(gerr, errRunRoleUndecidable) {
			TaskLogfWarn(AutobanTaskID, "failed", "角色读取失败，无法判定本节点是否主节点，本轮自动封禁未写库")
		}
		return gerr
	}

	var candidates []AutobanSuggestion
	var out autobanMergeOutcome
	reloadState := autobanReloadNone
	// merge 读改写+收敛并入同一 CaddyOpLock 临界区——与
	// handlers 名单写路径（AddIPToList/UpdateIPList 持 caddyOpMu=CaddyOpLock
	// 的读改写）交错会丢更新/复活条目；收敛回调（投影热路径/全量重载）均为
	// InLock 变体，临界区内直呼。
	// 候选评估（autobanCandidates，含过期桶先评估再删）
	// 同入本临界区——曾评估在锁外、merge 进锁用陈旧候选：handlers 解封（持
	// CaddyOpLock 的读改写+AutobanForgetIPs 清桶）落在「候选已评估」与「进锁
	// merge」之间时，本轮把刚解封的 IP 加回名单，解封被 ≤1 tick 撤销。评估入
	// 临界区后，解封清桶与本轮评估在锁上全序：解封先完成则候选为空（不回封），
	// 本轮先完成则解封写路径随后删条目（解封生效）。锁序安全：临界区内仅
	// autobanMu（叶锁，全仓无 autobanMu→CaddyOpLock 反向嵌套）。
	if err := func() error {
		CaddyOpLock.Lock()
		defer CaddyOpLock.Unlock()
		candidates = autobanCandidates(cfg, window)
		o, err := autobanMergeEntries(cfg, candidates)
		if err != nil {
			return err
		}
		out = o
		// 到期/挤出条目清桶与名单收敛由禁用收尾共用同一收尾实现；
		// 容量留痕和逐 IP 审计仍在锁外按角色门执行。
		reloadState = autobanApplyMergeOutcomeLocked("名单更新", out, nil)
		return nil
	}(); err != nil {
		return err
	}
	autobanSetSuggestions(nil)
	// 容量收敛留痕不在 Changed 门内、也不在审计写门后：满容量丢弃新封时名单
	// 内容不变（Changed=false），丢弃仍是真实发生的安全事件，必须留痕；降级
	// 窗口内同样留（说明丢弃已发生，避免排障时把「未达标」误当「无异常」）。
	autobanReportCapacityOutcome("", out)
	if out.Changed {
		// 审计写面前复核：merge/收敛已落定（名单变化是事实，终态仍按本轮
		// 成功计）——但降级/取消窗口内不再写逐 IP 审计（审计归因会
		// 失真为主节点作为），留 WARN 说明审计从简。
		if gerr := updateRunWriteGate(rc.Ctx); gerr != nil {
			TaskLogfWarn(AutobanTaskID, "audit", "节点降级/取消窗口：本轮名单已收敛，逐 IP 审计从简（名单内容为准，审计缺口见此行）")
			return nil
		}
		// 审计逐 IP「自动封禁」+ 每批「到期解封」汇总（系统操作者）。
		autobanAuditBanned(cfg, out)
		autobanAuditExpiredUnban(out.Expired, out.ExpiredManual)
	}
	TaskLogf(AutobanTaskID, "cycle", "本轮：计数 %d IP / 活跃 %d 个 IP / 候选 %d / 新封 %d / 到期解封 %d / 名单 %d 条%s%s",
		autobanTrackedCount(), autobanReachedCount(), len(candidates), len(out.Banned), len(out.Expired), out.Total, reloadNote(out.Changed, reloadState), feedNote)
	return nil
}

// autobanReportCapacityOutcome 容量收敛留痕（Run 轮与禁用收尾共用单一实现）：
// WARN 级任务日志行（含计数与挤出条目身份）+ 系统操作者审计行。
// 判据只看本轮是否发生挤出/丢弃，不看 Changed——kept 全为手动条目且满容量时
// 新封被整批丢弃而名单内容不变（Changed=false），留痕仍必须落（否则管理员
// 无法区分「未达标」与「满容量丢弃」，攻击流量静默未被封禁）。
func autobanReportCapacityOutcome(scope string, out autobanMergeOutcome) {
	if out.Evicted == 0 && out.DroppedNew == 0 {
		return
	}
	// 补充挤出条目身份（截断前 10 个+「等 N 个」）——点名被挤者便于核对清桶
	// 与判定是否需要手动加白/调容量。
	suffix := autobanEvictedIdentitySuffix(out.EvictedIPs)
	TaskLogfWarn(AutobanTaskID, "capacity", "自动封禁名单容量收敛%s：挤出 %d、丢弃 %d（上限 %d）%s",
		scope, out.Evicted, out.DroppedNew, AutobanListEntryCap, suffix)
	RecordAuditLog("system", "容量收敛", "IP 地址列表",
		fmt.Sprintf("自动封禁容量收敛%s：挤出 %d、丢弃 %d（上限 %d）%s", scope, out.Evicted, out.DroppedNew, AutobanListEntryCap, suffix), "")
}

// autobanAuditBanned 逐 IP「自动封禁」审计（Run 轮：降级窗口外、名单已收敛）。
// 时长报该 IP 的实际执法时长（out.BannedDurations，累犯升档后可能不同于
// 配置时长）；无 merge 详情（直调形态）回退配置时长。
// 逐 IP 行受单轮上限约束：超限时保留前 N 条并补一条汇总行（完整名单以预置
// IP 列表为准），避免洪峰下单轮写放大到 AutobanListEntryCap 行审计。
func autobanAuditBanned(cfg AutobanConfig, out autobanMergeOutcome) {
	banned := out.Banned
	if len(banned) == 0 {
		return
	}
	omitted := 0
	if len(banned) > autobanAuditPerRoundCap {
		omitted = len(banned) - autobanAuditPerRoundCap
		banned = banned[:autobanAuditPerRoundCap]
	}
	for i, ip := range banned {
		durationLabel := cfg.Duration
		if i < len(out.BannedDurations) {
			durationLabel = autobanEscalationDurationLabel(out.BannedDurations[i])
		}
		RecordAuditLog("system", AutobanAuditAction, "IP 地址列表",
			FormatAuditDetail("IP："+ip,
				autobanHitDetail(cfg),
				"时长："+AutobanDurationLabel(durationLabel),
				AuditResultPart("success")), "")
	}
	if omitted > 0 {
		RecordAuditLog("system", AutobanAuditAction, "IP 地址列表",
			fmt.Sprintf("%s%d 个 IP 省略逐条记录（本轮共 %d 个 IP，逐条上限 %d；完整名单见预置 IP 列表）",
				autobanAuditSummaryPrefix, omitted, len(banned)+omitted, autobanAuditPerRoundCap), "")
	}
}

// autobanHitDetail 封禁审计/日志的命中口径文案：classic 等权「N 次/M 分钟」；
// evidence 披露双阈值（确证 T1 / 嫌疑 T2=T1×倍率，打底比例）。
func autobanHitDetail(cfg AutobanConfig) string {
	if cfg.CountingMode == AutobanCountingEvidence {
		return fmt.Sprintf("命中：确证阈值 %d / 嫌疑阈值 %d（打底 %s）/%d 分钟",
			cfg.Threshold, cfg.Threshold*cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio, cfg.WindowMinutes)
	}
	return fmt.Sprintf("命中：%d 次/%d 分钟", cfg.Threshold, cfg.WindowMinutes)
}

// autobanAuditExpiredUnban 到期解封审计（Run 轮与禁用收尾共用单一实现，
// 系统操作者归因）。按条目来源分行：ips 中不在 manual 子集的是自动封禁
// 条目，manual 子集是手动封禁条目（remark≠自动封禁）——两者解封动作都由
// 系统在到期时执行，但把人工封禁说成「自动封禁的到期解封」会把来源说错，
// 排障时无从区分。
func autobanAuditExpiredUnban(ips, manual []string) {
	if len(ips) == 0 {
		return
	}
	manualSet := make(map[string]struct{}, len(manual))
	for _, ip := range manual {
		manualSet[ip] = struct{}{}
	}
	var autoIPs, manualIPs []string
	for _, ip := range ips {
		if _, ok := manualSet[ip]; ok {
			manualIPs = append(manualIPs, ip)
			continue
		}
		autoIPs = append(autoIPs, ip)
	}
	autobanAuditUnbanGroup(autoIPs, func(total int, joined string) string {
		return fmt.Sprintf("到期自动解封 %d 个自动封禁 IP：%s", total, joined)
	})
	autobanAuditUnbanGroup(manualIPs, func(total int, joined string) string {
		return fmt.Sprintf("到期解封 %d 个手动封禁条目（到期时间到达，系统自动执行）：%s", total, joined)
	})
}

// autobanUnbanAuditPerLine 单条「自动解封」审计行携带的 IP 数上限：detail
// 经 auditDetailMaxBytes(4KiB) 净化截断，IPv6 最长 45 字符 +「、」≈48 字节，
// 40 个 ≈2KB，留足前缀说明余量。旧实现把整批 IP 拼进一行——批量到期（≥~200
// 个 IP）时后半名单被净化截断静默丢失，与逐 IP 封禁审计的可追溯性不对称。
const autobanUnbanAuditPerLine = 40

// autobanAuditUnbanGroup 按行预算分片写解封审计（单轮逐条上限
// autobanAuditPerRoundCap 与封禁审计同口径；超出部分由汇总行点名数量）。
func autobanAuditUnbanGroup(ips []string, line func(total int, joined string) string) {
	if len(ips) == 0 {
		return
	}
	omitted := 0
	if len(ips) > autobanAuditPerRoundCap {
		omitted = len(ips) - autobanAuditPerRoundCap
		ips = ips[:autobanAuditPerRoundCap]
	}
	for start := 0; start < len(ips); start += autobanUnbanAuditPerLine {
		end := start + autobanUnbanAuditPerLine
		if end > len(ips) {
			end = len(ips)
		}
		RecordAuditLog("system", "自动解封", "IP 地址列表", line(len(ips), strings.Join(ips[start:end], "、")), "")
	}
	if omitted > 0 {
		RecordAuditLog("system", "自动解封", "IP 地址列表",
			fmt.Sprintf("%s%d 个 IP 省略逐条记录（本轮共 %d 个，逐条上限 %d）",
				autobanAuditSummaryPrefix, omitted, len(ips)+omitted, autobanAuditPerRoundCap), "")
	}
}

// autobanEvictedIdentitySuffix 容量收敛留痕的挤出条目身份片段
// 前 10 个逐一点名，超出并入「等 N 个」（N=总数）；空集返空串。
func autobanEvictedIdentitySuffix(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	shown := ips
	if len(shown) <= 10 {
		return "：挤出 IP " + strings.Join(shown, "、")
	}
	shown = shown[:10]
	return fmt.Sprintf("：挤出 IP %s 等 %d 个", strings.Join(shown, "、"), len(ips))
}

func reloadNote(changed bool, state autobanReloadState) string {
	if !changed {
		return ""
	}
	switch state {
	case autobanReloadHotApplied:
		return "（投影热路径收敛，零重载）"
	case autobanReloadUnreferenced:
		return "（名单未被引用，零重载）"
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

// AutobanScopeLabel 口径集合的用户可读标签（任务日志/审计/前端状态卡共用单源）。
func AutobanScopeLabel(scope string) string {
	labels := map[string]string{
		AutobanScopeBlocked:         "拦截",
		AutobanScopeLogged:          "检测",
		AutobanScopeChallengeIssued: "挑战发放",
		AutobanScopeChallengeFailed: "挑战失败",
	}
	order := []string{AutobanScopeBlocked, AutobanScopeLogged, AutobanScopeChallengeIssued, AutobanScopeChallengeFailed}
	set := AutobanScopeSet(scope)
	var parts []string
	for _, dim := range order {
		if set[dim] {
			parts = append(parts, labels[dim])
		}
	}
	if len(parts) == 0 {
		return "无"
	}
	return strings.Join(parts, "+")
}

func autobanTrackedCount() int {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	return len(autobanWindows)
}

// autobanRecomputeReached 按当前配置重算全部计数桶的达标标记（阈值变更时
// 调用；O(键数)，10 万键上限下为毫秒级）。Reached 只服务展示/过期摘要，
// 封禁判定用实时候选评估。evidence 模式按双条件重算。
func autobanRecomputeReached(cfg AutobanConfig) {
	autobanMu.Lock()
	evidence := cfg.CountingMode == AutobanCountingEvidence
	for _, w := range autobanWindows {
		if evidence {
			w.Reached = autobanEvidenceReached(w.Confirmed, w.Suspicion, cfg.Threshold, cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio)
		} else {
			w.Reached = cfg.Threshold > 0 && w.Count >= cfg.Threshold
		}
	}
	autobanMu.Unlock()
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
	id, err := ensureAutobanPresetListID()
	if err != nil {
		return nil, 0, err
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		return nil, id, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, id, err
	}
	return entries, id, nil
}

// autobanEntryExpired 条目到期判定（与渲染投影层
// loadIPListEntriesVia 的过滤共用单一判据——expires_at 可解析且
// <= now 视为已到期；空/畸形 expires_at 保留条目不误删）。
func autobanEntryExpired(e models.IPListEntry, now time.Time) bool {
	if e.ExpiresAt == "" {
		return false
	}
	exp := parseAutobanEntryTime(e.ExpiresAt)
	return !exp.IsZero() && !exp.After(now)
}

// AutobanActiveEntries 生效条目视图：过滤已到期未清理条目
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
// 单轮逐 IP 行有上限（autobanAuditPerRoundCap）时，超出部分只存在于汇总行，
// 故计数按「逐 IP 行各 1 + 汇总行携带的省略数」相加——行数上限不会让洪峰
// 轮次的封禁数被截断或重复计（旧实现直接 COUNT(*)：800 个 IP 的一轮以
// 501 条审计行计成 501；只加汇总总数则会把已逐条记录的 500 个再计一遍）。
//
// 折算在 SQL 侧单遍聚合完成（口径=autobanAuditEventCount：前缀命中行取
// 前缀后的省略数、其余行各计 1、不可解析汇总行保守计 1），不再把当日审计行
// 全量拉回 Go 逐行折算——洪峰日单轮 500 行逐条留痕，该查询在 /status 热路径。
// 两处口径的等价性由 TestAutobanBannedToday_countsOmittedBansBeyondRoundCap
// （混合形态端到端）与 autobanAuditEventCount 单测（逐形态）共同钉住。
func AutobanBannedToday() int {
	if db.AuditDB == nil {
		return 0
	}
	loc := CurrentLocation()
	now := autobanNow().In(loc)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC().Format(autobanTimeLayout)
	// substr 按字符定位（前缀含非 ASCII），rune 长度与 SQLite 字符语义对齐；
	// 汇总行前缀后的剩余文本以整数前缀解析（CAST 语义），解析不出按 1 计
	// （MAX(x,1)）——与 Go 侧折算的保守方向一致。
	prefixRunes := utf8.RuneCountInString(autobanAuditSummaryPrefix)
	var n int
	err := db.AuditDB.QueryRow(`SELECT COALESCE(SUM(
		CASE WHEN substr(COALESCE(detail,''),1,?) = ?
		THEN MAX(CAST(substr(COALESCE(detail,''),?) AS INTEGER), 1)
		ELSE 1 END), 0)
		FROM audit_log WHERE action=? AND created_at >= ?`,
		prefixRunes, autobanAuditSummaryPrefix, prefixRunes+1, AutobanAuditAction, dayStart).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// AutobanEscalatedCount 当前处于升级档（offense_count≥2）的累犯身份数。
// 状态卡「累犯升级」统计源；读失败保守 0（与 AutobanBannedToday 同口径）。
func AutobanEscalatedCount() int {
	d := db.GetDB()
	if d == nil {
		return 0
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism WHERE offense_count >= 2`).Scan(&n); err != nil {
		return 0
	}
	return n
}

// AutobanRecidivismRecord 累犯历史行（面板「累犯升级」下钻弹框投影）：
// identity 为封禁身份键（IPv6 /64 归一/IPv4 裸地址，与计数键同形）。
// IPLocation 由 handlers 层富化（enrichIPLocation 单源，与事件日志同口径；
// 服务层不依赖 GeoIP）。BanStatus/BanExpiresAt join 自动封禁名单生效条目
// （AutobanActiveEntries 同口径）；Hits24h/LastEventAt 按身份键聚合 metrics
// security_events 近 24h（IPv6 /64 归一，展示位容错）。
type AutobanRecidivismRecord struct {
	Identity          string `json:"identity"`
	OffenseCount      int    `json:"offense_count"`
	LastBanAt         string `json:"last_ban_at"`
	EscalatedDuration string `json:"escalated_duration"`
	IPLocation        string `json:"ip_location"`
	BanStatus         string `json:"ban_status"`
	BanExpiresAt      string `json:"ban_expires_at"`
	Hits24h           int    `json:"hits_24h"`
	LastEventAt       string `json:"last_event_at"`
}

// ListAutobanRecidivism 累犯历史筛选分页查询（offense_count 降序、identity
// 升序——面板弹框按再犯次数优先呈现）。hidePermanent=true 隐藏
// escalated_duration=permanent 行（默认视图只看可升级身份）；ipFilter 非空时
// 按 identity 子串匹配（LIKE 通配符 %/_/\ 转义为字面，与审计日志筛选同口径）。
// 返回 (本页记录, 筛选后总数)；空结果返回非 nil 空切片（JSON [] 契约）。
// page/pageSize 由调用方解析保证 ≥1（parsePaginationParam 统一口径）。
// 读失败返回错误，由调用方响亮 500——不以空列表冒充成功（与状态卡
// fail-closed 口径同族：确定态不得由故障伪造）。
func ListAutobanRecidivism(hidePermanent bool, ipFilter string, page, pageSize int) ([]AutobanRecidivismRecord, int, error) {
	d := db.GetDB()
	if d == nil {
		return nil, 0, errors.New("database unavailable")
	}
	where := " WHERE 1=1"
	var args []any
	if hidePermanent {
		where += " AND escalated_duration <> 'permanent'"
	}
	if ipFilter != "" {
		where += " AND identity LIKE ? ESCAPE '\\'"
		args = append(args, "%"+autobanEscapeLike(ipFilter)+"%")
	}
	var total int
	if err := d.QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Query(`SELECT identity, offense_count, last_ban_at, escalated_duration
		FROM autoban_recidivism`+where+` ORDER BY offense_count DESC, identity LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]AutobanRecidivismRecord, 0)
	for rows.Next() {
		var r AutobanRecidivismRecord
		if err := rows.Scan(&r.Identity, &r.OffenseCount, &r.LastBanAt, &r.EscalatedDuration); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	enrichAutobanRecidivismRows(out)
	return out, total, nil
}

// enrichAutobanRecidivismRows 行富化（名单封禁态 + 近 24h 事件聚合）：
//   - ban_status/ban_expires_at：join 自动封禁名单生效条目（AutobanListEntries
//   - AutobanActiveEntries，与 /status 生效面同口径——已到期未清理条目不算
//     封禁中）。条目值经 autobanEntryIdentity 归一匹配身份键（IPv6 /64 CIDR
//     与裸身份同键）；无到期时刻=permanent，有到期=timed（到期时刻透传）；
//     名单无条目/名单读取失败=none（展示位容错，列表主体已读成功，不因
//     join 失败整体 500）。
//   - hits_24h/last_event_at：metrics security_events 近 24h 按身份键聚合。
//     原始表 client_ip 为逐地址形态（非 /64 归一）：IPv4 身份走 client_ip IN
//     精确批量（idx_security_events_ip_time 索引范围扫描）；IPv6 身份取回窗口
//     内 IPv6 行后经 autobanIdentityKey 归一聚合（/64 漂移地址计入本段，与
//     计数身份同粒度）。窗口 [now-24h, now]（UTC 墙钟串，含边界）；metrics
//     句柄缺失/查询失败降级零值（状态卡统计位容错同族）。
func enrichAutobanRecidivismRows(records []AutobanRecidivismRecord) {
	if len(records) == 0 {
		return
	}
	byIdentity := make(map[string]int, len(records))
	for i := range records {
		records[i].BanStatus = "none"
		byIdentity[records[i].Identity] = i
	}
	if entries, _, err := AutobanListEntries(); err == nil {
		for _, e := range AutobanActiveEntries(entries) {
			idx, ok := byIdentity[autobanEntryIdentity(e.Value)]
			if !ok {
				continue
			}
			if e.ExpiresAt == "" {
				records[idx].BanStatus = "permanent"
				records[idx].BanExpiresAt = ""
			} else {
				records[idx].BanStatus = "timed"
				records[idx].BanExpiresAt = e.ExpiresAt
			}
		}
	}
	metrics := db.MetricsDB
	if metrics == nil {
		return
	}
	now := autobanNow()
	windowStart := now.Add(-24 * time.Hour).Format(autobanTimeLayout)
	nowText := now.Format(autobanTimeLayout)
	var v4Args []any
	var placeholders []string
	hasV6 := false
	for identity := range byIdentity {
		if strings.Contains(identity, ":") {
			hasV6 = true
			continue
		}
		placeholders = append(placeholders, "?")
		v4Args = append(v4Args, identity)
	}
	if len(placeholders) > 0 {
		rows, err := metrics.Query(`SELECT client_ip, COUNT(*), MAX(event_time) FROM security_events
			WHERE event_time >= ? AND event_time <= ? AND client_ip IN (`+strings.Join(placeholders, ",")+`)
			GROUP BY client_ip`, append([]any{windowStart, nowText}, v4Args...)...)
		if err == nil {
			for rows.Next() {
				var ip, last string
				var hits int
				if rows.Scan(&ip, &hits, &last) == nil {
					if idx, ok := byIdentity[ip]; ok {
						records[idx].Hits24h = hits
						records[idx].LastEventAt = autobanRecidivismEventTime(last)
					}
				}
			}
			rows.Close()
		}
	}
	if !hasV6 {
		return
	}
	rows, err := metrics.Query(`SELECT client_ip, event_time FROM security_events
		WHERE event_time >= ? AND event_time <= ? AND client_ip LIKE '%:%'`, windowStart, nowText)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var ip, eventTime string
		if rows.Scan(&ip, &eventTime) != nil {
			continue
		}
		idx, ok := byIdentity[autobanIdentityKey(ip)]
		if !ok {
			continue
		}
		records[idx].Hits24h++
		eventTime = autobanRecidivismEventTime(eventTime)
		if eventTime > records[idx].LastEventAt {
			records[idx].LastEventAt = eventTime
		}
	}
}

// autobanRecidivismEventTime 把 security_events.event_time 归一为 DB 墙钟布局：
// DATETIME 列经 SQLite datetime() 规范化可能呈 ISO 形态（"…T…Z"，采集默认值
// 路径），展示侧与 last_ban_at 同布局（YYYY-MM-DD HH:MM:SS，UTC）；不可解析
// 原样透传（不丢数据，前端 formatDate 双形态兼容）。
func autobanRecidivismEventTime(value string) string {
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts.UTC().Format(autobanTimeLayout)
	}
	return value
}

// autobanEscapeLike 使用户筛选输入在 SQL LIKE 中保持字面量子串语义
// （与 handlers.escapeLikePattern 同口径镜像——services 不反向依赖 handlers）；
// 调用方负责包裹 % 并在 SQL 中声明 ESCAPE '\\'。
func autobanEscapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// AutobanRecidivismDeleter 是单条删除的最小依赖面（库句柄或已开启的事务）。
// 事务形态是加名单处置的必需用法：处置与名单写入同事务原子提交，事务外
// DELETE 会与持写锁的调用方事务争 SQLITE_BUSY（与 AutobanConfigQuerier 同族）。
type AutobanRecidivismDeleter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// deleteAutobanRecidivismSQL 单条删除语句单源（库句柄/事务两形态共用）。
const deleteAutobanRecidivismSQL = `DELETE FROM autoban_recidivism WHERE identity=?`

// DeleteAutobanRecidivismFrom 在调用方给定的视图上删除单条累犯身份行。
// identity 经 autobanEntryIdentity 归一（与计数键/merge 记账键同形——
// 大写/完整形态 IPv6 与 /64 CIDR 均命中归一行）。
// 幂等：identity 不存在时同样成功（DELETE 零行不报错）。
func DeleteAutobanRecidivismFrom(ctx context.Context, e AutobanRecidivismDeleter, identity string) error {
	_, err := e.ExecContext(ctx, deleteAutobanRecidivismSQL, autobanEntryIdentity(identity))
	return err
}

// ErrAutobanIdentityBanned 单条移除守卫拒绝：身份正被自动封禁（名单生效
// 条目命中）。handlers 映射 400「封禁中」——须先取消封禁再移除前科。
var ErrAutobanIdentityBanned = errors.New("autoban identity actively banned")

// DeleteAutobanRecidivismGuarded 守卫+删除同一 BEGIN IMMEDIATE 事务
// （DSN _txlock=immediate：事务开始即持写锁）：守卫读到的名单即删除时刻
// 的名单——并发 merge/名单写在守卫读与 DELETE 之间无法提交，杜绝
// 「守卫放行→封禁落库→前科被删」的处置语义分裂（TOCTOU）。identity 在
// 入口归一（返回值供审计留痕）。封禁中返回 ErrAutobanIdentityBanned 且
// 事务回滚（零写入）；幂等：不存在也成功。只清历史记账，不动名单条目。
// DELETE 触发器 bump cluster_version，从端下一同步周期整表收敛。
func DeleteAutobanRecidivismGuarded(ctx context.Context, identity string) (string, error) {
	identity = autobanEntryIdentity(identity)
	d := db.GetDB()
	if d == nil {
		return identity, errors.New("database unavailable")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return identity, err
	}
	defer tx.Rollback()
	banned, err := autobanIdentityBannedInView(ctx, tx, identity)
	if err != nil {
		return identity, err
	}
	if banned {
		return identity, ErrAutobanIdentityBanned
	}
	if _, err := tx.ExecContext(ctx, deleteAutobanRecidivismSQL, identity); err != nil {
		return identity, err
	}
	return identity, tx.Commit()
}

// DeleteAutobanRecidivism 删除单条累犯身份行（取消累犯身份——下次达阈值按
// 首次档起算）。identity 经 autobanEntryIdentity 归一。幂等：identity 不存在
// 时同样成功（DELETE 零行不报错）。只清历史记账，不动名单条目：已生效封禁
// 保持至到期。守卫+删除原子形态见 DeleteAutobanRecidivismGuarded。
// DELETE 触发器 bump cluster_version，从端下一同步周期整表收敛。
func DeleteAutobanRecidivism(identity string) error {
	d := db.GetDB()
	if d == nil {
		return errors.New("database unavailable")
	}
	_, err := d.Exec(deleteAutobanRecidivismSQL, autobanEntryIdentity(identity))
	return err
}

// ResetAutobanRecidivism 清空全部累犯历史（重置计数——下次达阈值按首次档
// 重新起算）。只清历史记账，不动名单条目：已生效封禁保持至到期。
// DELETE 触发器 bump cluster_version，从端下一同步周期整表收敛。
func ResetAutobanRecidivism() error {
	d := db.GetDB()
	if d == nil {
		return errors.New("database unavailable")
	}
	_, err := d.Exec(`DELETE FROM autoban_recidivism`)
	return err
}

// autobanAuditEventCount 把一条「自动封禁」审计行折算成封禁事件数：汇总行
// 携带被省略的逐条记录数（前缀后的整数），逐 IP 行与历史文案各计 1——
// 无法识别的形态按 1 计是保守方向（不会凭空放大统计）。
//
// 折算口径的 Go 侧规格（AutobanBannedToday 的 SQL 聚合按本函数语义镜像）；
// 生产计数已不走本函数（见 AutobanBannedToday），保留作口径单源与单测锚。
func autobanAuditEventCount(detail string) int {
	if rest, ok := strings.CutPrefix(detail, autobanAuditSummaryPrefix); ok {
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			if n, err := strconv.Atoi(rest[:end]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1
}
