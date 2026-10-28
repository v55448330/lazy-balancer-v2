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
// Commit 后）喂 autobanObserveBatch（主节点+启用+口径+WAF 事件四重过滤）→
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// AutobanConfigQuerier 是六列读取的最小依赖面（库句柄或已开启的事务）。
// 事务形态是备份导入的必需用法：导入在写事务内比对「导入前」运行值，
// 事务外读 live 会与已开启的写事务争同一连接（单连接池下自锁）。
type AutobanConfigQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ReadAutobanConfigFrom 在调用方给定的视图上读六列（COALESCE 仅归一存量
// NULL；读失败显性返回错误）。GetAutobanConfig 与导入侧共用本单源——
// 两份手写 SELECT 的列/COALESCE 默认值漂移会让导入侧比对出假的「配置变化」。
func ReadAutobanConfigFrom(ctx context.Context, q AutobanConfigQuerier) (AutobanConfig, error) {
	var en, threshold, window, dry int
	var duration, scope string
	err := q.QueryRowContext(ctx, `SELECT COALESCE(autoban_enabled,?), COALESCE(autoban_threshold,?),
		COALESCE(autoban_window_minutes,?), COALESCE(autoban_duration,?), COALESCE(autoban_scope,?), COALESCE(autoban_dry_run,?)
		FROM global_config WHERE id=1`,
		db.DefaultAutobanEnabled, db.DefaultAutobanThreshold, db.DefaultAutobanWindowMinutes,
		db.DefaultAutobanDuration, db.DefaultAutobanScope, db.DefaultAutobanDryRun).Scan(&en, &threshold, &window, &duration, &scope, &dry)
	if err != nil {
		return AutobanConfig{}, err
	}
	return AutobanConfig{
		Enabled:       en == 1,
		Threshold:     threshold,
		WindowMinutes: window,
		Duration:      duration,
		Scope:         scope,
		DryRun:        dry == 1,
	}, nil
}

// GetAutobanConfig 读六项配置（COALESCE 仅归一存量 NULL；读失败显性返回错误）。
func GetAutobanConfig() (AutobanConfig, error) {
	cfg := AutobanConfig{
		Threshold:     db.DefaultAutobanThreshold,
		WindowMinutes: db.DefaultAutobanWindowMinutes,
		Duration:      db.DefaultAutobanDuration,
		Scope:         db.DefaultAutobanScope,
		DryRun:        db.DefaultAutobanDryRun == 1,
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

// ValidateAutobanConfig 写侧校验：阈值 1-10000、窗口 1-60 分钟、时长/口径枚举。
//
// 历史设计评审（显式声明）：六列配置的三条归一通道语义
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
// 旧计数不可与新口径混算）。禁用（enabled=false）同样清空计数桶与观察建议
// ——停用期无喂入，陈旧计数不得在重新启用后立即封禁（见下方调用点注释）。
func SetAutobanConfig(cfg AutobanConfig) error {
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
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=?, autoban_window_minutes=?, autoban_duration=?, autoban_scope=?, autoban_dry_run=? WHERE id=1`,
		en, cfg.Threshold, cfg.WindowMinutes, cfg.Duration, cfg.Scope, dry); err != nil {
		return err
	}
	// 运行期收敛（清桶/重算 Reached/禁用收尾/调度联动）与备份导入提交后
	// 共用同一单源——六列有第二条写入路径（导入/还原的通用
	// `UPDATE global_config`），各自内联判断会让不变量在导入面静默失效。
	ReconcileAutobanRuntimeAfterConfigReplace(prev, cfg)
	return nil
}

// autobanConfigReplaceEffects 是「六列配置已被替换」后的运行期收敛判定。
// 单源：ReconcileAutobanRuntimeAfterConfigReplace 的动作与
// AutobanConfigReplaceEffectNote 的文案共用本判定（判定与文案漂移会让
// 「响应说清了桶」与「实际清桶」分叉）。
type autobanConfigReplaceEffects struct {
	// resetCounters：口径/窗口变更 → 旧计数不可与新口径混算。
	resetCounters bool
	// recomputeReached：阈值变更 → 重算「已达阈值」读口径。
	recomputeReached bool
	// disableFlush：新配置为禁用 → 到期条目解封收尾 + 清桶。
	disableFlush bool
	// loopToggled：启用态翻转 → 调度随之启停。
	loopToggled bool
}

func autobanConfigReplaceEffectsOf(old, new AutobanConfig) autobanConfigReplaceEffects {
	effect := autobanConfigReplaceEffects{
		resetCounters:    old.WindowMinutes != new.WindowMinutes || old.Scope != new.Scope,
		recomputeReached: old.Threshold != new.Threshold,
		disableFlush:     !new.Enabled,
		loopToggled:      old.Enabled != new.Enabled,
	}
	return effect
}

// ReconcileAutobanRuntimeAfterConfigReplace 在「六列自动封禁配置已被替换」之后
// 收敛运行期状态（单源：PUT 保存 / 备份导入-还原提交后）。old/new 分别为
// 替换前后的运行值；调用方只需保证替换已完成（本函数不写库）。
//
// 前置条件：调用方**未持** CaddyOpLock——禁用收尾会自取（非重入锁，已在
// Caddy 临界区内调用必须在释放锁之后再调本函数）。
//
// 动作语义：
//   - 口径（scope）/统计窗口变更 → 清空固定窗口计数桶与观察建议：旧计数按
//     新口径不可混算（口径过滤集合变了、桶长也变了）；
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
		autobanRecomputeReached(new.Threshold)
	}
	if effect.disableFlush {
		AutobanDisableFlush()
		ResetAutobanCounters()
	}
	// 调度应用走与业务驱动整轮对齐共用的互斥（避免「库新/loop 旧」交错）。
	applyBusinessTaskLoop(AutobanTaskID, new.Enabled)
}

// AutobanConfigReplaceEffectNote 返回「替换六列后运行期收敛动作」的用户可读
// 说明（导入/还原响应的 warnings 与成功审计单源）；无收敛动作（六列相同，
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
	if effect.disableFlush {
		parts = append(parts, "自动封禁已停用，已执行禁用收尾（到期条目解封、统计计数清空）")
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
	if db.DB == nil {
		return false, false
	}
	var en int
	if err := db.DB.QueryRow(`SELECT COALESCE(autoban_enabled,0) FROM global_config WHERE id=1`).Scan(&en); err != nil {
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

// ResetAutobanCounters 清空计数器（口径/窗口变更/测试用）：计数桶+上一轮观察
// 建议一并清空——建议是同一窗口口径下的观察输出，口径变更/名单全量替换后旧
// 建议对现状失真（同款 ≤1 tick 展示残留，历史定性并入）。
func ResetAutobanCounters() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows = make(map[string]*autobanCounter)
	autobanSuggestions = nil
	autobanCapWarned = false
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

// autobanSourceEligible 只排除真实验证爬虫豁免事件；伪装爬虫是实际 deny，
// 与普通 WAF 事件一样进入计数。分类复用摄取评分的 ID 编解码单源。
func autobanSourceEligible(ruleTriggered string) bool {
	return !securityEventsIsCrawlerExemptRule(ruleTriggered)
}

func autobanObserveEventScopedAt(cfg AutobanConfig, ip, action, ruleTriggered string, at time.Time) {
	// 窗口无效（<=0，消费侧护栏）跳过计数——不落写死兜底（旧 5 分钟
	// 兜底已删，-③）。
	window := time.Duration(cfg.WindowMinutes) * time.Minute
	if ip == "" || ruleTriggered == "" || window <= 0 || !autobanActionMatches(cfg.Scope, action) || !autobanSourceEligible(ruleTriggered) {
		return
	}
	now := autobanNow()
	// 积压回放（摄取停摆恢复/轮转补采）不得按到达时间瞬时达标：早于当前
	// 窗口的事件不计数。
	if !at.IsZero() && now.Sub(at) > window {
		return
	}
	var capWarn bool
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
			w.Count = 0
			w.WindowStart = now
			w.Reached = false
		}
		w.Count++
		w.LastSeen = now
		if !w.Reached && cfg.Threshold > 0 && w.Count >= cfg.Threshold {
			w.Reached = true
		}
	}
	autobanMu.Unlock()
	if capWarn {
		Logf("warn", "自动封禁计数器达 %d 键上限，新 IP 不再计数（既有键不受影响）", autobanMaxTrackedIPs)
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

// autobanCandidates 评估候选：先评估后修剪——过期桶若计数
// 已跨阈值（桶尾达标形态：最后采样在窗口尾、周期 tick 晚于窗口到期）必须并入
// 候选再删，否则该 IP 永不封禁；未跨阈值的过期桶照常修剪不产生候选。曾达标
// IP 的过期桶修剪时按轮汇总一条 expire（与 Feed 路径同语义——窗口过期清零的
// 唯一两条发射面）。
func autobanCandidates(threshold int, window time.Duration) []AutobanSuggestion {
	now := autobanNow()
	var expiredReached []string
	autobanMu.Lock()
	var expiredCandidates []AutobanSuggestion
	for ip, w := range autobanWindows {
		if !w.WindowStart.IsZero() && now.Sub(w.WindowStart) >= window {
			// 先评估——过期桶已跨阈值的并入候选，再删桶。
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

// AutobanForgetIPs 解封侧计数清零（用户裁定「删除即解封」
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
	// 同步清 autobanSuggestions 对应 IP——建议列表是上一轮
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
	ListID  int64
	Expired []string // 到期解封的 IP（自动+手动条目全集，清桶口径按全集）
	// ExpiredManual 是 Expired 中 remark≠自动封禁（手动封禁）的子集：解封
	// 动作同样由系统执行，但审计文案若把人工封禁条目称「到期自动解封」会把
	// 来源说错（排障时无法区分自动/手动），故单列供审计分流。
	ExpiredManual []string
	Banned        []string // 本轮新封禁的 IP
	Evicted       int      // 超限挤出的自动条目数
	EvictedIPs    []string // 被挤出条目的 IP（挤出=解封同语义：调用方须随
	// Expired 一起清计数桶，否则旧计数仍 ≥ 阈值 → 下轮零新事件立即重封，
	// 形成「挤出→重封→再挤出」轮转；同时供容量收敛留痕点名身份）
	DroppedNew int // 容量不足丢弃的新封数
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
			if e.Remark != autobanEntryRemark {
				out.ExpiredManual = append(out.ExpiredManual, e.Value)
			}
			expiredThisRound[e.Value] = struct{}{}
			out.Changed = true
			continue
		}
		kept = append(kept, e)
		inList[e.Value] = struct{}{}
	}

	// 2) 新封过滤：已在名单跳过；其余追加（permanent 不带 expires_at）。
	// 本轮刚到期解封的 IP 不得在同一轮被计数桶立即重封
	// （window>duration 时计数仍跨阈值 → 封禁被延长到约 window+duration 并
	// 产生成对的「自动解封/自动封禁」审计）；计数桶由 RunAutobanCycle 随后
	// 清空，新流量重新计数/达标仍会再封（与手动解封同语义）。
	duration := autobanDurations[cfg.Duration]
	var toAdd []models.IPListEntry
	for _, c := range candidates {
		if c.IP == "" {
			continue
		}
		if _, justExpired := expiredThisRound[c.IP]; justExpired {
			continue
		}
		if _, exists := inList[c.IP]; exists {
			continue
		}
		entry := models.IPListEntry{Value: c.IP, Remark: autobanEntryRemark, CreatedAt: nowStr}
		if duration > 0 {
			entry.ExpiresAt = now.Add(duration).Format(autobanTimeLayout)
		}
		toAdd = append(toAdd, entry)
		inList[c.IP] = struct{}{}
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
		if e.Remark != autobanEntryRemark {
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
		toAdd = toAdd[:keep]
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
	if err := tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
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
		candidates := autobanCandidates(cfg.Threshold, window)
		if len(candidates) > autobanSuggestionCap {
			candidates = candidates[:autobanSuggestionCap]
		}
		autobanSetSuggestions(candidates)
		TaskLogf(AutobanTaskID, "cycle", "观察模式：计数 %d IP / 活跃 %d 个 IP / 达阈值 %d（阈值 %d 次/%d 分钟，口径 %s）%s",
			autobanTrackedCount(), autobanReachedCount(), len(candidates), cfg.Threshold, cfg.WindowMinutes, autobanScopeLabel(cfg.Scope), feedNote)
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
		candidates = autobanCandidates(cfg.Threshold, window)
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
		// 成功计）——但降级/取消窗口内不再写逐 IP 审计（审计归因会失真为
		// 主节点作为），留 WARN 说明审计从简。
		if gerr := updateRunWriteGate(rc.Ctx); gerr != nil {
			TaskLogfWarn(AutobanTaskID, "audit", "节点降级/取消窗口：本轮名单已收敛，逐 IP 审计从简（名单内容为准，审计缺口见此行）")
			return nil
		}
		// 审计逐 IP「自动封禁」+ 每批「到期解封」汇总（系统操作者）。
		autobanAuditBanned(cfg, out.Banned)
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
// 逐 IP 行受单轮上限约束：超限时保留前 N 条并补一条汇总行（完整名单以预置
// IP 列表为准），避免洪峰下单轮写放大到 AutobanListEntryCap 行审计。
func autobanAuditBanned(cfg AutobanConfig, banned []string) {
	if len(banned) == 0 {
		return
	}
	omitted := 0
	if len(banned) > autobanAuditPerRoundCap {
		omitted = len(banned) - autobanAuditPerRoundCap
		banned = banned[:autobanAuditPerRoundCap]
	}
	for _, ip := range banned {
		RecordAuditLog("system", AutobanAuditAction, "IP 地址列表",
			FormatAuditDetail("IP："+ip,
				fmt.Sprintf("命中：%d 次/%d 分钟", cfg.Threshold, cfg.WindowMinutes),
				"时长："+AutobanDurationLabel(cfg.Duration),
				AuditResultPart("success")), "")
	}
	if omitted > 0 {
		RecordAuditLog("system", AutobanAuditAction, "IP 地址列表",
			fmt.Sprintf("%s%d 个 IP 省略逐条记录（本轮共 %d 个 IP，逐条上限 %d；完整名单见预置 IP 列表）",
				autobanAuditSummaryPrefix, omitted, len(banned)+omitted, autobanAuditPerRoundCap), "")
	}
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

// autobanRecomputeReached 按当前阈值重算全部计数桶的达标标记（阈值变更时
// 调用；O(键数)，10 万键上限下为毫秒级）。Reached 只服务展示/过期摘要，
// 封禁判定用实时 Count>=threshold。
func autobanRecomputeReached(threshold int) {
	autobanMu.Lock()
	for _, w := range autobanWindows {
		w.Reached = threshold > 0 && w.Count >= threshold
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
func AutobanBannedToday() int {
	if db.AuditDB == nil {
		return 0
	}
	loc := CurrentLocation()
	now := autobanNow().In(loc)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC().Format(autobanTimeLayout)
	rows, err := db.AuditDB.Query(`SELECT COALESCE(detail,'') FROM audit_log WHERE action=? AND created_at >= ?`, AutobanAuditAction, dayStart)
	if err != nil {
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			return 0
		}
		n += autobanAuditEventCount(detail)
	}
	if err := rows.Err(); err != nil {
		return 0
	}
	return n
}

// autobanAuditEventCount 把一条「自动封禁」审计行折算成封禁事件数：汇总行
// 携带被省略的逐条记录数（前缀后的整数），逐 IP 行与历史文案各计 1——
// 无法识别的形态按 1 计是保守方向（不会凭空放大统计）。
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
