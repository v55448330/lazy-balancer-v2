package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/taskengine"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
)

var wafDir = "/app/waf"

// wafDistDir 镜像内 WAF 发行版目录（CRS 树/xdb/爬虫种子的兜底来源）。
// ConfigureWafDirs 随 data_dir 派生。
var wafDistDir = "/app/waf.dist"

// OverrideThreatWafDirForTest 测试注入临时 waf 目录（macOS 无 /app）。
func OverrideThreatWafDirForTest(dir string) (restore func()) {
	old := wafDir
	wafDir = dir
	return func() { wafDir = old }
}

// 威胁情报库（v2.3.2 名单化重构）：三个内置只读源（USTC/FireHOL level1/ET
// Compromised）的单一顺序更新任务。内容落 security_ip_lists 的 system=1
// 内置名单行（策略经 ip_acl_list_refs/ip_whitelist_refs 引用生效——
// 「引用即应用」，无全局兜底规则）；状态/计数/版本落 security_threat_sources
// （状态机镜像 CRS/IP2Region 更新族：idle/running/success/failed + 失败
// 指数退避）。内容与状态两表分离，渲染走名单引用的既有链路
// （mergedACLList → 聚合 → @ipListFast 文件投影）。

var ErrThreatUpdateRunning = errors.New("威胁情报库更新任务正在进行中")

// ErrThreatUpdateFailed 任一源失败即整体失败：失败终态
// 回传引擎——RunUpdate 曾恒返 nil，引擎 task_runs 把失败轮记成 success。口径与
// run 内 anyFailed/failSourceRow 对齐；skipped（角色复查）/cancelled（手动取消）
// 各有终态通道，不算失败。
var ErrThreatUpdateFailed = errors.New("威胁情报库更新失败：存在未更新成功的源（详见威胁库更新日志）")

const (
	threatMaxBodyBytes    = 16 << 20 // 16MB
	threatMaxEntries      = 200000
	threatMinParseRatio   = 0.5
	threatDownloadTimeout = 30 * time.Second
)

type ThreatUpdateManager struct {
	mu        sync.Mutex
	running   bool
	runCancel context.CancelCauseFunc
	// lastTrigger/lastFinishedAt 为任务级状态（status 端点 + 弹框展示）。
	lastTrigger     string
	lastStartedAt   string
	lastFinishedAt  string
	lastTaskOutcome string // success / failed / ""（未跑过）
	// lastRunEmptySources 标记本轮「启用源均未到期，无更新」。它是**审计动作
	// 的附加语义**而非终态：零到期源轮按成功轮落定（task_runs=success），审计
	// 动作仍记「更新」，detail 显式声明「无到期源」——与爬虫族同口径。
	// 「跳过」动作专留给降级中止，不再同时承载「正常空轮」。
	lastRunEmptySources bool
}

// nil-until-init（镜像 CRS/IP2Region 管理器）：仅 main.go 初始化。角色传播
// 统一由任务引擎 SetRole 驱动（BecomeSlave/Promote 仅调用 SetRole，不再有
// SetMasterRole 旁路）；未初始化时相关调度钩子经 nil 守卫跳过，不会把
// 调度器（首轮即下载）带进无关测试。
var threatUpdateManager *ThreatUpdateManager

// InitThreatUpdateManager 初始化单例（main.go 启动装配调用一次）。
func InitThreatUpdateManager() {
	threatUpdateManager = &ThreatUpdateManager{}
}

func GetThreatUpdateManager() *ThreatUpdateManager {
	return threatUpdateManager
}

// ResetThreatUpdateManagerForTest 换成全新实例（含停调度器）——测试二进制
// 中初始化入口（main 不运行），同时切断跨测试的 running/调度器残留。
func ResetThreatUpdateManagerForTest() {
	threatUpdateManager = &ThreatUpdateManager{}
}

// 威胁库自动更新总开关（v2.3.2 用户裁定）：global_config.threat_auto_update
// 为任务级总闸（规则库卡片父行开关）；逐源 update_enabled 决定任务更新
// 哪些源（弹框内开关）。两者解耦——总闸关闭时整任务不启动。
func SetThreatAutoUpdate(enabled bool) error {
	if err := setGlobalTaskAutoUpdate("threat", enabled); err != nil {
		return err
	}
	if enabled {
		ArmThreatFirstSlots()
	}
	return nil
}

// ThreatAutoUpdateEnabled 读威胁库总闸。
func ThreatAutoUpdateEnabled() bool { return globalTaskAutoUpdateEnabled("threat") }

// ClearThreatUpdateManagerForTest 清空单例（用于要求 manager 未初始化的
// 引擎接线测试；与 Reset 返回新实例的更新行为测试区分）。
func ClearThreatUpdateManagerForTest() { threatUpdateManager = nil }

// TaskStatus 任务级状态快照（status 端点）。
type ThreatTaskStatus struct {
	Running    bool   `json:"running"`
	Trigger    string `json:"trigger"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Outcome    string `json:"outcome"`
	// Cancellable: 运行中且支持手动取消（任务监控，v2.3.4）。
	Cancellable bool `json:"cancellable"`
}

func (m *ThreatUpdateManager) StatusSnapshot() ThreatTaskStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ThreatTaskStatus{
		Running:     m.running,
		Trigger:     m.lastTrigger,
		StartedAt:   m.lastStartedAt,
		FinishedAt:  m.lastFinishedAt,
		Outcome:     m.lastTaskOutcome,
		Cancellable: m.running,
	}
}

// threatReloader 残留 /load 收敛回调（main.go 注入 caddyReloader）：仅热路径
// 未证实收敛（发射面变化/运行配置不可读/刷新被拒）时的 fail-safe 回退使用
// ——受信代理引用面 2026-10-15 随 tp.txt/lb_file 热路径化退役，不再有
// 「按引用面定向重载」形态。
var threatReloader func() error

// threatProjectionRefresher 投影热路径回调（main.go 注入
// CaddyService.RefreshIPListProjections，2026-10-15 用户裁定 threatReloader
// 重载门退役）：被启用策略引用的名单内容变化后重写投影文件收敛（零 /load，
// @ipListFast 匹配器 ≤1s stat 热感知）。返回 ProjectionConverged=已证实收敛
// ProjectionNeedForce（本轮渲染物化了证书文件）与
// ProjectionFallback（发射面变化/运行配置不可读）均未证实收敛，调用方回退
// threatReloader 强制 /load 收敛（宁可一次重载，不欠引用方渲染收敛；强制
// 形态同时满足）。失败自愈标记（threatReloadPending）随之
// 退役：热路径无失败态（回退即当轮 /load）；残留受信代理分支的失败由配置
// 一致性看门狗漂移横幅 + 下次任意配置变更收敛兜底。
var threatProjectionRefresher func() (IPListProjectionOutcome, error)

// SetThreatReloader 注册残留 /load 回调（nil=清除，测试用）。
func SetThreatReloader(fn func() error) {
	threatReloader = fn
}

// SetThreatProjectionRefresher 注册投影热路径回调（nil=清除，测试用）。
func SetThreatProjectionRefresher(fn func() (IPListProjectionOutcome, error)) {
	threatProjectionRefresher = fn
}

// StartUpdate 异步启动更新任务（单实例在飞）；返回完成通道。rc 语义同 CRS。
func (m *ThreatUpdateManager) StartUpdate(trigger string, rc *taskengine.RunContext) (chan struct{}, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, ErrThreatUpdateRunning
	}
	m.running = true
	// 同族（家族收敛）：可取消 ctx 与 running
	// 在同一临界区登记——StartUpdate 返回后立刻 CancelRunning（任务引擎
	// CancelHook／前端连点／自动化脚本）必须命中，不得因 run goroutine 尚未
	// 执行而读到 runCancel==nil（首次）或上一轮的陈旧 cancel（非首次）静默
	// 失效/取消错轮。CRS/IP2Region 已同形收敛。
	runCtx, runCancel := context.WithCancelCause(updateRunBaseContext(rc))
	m.runCancel = runCancel
	done := make(chan struct{})
	m.mu.Unlock()

	go func() {
		defer close(done)
		defer runCancel(nil)
		// 自建 goroutine 不被引擎 runGuarded 覆盖——未捕获 panic=整个
		// admin 进程退出（与 ip2region/CRS 族同形护栏）。正常路径由
		// runWithContext 内部 recover 先行落定 failed 终态，此处仅兜底。
		defer func() {
			if r := recover(); r != nil {
				Logf("error", "threat update: run panicked: %v\n%s", r, debug.Stack())
				m.mu.Lock()
				m.running = false
				m.mu.Unlock()
			}
		}()
		m.runWithContext(runCtx, trigger, rc)
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	return done, nil
}

// RunUpdate 同步执行更新任务（测试与内部路径）。rc 语义同 CRS StartUpdate
// （RunID>0=引擎已记跳自记；Operator 审计归人）。
func (m *ThreatUpdateManager) RunUpdate(trigger string, rc *taskengine.RunContext) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrThreatUpdateRunning
	}
	m.running = true
	// 同族（家族收敛）：可取消 ctx 与 running 在同一临界区登记——生产入口
	// 即本函数，解锁到管线执行之间不得留下「取消读不到本轮 ctx」的窗口
	//（首次读到 nil=判不可取消；非首次读到上一轮陈旧 cancel=取消错轮）。
	// StartUpdate（异步入口）同形。
	runCtx, runCancel := context.WithCancelCause(updateRunBaseContext(rc))
	m.runCancel = runCancel
	m.mu.Unlock()
	defer func() {
		runCancel(nil)
		m.mu.Lock()
		m.running = false
		m.runCancel = nil
		m.mu.Unlock()
	}()
	m.runWithContext(runCtx, trigger, rc)
	// 失败终态回传引擎（镜像 crs/ip2region wire Run
	// 体读 StatusSnapshot 判 failed 的口径）——恒返 nil 时引擎 task_runs 把
	// 失败轮记成 success。
	if m.StatusSnapshot().Outcome == "failed" {
		return ErrThreatUpdateFailed
	}
	return nil
}

type threatSourceRow struct {
	id   int
	name string
	url  string
}

// threatDueSources 返回本次任务处理的源：manual=全部启用源；auto=启用且到期
// （next_update 空或已过）——失败重试在任务内完成（runWithInTaskRetry），
// 落定后下一运行=下一排程槽，不拖累健康源的重下载。
func threatDueSources(trigger string) ([]threatSourceRow, error) {
	// 源名由内置名单注册表驱动：未来新增源只需扩充注册表与源表种子，
	// 不再复制第三份硬编码名单；未注册的历史爬虫源仍不会混入威胁任务。
	args := make([]any, 0, len(db.ThreatSystemLists()))
	for _, source := range db.ThreatSystemLists() {
		if source.Source != "" {
			args = append(args, source.Source)
		}
	}
	if len(args) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	rows, err := db.DB.Query(`SELECT id, name, url, COALESCE(next_update,''), COALESCE(consecutive_failures,0)
		FROM security_threat_sources
		WHERE update_enabled=1 AND name IN (`+placeholders+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []threatSourceRow
	now := time.Now().UTC()
	for rows.Next() {
		var s threatSourceRow
		var nextUpdate string
		var consecutiveFailures int
		if err := rows.Scan(&s.id, &s.name, &s.url, &nextUpdate, &consecutiveFailures); err != nil {
			return nil, err
		}
		// 名单为空视为到期（v2.3.2 名单化升级窗口：旧版写文件新版写名单，
		// 不补这条则升级后最长 24h 名单为空、引用策略零拦截）——但仅限
		// 「从未失败」形态（consecutive_failures=0，用户裁
		// 定）：持续产不出条目的失败源按排程门控，不再每分钟整任务重跑。
		// v2.3.4 RDB 文件化：.iplist 文件缺失同此语义（哈希命中会跳过写
		// 文件，不补这条则升级后文件永不落地、严格渲染持续跳过策略）。
		if trigger != "manual" && nextUpdate != "" {
			isEmpty := threatListEmpty(s.name)
			gated := !isEmpty || consecutiveFailures > 0
			if gated {
				// 到期判定必须与全域「双布局」契约同源（parseUTCSlot 兼容
				// crsTimeLayout 平面串 + RFC3339）：next_update 可因集群快照/
				// 备份导入/旧版本残留而出现混格式，单布局解析失败会被当作
				// 「已到期」→ 未到期源被同轮额外下载一次。解析失败仍按到期
				// 处理（fail-safe：只会多跑不会漏跑）。
				if due := parseUTCSlot(nextUpdate); !due.IsZero() && now.Before(due) {
					continue
				}
			}
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

// threatListEmpty 报告源是否「未装载」（排程到期判定用）。语义名，判据实现在
// threatFilesUnusable 单源（.iplist 缺失或 .fast 不可用），到期判定与哈希快路径
// /writeThreatSystemList 跳过判定必须逐点相等。
// v2.3.4 RDB 文件化（稳态修复）：system 列表条目已迁至文件，DB entries=”
// 是**正常态**而非空信号——若按 DB 判空则每个调度 tick 都视为到期，主节点
// 每分钟空转更新（USTC 内容逐请求漂移 → .fast 每轮变化 → 从节点每轮
// 「已同步」刷屏）。判据改为文件物化状态：.iplist 缺失 = 未装载。
func threatListEmpty(source string) bool {
	return threatFilesUnusable(source)
}

// runWithContext 是更新管线本体，runCtx 由调用方创建（StartUpdate 或
// RunUpdate），生命周期归还调用方。
func (m *ThreatUpdateManager) runWithContext(runCtx context.Context, trigger string, rc *taskengine.RunContext) {
	operator := "system"
	if rc != nil && rc.Operator != "" {
		operator = rc.Operator
	}
	// 任务自记审计（2026-09-29 用户裁定）：defer 在函数头注册
	// 曾注册在源循环后，角色早退/源读取失败/零源路径零审计、「skipped」映射
	// 不可达）。
	defer func() {
		m.mu.Lock()
		outcome := m.lastTaskOutcome
		emptySources := m.lastRunEmptySources
		m.mu.Unlock()
		detail := fmt.Sprintf("更新%s（触发：%s）", map[string]string{
			"success": "成功", "failed": "失败", "cancelled": "已取消", "skipped": "跳过",
		}[outcome], trigger)
		if emptySources && outcome == "success" {
			// 零到期源的语义单源：动作「更新」（与常态成功轮同族），detail
			// 声明空轮事实——此前该轮 detail 只有「成功」，与真更新轮不可区分。
			detail = fmt.Sprintf("无到期源，本轮无更新（触发：%s）", trigger)
		}
		switch outcome {
		case "failed":
			RecordAuditLog(operator, "更新失败", "威胁情报库", detail, "")
		case "cancelled":
			RecordAuditLog(operator, "取消", "威胁情报库", detail, "")
		case "skipped":
			// 与爬虫族同口径：降级中止记「跳过」——此前落 default 记「更新」，
			// 同一安全语义在两族分叉且被伪装成正常轮。
			RecordAuditLog(operator, "跳过", "威胁情报库", detail, "")
		default:
			RecordAuditLog(operator, "更新", "威胁情报库", detail, "")
		}
	}()
	// 函数内 recover：本 defer 注册在上方审计 defer 之后，恢复先于审计执行
	// ——panic 轮先落定 failed 终态，审计再读取（此前 panic 时
	// lastTaskOutcome 仍是上一轮的值，首轮为空串 → 记成「更新成功」，与引擎
	// runGuarded 的 task_runs failed 形成双口径，且该轮无失败审计）。
	// 外层 goroutine 的 recover 退化为兜底（defer 自身 panic 等形态）。
	defer func() {
		if r := recover(); r != nil {
			Logf("error", "threat update: run panicked: %v\n%s", r, debug.Stack())
			m.mu.Lock()
			m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
			m.lastTaskOutcome = "failed"
			m.mu.Unlock()
		}
	}()
	// 本轮四个状态字段在角色门之前初始化——旧实现 skipped
	// 早退只写 lastFinishedAt/lastTaskOutcome，status 端点会展示上一成功轮的
	// trigger/start/cancelled，四个字段不同轮（自相矛盾）。
	// runCtx 由调用方创建（StartUpdate 预建并登记取消 / run 同步自建）。
	m.mu.Lock()
	m.lastTrigger = trigger
	m.lastStartedAt = time.Now().UTC().Format(crsTimeLayout)
	m.lastRunEmptySources = false
	m.mu.Unlock()
	// 起点角色复查：调度器 tick 的 is_master
	// 守卫与更新启动之间存在 demote 竞态窗口——从节点继续执行会写
	// security_ip_lists 并触发重载，打破只读不变量。NULL 兜底归一为 1（同
	// crsupdate/ip2regionupdate 口径）。
	if isMaster, roleErr := RoleOf(context.Background(), db.DB); roleErr != nil {
		// 角色读取失败（DB 瞬断/脏行）≠从节点——按失败落定（任务监控可见），
		// 不得静默跳过（err!=nil||!isMaster 把 DB 故障当从节点）。
		AppendThreatUpdateLog("WARN", "failed", fmt.Sprintf("角色读取失败，无法判定本节点是否主节点，已中止威胁情报库更新: %v", roleErr))
		m.mu.Lock()
		m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
		m.lastTaskOutcome = "failed"
		m.mu.Unlock()
		return
	} else if !isMaster {
		AppendThreatUpdateLog("WARN", "skipped", "当前节点为从节点，终止威胁情报库更新")
		m.mu.Lock()
		m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout) // 早退同样落终态
		m.lastTaskOutcome = "skipped"
		m.mu.Unlock()
		return
	}
	// 单写方：task_runs 由引擎统一记录。
	sources, err := threatDueSources(trigger)
	finishWith := func(outcome string) {
		m.mu.Lock()
		m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
		m.lastTaskOutcome = outcome
		m.mu.Unlock()
	}
	if err != nil {
		Logf("error", "威胁情报库: 读取源列表失败: %v", err)
		finishWith("failed") // 早退路径同样落终态，状态端点不失真
		return
	}
	if len(sources) == 0 {
		// 零到期源=正常空轮：终态 success（task_runs 成功），审计动作仍为
		// 「更新」但 detail 声明空轮事实（见审计 defer）。
		m.mu.Lock()
		m.lastRunEmptySources = true
		m.mu.Unlock()
		finishWith("success")
		return
	}
	AppendThreatUpdateLog("INFO", "checking", fmt.Sprintf("开始更新威胁情报库（%d 个启用源）", len(sources)))
	anyChanged := false // 内容真实变化的源存在（收敛分支的判定面）
	anyFailed := false
	cancelled := false
	demoted := false  // demote 在途中止标记（outcome=skipped，优先于 cancelled/failed）
	roleLost := false // 角色不可判定（DB 读失败）：outcome=failed——DB 故障不得
	// 误报「手动取消」（cancelled）或「已降级」（skipped），与爬虫族三态归因同口径。
	runStartedAt := taskRunStartedAt(rc)
	for _, source := range sources {
		if runCtx.Err() != nil {
			// 取消源分流——demote（角色已翻转）落 skipped（与起点
			// 角色复查同语义：从节点中止非故障）；主节点=手动取消 cancelled；
			// 角色不可判定（DB 读失败）= failed（与爬虫族同口径，不误报取消/降级）。
			switch master, known := updateRunRole(); {
			case !known:
				roleLost = true
				AppendThreatUpdateLog("WARN", "failed", "角色读取失败，无法判定中止原因（降级/手动取消不可判定），终止威胁情报库更新（已完成源的结果保留）")
			case !master:
				demoted = true
				AppendThreatUpdateLog("WARN", "skipped", "节点已降级为从节点，终止威胁情报库更新（已完成源的结果保留）")
			default:
				cancelled = true
				AppendThreatUpdateLog("WARN", "cancelled", "威胁情报库更新已被手动取消（已完成源的结果保留）")
			}
			break
		}
		changed, failed := m.updateOneSource(runCtx, source, trigger, runStartedAt)
		// 判定面只需「是否有源变化」。旧实现逐源查
		// 一次名单 id 只被 len() 消费（元素从不读取），且 id 查询失败时该源的
		// 变化被静默排除出收敛面——纯冗余 + 可观测性缺口，查询已删除。
		anyChanged = anyChanged || changed
		anyFailed = anyFailed || failed
	}
	// 中止点归一：末源在途取消时循环自然结束（无下一轮顶部
	// 检查）——补判一次取消源；demote 优先于源失败（中止非故障）。
	if !demoted && !cancelled && !roleLost && runCtx.Err() != nil {
		switch master, known := updateRunRole(); {
		case !known:
			roleLost = true
		case !master:
			demoted = true
		default:
			cancelled = true
		}
	}
	// 用户取消自动轮=显式放弃本槽（与失败同源）：把全部到期/空源槽推进到
	// 下一排程槽。引擎侧取消时已消费本槽，而未处理的到期源仍留在被消费的
	// 槽值上（引擎排程槽=启用源最早 next_update）——不推进则整个威胁库自动
	// 更新永久静默停摆。demote/导入排空/进程停止的取消不推进（引擎侧同样不
	// 消费槽，恢复后到期轮补跑）。
	if cancelled && userCancelledRun(runCtx) {
		advanceSourceSlotsAfterUserCancel("security_threat_sources", trigger, threatSourceRegistryNames(), threatNextSlotStrict)
	}
	m.mu.Lock()
	m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
	if demoted {
		m.lastTaskOutcome = "skipped"
	} else if roleLost {
		m.lastTaskOutcome = "failed"
	} else if cancelled {
		m.lastTaskOutcome = "cancelled"
	} else if anyFailed {
		m.lastTaskOutcome = "failed"
	} else {
		m.lastTaskOutcome = "success"
	}
	m.mu.Unlock()
	// demote 中止直接返回（降级中止收敛门，与 crawler_update 降级中止同构）：从节点
	// 零写优先——收敛段会写投影文件并可能回退 /load，降级节点不得触碰；
	// 已完成源的名单内容由集群同步与主节点后续轮次收敛。
	// 角色不可判定（roleLost）同门不收敛：投影重写/回退重载是主节点写面动作，
	// DB 故障下角色无法证实时宁停勿写（与成功写路径复核同一不变量）。
	if demoted || roleLost {
		return
	}
	// 名单内容变化后的收敛（热路径架构，2026-10-15 用户裁定：threatReloader
	// 重载门退役）：threat-<source>.iplist 同稳定路径原子重写（上面
	// writeThreatIplistCompiled）+ 引用面投影文件热路径重写即收敛，零 /load
	// ——@ipListFast 匹配器与受信代理网段（tp.txt/lb_file）按 mtime+size
	// ≤1s stat 热感知。原「受信代理引用 → /load」分支随受信代理热路径化
	// 整体退役（2026-10-15）。刷新不再按「被启用策略引用」预筛（2026-10-15
	// 受信代理引用面加入后引用方=策略投影∪tp.txt，引用面判据只会再犯同类
	// 漏判）：内容变化即全量渲染（投影重写为渲染副作用），结构级比对证实
	// 零发射面变化 → 零 /load，天然覆盖一切引用形态；未被引用的变化同样是
	// 「渲染证实无发射面 → 零重载」，成本=一次毫秒级渲染+比对。
	if !anyChanged {
		AppendThreatUpdateLog("INFO", "unchanged", "全部源名单内容未变化，不重载 Caddy 配置")
	} else if threatProjectionRefresher == nil {
		// 未注册热路径（测试二进制/异常装配）：名单文件已更新，引用方投影
		// 由下次任意配置变更的全量渲染收敛。
		AppendThreatUpdateLog("WARN", "unchanged", "投影刷新器未注册，跳过热路径（引用方渲染由下次配置变更收敛）")
	} else if hot, rerr := threatProjectionRefresher(); rerr != nil || hot != ProjectionConverged {
		// 投影刷新被拒（生成失败）/发射面变化/运行配置不可读/
		// 证书材料被物化（NeedForce，——重载回调为强制形态，
		// 击穿 errSameConfig 让新证书进 Caddy 内存）→ 回退 /load 收敛——宁可
		// 一次重载，不欠引用方渲染收敛。
		AppendThreatUpdateLog("INFO", "reloading", "投影热路径未证实收敛（发射面变化/证书物化或刷新失败），回退重载 Caddy 配置")
		if threatReloader != nil {
			err := threatReloader()
			recordSystemReloadAudit("threat_update", err)
			if err != nil {
				Logf("error", "威胁情报库: 名单变化后重载失败: %v", err)
				AppendThreatUpdateLog("ERROR", "reloading", fmt.Sprintf("重载 Caddy 配置失败: %v", err))
			}
		}
	} else {
		Logf("info", "威胁情报库: 名单内容变化经投影热路径收敛（零 Caddy 重载，匹配器 ≤1s 热感知生效）")
		AppendThreatUpdateLog("INFO", "hot", "名单内容变化经投影热路径收敛（零重载，匹配器 ≤1s 热感知生效）")
	}
}

// IPListsReferencedByEnabledPolicy 名单写路径热路径资格判定（2026-10-15 用户
// 裁定）的导出包装：与威胁库收敛门同一查询核心（单源），日志前缀区分来源。
// （原 threatListsReferencedByEnabledPolicy 威胁库包装已随 2026-10-15 引用面
// 预筛退役删除——威胁收敛改为内容变化即渲染，引用面判据不再需要。）
func IPListsReferencedByEnabledPolicy(listIDs []int) bool {
	return ipListsReferencedByEnabledPolicyLabeled("IP 名单写路径", listIDs)
}

func ipListsReferencedByEnabledPolicyLabeled(logPrefix string, listIDs []int) bool {
	want := map[int]bool{}
	for _, id := range listIDs {
		want[id] = true
	}
	// 历史 引用面补全——除 ACL/信任引用外，CRS 排除 scope=ip/list
	// 条目的 ListRefs（emitScopedCRSExclusions 投影消费，后同为
	// @ipListFast 文件热感知面）与受信代理网段引用（global_config.
	// trusted_proxy_range_refs，tp.txt 投影消费，仅 trusted_proxy_enabled=1
	// 时渲染）都是渲染引用方；漏查会让「仅被这两面引用」的名单在写路径被
	// 资格门误判未引用→无谓回退全量链/全量重载（保守口径缺口）。查询/解析
	// 失败按「可能被引用」处理。
	rows, err := db.DB.Query(`SELECT COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(crs_excluded_rules,'[]') FROM security_policies WHERE enabled=1`)
	if err != nil {
		Logf("error", "%s: 读取策略引用失败（按被引用处理）: %v", logPrefix, err)
		return true
	}
	defer rows.Close()
	for rows.Next() {
		var aclRefs, wlRefs, xcRules string
		if err := rows.Scan(&aclRefs, &wlRefs, &xcRules); err != nil {
			Logf("error", "%s: 扫描策略引用失败（按被引用处理）: %v", logPrefix, err)
			return true
		}
		for _, raw := range []string{aclRefs, wlRefs} {
			var ids []int
			if err := json.Unmarshal([]byte(raw), &ids); err != nil {
				// 解析失败按「可能被引用」处理（与查询失败同口径）。
				Logf("error", "%s: 策略引用 JSON 解析失败（按被引用处理）: %v", logPrefix, err)
				return true
			}
			for _, id := range ids {
				if want[id] {
					return true
				}
			}
		}
		// CRS 排除作用域限定条目（scope=ip/list）的 ListRefs——与发射侧
		// 同一解析单源 ParseCRSExcludedRules（scope=all 条目的 ListRefs 不
		// 参与发射，不计入引用面）。
		for _, entry := range ParseCRSExcludedRules(xcRules) {
			if entry.Scope != "ip" && entry.Scope != "list" {
				continue
			}
			for _, id := range entry.ListRefs {
				if want[int(id)] {
					return true
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		// ⑪：迭代失败与查询/解析失败同口径——按被引用
		// 处理，漏查会跳过名单收敛致引用方渲染不收敛。
		Logf("error", "%s: 遍历策略引用失败（按被引用处理）: %v", logPrefix, err)
		return true
	}
	// 受信代理网段引用（全局单份；未启用时不渲染 tp.txt，引用面不存在）。
	var tpEnabled int
	var tpRefs string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_enabled,0), COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&tpEnabled, &tpRefs); err != nil {
		if err != sql.ErrNoRows {
			Logf("error", "%s: 读取受信代理引用失败（按被引用处理）: %v", logPrefix, err)
			return true
		}
		return false
	}
	if tpEnabled == 1 {
		var ids []int
		if err := json.Unmarshal([]byte(tpRefs), &ids); err != nil {
			Logf("error", "%s: 受信代理引用 JSON 解析失败（按被引用处理）: %v", logPrefix, err)
			return true
		}
		for _, id := range ids {
			if want[id] {
				return true
			}
		}
	}
	return false
}

// updateOneSource 下载→解析→写内置名单→更新行状态；失败仅影响该源。
// 返回（名单内容是否变化， 是否失败）。
func (m *ThreatUpdateManager) updateOneSource(ctx context.Context, source threatSourceRow, trigger string, runStartedAt string) (bool, bool) {
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='running', message='', trigger=?, started_at=?, last_checked=?, updated_at=datetime('now') WHERE id=?`,
		trigger, runStartedAt, runStartedAt, source.id); err != nil {
		Logf("error", "威胁情报库: 标记源 %s 运行中失败: %v", source.name, err)
		return false, true
	}
	AppendThreatUpdateLog("INFO", "downloading", fmt.Sprintf("下载 %s（%s）", source.name, source.url))

	// fast 不可用（缺失/损坏）而文本仍在时优先从现有
	// 文本重建，不依赖重新下载。
	//
	// 自愈是写盘副作用（重编译 .fast 落 live），与慢路径写库同权：必须先过
	// 角色+取消写门。自愈发生在下载之前，此前的唯一角色/取消复核在写库前，
	// 降级窗口内的入口自愈会在从节点写出非集群同步来源的 .fast 代际。
	// 取消形态不在此收口（源行 cancelled 终态与日志由下方下载失败的取消分支
	// 统一落库），只跳过自愈写盘后走原有编舞。
	healAllowed := true
	if gerr := updateRunWriteGate(ctx); gerr != nil {
		if !errors.Is(gerr, context.Canceled) && !errors.Is(gerr, context.DeadlineExceeded) {
			return threatWriteGateAbort(source.name, gerr)
		}
		healAllowed = false
	}
	var entries []string
	var rawHash string
	healed := false
	if healAllowed && !threatIplistMissing(source.name) && threatFastUnusable(source.name) {
		if e, ok := healThreatFastFromText(source.name); ok {
			// heal 的文本 sha256 不是上游原始字节哈希：留空使慢路径不写
			// raw_hash，保留上次真实下载哈希。
			entries, rawHash, healed = e, "", true
		}
	}
	// 任务内重试（2026-09-25 用户裁定）：瞬断在当前任务内重试，耗尽才落定——
	// 失败退避不再改写排程槽（failSourceRow 写下一排程槽）。
	err := error(nil)
	if !healed {
		err = runWithInTaskRetry(ctx, func() error {
			var derr error
			entries, rawHash, derr = downloadAndParseThreatSourceCtx(ctx, source)
			return derr
		}, func(nextAttempt int, wait time.Duration, rerr error) {
			AppendThreatUpdateLog("WARN", "retry", fmt.Sprintf("源 %s 下载失败: %v；等待 %s 重试，第 %d 次，共 %d 次", source.name, rerr, wait, nextAttempt, updateMaxAttempts))
		})
	}
	finished := time.Now().UTC().Format(crsTimeLayout)
	if err != nil {
		if ctx.Err() != nil {
			switch master, known := updateRunRole(); {
			case !known:
				// 角色不可判定（DB 读失败）≠降级≠手动取消（与爬虫族三态
				// 归因同口径）：不写源行终态（避免失真），按失败返回——
				// 任务监控可见，旧形态并入 cancelled 会把 DB 故障误报为
				// 手动取消。
				AppendThreatUpdateLog("WARN", "failed", fmt.Sprintf("角色读取失败，无法判定源 %s 中止原因（降级/手动取消不可判定），源行保留运行态由后续轮收敛", source.name))
				return false, true
			case !master:
				// demote 中止从节点零写（降级零写 裁定=从节点零写优先）：
				// 不写源行终态（从节点 DB 由集群同步收敛），仅以任务日志
				// 「降级中止」留痕；源行滞留 running 由下次主节点同步覆盖。
				AppendThreatUpdateLog("WARN", "skipped", fmt.Sprintf("节点已降级，源 %s 更新降级中止（从节点零写，源行由集群同步收敛）", source.name))
			default:
				cancelSourceRow(source.id, finished, ctx.Err())
				AppendThreatUpdateLog("WARN", "cancelled", fmt.Sprintf("源 %s 更新已手动取消（保留上次快照）", source.name))
			}
			return false, false
		}
		failSourceRow(source.id, finished, err, trigger)
		AppendThreatUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", source.name, err))
		return false, true
	}

	// 两层哈希（2026-09-24 用户裁定）：原始字节哈希一致 → 内容必然未变，
	// 跳过聚合/写库（稳定源零聚合成本）；原始不同才聚合（乱序源如 USTC
	// 每次请求换序——原始哈希必然不同，聚合规范字节哈希终判防误判变化）。
	var storedRaw string
	if err := db.DB.QueryRow(`SELECT COALESCE(raw_hash,'') FROM security_threat_sources WHERE id=?`, source.id).Scan(&storedRaw); err != nil {
		Logf("error", "威胁情报库: 读源 %s 原始哈希失败: %v", source.name, err)
	}
	if storedRaw != "" && storedRaw == rawHash {
		// 名单行缺失（备份还原/异常清理）须穿透快速路径补建——存在性判定
		// 与写路径同口径限定 system=1（:793 慢路径同款）：同名用户自建列表
		// （system=0）不得抑制内置行补建，否则引用旧 id 的策略漏拦且无任何
		// 告警，直到上游内容变化才自愈。
		var listExists int
		err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND system=1`, db.ThreatListNameBySource(source.name)).Scan(&listExists)
		switch {
		case err != nil:
			// 存在性判定失败不得按「存在」跳过（名单可能已缺失，
			// 跳过快照=拦截面静默为空）——记错并继续完整聚合/写库路径。
			Logf("error", "威胁情报库: 检查源 %s 内置名单存在性失败: %v", source.name, err)
		case listExists > 0 && threatFilesUnusable(source.name):
			// RDB 文件化升级引导 +：名单行在但.iplist 缺失或.fast
			// 缺失/损坏（v2.3.3 升级、带外损坏形态）——穿透快速路径照常写盘/
			// 重编译，否则文件永不落地/损坏永不修复。
			Logf("info", "威胁情报库: 源 %s 原始哈希一致但名单文件不可用（缺失/损坏），执行落盘修复", source.name)
		case listExists > 0:
			AppendThreatUpdateLog("INFO", "unchanged", fmt.Sprintf("源 %s 名单内容未变化（原始内容哈希一致），跳过解析写入", source.name))
			// 成功写路径前复核：哈希比对到成功落库之间的降级窗口——从节点
			// 写源行终态违反零写不变量（与慢路径写库前门同一不变量）。
			if gerr := updateRunWriteGate(ctx); gerr != nil {
				return threatWriteGateAbort(source.name, gerr)
			}
			// 内容未变化不得用本次原始解析条数覆盖源行（源行口径=
			// 上次聚合后条数，与内置名单行数一致）。
			if err := markSourceSuccess(source.id, -1, finished, trigger); err != nil {
				return false, true
			}
			return false, false
		}
	}

	// 成功写路径前复核（与 CRS observeCancelAfterSwap 同族三态）：下载/解析
	// 完成到写库之间存在毫秒级降级窗口——从节点继续写内置名单打破只读
	// 不变量（既有钉测只覆盖下载期取消，本门补成功路径窗）。
	if gerr := updateRunWriteGate(ctx); gerr != nil {
		return threatWriteGateAbort(source.name, gerr)
	}
	// 聚合归一后写内置名单（内容未变化零写入——不重载、不 bump 集群版本）。
	merged := wafiplist.AggregateIPEntries(entries)
	// 条数塌缩门先于写盘：解析率/上限只约束「合法行占比」与绝对值，无法发现
	// 「每行都合法但整体只剩几十条」的自洽短名单替换（上游错页/劫持）。
	if gerr := threatEntryShrinkGuard(source.id, len(merged)); gerr != nil {
		failSourceRow(source.id, finished, gerr, trigger)
		AppendThreatUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", source.name, gerr))
		return false, true
	}
	changed, werr := writeThreatSystemList(source.name, merged)
	if werr != nil {
		failSourceRow(source.id, finished, fmt.Errorf("写入内置名单失败: %w", werr), trigger)
		AppendThreatUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 写入名单失败: %v", source.name, werr))
		return false, true
	}
	// 未变化也留痕（2026-09-24 用户裁定）：源级一条「未变化」日志，
	// 否则日志只见成功不见比对结论，无法区分「未拉取」与「未变化」。
	if !changed {
		AppendThreatUpdateLog("INFO", "unchanged", fmt.Sprintf("源 %s 名单内容未变化（哈希一致），跳过写入", source.name))
	}
	// 条数口径单源——聚合后条数（与 writeThreatSystemList 写入.iplist
	// 的行数一致）；此前传原始 len(entries)，后写者胜使「N 条」恒为聚合前值。
	markErr := func() error {
		if rawHash != "" {
			return markSourceSuccess(source.id, len(merged), finished, trigger, rawHash)
		}
		return markSourceSuccess(source.id, len(merged), finished, trigger)
	}()
	if markErr != nil {
		// 排程不可读（槽未推进）与落库失败同按本源失败收口：源状态已 success
		// 但本轮必须让引擎按失败退避重投，否则过期槽会被引擎消费（静默停摆）。
		if errors.Is(markErr, errScheduleSlotNotAdvanced) {
			AppendThreatUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 已更新但排程不可读，本轮排程槽未推进（引擎将退避重投）", source.name))
		}
		return changed, true
	}
	return changed, false
}

// threatWriteGateAbort 成功写路径复核（updateRunWriteGate）未通过的统一处置：
// 已降级/手动取消=零写中止（failed=false——中止非故障，由 run 循环顶部/归一
// 检查归因落 skipped/cancelled）；角色不可判定=按源失败（failed=true，
// 任务可见，不误报取消/降级）。三态语义与爬虫族下载期归因同一口径。
func threatWriteGateAbort(source string, gerr error) (bool, bool) {
	switch {
	case errors.Is(gerr, errRunRoleUndecidable):
		AppendThreatUpdateLog("WARN", "failed", fmt.Sprintf("角色读取失败，无法判定本节点是否主节点，源 %s 结果未写库（防降级窗口从节点写主库）", source))
		return false, true
	case errors.Is(gerr, taskengine.ErrTaskSkipped):
		AppendThreatUpdateLog("WARN", "skipped", fmt.Sprintf("节点已降级，源 %s 结果未写库（从节点零写，由集群同步收敛）", source))
		return false, false
	default:
		AppendThreatUpdateLog("WARN", "cancelled", fmt.Sprintf("源 %s 更新已手动取消（结果未写库，保留上次快照）", source))
		return false, false
	}
}

// markSourceSuccess 源成功状态落库（版本/条数/退避清零/下一窗口 + 原始字节哈希）。
// 排程槽生命周期：仅现存槽空/过期才推进（未来槽不回拨）；成功轮 auto 与 manual
// 同权——引擎成功后会消费过期槽，手动成功不推进会让引擎水位与业务槽单边分叉
// （该族自动更新永久静默停摆）。
// rawHash 缺省=兼容旧调用形态【不写】raw_hash 列（无条件覆写
// 空串曾使快路径自我失效——缺省时动态剔除该列，保留上次慢路径哈希）。
// 返回成功状态落库错误（吞错会让任务终态 success 掩盖状态机不闭环）。
func markSourceSuccess(id int, entryCount int, finished string, trigger string, rawHash ...string) error {
	version := time.Now().UTC().Format("2006.01.02")
	// 排程不可读时槽片段为 no-op（保留旧预约），其余状态列照常落库；随后把
	// 「槽未推进」作为错误返回——源状态 success + 过期槽原样保留会让引擎
	// 按「成功未推进」消费本槽，该族自动更新从此静默停摆（失败轮由引擎退避
	// 重投 1s/5s/30s；连续 4 轮仍未推进由引擎停调，需业务页重新保存或重启）。
	slotSQL, slotArgs, slotErr := threatSlotSuccessAssign(trigger)
	// entry_count 的唯一口径是**聚合后**条数（writeThreatSystemList 的
	// len(merged)，与内置名单 .iplist 行数一致）。entryCount<0 = 内容未变化
	// 快路径：不覆写该列（源行已是上次聚合后值；用本次原始解析条数覆盖会让
	// 「N 条」卡片与名单详情长期不一致）。
	entrySet, entryArgs := "entry_count=?, ", []any{entryCount}
	if entryCount < 0 {
		entrySet, entryArgs = "", nil
	}
	baseArgs := append(append([]any{}, entryArgs...), version, finished)
	if len(rawHash) > 0 {
		args := append(append(append([]any{}, baseArgs...), slotArgs...), rawHash[0], id)
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='success', message='', `+entrySet+`version=?, finished_at=?, `+slotSQL+`, consecutive_failures=0, raw_hash=?, updated_at=datetime('now') WHERE id=?`,
			args...); err != nil {
			Logf("error", "威胁情报库: 更新源成功状态失败: %v", err)
			return err
		}
	} else {
		// raw_hash 缺省（快路径内容未变）不覆写该列。
		args := append(append(append([]any{}, baseArgs...), slotArgs...), id)
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='success', message='', `+entrySet+`version=?, finished_at=?, `+slotSQL+`, consecutive_failures=0, updated_at=datetime('now') WHERE id=?`,
			args...); err != nil {
			Logf("error", "威胁情报库: 更新源成功状态失败: %v", err)
			return err
		}
	}
	// 成功留痕（尾部共享，两分支同达，修法）：rawHash 分支=内容
	// 更新；无参分支=哈希一致跳过写入。原修复在 rawHash 分支加的 return
	// 切断了本段日志（真实更新零留痕），已撤除。
	// 源名仅用于日志，按 id 反查一次
	var name string
	_ = db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name)
	if entryCount >= 0 {
		Logf("info", "威胁情报库: 源 %s 更新成功（%d 条，版本 %s）", name, entryCount, version)
		AppendThreatUpdateLog("INFO", "success", fmt.Sprintf("源 %s 更新成功（%d 条，版本 %s）", name, entryCount, version))
	} else {
		Logf("info", "威胁情报库: 源 %s 更新成功（内容未变化，版本 %s）", name, version)
		AppendThreatUpdateLog("INFO", "success", fmt.Sprintf("源 %s 更新成功（内容未变化，版本 %s）", name, version))
	}
	if slotErr != nil {
		Logf("error", "威胁情报库: 源 %s 排程不可读，本轮排程槽未推进（引擎将退避重投）: %v", name, slotErr)
		return slotErr
	}
	return nil
}

// threatEntryShrinkGuard 条数塌缩门（与爬虫快照收缩门同口径）：新聚合名单
// 条数较当前快照收缩超过一半时拒绝写入、保留上次快照——解析率只保证「合法行
// 占比」，一个每行都是合法 CIDR 但只剩数十条的短名单可通过全部门禁并把
// 万余条内置威胁名单整体替换（静默削弱拦截）。
// 基线=security_threat_sources.entry_count（聚合后口径，与内置名单 .iplist
// 行数一致）；基线缺失或 <2（首装/升级引导）放行。基线读取失败按失败处理
// （保留上次快照，方向安全）。
func threatEntryShrinkGuard(sourceID int, newCount int) error {
	var baseline int
	err := db.DB.QueryRow(`SELECT COALESCE(entry_count,0) FROM security_threat_sources WHERE id=?`, sourceID).Scan(&baseline)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取威胁名单基线失败: %w", err)
	}
	if baseline >= 2 && newCount*2 < baseline {
		return fmt.Errorf("解析条数 %d 较当前快照 %d 收缩超过一半（疑似错误页/劫持），保留上次快照；如确认上游名单合法重构，需人工清理该源的条数基线后重试", newCount, baseline)
	}
	return nil
}

// writeThreatSystemList 把聚合条目写入源对应的内置只读名单行
// （security_ip_lists system=1，name 经 db.ThreatListNameBySource 映射）；
// 行缺失时补建（备份还原/异常清理后的自愈）。
// 变更判定=内容哈希比对（2026-09-24 用户裁定）：聚合规范字节的 sha256 存
// security_threat_sources.content_hash——源站乱序返回同一集合（USTC 实测）
// 经聚合排序后字节稳定，哈希一致即未变化（不写名单、不重载、不 bump 集群
// 版本）；升级存量空哈希首跑按变化处理一次（自愈写哈希）。
// 返回 changed=内容真实变化。
func writeThreatSystemList(source string, entries []string) (bool, error) {
	name := db.ThreatListNameBySource(source)
	if name == "" {
		return false, fmt.Errorf("源 %s 未登记内置名单", source)
	}
	payload := make([]models.IPListEntry, 0, len(entries))
	for _, e := range entries {
		payload = append(payload, models.IPListEntry{Value: e})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("编码名单条目失败: %w", err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(encoded))
	// 名单行存在（system=1）+ 哈希一致 → 未变化（名单行缺失即使哈希命中也须
	// 补建）。存在性判定按 system=1 限定——同名用户自建列表
	// （system=0）不得抑制内置行创建，否则威胁文件更新后无名单 ID 可引用。
	var listExists int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&listExists); err != nil {
		return false, fmt.Errorf("读内置名单失败: %w", err)
	}
	var storedHash string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_hash,'') FROM security_threat_sources WHERE name=?`, source).Scan(&storedHash); err != nil {
		return false, fmt.Errorf("读源哈希失败: %w", err)
	}
	// RDB 文件化：文件缺失时哈希命中不得跳过（升级引导——v2.3.3 升上来
	// 内容未变，但.iplist/.fast 尚未落地，须照常写盘）。.fast
	// 存在但损坏同样不得跳过——照常写盘完成重编译修复。
	if listExists > 0 && storedHash == hash && storedHash != "" && !threatFilesUnusable(source) {
		return false, nil
	}
	// RDB 文件化：条目写 .iplist 文件 + 编译 .fast，DB entries 恒空
	// 写+编译为 wafFileMu 互斥的原子文件相位（撕裂.iplist 会让
	// lbbak 内静默残缺名单——manifest 自洽不可检）。
	iplistPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", source))
	entryStrs := make([]string, len(payload))
	for i, e := range payload {
		entryStrs[i] = e.Value
	}
	if err := writeThreatIplistCompiled(iplistPath, entryStrs); err != nil {
		return false, err
	}
	entryCount := len(entryStrs)
	if listExists == 0 {
		// 行缺失自愈补建——统一走 db.EnsureSystemIPList（OR IGNORE 幂等 +
		// 描述归一 + 同名用户列表留痕），不再手写 INSERT（三条播种路径的
		// category/描述/幂等性曾漂移）。
		created, cerr := db.EnsureSystemIPList(db.DB, name, threatListDescription(source), "恶意 IP")
		if cerr != nil {
			return false, fmt.Errorf("补建内置名单失败: %w", cerr)
		}
		if created {
			// 同名用户自建列表与内置行并存时显式留痕（不静默双名）。
			var userOwned int
			if uerr := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=0`, name).Scan(&userOwned); uerr == nil && userOwned > 0 {
				Logf("warn", "威胁情报库: 内置名单 %q 已补建，但存在同名用户自建列表——请重命名用户列表以消除选择器歧义", name)
				RecordAuditLog("system", "重建", "威胁情报库", fmt.Sprintf("内置名单 %s 已补建（存在同名用户列表，建议重命名用户列表）", name), "")
			}
			// 补建产生新 id
			Logf("warn", "威胁情报库: 内置名单 %q 已重建为新 id，原策略引用已失效，需重新绑定", name)
			RecordAuditLog("system", "重建", "威胁情报库", fmt.Sprintf("内置名单 %s 重建为新 id，原策略引用已失效，需重新绑定", name), "")
		}
	} else {
		if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='', updated_at=datetime('now') WHERE name=? AND system=1`, name); err != nil {
			return false, fmt.Errorf("更新内置名单元数据失败: %w", err)
		}
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET content_hash=?, entry_count=? WHERE name=?`, hash, entryCount, source); err != nil {
		return false, fmt.Errorf("写源哈希失败: %w", err)
	}
	return true, nil
}

func threatListDescription(source string) string {
	for _, sl := range db.ThreatSystemLists() {
		if sl.Source == source {
			return sl.Description
		}
	}
	return ""
}

// cancelSourceRow 用户取消落库：保留上次快照与连续失败计数，源行自身不
// 推进排程槽——用户取消自动轮时由 run 级收口统一推进全部到期源槽
// （advanceSourceSlotsAfterUserCancel，见 runWithContext），demote/导入排空/
// 进程停止的取消则两者都不推进（引擎侧同样不消费槽，恢复后补跑）。
func cancelSourceRow(id int, finished string, cause error) {
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='cancelled', message=?, finished_at=?, updated_at=datetime('now') WHERE id=?`,
		cause.Error(), finished, id); err != nil {
		Logf("error", "威胁情报库: 取消状态落库失败: %v", err)
	}
}

// failSourceRow 失败落库：status=failed + message + consecutive_failures+1（遥测计数，
// 不再驱动排程）+ next_update=下一排程槽（2026-09-25 用户裁定：退避不污染排程，
// 重试已在任务内完成，耗尽后下一运行=下一排程槽）。
// 排程槽生命周期（2026-10-11 用户裁定）：仅 auto 且现存槽空/过期才推进——
// 手动触发不动预约槽、未来槽不回拨。
func failSourceRow(id int, finished string, cause error, trigger string) {
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET consecutive_failures=consecutive_failures+1 WHERE id=?`, id); err != nil {
		Logf("error", "威胁情报库: 失败计数更新失败: %v", err)
	}
	slotSQL, slotArgs := threatSlotAdvanceAssign(trigger)
	args := append(append([]any{cause.Error(), finished}, slotArgs...), id)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', message=?, finished_at=?, `+slotSQL+`, updated_at=datetime('now') WHERE id=?`,
		args...); err != nil {
		Logf("error", "威胁情报库: 失败状态落库失败: %v", err)
	}
	Logf("warn", "威胁情报库: 源更新失败: %v", cause)
}

// downloadAndParseThreatSourceCtx 下载并解析单源（ctx 可被任务监控取消）：
// 30s 超时、HTTP 200、body ≤16MB；空行与 #/; 注释跳过；可解析行比例 <50%
// 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
// 返回原始字节 sha256（两层哈希第一层快速路径，2026-09-24 用户裁定）：
// 原始一致即内容必然未变，调用方跳过聚合/写库；原始不同才走聚合规范哈希终判。
// 无 ctx 的零消费包装已删；生产统一走本函数（任务内重试 +
// 下一排程槽）。
func downloadAndParseThreatSourceCtx(parent context.Context, source threatSourceRow) ([]string, string, error) {
	ctx, cancel := context.WithTimeout(parent, threatDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "lazy-balancer-v2") // 空 UA 可能被源拒绝/插页（对齐 crshttp 同口径）
	}
	if err != nil {
		return nil, "", fmt.Errorf("构造请求失败: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, threatMaxBodyBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("读取响应失败: %w", err)
	}
	if len(body) > threatMaxBodyBytes {
		return nil, "", fmt.Errorf("响应体超过 16MB 上限")
	}
	rawHash := fmt.Sprintf("%x", sha256.Sum256(body))

	var entries []string
	total := 0
	// 行过滤口径单源 iterIPListTextLines（与渲染/编译侧同口径）。
	iterIPListTextLines(body, func(line string) bool {
		total++
		if _, err := wafiplist.ParseIPEntry(line); err == nil {
			entries = append(entries, line)
		}
		return true
	})
	if total == 0 {
		return nil, "", fmt.Errorf("响应无可解析条目（空名单）")
	}
	if float64(len(entries))/float64(total) < threatMinParseRatio {
		return nil, "", fmt.Errorf("可解析行比例 %d/%d 低于 50%%——疑似错页或劫持", len(entries), total)
	}
	if len(entries) > threatMaxEntries {
		return nil, "", fmt.Errorf("条目数 %d 超过 200000 上限", len(entries))
	}
	return entries, rawHash, nil
}

// threatIplistMissing 报告源的 .iplist 文件是否缺失（升级引导窗口用）。
func threatIplistMissing(source string) bool {
	_, err := os.Stat(filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", source)))
	return err != nil
}

// threatFastUnusable 报告源的 .fast 加速文件是否不可用：缺失（stat 失败）
// 或存在但损坏/不可读（旧口径只 stat，损坏文件
// 会让哈希快路径永久跳过修复、引用策略在渲染层被整体跳过）。可读性校验
// 用 ReadFastFile 全量判定（magic/flags/尺寸/bits/掩码/序/不相交）。
func threatFastUnusable(source string) bool {
	fastPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist.fast", source))
	if _, err := os.Stat(fastPath); err != nil {
		return true
	}
	if _, err := wafiplist.ReadFastFile(fastPath); err != nil {
		Logf("warn", "威胁情报库: 源 %s .fast 存在但读取/校验失败（按不可用处理，触发修复）: %v", source, err)
		return true
	}
	return false
}

// threatFilesUnusable .iplist 缺失或 .fast 不可用（缺失/损坏）。
func threatFilesUnusable(source string) bool {
	return threatIplistMissing(source) || threatFastUnusable(source)
}

// healThreatFastFromText 从现有.iplist 文本重建.fast（不依赖
// 重新下载）。返回条目；失败返回 false。不产出 raw_hash——本地文本哈希不是
// 上游原始字节哈希，写回会让快路径永久误判（唯一调用点只取条目）。
// 可解析率门（与下载侧 threatMinParseRatio 同源阈值）：文本大面积损坏时
// 拒绝修复——否则「文本损坏+.fast 损坏」双故障下垃圾行入列/聚合归零后
// 照常标 success（威胁名单静默归零）。合法行判定与下载侧同一解析器
// （wafiplist.ParseIPEntry），非法行不入列。
func healThreatFastFromText(source string) ([]string, bool) {
	iplistPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", source))
	data, err := os.ReadFile(iplistPath)
	if err != nil {
		return nil, false
	}
	entries := make([]string, 0, 1024)
	total := 0
	// 行过滤口径单源 iterIPListTextLines（与下载侧/渲染侧同口径）。
	iterIPListTextLines(data, func(line string) bool {
		total++
		if _, err := wafiplist.ParseIPEntry(line); err == nil {
			entries = append(entries, line)
		}
		return true
	})
	if total == 0 {
		Logf("warn", "威胁情报库: 源 %s .iplist 为空/仅注释，拒绝以空集重建 .fast（保留上次快照）", source)
		return nil, false
	}
	if float64(len(entries))/float64(total) < threatMinParseRatio {
		Logf("warn", "威胁情报库: 源 %s .iplist 可解析行比例 %d/%d 低于 50%%——文本疑似损坏，拒绝重建 .fast（保留上次快照，不静默归零）", source, len(entries), total)
		AppendThreatUpdateLog("WARN", "failed", fmt.Sprintf("源 %s .iplist 文本疑似损坏（可解析 %d/%d，低于 50%%），拒绝从文本重建 .fast", source, len(entries), total))
		return nil, false
	}
	wafFileMu.Lock()
	err = CompileFromIplistFile(iplistPath)
	wafFileMu.Unlock()
	if err != nil {
		Logf("warn", "威胁情报库: 源 %s .fast 从文本重建失败: %v", source, err)
		return nil, false
	}
	AppendThreatUpdateLog("INFO", "healed", fmt.Sprintf("源 %s .fast 缺失/损坏，已从现有文本重建（未重新下载）", source))
	return entries, true
}

// osLink 是测试 seam（镜像 crsinstall.go 的 osRename）：注入不支持硬链接
// 或跨设备失败形态，覆盖原子复制回退。生产恒为 os.Link。
var osLink = os.Link

// WriteThreatIplistCompiled 在同目录临时文件上完成文本写入与 .fast 编译，
// 全部成功后才替换 live 文件。fast 先替换时优先保留硬链接备份，硬链接失败
// 改用同目录原子复制；第二个 rename 若失败可恢复旧 fast。
// 任何前置失败均不触碰 live .iplist。
// 调用方必须持 WafFileLock（lbbak 导入与威胁更新器均已在外层持有）。
func WriteThreatIplistCompiled(iplistPath string, data []byte) error {
	fastPath := iplistPath + ".fast"
	for _, path := range []string{iplistPath, fastPath} {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("威胁库目标不是普通文件: %s", path)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(iplistPath), ".lbbak-threat-*.iplist")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer os.Remove(tmpPath + ".fast")
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// 数据落盘后再编译/rename；掉电窗口内空 .iplist/.fast 会让拦截静默
	// fail-open。
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := CompileFromIplistFile(tmpPath); err != nil {
		return err
	}

	fastBackup := ""
	if _, err := os.Stat(fastPath); err == nil {
		placeholder, err := os.CreateTemp(filepath.Dir(fastPath), ".lbbak-fast-backup-*")
		if err != nil {
			return err
		}
		fastBackup = placeholder.Name()
		if err := placeholder.Close(); err != nil {
			_ = os.Remove(fastBackup)
			return err
		}
		if err := os.Remove(fastBackup); err != nil {
			return err
		}
		if err := osLink(fastPath, fastBackup); err != nil {
			if copyErr := copyFile(fastPath, fastBackup); copyErr != nil {
				return errors.Join(
					fmt.Errorf("硬链接旧 .fast 备份失败: %w", err),
					fmt.Errorf("复制旧 .fast 备份失败: %w", copyErr),
				)
			}
		}
		defer os.Remove(fastBackup)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmpPath+".fast", fastPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, iplistPath); err != nil {
		if fastBackup != "" {
			if restoreErr := os.Rename(fastBackup, fastPath); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("恢复旧 .fast 失败: %w", restoreErr))
			}
		} else {
			_ = os.Remove(fastPath)
		}
		return err
	}
	if err := syncParentDir(iplistPath); err != nil {
		return err
	}
	return nil
}

// writeThreatIplistCompiled 威胁库文件相位：文本与编译产物
// 在 wafFileMu 互斥段内 staging 后替换，与 lbbak 导入共用同一实现。
func writeThreatIplistCompiled(path string, entries []string) error {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	content := strings.Join(entries, "\n") + "\n"
	return WriteThreatIplistCompiled(path, []byte(content))
}

// WafDir 返回 waf 目录路径（导入/导出用）。
func WafDir() string { return wafDir }

// CancelRunning 取消当前运行中的更新（下载阶段中断，已完成源结果保留）。
// 无运行中任务时返回 false。
func (m *ThreatUpdateManager) CancelRunning() bool {
	m.mu.Lock()
	cancel := m.runCancel
	running := m.running
	m.mu.Unlock()
	// 补 running 门（对齐 CRS/IP2Region 同形）——
	// runCancel 一次运行后不清空，单查 cancel 会把已结束任务误报为可取消。
	if cancel == nil || !running {
		return false
	}
	// 调用方只有用户取消通道（引擎 CancelHook／前端取消入口）——取消原因
	// 标记为 ErrUserCancelled，取消终态据此推进各源排程槽。
	cancel(taskengine.ErrUserCancelled)
	return true
}
