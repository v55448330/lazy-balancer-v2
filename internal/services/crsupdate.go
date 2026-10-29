package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/taskengine"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// CRSBundledVersion is the CRS release baked into the container image; it is
// only used to seed security_crs_version when the row does not exist yet.
const CRSBundledVersion = "v4.28.0"

var ErrCRSUpdateRunning = errors.New("CRS 更新任务正在进行中")

// crsUpdateLogFamily / ip2RegionUpdateLogFamily 排程槽未推进日志的族前缀
// （versionTableSlotRecorder 的单一实现按族区分文案，其余逐字相同）。
const (
	crsUpdateLogFamily       = "crs update"
	ip2RegionUpdateLogFamily = "ip2region update"
)

// versionTableSlotRecorder 版本表两族更新管理器（CRS / IP2Region）共用的
// 「排程槽未推进」记录器：状态枚举、版本读取与回滚钩子由各管理器承担，本类型
// 只承载「本轮成功落库但排程槽未推进」的原因，供任务引擎 Run 体按失败返回
// （引擎需要失败才能退避重投同一槽，而不是把本槽记入消费水位）。
// 此前两族各有一份逐字相同的 setSlotAdvanceError/ScheduleSlotError 实现
// （仅族前缀不同），任一侧改动都会让两族调度契约漂移。
type versionTableSlotRecorder struct {
	mu  sync.Mutex
	err error
}

// set 记录本轮原因（nil=槽已推进）并留痕；family 只用于日志前缀。
func (r *versionTableSlotRecorder) set(err error, family string) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
	if err != nil {
		Logf("error", "%s: 本轮排程槽未推进（引擎按 1s/5s/30s 退避重投；连续 4 轮仍未推进即停调，需在业务页重新保存自动更新或重启进程恢复）: %v", family, err)
	}
}

// get 返回本轮原因（nil=已推进或本轮未成功落库）。
func (r *versionTableSlotRecorder) get() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// versionTableTaskIsRunning 两族 IsRunning 的单一实现：锁与标志由调用方注入
// ——running 必须与 runCancel/state 在同一临界区维护（StartUpdate 的
// 「检查并置位」与 CancelRunning 的读取都依赖该原子性），不得搬到独立锁。
func versionTableTaskIsRunning(mu *sync.Mutex, running *bool) bool {
	mu.Lock()
	defer mu.Unlock()
	return *running
}

type CRSUpdateStatus string

const (
	CRSStatusIdle        CRSUpdateStatus = "idle"
	CRSStatusChecking    CRSUpdateStatus = "checking"
	CRSStatusDownloading CRSUpdateStatus = "downloading"
	CRSStatusInstalling  CRSUpdateStatus = "installing"
	CRSStatusReloading   CRSUpdateStatus = "reloading"
	CRSStatusSuccess     CRSUpdateStatus = "success"
	CRSStatusFailed      CRSUpdateStatus = "failed"
	// CRSStatusSkipped：起点角色复查中止的正常语义
	// 终态——对齐威胁族 lastTaskOutcome=skipped（从节点中止非故障）。
	CRSStatusSkipped CRSUpdateStatus = "skipped"
	// CRSStatusCancelled 用户主动取消：与 task_runs cancelled 同终态，
	// 不增加连续失败计数，也不与 demote skipped 混用。
	CRSStatusCancelled CRSUpdateStatus = "cancelled"
)

// defaultCRSLiveDir 是 CRS 活树容器内默认根：写侧（crsLiveDir）与渲染读侧
// （crsDirectivesDir）共用同一声明，ConfigureWafDirs 与测试缝同批转发两变量。
const defaultCRSLiveDir = "/app/waf/crs"

var (
	crsLiveDir     = defaultCRSLiveDir
	crsSnapshotDir = "/app/data/crs"
	crsDistDir     = "/app/waf.dist/crs"
)

const crsTimeLayout = "2006-01-02 15:04:05"

type crsTaskState struct {
	status     CRSUpdateStatus
	trigger    string
	startedAt  time.Time
	finishedAt time.Time
	message    string
	version    string
}

// CRSUpdateStatusSnapshot is the point-in-time view served to handlers.
type CRSUpdateStatusSnapshot struct {
	Status     string
	Trigger    string
	StartedAt  string
	FinishedAt string
	Message    string
	Version    string
}

// CRSUpdateManager runs CRS manual/auto updates single-flight and persists
// terminal state in security_crs_version.
type CRSUpdateManager struct {
	mu           sync.Mutex
	running      bool
	state        crsTaskState
	runDone      chan struct{}
	ruleCount    int
	hasRuleCount bool
	// ruleCountRetryAfter 扫描失败后的负缓存截止时刻：坏树（缺失/不可读/
	// 树交换窗口）期间 UI 轮询不再每次付递归 WalkDir + ERROR 日志。树被替换
	// 的通道（InvalidateRuleCount）会清零，允许立即重扫。
	ruleCountRetryAfter time.Time

	// overridesBakCreated 标记本次运行已在迁移分支创建 zz-user-overrides.conf.bak
	// restoreBackup 只消费本运行创建的 bak——三-1 跨运行保全的恢复
	// 副本在下次成功更新前始终可用，三-2 也不会把 overrides 还原到两版本之前。
	// 每次 downloadAndInstall 开始时重置，迁移分支创建成功后置位。
	overridesBakCreated bool

	// rulesBakCreated/setupBakCreated/stockBakCreated 同口径「本运行创建」标记
	// （镜像 overridesBakCreated 的 1.1）：上一运行
	// 在「备份已建→清理前」崩溃会残留完整的 rules/setup/stock .bak；本运行在
	// 到达备份点前失败（如下载失败走 fail/cancel(..., true)）时 restoreBackup
	// 不得消费这些陈旧备份覆盖 live——它们是崩溃现场的唯一排障/恢复素材
	// （与 overrides.bak 的三-1 保全语义一致），且消费陈旧 rules.bak 会把 live
	// 树回滚到更新前版本、与 DB 版本行形成跨代分叉。每次 downloadAndInstall
	// 开始时重置，对应备份点创建成功后置位。
	rulesBakCreated bool
	setupBakCreated bool
	stockBakCreated bool

	// setup/stock 在更新前明确不存在且本次交换成功后创建时，回滚须删除新文件，
	// 否则旧 rules 会与新 setup/stock 组成混合代。stat 错误不等于不存在，不标记。
	setupRemoveOnRollback bool
	stockRemoveOnRollback bool

	reloader func() error
	// runCancel 取消当前运行中的下载阶段（任务监控手动取消，v2.3.4）：
	// 用户取消路径携带 ErrUserCancelled 原因，取消终态据此推进排程槽。
	runCancel       context.CancelCauseFunc
	fetchLatestTag  func(ctx context.Context) (string, error)
	downloadTarball func(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error
	// crsDir 是测试注入的 live 目录覆盖；生产恒为空，取值为 liveDir() 的
	// 晚绑定全局 crsLiveDir——ConfigureWafDirs（自定义 data_dir）可能在构造
	// 之后再改全局，构造期快照会让更新写相位与渲染读相位分叉。
	crsDir string

	// slots 本运行「排程槽未推进」的原因：排程不可读（写路径严格读排程失败）
	// 或状态行写入失败（槽随之未落地）。与 IP2Region 族共用同一记录器实现
	// （versionTableSlotRecorder）；Run 体把本轮按失败返回给任务引擎——成功轮
	// 不推进槽却回 success 会被引擎记入本槽消费水位，此后同一槽永不再投递
	// （该族自动更新静默停摆，没有下一轮可以自愈）。每次运行起点清空。
	slots versionTableSlotRecorder

	latestMu         sync.Mutex
	latestTag        string
	latestKnown      bool
	latestFetchedAt  time.Time
	latestRefreshing bool
}

var (
	crsUpdateManager     *CRSUpdateManager
	crsUpdateManagerOnce sync.Once
)

func newCRSUpdateManager(reloader func() error) *CRSUpdateManager {
	return &CRSUpdateManager{
		reloader:        reloader,
		fetchLatestTag:  defaultFetchCRSLatestTag,
		downloadTarball: defaultDownloadCRSTarball,
		ruleCount:       -1,
		state:           crsTaskState{status: CRSStatusIdle},
	}
}

// liveDir 返回当前 live CRS 目录：测试注入覆盖优先，否则读全局 crsLiveDir
// （ConfigureWafDirs 在构造之后运行，晚绑定才不会让更新写路径与渲染读路径
// 分叉）。
func (m *CRSUpdateManager) liveDir() string {
	if m.crsDir != "" {
		return m.crsDir
	}
	return crsLiveDir
}

// InitCRSUpdateManager initializes the singleton with the Caddy reloader.
func InitCRSUpdateManager(reloader func() error) {
	crsUpdateManagerOnce.Do(func() {
		crsUpdateManager = newCRSUpdateManager(reloader)
		// Seed the version row at init so the scheduler never finds an empty
		// table on fresh installs while the card displays auto-update as ON.
		ensureCRSVersionRow()
	})
}

func GetCRSUpdateManager() *CRSUpdateManager {
	return crsUpdateManager
}

func ResetCRSUpdateManagerForTest() {
	crsUpdateManager = nil
	crsUpdateManagerOnce = sync.Once{}
}

// SetCRSAutoUpdate toggles the auto-update flag without touching the stored
// version; a missing row is seeded with the image-bundled version.
// （用户报告）：开启时与 IP2Region 的 SetIP2RegionAutoUpdate 同步写
// next_update（关闭清空）——开关动作即重排程（v2.3.x 起写下一个排程槽，
// 原 now+24h）。此前只翻标志，开启自动更新后「下次更新」一直显示 —，
// 直到调度器下一次小时级 tick 预写才有值（手动更新成功也不写，见 run()
// 成功分支的补齐）。
func SetCRSAutoUpdate(enabled bool) error {
	return setVersionTableAutoUpdate("security_crs_version", "CRS", CRSBundledVersion, "crs", enabled)
}

func ensureCRSVersionRow() {
	ensureVersionTableRow("security_crs_version", CRSBundledVersion, "crs update")
}

// CurrentCRSVersionForLog 面向日志的当前 CRS 版本（main 载入摘要行消费）。
func CurrentCRSVersionForLog() string { return currentCRSVersion() }

// LatestVersionCached returns the last fetched upstream tag without network I/O.
func (m *CRSUpdateManager) LatestVersionCached() (string, bool) {
	m.latestMu.Lock()
	defer m.latestMu.Unlock()
	return m.latestTag, m.latestKnown
}

// RefreshLatestAsync refreshes the cached upstream tag in the background when
// the cache is older than 10 minutes; it never blocks the caller.
// latestFetchedAt 记录最近一次尝试（含失败）：失败路径同样受 10 分钟守卫约束。
func (m *CRSUpdateManager) RefreshLatestAsync() {
	m.latestMu.Lock()
	if m.latestRefreshing || time.Since(m.latestFetchedAt) < 10*time.Minute {
		m.latestMu.Unlock()
		return
	}
	m.latestRefreshing = true
	m.latestMu.Unlock()
	// 句柄在派发时捕获：后台续体不得再读全局 db.DB——测试/关闭序列会把
	// 全局句柄换成新库或 nil，迟到写入会串库或空指针。
	handle := db.DB

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tag, err := m.fetchLatestTag(ctx)
		m.latestMu.Lock()
		m.latestRefreshing = false
		m.latestFetchedAt = time.Now()
		if err == nil {
			m.latestTag = tag
			m.latestKnown = true
		}
		m.latestMu.Unlock()
		if handle == nil {
			return
		}
		if isMaster, qerr := RoleOf(context.Background(), handle); qerr == nil && isMaster {
			if _, dbErr := handle.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
				Logf("error", "crs update: failed to record last_checked: %v", dbErr)
			}
		}
		if err != nil {
			Logf("error", "crs update: background version check failed: %v", err)
		}
	}()
}

// readCurrentCRSVersion 是版本读取的唯一真源：区分
// 「行缺失/空值（首装→镜像捆绑版本，与 ensureCRSVersionRow 播种同口径）」与
// 「读失败（返回错误，由调用方 fail-visible）」。此前二者共用一处回落逻辑，
// 版本行瞬时读取失败被当作 bundled 参与「已是最新」短路——远端 tag 恰等于
// bundled 时更新被静默跳过（下一轮才重试，且无任何可见失败信号）。
func readCurrentCRSVersion() (string, error) {
	var version string
	err := db.DB.QueryRow("SELECT version FROM security_crs_version WHERE id=1").Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return CRSBundledVersion, nil
	}
	if err != nil {
		return "", err
	}
	if version == "" {
		return CRSBundledVersion, nil
	}
	return version, nil
}

// currentCRSVersion 是展示/日志口径的容错读取（更新判定使用
// crsCurrentVersionForRun 拿错误，不得用本函数短路）：读失败记 warn 后回落
// 镜像捆绑版本，避免展示层因瞬时 DB 故障中断。
func currentCRSVersion() string {
	version, err := readCurrentCRSVersion()
	if err != nil {
		Logf("warn", "crs update: 读取当前 CRS 版本失败，按镜像捆绑版本展示: %v", err)
		return CRSBundledVersion
	}
	return version
}

// crsCurrentVersionForRun 安装前版本判定的测试缝；生产恒指向
// readCurrentCRSVersion（读错误必须上抛，不得静默回落 bundled）。
var crsCurrentVersionForRun = readCurrentCRSVersion

// StartUpdate begins an async update; only one may run at a time. 返回本次 run
// 的完成通道：调度器 rearm 须等待该捕获通道而非回读现行 m.runDone
// ——StartUpdate 返回与 rearm 取锁之间存在微秒级窗口，快失败的 auto run 被手动
// 更新插队覆盖 m.runDone 时，rearm 会错等手动 run 的完成并按其终态跳过 auto 的
// 失败退避重写。手动调用方可忽略返回通道。
// rc 非 nil 且 RunID>0=引擎已预插 task_runs 行（-④ 单写方：族体跳过自记，
// 行终态由引擎 finishRun 按 Run 返回错误落）；Operator 供审计归人。
func (m *CRSUpdateManager) StartUpdate(trigger string, rc *taskengine.RunContext) (chan struct{}, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, ErrCRSUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	m.state = crsTaskState{status: CRSStatusChecking, trigger: trigger, startedAt: time.Now().UTC()}
	// 可取消 ctx 与 running 在同一临界区登记——StartUpdate 返回后
	// 立刻 CancelRunning（任务引擎 CancelHook／前端连点／自动化脚本）必须命中，
	// 不得因 run goroutine 尚未执行而读到 runCancel==nil 静默返回 false。
	runCtx, runCancel := context.WithCancelCause(updateRunBaseContext(rc))
	m.runCancel = runCancel
	done := m.runDone
	m.mu.Unlock()

	go func() {
		defer close(done)
		defer runCancel(nil)
		// 自建 goroutine 不被引擎 runGuarded 覆盖——未捕获 panic=整个
		// admin 进程退出。正常路径由 runWithContext 内部 recover 先行落定
		// failed 终态（审计同口径），此处仅兜底（defer 自身 panic 等）。
		defer func() {
			if r := recover(); r != nil {
				Logf("error", "crs update: run panicked: %v\n%s", r, debug.Stack())
				m.recoverRunPanic(r)
			}
		}()
		m.runWithContext(runCtx, trigger, rc)
	}()
	return done, nil
}

// recoverRunPanic 把更新 goroutine 的 panic 收敛为 failed 终态（两层 recover
// 共用）：db 未初始化（启动早期/测试缝）时无版本行可写，只落内存终态与更新
// 日志——不得因 panic 的恢复路径本身再 panic。
func (m *CRSUpdateManager) recoverRunPanic(r any) {
	cause := fmt.Errorf("更新任务内部异常（已拦截进程级崩溃）: %v", r)
	if db.DB == nil {
		m.setStage(CRSStatusFailed, cause.Error())
		return
	}
	m.fail(cause, false)
}

// updateRunBaseContext 任务运行上下文基座（CRS/IP2Region 同源）
// 引擎 demote 中止（SetRole 取消在途 Scheduled）与手动取消同通道传播；
// nil rc（测试/内部路径）回退 Background 保持旧语义。
func updateRunBaseContext(rc *taskengine.RunContext) context.Context {
	if rc != nil && rc.Ctx != nil {
		return rc.Ctx
	}
	return context.Background()
}

func (m *CRSUpdateManager) IsRunning() bool {
	return versionTableTaskIsRunning(&m.mu, &m.running)
}

func (m *CRSUpdateManager) setStage(status CRSUpdateStatus, message string) {
	m.mu.Lock()
	m.state.status = status
	m.state.message = message
	m.mu.Unlock()
	level := "INFO"
	switch status {
	case CRSStatusFailed:
		level = "ERROR"
	case CRSStatusSkipped, CRSStatusCancelled:
		// 跳过/用户取消均为非故障中止，使用 WARN。
		level = "WARN"
	}
	WriteCRSUpdateLog(level, string(status), message)
}

// recordLatestSkip 记录「已是最新版本」终态（DB 行与内存状态单点实现）。
func (m *CRSUpdateManager) recordLatestSkip(trigger string) {
	slotSQL, slotArgs, slotErr := versionTableSlotSuccessAssign("security_crs_version", trigger)
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), consecutive_failures=0, "+slotSQL+" WHERE id=1",
		slotArgs...,
	); err != nil {
		// 状态行没落地=本轮对调度契约而言失败（排程槽同样未推进）：并入
		// 「槽未推进」通道，由 Run 体按失败返回给引擎——引擎据失败退避重投，
		// 再次成功落库即推进槽；若吞错按 success 收尾，引擎会把过期槽记入
		// 消费水位而库里的槽仍是旧值，该族自动更新此后无路径自愈。
		slotErr = errors.Join(slotErr, fmt.Errorf("%w: 状态行写入失败: %w", errScheduleSlotNotAdvanced, err))
	}
	m.setSlotAdvanceError(slotErr)
	m.mu.Lock()
	m.state.status = CRSStatusSuccess
	m.state.message = "已是最新版本"
	m.state.finishedAt = time.Now().UTC()
	m.state.version = currentCRSVersion()
	m.mu.Unlock()
}

// run 同步执行一次更新（测试/内部直调路径）：自建可取消 ctx 并登记
// runCancel；生产入口经 StartUpdate 预建 ctx（——取消能力不得晚于
// StartUpdate 返回才就绪）。
func (m *CRSUpdateManager) run(trigger string, rc *taskengine.RunContext) {
	runCtx, runCancel := context.WithCancelCause(updateRunBaseContext(rc))
	defer runCancel(nil)
	m.mu.Lock()
	m.runCancel = runCancel
	m.mu.Unlock()
	m.runWithContext(runCtx, trigger, rc)
}

// runWithContext 是更新管线本体；runCtx 由调用方创建（StartUpdate 或 run），
// 生命周期归还调用方。
func (m *CRSUpdateManager) runWithContext(runCtx context.Context, trigger string, rc *taskengine.RunContext) {
	operator := "system"
	if rc != nil && rc.Operator != "" {
		operator = rc.Operator
	}
	// running 复位必须先注册（LIFO 最后执行）：审计 defer 要在 running 仍置位时
	// 读取本轮终态快照。旧序（审计先注册、复位后注册）让复位先执行，两步之间
	// StartUpdate 可成功进入并写 checking，旧轮审计读到下一轮状态（「更新检测中
	// （触发：新）」），本轮真实终态丢失。
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	// 任务自记审计：手动/自动同一审计（用户裁定 2026-09-29）。manager 内联
	// 结果审计已撤（审计单记——曾是 defer+内联双记）。
	defer func() {
		snap := m.StatusSnapshot()
		// 状态中文归一（曾混英文 status token，与 threat 族口径不一）
		statusLabel := map[string]string{
			string(CRSStatusSuccess): "成功", string(CRSStatusFailed): "失败",
			string(CRSStatusSkipped): "跳过", string(CRSStatusCancelled): "已取消",
			string(CRSStatusIdle): "空闲", string(CRSStatusChecking): "检测中",
		}[snap.Status]
		if statusLabel == "" {
			statusLabel = snap.Status
		}
		detail := fmt.Sprintf("更新%s（触发：%s）%s", statusLabel, trigger, snap.Message)
		switch snap.Status {
		case string(CRSStatusFailed):
			RecordAuditLog(operator, "更新失败", "CRS规则库", detail, "")
		case string(CRSStatusCancelled):
			RecordAuditLog(operator, "取消", "CRS规则库", detail, "")
		default:
			RecordAuditLog(operator, "更新", "CRS规则库", detail, "")
		}
	}()

	// 单写方：task_runs 由引擎统一记录（manual 预插/ SilentProbes 有工作标记后插入）
	// 族体零 RecordRun 调用。
	// runCtx 派生自 rc.Ctx——引擎 demote 中止（SetRole
	// 取消在途 Scheduled）与手动取消同通道传播；nil rc（测试/内部路径）回退
	// Background 保持旧语义。ctx 由调用方（StartUpdate/run）预建。

	// 每次运行起点清空「排程槽未推进」状态：上一轮的读失败不得让本轮成功
	// 轮仍被引擎判失败（读恢复后必须立即自愈）。
	m.slots.set(nil, crsUpdateLogFamily)

	// 函数内 recover：本 defer 注册在上方审计 defer 之后 → 恢复先于审计执行
	// （panic 轮先落定 failed 终态，审计读到失败语义而不是 checking 等中间
	// 阶段被记成「更新」）。外层 goroutine 的 recover 退化为兜底（defer 自身
	// panic 等形态）。
	defer func() {
		if r := recover(); r != nil {
			Logf("error", "crs update: run panicked: %v\n%s", r, debug.Stack())
			m.recoverRunPanic(r)
		}
	}()

	// 起点角色复查：调度器 tick 的 is_master 守卫与更新启动之间存在
	// demote 竞态窗口——tick 越过守卫、更新刚发出时节点被降级，从节点继续执行
	// 会写本地版本行、替换规则树并 reload，瞬时打破只读不变量。
	// NULL 兜底归一为 1，与 IsMaster/readonly 写闸/
	// 调度器 tick 的 COALESCE(is_master,1) 同口径（NULL 视为主节点）。
	if isMaster, roleErr := RoleOf(context.Background(), db.DB); roleErr != nil {
		// 角色读取失败（DB 瞬断/脏行）≠从节点——按失败落定（task_runs/任务
		// 监控可见），不得静默跳过（err!=nil||!isMaster 把 DB 故障
		// 当从节点）。
		m.fail(fmt.Errorf("角色读取失败，无法判定本节点是否主节点，已中止 CRS 更新: %w", roleErr), false)
		m.advanceSlotIfAuto(trigger)
		return
	} else if !isMaster {
		// 从节点中止是正常跳过语义，对齐威胁族——内存终态 + 更新日志/审计
		// 留痕（「更新跳过」），不写版本表（从节点只读不变量：版本行由集群
		// 同步治理），因此进程重启后 StatusSnapshot 会回退为存储行的 idle。
		m.syncInstalledVersionToState()
		m.setStage(CRSStatusSkipped, "当前节点为从节点，终止 CRS 更新")
		return
	}

	ensureCRSVersionRow()
	runStartedAt := taskRunStartedAt(rc)
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET trigger=?, started_at=?, last_checked=?, finished_at=NULL WHERE id=1",
		trigger, runStartedAt, runStartedAt,
	); err != nil {
		Logf("error", "crs update: failed to mark start: %v", err)
	}

	m.setStage(CRSStatusChecking, "查询最新 CRS 版本")
	// 任务内重试（2026-09-25 用户裁定）：瞬断在当前任务内重试，耗尽才落定失败——
	// 失败退避不再改写排程槽，下一运行=下一排程槽。
	var tag string
	err := runWithInTaskRetry(runCtx, func() error {
		var ferr error
		tag, ferr = m.fetchLatestTag(runCtx)
		if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET last_checked=? WHERE id=1", runStartedAt); dbErr != nil {
			Logf("error", "crs update: failed to record last_checked: %v", dbErr)
		}
		return ferr
	}, func(nextAttempt int, wait time.Duration, rerr error) {
		WriteCRSUpdateLog("WARN", "retry", fmt.Sprintf("查询 CRS 最新版本失败: %v；等待 %s 重试，第 %d 次，共 %d 次", rerr, wait, nextAttempt, updateMaxAttempts))
	})
	if err != nil {
		// runCtx 取消且已非主节点=demote 在途中止——落 skipped
		// （与起点角色复查同语义），不走 fail（从节点中止非故障、不 restore）。
		if master, known := updateRunRole(); runCtx.Err() != nil && known && !master {
			m.syncInstalledVersionToState()
			m.setStage(CRSStatusSkipped, "节点已降级为从节点，终止 CRS 更新")
			return
		}
		if runCtx.Err() != nil {
			m.cancel(err, false, trigger, runCtx)
			return
		}
		m.fail(err, false)
		m.advanceSlotIfAuto(trigger)
		return
	}
	WriteCRSUpdateLog("INFO", string(CRSStatusChecking), fmt.Sprintf("最新版本 %s，当前版本 %s", tag, currentCRSVersion()))

	// tag < current 时也跳过(防静默降级)——
	// 此前仅精确相等跳过,捆绑版本 > 远端最新(如上游 release 被删/转 pre)时
	// 无条件 downloadAndInstall 降级为更旧树,与 UI IsLatest(<=0 即最新)语义相悖。
	// 精确相等短路（与格式无关）——相同版本即「已是最新」，不再依赖
	// 版本解析；不同且不可比较显式 fail-visible（见下方 else-if）。
	// 读版本行失败（非「行缺失」）不再回落 bundled 参与短路——
	// 以 bundled 参与「已是最新」判定会在远端 tag 恰等于 bundled 时静默跳过，
	// 且掩盖瞬时 DB 故障；此处显式失败（下一排程槽重试）。
	currentVersion, verErr := crsCurrentVersionForRun()
	if verErr != nil {
		m.fail(fmt.Errorf("读取当前 CRS 版本失败: %w", verErr), false)
		m.advanceSlotIfAuto(trigger)
		return
	}
	if tag == currentVersion {
		WriteCRSUpdateLog("INFO", string(CRSStatusSuccess), "已是最新版本，无需更新")
		m.recordLatestSkip(trigger)
		return
	}
	if cmp, cmpErr := CompareCRSVersions(tag, currentVersion); cmpErr != nil && currentVersion != "" && !strings.EqualFold(currentVersion, "unknown") {
		// 不同且不可比较：不再隐含「必然更新」（格式漂移静默降级/升级的温床），
		// 显式失败等待人工确认。空 current（首装）走安装路径。
		m.fail(fmt.Errorf("版本格式不可比较（远端 %q / 当前 %q），已中止更新以避免静默降级", tag, currentVersion), false)
		m.advanceSlotIfAuto(trigger)
		return
	} else if cmpErr == nil && cmp <= 0 {
		WriteCRSUpdateLog("INFO", string(CRSStatusSuccess), "已是最新版本，无需更新")
		m.recordLatestSkip(trigger)
		return
	}

	m.mu.Lock()
	m.state.version = tag
	m.mu.Unlock()

	var installErr error
	installRetErr := runWithInTaskRetry(runCtx, func() error {
		installErr = m.downloadAndInstall(runCtx, tag)
		// crsReloadError=安装成功但重载失败（restore 编舞已执行）——非瞬断，不重试
		// （errIP2RegionReload 同型先例）。
		var rerr *crsReloadError
		if errors.As(installErr, &rerr) {
			return nil
		}
		return installErr
	}, func(nextAttempt int, wait time.Duration, rerr error) {
		WriteCRSUpdateLog("WARN", "retry", fmt.Sprintf("下载安装 CRS %s 失败: %v；等待 %s 重试，第 %d 次，共 %d 次", tag, rerr, wait, nextAttempt, updateMaxAttempts))
	})
	// 取消可能发生在安装循环执行 op 之前：此时 installErr 仍为 nil，但
	// runWithInTaskRetry 已返回 ctx 错误。必须消费返回值，禁止写成功版本。
	if installRetErr != nil && (installErr == nil || runCtx.Err() != nil) {
		installErr = installRetErr
	}
	if installErr == nil && runCtx.Err() != nil {
		installErr = runCtx.Err()
	}
	if installErr != nil {
		// 同上方 fetch 分支——demote 在途中止落 skipped（不 restore
		// 从节点不回滚不 reload，保持只读不变量）。
		if master, known := updateRunRole(); runCtx.Err() != nil && known && !master {
			m.syncInstalledVersionToState()
			m.setStage(CRSStatusSkipped, "节点已降级为从节点，终止 CRS 更新")
			return
		}
		if runCtx.Err() != nil {
			m.cancel(installErr, m.crsRestorePointCreated(), trigger, runCtx)
			return
		}
		m.fail(installErr, m.crsRestorePointCreated())
		m.advanceSlotIfAuto(trigger)
		return
	}
	slotSQL, slotArgs, slotErr := versionTableSlotSuccessAssign("security_crs_version", trigger)
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET version=?, updated_at=datetime('now'), update_status='success', message='', finished_at=datetime('now'), consecutive_failures=0, "+slotSQL+" WHERE id=1",
		append([]any{tag}, slotArgs...)...,
	); err != nil {
		// 同「已是最新」分支：版本/状态行没落地即本轮失败（槽也未推进），
		// 走同一「槽未推进」通道让引擎退避重投（重投幂等：写成功即推进槽）。
		slotErr = errors.Join(slotErr, fmt.Errorf("%w: 状态行写入失败: %w", errScheduleSlotNotAdvanced, err))
	}
	m.setSlotAdvanceError(slotErr)
	m.rescanRuleCount()
	m.mu.Lock()
	m.state.status = CRSStatusSuccess
	m.state.message = ""
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteCRSUpdateLog("INFO", string(CRSStatusSuccess), fmt.Sprintf("CRS 已更新到 %s", tag))
	// 复审裁定 3：清理之前版本残留在 live 目录的瞬态工件（仅更新成功后执行）
	m.cleanupLegacyCRSTransient()
}

// advanceSlotIfAuto 落定推进排程槽（失败/取消路径）：①仅 auto 触发——手动轮
// 失败时引擎按退避重投同一槽，业务抢先推进会把该自动槽静默吃掉（手动**成功**
// 按 schedule.go 的成功门推进，不经过本函数）；②仅当现存槽为空或已过期——
// 未来槽（配置变更/自定义槽）不被回拨污染。
// 此前失败不推进：过期槽经 NextSlotFn 步进（coveredSlotStepPast）每 tick 重算
// 永远领先 now 一步，due 判定窗口零宽，排程永久停摆（10-06 失败后停摆 5 天实证）。
func (m *CRSUpdateManager) advanceSlotIfAuto(trigger string) error {
	if trigger != "auto" {
		return nil
	}
	return advanceVersionSlotIfDue("security_crs_version")
}

// advanceVersionSlotIfDue 版本表槽推进共享实现（CRS/IP2Region 同构）：空或过期
// 才写紧邻下一排程槽；auto_update=0 不动（IIF 兜底）。排程不可读时不写——写
// 路径不得用默认排程覆盖用户的预约（失败已由严格读单源留痕）。
func advanceVersionSlotIfDue(table string) error {
	var cur string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE id=1`).Scan(&cur); err != nil {
		return fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	if cur != "" {
		// 双布局（crsTimeLayout + RFC3339）单源解析：单布局会把旧备份/快照
		// 带入的 RFC3339 未来槽解析失败并按「过期」覆写；同族读取面
		// （versionTableNextUpdate/earliestEnabledSourceUpdate）均能正确解析。
		if t := parseUTCSlot(cur); !t.IsZero() && t.After(time.Now().UTC()) {
			return nil // 未来槽不污染
		}
	}
	slotSQL, slotArgs, slotErr := versionTableSlotAdvanceAssign(table)
	if slotErr != nil {
		return slotErr
	}
	if _, err := db.DB.Exec(`UPDATE `+table+` SET `+slotSQL+` WHERE id=1`, slotArgs...); err != nil {
		return fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	return nil
}

// crsRestorePointCreated 报告本运行是否真的动过 live 树——restoreBackup 的
// 消费门与 reload 的必要性都由它决定。download/extract/validate/完整性校验
// 任一步失败时树尚未触碰（备份点在第一份备份拷贝成功后才置位），此时既不
// 需还原也无需重载（reload 要取 CaddyOpLock 并跑一轮渲染；失败重试场景会
// 把它放大成每轮一次）。installAttempted 旧语义是「进入安装循环」，
// 与「树已变更」不等价。
func (m *CRSUpdateManager) crsRestorePointCreated() bool {
	return m.rulesBakCreated || m.setupBakCreated || m.stockBakCreated || m.overridesBakCreated
}

func (m *CRSUpdateManager) restoreAfterInstallError(restore bool) {
	if restore {
		m.restoreBackup()
		// reloader nil 守卫(与 crsinstall.go 的
		// swapCRSTreeFromStaging 内守卫同口径)——
		// 测试注入 nil reloader 时 panic。
		if m.reloader != nil {
			if err := m.reloader(); err != nil {
				Logf("error", "crs update: reload after restore failed: %v", err)
			}
		}
	}
}

// cancel 记录取消终态：安装段已发生树变更时沿用失败路径的回滚/重载
// 安全编舞，但终态不是 failed，连续失败计数不增加。
// 若取消发生在树交换之后，downloadAndInstall 已在返回前走
// rollbackAfterReloadFailure 同代回滚（树+VERSION 标记+DB 版本行）——此处
// restoreAfterInstallError 的 restoreBackup 是幂等兜底（本运行备份已被回滚
// 消费），reloader 负责让 Caddy 追上还原后的旧树。
// syncInstalledVersionToState 终态（失败/取消/跳过）把 state.version 归位为
// 已安装版本：run 在安装前就把 state.version 写成远端 tag，
// 失败/取消后不复位会让 status 端点把「尝试安装但未安装」的版本当作当前版本
// 返回（DB 版本行与磁盘仍是旧版本）。读失败留空并留痕，不猜测。
//
// 排程槽：**用户取消自动轮**与失败同源——本槽显式放弃，预约推进到紧邻下一
// 排程槽（引擎侧取消时已消费本槽，业务不推进则 tick 的「槽 > 已消费水位」门
// 永远不成立，该库自动更新从此静默停摆）。demote/导入排空/进程停止的取消
// 不推进（引擎侧同样不消费槽，恢复后到期轮补跑）。
func (m *CRSUpdateManager) syncInstalledVersionToState() {
	installed, err := crsCurrentVersionForRun()
	if err != nil {
		Logf("warn", "crs update: 读取已安装版本失败，状态 version 留空: %v", err)
		installed = ""
	}
	m.mu.Lock()
	m.state.version = installed
	m.mu.Unlock()
}

func (m *CRSUpdateManager) cancel(cause error, restore bool, trigger string, runCtx context.Context) {
	m.restoreAfterInstallError(restore)
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='cancelled', message=?, finished_at=datetime('now') WHERE id=1",
		cause.Error(),
	); err != nil {
		Logf("error", "crs update: failed to record cancellation: %v", err)
	}
	if userCancelledRun(runCtx) {
		// 用户取消=显式放弃本槽（与失败同源）；推进失败必须显式上报，
		// 让引擎释放已消费槽并退避重试。
		m.setSlotAdvanceError(m.advanceSlotIfAuto(trigger))
	}
	m.syncInstalledVersionToState()
	m.mu.Lock()
	m.state.status = CRSStatusCancelled
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteCRSUpdateLog("WARN", string(CRSStatusCancelled), cause.Error())
}

func (m *CRSUpdateManager) fail(cause error, restore bool) {
	m.restoreAfterInstallError(restore)
	// 连续失败计数 +1（失败趋势可观测；操作审计由 run 的 defer 单记——
	// 收敛后内联首败审计已撤）。
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='failed', message=?, finished_at=datetime('now'), consecutive_failures=consecutive_failures+1 WHERE id=1",
		cause.Error(),
	); err != nil {
		Logf("error", "crs update: failed to record failure: %v", err)
	}
	m.syncInstalledVersionToState()
	m.mu.Lock()
	m.state.status = CRSStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteCRSUpdateLog("ERROR", string(CRSStatusFailed), cause.Error())
}

// downloadTarballLogged 包装下载 seam 写更新日志：开始行由下载函数的
// (0, total) 开始信号触发，携带完整来源 URL（含 GitHub 加速代理前缀，代理
// 取值经 github_proxy_url 白名单，历史硬编码 ghfast.top 已废弃），
// 已知时附预计大小；进度行经节流闭包按 10%（总量已知）/5MB
// （未知）步进；完成行记录落盘字节与耗时。stage 沿用下载阶段的 downloading。
func (m *CRSUpdateManager) downloadTarballLogged(ctx context.Context, tag, destPath string) error {
	logLine := func(message string) { WriteCRSUpdateLog("INFO", string(CRSStatusDownloading), message) }
	startedAt := time.Now()
	progress := newDownloadProgressLogger(crsTarballSourceURL(tag), logLine)
	if err := m.downloadTarball(ctx, tag, destPath, progress); err != nil {
		return err
	}
	logDownloadCompletion(logLine, destPath, startedAt)
	return nil
}

// CancelRunning 取消当前运行中的更新（下载阶段中断）。无运行中任务返回 false。
// 调用方只有用户取消通道（引擎 CancelHook／前端取消入口）——取消原因标记为
// ErrUserCancelled，取消终态据此把排程槽推进到下一槽。
func (m *CRSUpdateManager) CancelRunning() bool {
	m.mu.Lock()
	cancel := m.runCancel
	running := m.running
	m.mu.Unlock()
	if cancel == nil || !running {
		return false
	}
	cancel(taskengine.ErrUserCancelled)
	return true
}

// setSlotAdvanceError 记录「本轮排程槽未推进」的原因（排程不可读，或状态行
// 写入失败连带槽一起没落地）——任务引擎 Run 体据此把本轮按失败返回（不是把
// 状态行改成 failed：更新本身可能已成功，失败的是调度契约；引擎需要失败才能
// 退避重投同一槽，而不是把本槽记入消费水位）。
func (m *CRSUpdateManager) setSlotAdvanceError(err error) {
	m.slots.set(err, crsUpdateLogFamily)
}

// ScheduleSlotError 本运行成功落库但排程槽未推进的原因（nil=槽已推进或本轮
// 未成功）。驱动任务引擎 Run 体在状态为 success 时复核：非 nil 时返回该错误，
// 让引擎按失败退避重投而不是消费本槽。
func (m *CRSUpdateManager) ScheduleSlotError() error {
	return m.slots.get()
}

// StatusSnapshot returns the in-memory task view, falling back to the stored
// terminal state when no update has run since process start.
func (m *CRSUpdateManager) StatusSnapshot() CRSUpdateStatusSnapshot {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state.trigger != "" || !state.startedAt.IsZero() {
		return snapshotFromState(state)
	}
	return storedStatusSnapshot()
}
