package services

import (
	"context"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/taskengine"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// CRSBundledVersion is the CRS release baked into the container image; it is
// only used to seed security_crs_version when the row does not exist yet.
const CRSBundledVersion = "v4.28.0"

var ErrCRSUpdateRunning = errors.New("CRS 更新任务正在进行中")

type CRSUpdateStatus string

const (
	CRSStatusIdle        CRSUpdateStatus = "idle"
	CRSStatusChecking    CRSUpdateStatus = "checking"
	CRSStatusDownloading CRSUpdateStatus = "downloading"
	CRSStatusInstalling  CRSUpdateStatus = "installing"
	CRSStatusReloading   CRSUpdateStatus = "reloading"
	CRSStatusSuccess     CRSUpdateStatus = "success"
	CRSStatusFailed      CRSUpdateStatus = "failed"
	// CRSStatusSkipped U2-66-05（第 66 轮审计）：起点角色复查中止的正常语义
	// 终态——对齐威胁族 lastTaskOutcome=skipped（从节点中止非故障）。
	CRSStatusSkipped CRSUpdateStatus = "skipped"
)

var (
	crsLiveDir     = "/app/waf/crs"
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
	// Cancellable: 运行中且支持手动取消（任务监控，v2.3.4）。
	Cancellable bool
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

	// overridesBakCreated 标记本次运行已在迁移分支创建 zz-user-overrides.conf.bak
	// （R39 1.1）：restoreBackup 只消费本运行创建的 bak——三-1 跨运行保全的恢复
	// 副本在下次成功更新前始终可用，三-2 也不会把 overrides 还原到两版本之前。
	// 每次 downloadAndInstall 开始时重置，迁移分支创建成功后置位。
	overridesBakCreated bool

	reloader func() error
	// runCancel 取消当前运行中的下载阶段（任务监控手动取消，v2.3.4）。
	runCancel       context.CancelFunc
	fetchLatestTag  func(ctx context.Context) (string, error)
	downloadTarball func(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error
	crsDir          string

	latestMu         sync.Mutex
	latestTag        string
	latestKnown      bool
	latestFetchedAt  time.Time
	latestRefreshing bool

	schedulerMu       sync.Mutex
	schedulerStop     chan struct{}
	schedulerDone     chan struct{}
	schedulerInterval time.Duration
}

var (
	crsUpdateManager     *CRSUpdateManager
	crsUpdateManagerOnce sync.Once
)

func newCRSUpdateManager(reloader func() error) *CRSUpdateManager {
	return &CRSUpdateManager{
		reloader:          reloader,
		fetchLatestTag:    defaultFetchCRSLatestTag,
		downloadTarball:   defaultDownloadCRSTarball,
		crsDir:            crsLiveDir,
		ruleCount:         -1,
		schedulerInterval: time.Minute,
		state:             crsTaskState{status: CRSStatusIdle},
	}
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
	if crsUpdateManager != nil {
		crsUpdateManager.StopScheduler()
	}
	crsUpdateManager = nil
	crsUpdateManagerOnce = sync.Once{}
}

// SetCRSAutoUpdate toggles the auto-update flag without touching the stored
// version; a missing row is seeded with the image-bundled version.
// R69（用户报告）：开启时与 IP2Region 的 SetIP2RegionAutoUpdate 同步写
// next_update（关闭清空）——开关动作即重排程（v2.3.x 起写下一个排程槽，
// 原 now+24h）。此前只翻标志，开启自动更新后「下次更新」一直显示 —，
// 直到调度器下一次小时级 tick 预写才有值（手动更新成功也不写，见 run()
// 成功分支的补齐）。
func SetCRSAutoUpdate(enabled bool) error {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, ?)",
		CRSBundledVersion, enabled,
	); err != nil {
		return fmt.Errorf("初始化 CRS 版本记录: %w", err)
	}
	nextUpdate := ""
	if enabled {
		nextUpdate = versionTableNextSlot("security_crs_version", time.Now().UTC())
	}
	// 2026-09-25 用户裁定：失败退避机制撤除——开启重排一律写下一排程槽，
	// 失败行不再保留退避点（重试在任务内完成）；关闭仍无条件清空。
	if _, err := db.DB.Exec("UPDATE security_crs_version SET auto_update=?, next_update=CASE WHEN ? THEN ? ELSE '' END WHERE id=1", enabled, enabled, nextUpdate); err != nil {
		return fmt.Errorf("更新 CRS 自动更新开关: %w", err)
	}
	syncTaskLoop("crs", enabled)
	return nil
}

func ensureCRSVersionRow() {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, TRUE)",
		CRSBundledVersion,
	); err != nil {
		Logf("error", "crs update: failed to ensure version row: %v", err)
	}
}

// CurrentCRSVersionForLog 面向日志的当前 CRS 版本（main 载入摘要行消费）。
func CurrentCRSVersionForLog() string { return currentCRSVersion() }

func currentCRSVersion() string {
	var version string
	if err := db.DB.QueryRow("SELECT version FROM security_crs_version WHERE id=1").Scan(&version); err != nil || version == "" {
		return CRSBundledVersion
	}
	return version
}

// StartUpdate begins an async update; only one may run at a time. 返回本次 run
// 的完成通道（R64 B-F2）：调度器 rearm 须等待该捕获通道而非回读现行 m.runDone
// ——StartUpdate 返回与 rearm 取锁之间存在微秒级窗口，快失败的 auto run 被手动
// 更新插队覆盖 m.runDone 时，rearm 会错等手动 run 的完成并按其终态跳过 auto 的
// 失败退避重写。手动调用方可忽略返回通道。
// rc 非 nil 且 RunID>0=引擎已预插 task_runs 行（P2-④ 单写方：族体跳过自记，
// 行终态由引擎 finishRun 按 Run 返回错误落）；Operator 供审计归人（U1-P3-1）。
func (m *CRSUpdateManager) StartUpdate(trigger string, rc *taskengine.RunContext) (chan struct{}, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, ErrCRSUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	m.state = crsTaskState{status: CRSStatusChecking, trigger: trigger, startedAt: time.Now().UTC()}
	done := m.runDone
	m.mu.Unlock()

	go func() {
		defer close(done)
		m.run(trigger, rc)
	}()
	return done, nil
}

// AutoUpdateEnabled CRS 自动更新是否开启（从 wire Run 体到期检查消费）。
func (m *CRSUpdateManager) AutoUpdateEnabled() bool {
	var v bool
	db.DB.QueryRow("SELECT COALESCE(auto_update,0) FROM security_crs_version WHERE id=1").Scan(&v)
	return v
}

// NextScheduledSlot 返回下次更新排程槽（空串=未设置）。
func (m *CRSUpdateManager) NextScheduledSlot() string {
	var s string
	db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&s)
	return s
}

func (m *CRSUpdateManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
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
	case CRSStatusSkipped:
		// U2-66-05：跳过语义用 WARN（对齐威胁族 AppendThreatUpdateLog WARN skipped）。
		level = "WARN"
	}
	WriteCRSUpdateLog(level, string(status), message)
}

// run executes the full update pipeline synchronously.
func (m *CRSUpdateManager) run(trigger string, rc *taskengine.RunContext) {
	operator := "system"
	if rc != nil && rc.Operator != "" {
		operator = rc.Operator
	}
	// 任务自记审计：手动/自动同一审计（用户裁定 2026-09-29）。manager 内联
	// 结果审计已撤（U1-P3-2 审计单记——曾是 defer+内联双记）。
	defer func() {
		snap := m.StatusSnapshot()
		// 状态中文归一（U2-P5-08b：曾混英文 status token，与 threat 族口径不一）
		statusLabel := map[string]string{
			string(CRSStatusSuccess): "成功", string(CRSStatusFailed): "失败",
			string(CRSStatusSkipped): "跳过",
			string(CRSStatusIdle):    "空闲", string(CRSStatusChecking): "检测中",
		}[snap.Status]
		if statusLabel == "" {
			statusLabel = snap.Status
		}
		detail := fmt.Sprintf("更新%s（触发：%s）%s", statusLabel, trigger, snap.Message)
		if snap.Status == string(CRSStatusFailed) {
			RecordAuditLog(operator, "更新失败", "CRS规则库", detail, "")
		} else {
			RecordAuditLog(operator, "更新", "CRS规则库", detail, "")
		}
	}()

	// R63 单写方：task_runs 由引擎统一记录（manual 预插/ SilentProbes 有工作标记后插入）
	// 族体零 RecordRun 调用。
	// F-L2-68-01（第 68 轮）：runCtx 派生自 rc.Ctx——引擎 demote 中止（SetRole
	// 取消在途 Scheduled）与手动取消同通道传播；nil rc（测试/内部路径）回退
	// Background 保持旧语义。
	runBase := context.Background()
	if rc != nil && rc.Ctx != nil {
		runBase = rc.Ctx
	}
	runCtx, runCancel := context.WithCancel(runBase)
	m.mu.Lock()
	m.runCancel = runCancel
	m.mu.Unlock()
	defer func() {
		runCancel()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	// 起点角色复查（R54-N5）：调度器 tick 的 is_master 守卫与更新启动之间存在
	// demote 竞态窗口——tick 越过守卫、更新刚发出时节点被降级，从节点继续执行
	// 会写本地版本行、替换规则树并 reload，瞬时打破只读不变量。
	// SEC42-2（第 42 轮审计）：NULL 兜底归一为 1，与 IsMaster/readonly 写闸/
	// 调度器 tick 的 COALESCE(is_master,1) 同口径（历史 NULL 视为主节点）。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		// U2-66-05（第 66 轮审计）：从节点中止是正常跳过语义，对齐威胁族——
		// 落 skipped 终态、审计「更新跳过」，不再记「更新失败」。
		m.setStage(CRSStatusSkipped, "当前节点为从节点，终止 CRS 更新")
		return
	}

	ensureCRSVersionRow()
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET trigger=?, started_at=datetime('now'), finished_at=NULL WHERE id=1",
		trigger,
	); err != nil {
		Logf("error", "crs update: failed to mark start: %v", err)
	}

	m.setStage(CRSStatusChecking, "查询最新 CRS 版本")
	// 任务内重试（2026-09-25 用户裁定）：瞬断在当前任务内重试，耗尽才落定失败——
	// 失败退避不再改写排程槽，下一运行=下一排程槽。
	var tag string
	err := runWithInTaskRetry(func() error {
		var ferr error
		tag, ferr = m.fetchLatestTag(runCtx)
		if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
			Logf("error", "crs update: failed to record last_checked: %v", dbErr)
		}
		return ferr
	}, func(nextAttempt int, wait time.Duration, rerr error) {
		WriteCRSUpdateLog("WARN", "retry", fmt.Sprintf("查询 CRS 最新版本失败: %v；等待 %s 重试，第 %d 次，共 %d 次", rerr, wait, nextAttempt, updateMaxAttempts))
	})
	if err != nil {
		// F-L2-68-01：runCtx 取消且已非主节点=demote 在途中止——落 skipped
		// （与起点角色复查同语义），不走 fail（从节点中止非故障、不 restore）。
		if runCtx.Err() != nil && !updateRunStillMaster() {
			m.setStage(CRSStatusSkipped, "节点已降级为从节点，终止 CRS 更新")
			return
		}
		m.fail(err, false)
		m.advanceSlotIfAuto(trigger)
		return
	}
	WriteCRSUpdateLog("INFO", string(CRSStatusChecking), fmt.Sprintf("最新版本 %s，当前版本 %s", tag, currentCRSVersion()))

	// CRS-1(第 5 轮审计 P2):tag < current 时也跳过(防静默降级)——
	// 此前仅精确相等跳过,捆绑版本 > 远端最新(如上游 release 被删/转 pre)时
	// 无条件 downloadAndInstall 降级为更旧树,与 UI IsLatest(<=0 即最新)语义相悖。
	if cmp, cmpErr := CompareCRSVersions(tag, currentCRSVersion()); cmpErr == nil && cmp <= 0 {
		WriteCRSUpdateLog("INFO", string(CRSStatusSuccess), "已是最新版本，无需更新")
		if _, err := db.DB.Exec(
			// 排程槽——手动触发不得改变下一次预约执行时间；现存未来槽不被回拨。
			"UPDATE security_crs_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), consecutive_failures=0, "+versionTableSlotAdvanceSQL+" WHERE id=1",
			trigger, versionTableNextSlot("security_crs_version", time.Now().UTC()),
		); err != nil {
			Logf("warn", "crs update: failed to record latest-version skip: %v", err)
		}
		m.mu.Lock()
		m.state.status = CRSStatusSuccess
		m.state.message = "已是最新版本"
		m.state.finishedAt = time.Now().UTC()
		// SLB12-P3-11:跳过分支补 version——StatusSnapshot 内存态优先后 version
		// 此前从有值退化为空串,状态端点数据不自洽。
		m.state.version = currentCRSVersion()
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	m.state.version = tag
	m.mu.Unlock()

	var installErr error
	_ = runWithInTaskRetry(func() error {
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
	if installErr != nil {
		// F-L2-68-01：同上方 fetch 分支——demote 在途中止落 skipped（不 restore：
		// 从节点不回滚不 reload，保持只读不变量）。
		if runCtx.Err() != nil && !updateRunStillMaster() {
			m.setStage(CRSStatusSkipped, "节点已降级为从节点，终止 CRS 更新")
			return
		}
		m.fail(installErr, true)
		m.advanceSlotIfAuto(trigger)
		return
	}
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET version=?, updated_at=datetime('now'), update_status='success', message='', finished_at=datetime('now'), consecutive_failures=0, "+versionTableSlotAdvanceSQL+" WHERE id=1",
		tag, trigger, versionTableNextSlot("security_crs_version", time.Now().UTC()),
	); err != nil {
		Logf("error", "crs update: failed to record success: %v", err)
	}
	m.rescanRuleCount()
	m.mu.Lock()
	m.state.status = CRSStatusSuccess
	m.state.message = ""
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteCRSUpdateLog("INFO", string(CRSStatusSuccess), fmt.Sprintf("CRS 已更新到 %s", tag))
	// 复审裁定 3：清理 M24 之前版本残留在 live 目录的瞬态工件（仅更新成功后执行）
	m.cleanupLegacyCRSTransient()
}

// advanceSlotIfAuto 落定推进排程槽（排程槽生命周期，2026-10-11 用户裁定）：
// ①仅 auto 触发——手动触发不得改变下一次预约执行时间；②仅当现存槽为空或
// 已过期——未来槽（配置变更/自定义槽）不被回拨污染。
// 此前失败不推进：过期槽经 NextSlotFn 步进（coveredSlotStepPast）每 tick 重算
// 永远领先 now 一步，due 判定窗口零宽，排程永久停摆（10-06 失败后停摆 5 天实证）。
func (m *CRSUpdateManager) advanceSlotIfAuto(trigger string) {
	if trigger != "auto" {
		return
	}
	advanceVersionSlotIfDue("security_crs_version")
}

// advanceVersionSlotIfDue 版本表槽推进共享实现（CRS/IP2Region 同构）：空或过期
// 才写紧邻下一排程槽；auto_update=0 不动（IIF 兜底）。
func advanceVersionSlotIfDue(table string) {
	var cur string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE id=1`).Scan(&cur); err != nil {
		return
	}
	if cur != "" {
		if t, err := time.ParseInLocation(crsTimeLayout, cur, time.UTC); err == nil && t.After(time.Now().UTC()) {
			return // 未来槽不污染
		}
	}
	if _, err := db.DB.Exec(`UPDATE `+table+` SET next_update=IIF(auto_update=1, ?, next_update) WHERE id=1`,
		versionTableNextSlot(table, time.Now().UTC())); err != nil {
		Logf("warn", "推进排程槽失败（%s）: %v", table, err)
	}
}

func (m *CRSUpdateManager) fail(cause error, restore bool) {
	if restore {
		m.restoreBackup()
		// CRS25-8(第 25 轮审计):reloader nil 守卫(与 crsinstall.go:314 同口径)——
		// 测试注入 nil reloader 时 panic。
		if m.reloader != nil {
			if err := m.reloader(); err != nil {
				Logf("error", "crs update: reload after restore failed: %v", err)
			}
		}
	}
	// 连续失败计数 +1（失败趋势可观测；操作审计由 run 的 defer 单记——
	// U1-P3-2 收敛后内联首败审计已撤）。
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='failed', message=?, finished_at=datetime('now'), consecutive_failures=consecutive_failures+1 WHERE id=1",
		cause.Error(),
	); err != nil {
		Logf("error", "crs update: failed to record failure: %v", err)
	}
	m.mu.Lock()
	m.state.status = CRSStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteCRSUpdateLog("ERROR", string(CRSStatusFailed), cause.Error())
}

// downloadTarballLogged 包装下载 seam 写更新日志（R57）：开始行由下载函数的
// (0, total) 开始信号触发，携带完整来源 URL（含 GitHub 加速代理前缀，代理
// 取值经 github_proxy_url 白名单，历史硬编码 ghfast.top 已废弃），
// Content-Length 已知时附预计大小；进度行经节流闭包按 10%（总量已知）/5MB
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
func (m *CRSUpdateManager) CancelRunning() bool {
	m.mu.Lock()
	cancel := m.runCancel
	running := m.running
	m.mu.Unlock()
	if cancel == nil || !running {
		return false
	}
	cancel()
	return true
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
