package services

// 任务引擎接线（v2.0 四类型标准）：Kind 决定调度/记录/日志——零 flag。
// 注册全集 19：定时(5)/常驻(3)/循环(10)/触发(1)——以 DescribeAll 输出为准。
// 触发(1)：仅手动/代码触发
// 默认调度关闭——入队时唤醒，全部终态自动停。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// taskEnginePtr 全局引擎代际。启动/关停与后台 goroutine（角色对账、集群
// 翻转、证书唤醒、autoban 等）并发访问——裸指针在 StopTaskEngine 置 nil
// 与读者之间构成数据竞争，改用原子指针（读者要么拿到旧代，要么拿到 nil）。
var taskEnginePtr atomic.Pointer[taskengine.Engine]

// configLoadRerun 系统配置载入手动重载钩子（main 注入：DB 渲染→强制应用）。
// operator 透传：手动重载归因操作者，启动 BootSync 传空。
var configLoadRerun func(operator string) error

// SetConfigLoadRerun 注入手动重载实现。
func SetConfigLoadRerun(fn func(operator string) error) { configLoadRerun = fn }

// B（后裁定·完全标准化）：常驻服务真实生命周期挂钩——daemon Run
// start→阻塞→deferred stop，调度开关/角色翻转即真实启停服务。
var (
	syncLifecycleStart, syncLifecycleStop                 func()
	syncLifecycleHalted                                   func() bool
	syncLifecycleResume                                   func()
	certIssuanceLifecycleStart, certIssuanceLifecycleStop func()
)

// SetSyncLifecycleHooks 注入集群同步真实启停（main: syncService.Start/Stop）。
func SetSyncLifecycleHooks(start, stop func()) { syncLifecycleStart, syncLifecycleStop = start, stop }

// SetSyncLifecycleHaltedProbe 注入同步子状态只读探针；nil 表示无状态镜像。
func SetSyncLifecycleHaltedProbe(probe func() bool) { syncLifecycleHalted = probe }

// SetSyncLifecycleResumeHook 注入同步服务复活入口（main: syncService.Resume）。
// 「Halted 的同步服务必须能被自愈链重新拉起」——Start 对 Halted 是 no-op，
// 只有 Resume 会重建循环；两条入口必须成对注入（halting probe 判据 + resume 动作）。
func SetSyncLifecycleResumeHook(resume func()) { syncLifecycleResume = resume }

// resumeHaltedSyncLifecycle 在降级收尾复活 Halted 的同步服务：只有探针明确
// 报告 Halted 才调用（Resume 对健康态是 no-op，但避免无谓抖动）。探针/入口
// 任一未注入即跳过（测试/未装配形态）。
func resumeHaltedSyncLifecycle() {
	if syncLifecycleHalted == nil || syncLifecycleResume == nil || !syncLifecycleHalted() {
		return
	}
	syncLifecycleResume()
}

// SetCertIssuanceLifecycleHooks 注入证书签发真实启停（main: lifecycle.StartACME/StopACME）。
func SetCertIssuanceLifecycleHooks(start, stop func()) {
	certIssuanceLifecycleStart, certIssuanceLifecycleStop = start, stop
}

// certIssuanceStartDeferred 导入窗口内被延迟的证书生命周期启动意图：常驻
// cert-issuance 的 Run 体（异常退出有界重拉/角色对账 SetRole(true)）在导入
// 期间启动会把已排空的 CA 队列重新打开（StartACME→queue.Start→恢复部署
// 重试）并与导入事务并发写库。屏障期只记意图，导入结束补启动；若该代 Run
// 已退出，stop 包装清除意图（不得为无主 Run 拉起服务）。
var certIssuanceStartDeferred atomic.Bool

// startCertIssuanceLifecycle 证书签发常驻 Run 的生命周期启动（导入屏障门）。
// 屏障活跃时只登记意图（导入结束由 EndConfigImportHold 兑现）；「判定活跃 →
// 登记意图」之间的屏障退出由 takeDeferredCertIssuanceStartIfReleased 兜底：
// 若 EndConfigImportHold 已在这两步之间读完意图并退出，本代立即取走意图自行
// 启动——否则意图永不兑现，CA 队列/部署重试/签发 worker 整代不启动。
func startCertIssuanceLifecycle() {
	if !configImportHoldActive() {
		startCertIssuanceLifecycleIgnoringHold()
		return
	}
	if configImportHoldDeferHook != nil {
		configImportHoldDeferHook()
	}
	certIssuanceStartDeferred.Store(true)
	// 屏障可能在本次判定与登记之间退出（EndConfigImportHold 已读完意图并
	// 退出）：取走意图并自启动，否则该意图永无人兑现。
	if takeDeferredCertIssuanceStartIfReleased() {
		startCertIssuanceLifecycleIgnoringHold()
	}
}

// startCertIssuanceLifecycleIgnoringHold 直接启动（跳过屏障判定）：屏障不在场
// 的正常路径与 EndConfigImportHold 兑现延迟意图共用。
func startCertIssuanceLifecycleIgnoringHold() {
	if certIssuanceLifecycleStart != nil {
		certIssuanceLifecycleStart()
	}
}

// stopCertIssuanceLifecycle 生命周期停止：同时作废延迟启动意图（该代 Run
// 已退出，兑现一个已无主的启动会让 ACME 队列留在无人停止的运行态）。
func stopCertIssuanceLifecycle() {
	certIssuanceStartDeferred.Store(false)
	if certIssuanceLifecycleStop != nil {
		certIssuanceLifecycleStop()
	}
}

// daemonLifecycleRun 常驻生命周期包装：start→阻塞 ctx→stop（nil 挂钩=测试
// 环境空载体回退）。stop 恒执行（deferred）：不仅正常停止/角色翻转，start
// 半启动后 panic 也必须清理（runGuarded 会判定 daemon 已死——已启动的 ACME
// 队列/同步循环不得残留运行，否则翻转后仍写库/签发）。

func daemonLifecycleRun(rc taskengine.RunContext, start, stop func()) error {
	if stop != nil {
		defer stop()
	}
	if start != nil {
		start()
	}
	<-rc.Ctx.Done()
	return nil
}

// certJobsActiveFn 测试缝；生产=certJobsActive。
var certJobsActiveFn = certJobsActive

// TaskEngine 返回全局引擎实例（未初始化返回 nil——测试环境）。
func TaskEngine() *taskengine.Engine { return taskEnginePtr.Load() }

// SetTaskEngineForTest 测试替换全局引擎；生产装配只能走 InitTaskEngine。
// 用于需要独立描述符集合的 API 行为测试，禁止用于绕过 Register 校验。
func SetTaskEngineForTest(te *taskengine.Engine) { taskEnginePtr.Store(te) }

// reconcileTaskEngineRole 把引擎角色对齐到 DB 单源角色。
//
// 引擎角色此前只在 InitTaskEngine 播种一次：播种连续失败即 SetRole(false)，
// 若 DB 实为主节点则形成「DB=主/引擎=从」的进程内半主半从——master-only
// 任务全部静默停摆，且再次 Promote 返回 ErrAlreadyMaster 无法自愈。本函数
// 由独立 startRoleReconciler 每 60s 调用（不是 config-watchdog
// 任务体），使角色成为可收敛的 DB 投影，且不受用户停止看门狗影响。
//
// 并发安全：与 ClusterService.Promote/BecomeSlave 的 roleMu 串行——两处
// 翻转都在持 roleMu 时完成「DB 更新 + SetRole」。不串行则对账可能读到翻转
// 前的旧角色，并在降级落定后把引擎重新升主（从节点启动 master-only daemon
// 写库）。锁序 roleMu → 引擎内部锁，与翻转路径同序，无反向获取。
func reconcileTaskEngineRole() {
	reconcileTaskEngineRoleFor(TaskEngine())
}

// reconcileTaskEngineRoleFor 限定到调用方持有的引擎代际，防止旧 reconciler
// 在快速重建后误操作新一代实例。
func reconcileTaskEngineRoleFor(te *taskengine.Engine) {
	database := db.DB
	if database == nil || te == nil {
		return
	}
	instances := clusterServicesFor(database)
	for _, instance := range instances {
		instance.roleMu.Lock()
	}
	defer func() {
		for index := len(instances) - 1; index >= 0; index-- {
			instances[index].roleMu.Unlock()
		}
	}()
	roleMaster, err := RoleOf(context.Background(), database)
	if err != nil {
		Logf("warn", "任务引擎角色对账读取失败（下一轮看门狗重试）: %v", err)
		return
	}
	if roleMaster == te.IsMaster() {
		return
	}
	Logf("warn", "任务引擎角色与数据库不一致（数据库主节点=%v，引擎主节点=%v），按数据库修正",
		roleMaster, te.IsMaster())
	// 只翻引擎半边（旧实现仅 SetRole）会把旧角色时代的快照缓存/分区上报/
	// 看门狗漂移态带入新角色：DB=从/引擎=主 修正后不清缓存，后续再升主会
	// 沿用降级期缓存（Promote 注释登记过同一风险）；漂移态不复位则新角色的
	// 首轮看门狗按旧基线误报。数据/状态半边与 Promote/BecomeSlave 共用单源
	// （applyRoleSideEffects + clearAppliedTopologyState）。
	for _, instance := range instances {
		instance.applyRoleSideEffects()
	}
	if len(instances) == 0 {
		// 未登记 ClusterService（测试/嵌入形态）：快照缓存以库句柄为键直接
		// 失效；分区上报缓存无实例可清（该形态不存在上报面），漂移态仍须
		// 同源复位。
		clusterSnapshotCaches.Delete(database)
		ResetConfigDrift()
	}
	// 旧拓扑的节记账/WAF 文件态复位：翻转路径在事务内完成，对账路径库角色
	// 已是目标值，此处幂等补做（失败留痕；下一次升主/切从会重做同一清理）。
	if err := clearAppliedTopologyState(context.Background(), database); err != nil {
		Logf("warn", "任务引擎角色对账：旧拓扑记账清理失败（下一次角色翻转会重做）: %v", err)
	}
	te.SetRole(roleMaster)
	// 方向性收尾与翻转路径同源：升主重建爬虫快照 + 任务面收尾（业务驱动
	// 任务对齐 + 规则库首槽重装）；切从恢复拉取调度。
	if roleMaster {
		rebuildCrawlerSnapshotAfterPromote()
		applyPromoteTaskSideEffects()
		return
	}
	restoreClusterSyncSchedulingAfterDemote()
}

// mustRegisterTask 装配期统一注册入口：描述符非法属于静态装配错误，
// 必须启动即响亮失败，不得静默少一个任务。
func mustRegisterTask(te *taskengine.Engine, d taskengine.Descriptor) {
	// 业务驱动任务的调度开关在任务页只读（唯一事实源是业务表）：引擎停调日志
	// 的恢复入口提示按 businessTaskDrivers 唯一清单注入，引擎层因此不必依赖
	// 业务清单，也不会在调度层出现第二份「业务驱动」ID 表。
	if d.LoopRecoveryHint == "" && IsBusinessDrivenTask(d.ID) {
		d.LoopRecoveryHint = "对应业务页保存一次自动更新/备份设置（任务页调度开关对该任务只读），或重启进程"
	}
	if err := te.Register(d); err != nil {
		panic(fmt.Sprintf("taskengine: %s 注册失败: %v", d.ID, err))
	}
}

// （coveredSlotStepPast/slotCoveredByRun/crsNextSlotAware/ip2regionNextSlotAware 已退役——
// 排程槽生命周期 2026-10-11：失败落定落库推进，NextSlotFn 纯读库。）

// interruptedUpdateStatusFamilies 持久化「更新中」活动态的四族。表名只接受
// 包内常量；taskID 必须是**注册任务 ID**（告警经 TaskLogfWarn 写入该任务的
// 任务日志，未注册 ID 会产生无人查看的游离日志文件）。
//   - 版本表族（id=1 单行）：活动态词表由 active 给出；
//   - 源表族（多行，状态列逐行）perSourceRow=true：活动态恒为包级常量
//     sourceUpdateStatusRunning（谓词单源，族表不另发词表，active 留 nil）。
//
// 源表此前完全无启动归一：主节点靠「槽未推进→首个 tick 重跑覆盖」自愈，但
// 同一残留落到从节点时该任务不运行（RunsOn=RoleMasterOnly），行会永久滞留
// 「更新中」（与任务视图自相矛盾）。主节点侧归一仍幂等（重跑轮会覆盖 failed）。
var interruptedUpdateStatusFamilies = []struct {
	table  string
	taskID string
	// active 版本表族的活动态词表；perSourceRow=true 时忽略（见上）。
	active func(string) bool
	// perSourceRow=true 表示状态列分散在多行源表（无 id=1 单行约定），
	// 归一按行集执行；否则按版本表单行 id=1 归一。
	perSourceRow bool
}{
	{table: "security_crs_version", taskID: "crs", active: IsActiveCRSStatus},
	{table: "security_ip2region_version", taskID: "ip2region", active: IsActiveIP2RegionStatus},
	{table: "security_threat_sources", taskID: "threat", perSourceRow: true},
	{table: "security_crawler_sources", taskID: "crawlerbot-update", perSourceRow: true},
}

// sourceUpdateStatusRunning 源表族唯一活动态（v2.3.x 写侧只写 running）：
// 状态词表与归一的 WHERE 谓词共用，禁止两处各写字面量。
const sourceUpdateStatusRunning = "running"

// normalizeInterruptedUpdateStatuses 把上次进程退出时残留的活动态归一为
// failed：活动态只在本进程更新运行期间成立，进程重建后它既无真实执行也无
// 终态——不归一则规则库页与任务视图恒显「更新中」（运行/取消按钮失效），
// 直到下一个排程槽才自愈。UPDATE 带旧值条件，避免与并发终态写相互覆盖。
func normalizeInterruptedUpdateStatuses() {
	if db.DB == nil {
		return
	}
	for _, family := range interruptedUpdateStatusFamilies {
		if family.perSourceRow {
			normalizeInterruptedSourceStatusRows(family.table, family.taskID)
			continue
		}
		row, ok, err := versionTableStatusRowOf(family.table)
		if err != nil || !ok || !family.active(row.status) {
			continue
		}
		res, err := db.DB.Exec(`UPDATE `+family.table+
			` SET update_status='failed', message='（进程重启回收）', finished_at=datetime('now') WHERE id=1 AND update_status=?`,
			row.status)
		if err != nil {
			Logf("warn", "任务状态归一失败（%s 残留活动态 %s）: %v", family.taskID, row.status, err)
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		TaskLogfWarn(family.taskID, "failed", "上次更新在进程退出时中断（残留状态 %s），已归一为 failed", row.status)
		Logf("warn", "任务状态归一: %s 残留活动态 %s 已归一为 failed（进程重启回收）", family.taskID, row.status)
	}
}

// normalizeInterruptedSourceStatusRows 按行集归一源表族的活动态（源表无 id=1
// 单行约定，状态列逐行写）。幂等：WHERE 只命中活动行，无命中即静默。
func normalizeInterruptedSourceStatusRows(table, taskID string) {
	res, err := db.DB.Exec(`UPDATE `+table+
		` SET update_status='failed', message='（进程重启回收）', finished_at=datetime('now') WHERE update_status=?`,
		sourceUpdateStatusRunning)
	if err != nil {
		Logf("warn", "任务状态归一失败（%s 残留活动行）: %v", taskID, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return
	}
	TaskLogfWarn(taskID, "failed", "上次更新在进程退出时中断，%d 个源的残留「更新中」状态已归一为 failed", n)
	Logf("warn", "任务状态归一: %s %d 个源残留活动态已归一为 failed（进程重启回收）", taskID, n)
}

// normalizeUnregisteredThreatSourceSlots 清空威胁源表里「注册表外」启用行的
// 排程槽（幂等、最小破坏：只清 next_update，不改 update_enabled/url/内容）。
// 注册表外的行不会被 threatDueSources 处理，其槽没有任何推进写点；一旦过期，
// 「启用源最早槽」就恒钉在该值上，威胁库自动更新静默停摆（槽域 ⊋ 运行域）。
// 读侧与写侧（首槽武装、时区重排）都已按注册表名收窄，本函数让数据面同步
// 收敛且不再被同一次装配的武装反向补回；未来若该名重新进入注册表，行以
// 「空槽=到期」语义自然恢复运行。
func normalizeUnregisteredThreatSourceSlots() {
	names := threatSourceRegistryNames()
	if len(names) == 0 {
		return
	}
	clause, args := sourceNameSetClause("name", names, true)
	res, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=NULL
		WHERE update_enabled=1 AND NULLIF(next_update,'') IS NOT NULL`+clause, args...)
	if err != nil {
		Logf("warn", "威胁源表注册表外启用行槽清理失败（不影响调度读侧收窄）: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		Logf("warn", "威胁源表: %d 个注册表外的启用行排程槽已清空（这些行不会被更新任务处理，保留槽会让自动更新停摆）", n)
	}
}

// InitTaskEngine 建引擎、恢复孤儿运行、注册全部 19 任务并启动默认循环。
// 非幂等——调用方保证单次装配；重复调用前须先
// StopTaskEngine（否则旧 scheduleLoop goroutine 泄漏、双引擎双写 task_runs）。
// 测试环境须先 db.Initialize。
func InitTaskEngine(watchdogAdminURL, runtimeLogFile string) *taskengine.Engine {
	taskengine.SetLocation(CurrentLocation())
	logsDir := "/app/logs"
	if runtimeLogFile != "" {
		logsDir = filepath.Dir(runtimeLogFile)
	}
	tasksLogDir := filepath.Join(logsDir, "tasks")
	if err := os.MkdirAll(tasksLogDir, 0755); err != nil {
		Logf("error", "任务日志目录创建失败（%s）: %v", tasksLogDir, err)
	}
	taskengine.SetLogDir(tasksLogDir)
	taskengine.SetTaskLogSizeBytesFn(getTaskLogSizeBytes)
	// 以暂停 tick 形态建引擎——BootSync（startup:config-load）
	// 完成前面板装配期的周期/定时任务不得抢跑（配置未加载即执行首轮）；下方
	// RunBootSyncTasks 之后 ResumeScheduling 恢复调度。
	te := taskengine.NewEngine(taskengine.Options{StartPaused: true})
	taskEnginePtr.Store(te)
	// 角色种子（v2.0 角色门前置）：按 DB 角色初始化——从节点不瞬启
	// master-only daemon（否则 boot 行噪音：启动→SetRole 停止）。
	// 修复：曾在此前多建一个引擎（种子落在被弃实例上失效+泄漏）。
	// 读失败 warn+重试一次；仍失败按 fail-closed 从节点启动——
	// 不得因读错误保持 NewEngine 默认主节点（会拉起 master-only daemon 并
	// 放开写面）。并发角色翻转由后续 SetRole 正常收敛。
	var roleMaster bool
	roleErr := errors.New("数据库未初始化")
	for attempt := 0; attempt < 2 && db.DB != nil; attempt++ {
		if roleMaster, roleErr = RoleOf(context.Background(), db.DB); roleErr == nil {
			break
		}
	}
	if roleErr != nil {
		Logf("warn", "任务引擎角色种子读取失败（已重试一次），按从节点启动（fail-closed）: %v", roleErr)
		te.SetRole(false)
	} else {
		te.SetRole(roleMaster)
	}
	_ = te.RecoverOrphans()
	// 持久化「更新中」态同样属于上次进程的生命周期——启动期归一为 failed，
	// 否则规则库页与任务视图恒显更新中（运行/取消按钮失效）。
	// 仅主节点：本函数语义是「上次**本进程**执行被中断」，从节点从不运行这些
	// 任务（RunsOn=RoleMasterOnly），其版本行是主端镜像——本地改写会把主端
	// 仍在进行中的状态伪造成「失败（进程重启回收）」，且版本行不进节哈希，
	// 假 failed 会保持到下一次真实快照应用才被纠正。角色读失败(roleMaster=
	// false)同样跳过，与 fail-closed 从节点种子一致。
	if roleMaster {
		normalizeInterruptedUpdateStatuses()
		// 槽域与运行域收敛（数据面）：注册表外启用行的槽没有任何推进写点，
		// 保留会在过期后让「最早槽」恒钉过去。读侧已收窄，这里让库值同步。
		normalizeUnregisteredThreatSourceSlots()
	}

	// ============ 循环（10）============

	// 看门狗：60s 一致性检查（漂移/恢复+小时级心跳——一致轮不逐轮记录）
	watchdogAdminURLValue = watchdogAdminURL
	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "config-watchdog",
		Family:      "system",
		Name:        "配置漂移看门狗",
		Description: "每 60 秒比对运行中 Caddy 配置与数据库期望配置，漂移时面板横幅告警（恢复经手动重启）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 60 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			// 角色对账已移至独立 startRoleReconciler（不受用户停止看门狗影响）。
			// 整轮未判定（Caddy 不可达/规则读取失败）必须落 failed——
			// 直接透传看门狗错误，引擎通用行为不变。rc.Ctx 传入（降级/停机
			// 取消在途轮——不覆写 BecomeSlave 复位后的漂移态）。
			return WatchdogCheckOnce(rc.Ctx)
		},
	})

	// 运行日志清理：每日
	logFile := runtimeLogFile
	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "log-cleanup",
		Family:      "system",
		Name:        "日志清理与轮转",
		Description: "清理超保留期的应用日志轮转副本（app.log.*）；统一清理任务日志（tasks/*.log：仅保留期删除，尺寸滚动由写入侧统一执行）；并按存活规则清单清理已删除规则的访问日志（logs/rules/*，含轮转副本）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			// 清理失败必须进 task_runs failed 与任务日志失败行，摘要不得称
			// 「完成」（同族 audit-retention / security-events-retention /
			// metrics-orphan-cleanup 均失败上抛）。此前恒 return nil —— daemon
			// 停机时 waf-audit 兜底轮转失败、单文件删除失败全部只打应用日志。
			res, line := logCleanupRound(rc.Ctx, logFile)
			if err := res.Err(); err != nil {
				TaskLogfWarn("log-cleanup", "cleanup", "%s", line)
				return err
			}
			TaskLogf("log-cleanup", "cleanup", "%s", line)
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "audit-retention",
		Family:      "system",
		Name:        "审计日志保留清理",
		Description: "按「审计保留月数」配置删除 audit 库过期操作日志（基础设置可调）；并清理 90 天前的任务运行历史（task_runs）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			// 传任务 ctx——Stop(cancel) 可在大批量分批删除中途生效（批间
			// 复检），且取消后不再启动任务历史删除，不让清理拖过关停预算。
			auditDeleted, runsDeleted, err := auditRetentionRound(rc.Ctx)
			// 失败传播：两段清理任一失败都让 task_runs 落 failed，且摘要行
			// 不得称「清理完成」（失败轮谎报完成会把排障方向带偏）。
			if err != nil {
				TaskLogfWarn("audit-retention", "cleanup", "清理未完成：审计日志已删除 %d 条、任务运行历史已删除 %d 行后中止，错误：%v", auditDeleted, runsDeleted, err)
				return err
			}
			TaskLogf("audit-retention", "cleanup", "清理完成：审计日志 %d 条、任务运行历史 %d 行（无过期数据时为 0）", auditDeleted, runsDeleted)
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "security-events-retention",
		Family:      "system",
		Name:        "安全事件保留清理",
		Description: "按保留期配置删除 metrics 库中过期的安全事件记录",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			// 传任务 ctx——Stop(cancel) 可在大批量首遍中途生效。
			// 清理失败必须让 task_runs 落 failed，不得恒成功。
			retention, err := SecurityEventsRetentionCleanupDetail(rc.Ctx)
			// 失败轮不得写「清理完成」——task_runs 已落
			// failed，任务日志称完成会把排障方向带偏。
			if err != nil {
				TaskLogfWarn("security-events-retention", "cleanup", "安全事件保留清理失败：本轮已删除事件 %d 条 · 聚合/高水位 %d 行后中止（保留期与条数上限），错误：%v", retention.Events, retention.Aggregates(), err)
				return err
			}
			// 按构成披露：聚合/高水位删除不计入事件数时，仅报「删除 N 条事件」
			// 会让停摆后首次清理显示 0（运维误判保留策略未生效）。
			TaskLogf("security-events-retention", "cleanup", "安全事件保留清理完成：删除事件 %d 条 · 聚合 %d 行 · 被攻击目标聚合 %d 行 · 分钟状态键 %d 个（保留期与条数上限，无过期为 0）", retention.Events, retention.Rollup, retention.TargetRollup, retention.Highwater)
			if retention.AgeDeferred {
				TaskLogf("security-events-retention", "cleanup", "年龄裁剪本轮跳过：等待预聚合（大屏窗口）回填完成后执行，过期原始事件暂不删除")
			}
			// 行帽延后必须可见：否则运维会把「行数未收敛」当成清理失效。
			if retention.RowCapDeferred {
				TaskLogf("security-events-retention", "cleanup", "行帽裁剪本轮跳过：等待预聚合（大屏窗口）回填完成后执行，原始事件暂不按行数上限裁剪")
			}
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "metrics-orphan-cleanup",
		Family:      "system",
		Name:        "孤儿规则指标清理",
		Description: "删除 metrics 库中已删除规则的残留历史指标——规则删除时清理失败的兜底（操作审计留痕）与有界重试收敛，每轮限量分批",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			// 清理失败必须让 task_runs 落 failed，不得恒成功；
			// 有界=单轮最多清理 metricsOrphanPurgeRulesPerRun 个规则，余量下轮收敛。
			deletedRules, err := PurgeOrphanMetricsHistory(rc.Ctx)
			// 失败轮不得写「清理完成」（task_runs 已落 failed）。
			if err != nil {
				TaskLogfWarn("metrics-orphan-cleanup", "cleanup", "孤儿规则指标清理失败：本轮已清理 %d 个规则后中止，错误：%v", deletedRules, err)
				return err
			}
			TaskLogf("metrics-orphan-cleanup", "cleanup", "孤儿规则指标清理完成：删除 %d 个规则的历史指标（无残留为 0）", deletedRules)
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "crawlerbot-update", Family: "security", Name: "爬虫地址更新",
		Description: "定时更新 Google/OpenAI/Bing/360 官方爬虫 IP 段（security_crawler_sources 独立源表）→ security_ip_lists 系统名单原子快照 + wafiplist .fast 预编译加速；主节点执行，从节点经集群快照同步",
		Category:    "安全防护",
		Kind:        taskengine.KindScheduled,
		RunsOn:      taskengine.RoleMasterOnly,
		Cancelable:  true,
		NextSlotFn: func() time.Time {
			if !CrawlerAutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(earliestCrawlerNextUpdate())
		},
		EnabledFn: func() bool { return CrawlerAutoUpdateEnabled() },
		Run: func(rc taskengine.RunContext) error {
			return GetCrawlerUpdateManager().RunUpdate(rc.Ctx, rc)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "cert-renewal-scan", Family: "certificates", Name: "证书续期扫描",
		Description: "扫描全部证书配置的到期时间，临期证书自动入队续签；入队时唤醒 CA 等待补扫",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			// 长跑期间 StopTaskEngine 可能把全局置 nil；闭包内固定句柄，
			// 收尾调用不会 nil 解引用。
			te := TaskEngine()
			result := CertRenewalScanOnce()
			// 入队即唤醒 CA 等待补扫（默认调度关闭）。走 RearmLoop
			// 有活唤醒——仅在确有在途任务时越过「已停止」态，不再无条件
			// StartLoop（避免把用户手动停止的调度隐式打开）。
			if te != nil {
				te.RearmLoop("cert-waiting-ca", certJobsActiveFn())
			}
			return result
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "cert-reconcile", Family: "certificates", Name: "证书状态对账",
		Description: "核对证书文件与数据库状态一致性，修复中断任务残留的中间态",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { return CertReconcileOnce(rc.Ctx) },
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "cert-manual-poll", Family: "certificates", Name: "手动证书到期巡检",
		Description: "每 10 分钟检查手动上传证书的过期/临期并按日去重告警",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 10 * time.Minute },
		// 巡检读失败上抛（task_runs 失败终态），不再恒 return nil。
		Run: func(rc taskengine.RunContext) error { return CertManualCheckOnce() },
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "cert-waiting-ca", Family: "certificates", Name: "CA 等待补扫",
		Description: "证书任务在途时的兜底补扫：CA 冷却到期重排、滞留 queued 重入队、断链部署重试重建。默认调度关闭——续期扫描入队时自动开启，全部终态自动停止",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 30 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			te := TaskEngine()
			if !certJobsActiveFn() {
				// 全部终态——自动关闭调度（回到默认关闭态）。
				// StopLoop 后复检——首查（T0）到停调度
				// 之间的入队若经入队侧 StartLoop 先落地，会被本次 StopLoop
				// 覆盖成「任务活跃但调度已停」死态；复检捕获则重新拉回（复检
				// 之后的新入队由入队侧 StartLoop 承担，窗口闭合）。
				if te != nil {
					te.StopLoop("cert-waiting-ca")
				}
				if certJobsActiveFn() {
					if te != nil {
						te.RearmLoop("cert-waiting-ca", true) // 确有新活才越过停止态
					}
					return nil
				}
				TaskLogf("cert-waiting-ca", "idle", "证书任务全部终态，自动停止补扫")
				// 审计项：用户显式开启该任务时，本轮自停会覆盖引擎内存
				// loopEnabled，但 task_loop_prefs 仍记 enabled=1——重启后按偏好
				// 复活、下一轮又因无活自停（空转）。自停即把偏好同步写回关闭，
				// 并留一行说明；证书任务入队会经 RearmLoop(hasWork=true) 越过
				// 停止态自动唤醒，不损失补扫能力。仅在偏好行确为开启时写
				// （无记录=默认关闭，不新建行；业务驱动任务不适用本任务）。
				if prefs := loadTaskLoopPrefs(); prefs["cert-waiting-ca"] {
					if err := RecordTaskLoopPref("cert-waiting-ca", false); err != nil {
						TaskLogfWarn("cert-waiting-ca", "idle", "写回调度偏好失败（重启后可能空转一轮）：%v", err)
					} else {
						TaskLogf("cert-waiting-ca", "idle", "已把用户开启的调度偏好同步回关闭：无在途证书任务；有任务入队时自动唤醒")
					}
				}
				return nil
			}
			// 三路扫描的读失败上抛（task_runs 失败终态）——此前恒 return nil，
			// 持续性读故障下证书自动恢复停摆而任务监控全绿。
			// ctx 传入：本轮窗口内的降级/取消由逐写点门收口（从节点零写）。
			return CertWaitingCATickOnce(rc.Ctx)
		},
	})

	// ============ 常驻（3）============

	// 安全事件摄取：IPC 主路径（Caddy 写侧经 Unix socket 直接投递）+ 旧
	// audit.log 存量跟随 + fallback spool 补采，自管理 2s 循环（引擎仅管生命周期）
	mustRegisterTask(te, taskengine.Descriptor{
		ID:          securityEventsIngestionTaskID,
		Family:      "system",
		Name:        "安全事件采集",
		Description: "摄取安全事件为安全日志（安全总览/事件页的数据源）：IPC 主路径入库，另跟随旧审计日志存量与 fallback spool 待补采文件",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run:         func(rc taskengine.RunContext) error { return runIngestionLoop(rc.Ctx) },
	})

	// 证书签发：daemonLifecycleRun 真实生命周期挂钩（StartACME/StopACME——
	// 队列+证书 worker+active 指针随调度开关/角色启停；幂等守卫吸收角色链
	// 双调用）。RunsOn=MasterOnly：从节点禁签发——daemon 不在从节点启动
	// （promote 经 SetRole 自动拉起），状态显示实态（从节点=空闲）。
	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "cert-issuance",
		Family:      "certificates",
		Name:        "证书签发",
		Description: "ACME 证书签发队列——含新签发与续签（由证书任务队列调度，活跃任务显示为动态行；仅主节点运行，从节点只读镜像）",
		Category:    "证书",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleMasterOnly,
		Run: func(rc taskengine.RunContext) error {
			// B 完全标准化：真实生命周期挂钩（StartACME/StopACME 语义——队列+
			// 证书 worker+active 指针；幂等守卫吸收角色链双调用）。启动经导入
			// 屏障门（导入期间延迟，结束后补启动）。
			return daemonLifecycleRun(rc, startCertIssuanceLifecycle, stopCertIssuanceLifecycle)
		},
	})

	// 集群同步：真实生命周期常驻（2026-10-03 裁定：主从两角色纳入引擎统一
	// 生命周期，状态镜像废除）。Run 体按角色分流：
	// · 从节点=同步轮询（原样——daemonLifecycleRun 挂 SyncService 起停，
	//   内部 Halted/Resume 状态机全保留，幂等守卫吸收 lifecycle 直调与
	//   daemon 挂钩的双调用）；
	// · 主节点=服务面巡检（真实工作体——节点在线/版本滞后巡检，日志零
	//   噪音口径见 cluster_masterserving.go）。
	// RunsOn=RoleAny + RestartOnRoleFlip：两角色同启停语义（调度开关/引擎
	// 生命周期一致）；角色翻转换代重启使 Run 分支与角色同步切换；boot/
	// 停止/成功/失败行与 tasks/cluster-sync.log 两角色共写（各节点本地文件）。
	mustRegisterTask(te, taskengine.Descriptor{
		ID:                "cluster-sync",
		Family:            "cluster",
		Name:              "集群同步",
		Description:       "集群同步服务：从节点按配置间隔轮询主节点快照并增量回放；主节点巡检集群服务面（节点在线/版本滞后）。启停真实生效",
		Category:          "集群",
		Kind:              taskengine.KindDaemon,
		RunsOn:            taskengine.RoleAny,
		RestartOnRoleFlip: true,
		Run:               clusterSyncDaemonRun,
		StatusFn:          clusterSyncStatusMirror,
	})

	// ============ 定时（5）============

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新",
		Description: "每日从 USTC/FireHOL/ET 三源下载恶意 IP 名单，聚合去重后写入威胁库文件并同步从节点——引用名单的安全策略据此拦截",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			if !ThreatAutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(earliestThreatNextUpdate())
		},
		EnabledFn: func() bool { return ThreatAutoUpdateEnabled() }, // 业务开关门（关=已停止——展示+调度面跳过）
		StatusFn: func() string {
			if m := GetThreatUpdateManager(); m != nil && m.StatusSnapshot().Running {
				return "running"
			}
			return ""
		},
		CancelHook: func() bool { return GetThreatUpdateManager() != nil && GetThreatUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			m := GetThreatUpdateManager()
			if m == nil {
				// manager 初始化必须前置于 InitTaskEngine——曾 return nil
				// 使 due 槽落 success（装配顺序缺陷被静默吞掉，威胁库永不更新）。
				return errors.New("威胁库管理器未初始化（InitThreatUpdateManager 必须先于 InitTaskEngine）")
			}
			// 引擎已在排程槽调用——直接执行（manager 内部自带总闸/单飞/到期源筛选）
			// demote/中止语义（lastTaskOutcome=skipped）不再失真为 success——
			// 映射引擎 skipped 终态（ErrTaskSkipped 哨兵，task_runs CHECK 既有值）。
			if err := m.RunUpdate(rc.Trigger, &rc); err != nil {
				return err
			}
			if m.StatusSnapshot().Outcome == "skipped" {
				return taskengine.ErrTaskSkipped
			}
			if m.StatusSnapshot().Outcome == "cancelled" {
				// 用户取消确定性映射 cancelled 终态——manager 取消先于引擎
				// ctx 取消落定，仅靠 ctx.Err() 判定存在竞态窗（误记 success）。
				return taskengine.ErrRunCancelled
			}
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新",
		Description: "检查并更新 OWASP CoreRuleSet 规则集到最新版本（保留用户 overrides），供 WAF 拦截模式消费",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			// 同批：DB 直读不依赖管理器实例（EnabledFn 亦同源直读）——
			// 测试环境不建管理器，生产管理器初始化晚于引擎注册，管理器门会让
			// 首槽武装在窗口期读不到。开关/槽统一读单源 helper
			// （versionTableAutoUpdateEnabled/versionTableNextUpdate，nil 库与
			// 读错均 fail-closed 零值槽）。
			if !versionTableAutoUpdateEnabled("security_crs_version") {
				return time.Time{}
			}
			// 排程槽生命周期（2026-10-11 用户裁定）：纯读库——失败落定已由
			// advanceSlotIfAuto 落库推进，不再存在待步进的过期被覆盖槽
			//（coveredSlotStepPast 每 tick 重算永远领先 now 一步=零宽窗口停摆，已退役）。
			return parseUTCSlot(versionTableNextUpdate("security_crs_version"))
		},
		// 业务开关门（关=已停止——展示+调度面跳过，；DB 直读——manager
		// 未初始化窗口也正确；与 NextSlotFn 共用单源 helper）。
		EnabledFn: func() bool { return versionTableAutoUpdateEnabled("security_crs_version") },
		StatusFn: func() string {
			m := GetCRSUpdateManager()
			if m == nil || !m.IsRunning() {
				// 只采纳本进程真实在途状态：持久化活动态（进程崩溃残留/
				// 集群快照回放）不属于本进程的运行，采纳即伪造「运行中」死态。
				return ""
			}
			// 仅在途阶段映射 running——failed/skipped
			// 持久终态曾落入 running，任务监控恒显「运行中」。
			if IsActiveCRSStatus(m.StatusSnapshot().Status) {
				return "running"
			}
			return ""
		},
		CancelHook: func() bool { m := GetCRSUpdateManager(); return m != nil && m.CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			m := GetCRSUpdateManager()
			if m == nil {
				// 响亮失败（与 threat 族同构）：return nil 会让 due 槽落
				// success（装配顺序缺陷被静默吞掉，CRS 永不更新）且不推进
				// 排程槽——过期槽每 tick 重投。失败落定+任务日志行+auto
				// 推进槽（与 m.advanceSlotIfAuto 同口径）。
				TaskLogfWarn("crs", "failed", "CRS 更新管理器未初始化（InitCRSUpdateManager 必须先于 InitTaskEngine）")
				if rc.Trigger == "auto" {
					advanceVersionSlotIfDue("security_crs_version")
				}
				return errors.New("CRS 更新管理器未初始化（InitCRSUpdateManager 必须先于 InitTaskEngine）")
			}
			done, err := m.StartUpdate(rc.Trigger, &rc)
			if err != nil {
				return err
			}
			<-done
			if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusSkipped) {
				// demote 中止落 skipped 终态而非 success
				return taskengine.ErrTaskSkipped
			}
			if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusCancelled) {
				// 用户取消确定性落 cancelled（引擎 ctx 取消生效前的竞态窗
				// 不再误记 success）。
				return taskengine.ErrRunCancelled
			}
			if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusFailed) {
				return fmt.Errorf("CRS 更新失败: %s", snap.Message)
			}
			// 状态行 success 但排程槽未推进（写路径严格读排程失败，或状态行
			// 写入失败）：不得以 success 收尾——引擎会把本槽记入消费水位，该族
			// 自动更新静默停摆。按失败返回走退避重投（1s/5s/30s；连续 4 轮
			// 仍未推进由引擎停调，需在业务页重新保存或重启）。
			if serr := m.ScheduleSlotError(); serr != nil {
				return serr
			}
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "ip2region", Family: "security", Name: "IP2Region 地理库更新",
		Description: "更新 IP 地理位置离线库（xdb），供 GeoIP 地域拦截与归属地展示使用",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			// 同批：DB 直读不依赖管理器实例（与 crs 同形）。
			// 开关/槽统一读单源 helper（nil 库/读错 fail-closed 零值槽）。
			if !versionTableAutoUpdateEnabled("security_ip2region_version") {
				return time.Time{}
			}
			return parseUTCSlot(versionTableNextUpdate("security_ip2region_version"))
		},
		// 业务开关门（关=已停止——展示+调度面跳过，；DB 直读）。
		// 读库失败 fail-closed（helper 同源，与 crs/threat 同口径）。
		EnabledFn: func() bool { return versionTableAutoUpdateEnabled("security_ip2region_version") },
		StatusFn: func() string {
			// 只采纳本进程真实在途状态：DB 残留活动态（进程崩溃/快照回放）
			// 不属于本进程的运行。
			m := GetIP2RegionUpdateManager()
			if m == nil || !m.IsRunning() {
				return ""
			}
			// nil 库守卫——空状态 fail-closed。
			if db.DB == nil {
				return ""
			}
			var status string
			if err := db.DB.QueryRow("SELECT COALESCE(update_status,'') FROM security_ip2region_version WHERE id=1").Scan(&status); err != nil {
				// 读失败不得静默：状态列会回落「执行实态」，与「确实空闲」不可
				// 区分（运行按钮可点，点击由单飞 CAS 兜住），且排障无信号。
				// 按失败态转换留痕（同 taskMonitorCertJobsLogKey 范式）。
				if lvl := logStateTransition(taskIP2RegionStatusLogKey, true); lvl != "" {
					Logf(lvl, "IP2Region 更新状态读取失败（状态列按执行实态回落）: %v", err)
				}
				return ""
			}
			if lvl := logStateTransition(taskIP2RegionStatusLogKey, false); lvl != "" {
				Logf(lvl, "IP2Region 更新状态读取恢复")
			}
			// 同 CRS——仅在途阶段映射 running，
			// failed/skipped 持久终态不再失真为「运行中」。
			if IsActiveIP2RegionStatus(status) {
				return "running"
			}
			return ""
		},
		CancelHook: func() bool { return GetIP2RegionUpdateManager() != nil && GetIP2RegionUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			m := GetIP2RegionUpdateManager()
			if m == nil {
				// 响亮失败（与 threat/crs 族同构）：return nil=静默 success
				// 吞掉装配顺序缺陷，且不推进排程槽（过期槽每 tick 重投）。
				TaskLogfWarn("ip2region", "failed", "IP2Region 更新管理器未初始化（InitIP2RegionUpdateManager 必须先于 InitTaskEngine）")
				if rc.Trigger == "auto" {
					advanceVersionSlotIfDue("security_ip2region_version")
				}
				return errors.New("IP2Region 更新管理器未初始化（InitIP2RegionUpdateManager 必须先于 InitTaskEngine）")
			}
			done, err := m.StartUpdate(rc.Trigger, &rc)
			if err != nil {
				return err
			}
			<-done
			if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusSkipped) {
				// demote 中止落 skipped 终态而非 success
				return taskengine.ErrTaskSkipped
			}
			if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusCancelled) {
				// 用户取消确定性落 cancelled（与 CRS/威胁族同口径）。
				return taskengine.ErrRunCancelled
			}
			if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusFailed) {
				return fmt.Errorf("IP2Region 更新失败: %s", snap.Message)
			}
			// 状态行 success 但排程槽未推进（见 CRS 族同型说明）：按失败返回
			// 让引擎退避重投同一槽。
			if serr := m.ScheduleSlotError(); serr != nil {
				return serr
			}
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "autoban", Family: "security", Name: "自动封禁",
		Description: "按固定窗口统计 WAF 安全事件（口径可配：拦截/检测/全部），同一 IP 计数达阈值即写入「自动封禁名单」并在到期后自动解封；默认观察模式仅记录建议不封禁。计数数据源=安全事件采集提交点（仅主节点）",
		Category:    "安全防护", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return time.Minute },
		// 无 EnabledFn（2026-10-14 用户裁定）：调度唯一前提=业务启用（PUT
		// 保存联动启停+启动按库实态对齐）；挂 EnabledFn 会让域 E 调度门在
		// 调度面静默拦截，到不了 Run 体业务门（未启用空转无落痕）。启停语义
		// 全在调度开关+事件页业务开关。
		Run: func(rc taskengine.RunContext) error {
			return RunAutobanCycle(rc)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID: "auto-backup", Family: "backup", Name: "自动备份",
		Description: "按排程把全量配置打包为 lbbak 落盘 backup 目录（含 CRS/IP2Region/威胁库数据文件），保留份数自动清理",
		Category:    "备份", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly,
		NextSlotFn: func() time.Time {
			if t, ok := nextAutoBackupSlot(time.Now()); ok {
				return t
			}
			return time.Time{}
		},
		EnabledFn: func() bool { // 业务开关门（备份未启用=已停止——展示+调度面跳过）
			// 读库失败 fail-closed——曾 err!=nil||enabled
			// 把读错误报为启用。
			row, err := loadAutoBackupSettings()
			return err == nil && row.enabled
		},
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				exec := currentAutoBackupExecutor()
				if exec == nil {
					return errors.New("备份执行器未就绪")
				}
				return exec(rc.Ctx, "manual", rc.Operator, rc.RunID)
			}
			return runAutoBackupScheduled(rc.Ctx, rc.RunID)
		},
	})

	// ============ 触发（1）============

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "startup:config-load",
		Family:      "startup",
		Name:        "系统配置载入",
		Description: "启动时从数据库装载运行态：规则库（CRS 种子/对账）→ 证书文件物化 → Caddy 配置渲染与应用（失败回退最后已知正确配置）。完成前面板不监听",
		Category:    "系统",
		Kind:        taskengine.KindOneshot,
		RunsOn:      taskengine.RoleAny, // R3：BootSync 仅 RoleAny（注册期强制；启动执行面无角色语义）
		BootSync:    true,               // B1（后裁定）：启动执行=引擎同步触发（面板监听前完成）
		Run: func(rc taskengine.RunContext) error {
			// caddy-restart=Caddy 崩溃自愈 watcher 经引擎调度
			// （曾 watcher 直调执行体绕过引擎——task_runs/单飞/日志双行）。
			if rc.Trigger != "manual" && rc.Trigger != "startup" && rc.Trigger != "caddy-restart" {
				// 未知触发来源必须响亮失败：静默 return nil 会落一条 success
				// 行却零动作（silent success），与装配缺陷可观测口径相反。
				return fmt.Errorf("未知触发来源 %q", rc.Trigger)
			}
			if configLoadRerun == nil {
				return errors.New("配置重载未接线")
			}
			return configLoadRerun(rc.Operator) // 启动与手动同体（2026-09-29 裁定）；operator 归因
		},
	})

	// ============ 手动触发语义 + 默认调度启动 ============

	// 手动触发=类型派生（2026-10-11 用户裁定，取代 SetManualRun 白名单——
	// config-watchdog 曾被白名单遗漏致循环任务无「运行」操作）：
	// 定时/循环/触发均可手动调度；常驻族恒不可（启停即可，启停由调度开关+重启承担）。

	// 默认调度启动：
	// - 循环共 10 个，默认启动 8 个（cert-waiting-ca 除外——默认关闭，续期扫描唤醒；
	//   autoban 除外——调度唯一前提=业务启用，见下）
	// - 常驻 3 个全启动（系统启动即运行；关闭调度=启动也不运行）
	// - 定时 4 个启动排程（threat/crs/ip2region/auto-backup——EnabledFn/
	//   NextSlotFn 内含开关判断；crawlerbot-update 不在本清单，调度由
	//   SyncBusinessTaskDrivers 按业务开关对齐）
	// 默认启动前先读偏好——显式停止的 daemon 必须在任何
	// StartLoop 副作用（启动记录/首轮执行）之前跳过；否则先启动再 StopLoop
	// 会留下假启动记录并可能实际跑一轮。
	taskLoopPrefs := loadTaskLoopPrefs()
	// 装配期服务屏障：部署面常驻任务（cert-issuance）的 Run 体起步即真实接管
	// 服务（cert-issuance → StartACME → CA 队列/证书部署重试 → Caddy /load），
	// 而本循环先于 startup:config-load（规则库载入 → 证书物化 → Caddy
	// 渲染/应用）执行。schedPaused 只覆盖 tick 与执行登记（启动执行面唯一豁免
	// 是 BootSync），常驻族启停由 loopEnabled 与角色门管理，故须单独用同一道
	// 配置屏障（configImportHoldActive 单源门）挡住部署面：屏障期内只登记启动
	// 意图，BootSync 完成后 EndConfigImportHold 兑现。不扩大 schedPaused 作用域
	// ——混入装配暂停会让两种语义纠缠并影响 pendingRestart 通道。
	// 屏障实际只拦部署面（startCertIssuanceLifecycle 与 caqueue 的
	// configImportHoldActive 门）：security-events-ingestion（只读尾读）与
	// cluster-sync 照常先启动（行为与引入屏障前一致；从节点快照应用由快照
	// 应用自身收敛），不得据此宣称「全部常驻族被挡在配置载入之后」。
	BeginConfigImportHold()
	for _, id := range []string{
		"config-watchdog", "log-cleanup", "audit-retention", "security-events-retention",
		"metrics-orphan-cleanup",
		"cert-renewal-scan", "cert-reconcile", "cert-manual-poll",
		"security-events-ingestion", "cert-issuance", "cluster-sync",
		"threat", "crs", "ip2region", "auto-backup",
	} {
		if enabled, found := taskLoopPrefs[id]; found && !enabled {
			continue
		}
		te.StartLoop(id)
	}
	// 导入哨兵行崩溃窗口自愈必须先于首槽武装：导入事务提交后、提交后 CAS
	// 清理前进程被 SIGKILL/OOM/驱逐时，哨兵行（version=哨兵串、auto_update=0）
	// 会永久残留——版本页显示哨兵串，且 INSERT OR IGNORE 挡住补种、auto_update=0
	// 挡住武装，该库自动更新永久停摆。启动是崩溃后唯一的恢复入口（进程已死），
	// 故只在启动路径修复，不影响导入成功路径的「rearm 后 CAS 删除」顺序
	//（那一步依赖哨兵形态未被改写）。
	healSecurityVersionImportSentinels()
	// 首槽武装先落默认源/版本行，随后的业务开关同步才能读到全新库的
	// 默认启用态（否则 ErrNoRows 被 fail-closed 误译为关闭并 StopLoop）。
	armSecurityLibraryFirstSlots()
	// 套用用户显式启停偏好——覆盖默认启动清单（停止态不复活；
	// 用户主动开启的默认关闭任务恢复调度）；业务驱动任务跳过。
	// 复用上方已读取的偏好快照，不再二次查表。
	applyTaskLoopPrefs(te, taskLoopPrefs)
	// 业务驱动任务启动均按业务实态对齐（唯一清单见 businessTaskDrivers）。
	SyncBusinessTaskDrivers()
	// BootSync 任务同步执行（startup:config-load——面板监听前完成，
	// 替代 main.go 直调+legacy startupPhase 记录旁路）
	te.RunBootSyncTasks()
	// 配置载入完成：解除装配期服务屏障，兑现常驻族被延迟的服务启动
	// （CA 队列/证书部署重试），此后常驻族才真正接管部署面。
	EndConfigImportHold()
	// BootSync 完成后解除 tick 暂停——此前 ticker 在
	// NewEngine 即起跑，周期/定时任务可在配置载入前执行首轮。
	te.ResumeScheduling()
	startRoleReconciler(te)
	return te
}

// startRoleReconciler 把引擎角色对账从用户可停止的 config-watchdog 中解耦
// 看门狗被停后，播种失败/角色漂移仍能每 60s 自愈。
// 每次 InitTaskEngine 启动一个并绑定该代引擎；全局换代或本代停止后退出。
var roleReconcilerInterval = 60 * time.Second

// roleReconcilerState 当前代对账 goroutine 的退出信号（StopTaskEngine 关停
// 等待用；引擎代际绑定，快速重建时只登记最新一代）。
var roleReconcilerState struct {
	sync.Mutex
	engine *taskengine.Engine
	done   chan struct{}
}

func startRoleReconciler(te *taskengine.Engine) <-chan struct{} {
	done := make(chan struct{})
	roleReconcilerState.Lock()
	roleReconcilerState.engine = te
	roleReconcilerState.done = done
	roleReconcilerState.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(roleReconcilerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-te.Done():
				// 本代引擎停止完成：立即退出（不再等下一个对账周期）。
				return
			case <-ticker.C:
				// 不能每 tick 重读全局后继续运行——StopTaskEngine
				// 置 nil 后快速 Init 会让旧 goroutine 误认新引擎而永久泄漏。
				if TaskEngine() != te || te.IsStopped() {
					return
				}
				reconcileTaskEngineRoleFor(te)
				// 业务驱动调度对齐的读失败重试：复用 60s 对账周期，
				// 读恢复即把上一次保持的调度态收敛到业务实态。
				retryPendingBusinessTaskDrivers()
			}
		}
	}()
	return done
}

// roleReconcilerDoneFor 返回绑定到指定引擎代际的对账退出信号（无则 nil）。
func roleReconcilerDoneFor(te *taskengine.Engine) <-chan struct{} {
	roleReconcilerState.Lock()
	defer roleReconcilerState.Unlock()
	if roleReconcilerState.engine != te {
		return nil
	}
	return roleReconcilerState.done
}

// businessTaskDriver 业务开关与引擎调度同步的唯一任务清单条目。
// 启动装配与任务监控只读门共用，禁止在 handler 另维护第二份 ID 列表。
// stateFn 返回 (enabled, known)：known=false=启用状态不可判定（读库失败）——
// 对齐必须保持上一次生效的调度态，不得把一次读失败固化为调度关闭。
type businessTaskDriver struct {
	id      string
	stateFn func() (enabled, known bool)
}

var businessTaskDrivers = []businessTaskDriver{
	{id: "threat", stateFn: func() (bool, bool) { return globalTaskAutoUpdateState("threat") }},
	{id: "crs", stateFn: func() (bool, bool) { return versionTableAutoUpdateState("security_crs_version") }},
	{id: "ip2region", stateFn: func() (bool, bool) { return versionTableAutoUpdateState("security_ip2region_version") }},
	{id: "crawlerbot-update", stateFn: func() (bool, bool) { return globalTaskAutoUpdateState("crawler") }},
	{id: "auto-backup", stateFn: AutoBackupEnabledState},
	{id: AutobanTaskID, stateFn: autobanEnabledState},
}

// businessDriverSyncPending 上一次对齐存在不可判定的读取（未落任何调度
// 动作）——由 60s 角色对账周期重试，读恢复即收敛到业务实态。无待重试时
// 周期对账不重复对齐（避免每 60s 无意义地重写调度开关）。
var businessDriverSyncPending atomic.Bool

// businessDriverSyncMu 串行化整次对齐：pending 是「本次全量遍历的结论」，
// 并发调用方（配置导入提交 / 60s 对账重试）交错时后写的 Store 会覆盖前者——
// 一次全部读成功的对齐可以把另一方「某驱动读失败」置位的重试标记清除，该
// 驱动的调度态从此停在旧值直到下次角色翻转/导入/重启。串行化后最后完成的一
// 次遍历必然是完整的，其结论对整个驱动集成立。
var businessDriverSyncMu sync.Mutex

// SyncBusinessTaskDrivers 按当前 DB 实态统一对齐六个业务驱动任务调度。
// 启动装配、配置导入、无待重试时的周期对账与 Promote 共用，避免只恢复其中
// 一族。读失败（known=false）的任务保持现有调度态并登记重试：tick 侧
// EnabledFn 本身 fail-closed（本轮不跑、下轮重新求值），无需在对齐层
// 再写一个持续到重启的关闭态。
func SyncBusinessTaskDrivers() {
	businessDriverSyncMu.Lock()
	defer businessDriverSyncMu.Unlock()
	pending := false
	for _, driver := range businessTaskDrivers {
		enabled, known := driver.stateFn()
		if !known {
			pending = true
			continue
		}
		syncTaskLoop(driver.id, enabled)
	}
	businessDriverSyncPending.Store(pending)
}

// retryPendingBusinessTaskDrivers 周期对账入口：仅在上一次对齐有读失败时
// 重新对齐（读恢复即把调度态收敛到业务实态）。
func retryPendingBusinessTaskDrivers() {
	if businessDriverSyncPending.Load() {
		SyncBusinessTaskDrivers()
	}
}

// businessTaskDriverOf 按 ID 取业务驱动清单条目（唯一清单见
// businessTaskDrivers）。
func businessTaskDriverOf(id string) (businessTaskDriver, bool) {
	for _, driver := range businessTaskDrivers {
		if driver.id == id {
			return driver, true
		}
	}
	return businessTaskDriver{}, false
}

// IsBusinessDrivenTask 返回任务是否只能由对应业务页开关驱动调度。
func IsBusinessDrivenTask(id string) bool {
	_, ok := businessTaskDriverOf(id)
	return ok
}

// applyBusinessTaskLoop 业务开关 setter 的调度应用入口：与
// SyncBusinessTaskDrivers 共用 businessDriverSyncMu，串行化「单点应用」与
// 「整轮对齐」。fallbackEnabled 只是读库失败时的回退值（调用方刚提交的值）。
//
// setter 提交 DB 后直接调 syncTaskLoop 会与整轮对齐交错：对齐先读旧态 →
// setter 提交并应用新态 → 对齐再应用旧态，最终「库已新、loop 仍旧」且
// businessDriverSyncPending=false（对齐全部读数成功），60s 对账不会纠正。
// DB 写入保持在锁外（锁只保护「读实态并应用」这一段）。
//
// 应用值同样必须来自锁内读库，而不是调用方参数：两个方向相反的开关请求
// 并发时提交顺序与应用顺序无关（OFF 先提交、ON 后提交，但 OFF 的应用段可能
// 后进锁）——按调用方参数应用会让最后一次应用落在过期意图上，留下「库=开 /
// loop=关」的持久错态（四族 Scheduled 零投递，且两端读数成功、无重试纠正）。
// 锁内读库后，最后一次应用恒等于应用时刻的库值，交错只产生与库一致的终态。
func applyBusinessTaskLoop(id string, fallbackEnabled bool) {
	businessDriverSyncMu.Lock()
	defer businessDriverSyncMu.Unlock()
	enabled := fallbackEnabled
	if driver, ok := businessTaskDriverOf(id); ok {
		if state, known := driver.stateFn(); known {
			enabled = state
		} else {
			businessDriverSyncPending.Store(true)
		}
	}
	syncTaskLoop(id, enabled)
}

// syncTaskLoop 将业务开关直接映射为引擎调度开关：开启自动更新=StartLoop，
// 关闭=StopLoop。所有规则库 setter 与任务监控 toggle 共用此单一动作。
func syncTaskLoop(id string, enabled bool) {
	te := TaskEngine()
	if te == nil {
		return
	}
	if enabled {
		te.StartLoop(id)
	} else {
		te.StopLoop(id)
	}
}

// applyPromoteTaskSideEffects 升主后的任务面收尾单源（集群 Promote 与角色
// 对账的升主分支共用）：
//   - 按库实态统一对齐六个业务驱动任务的调度（开启启用、关闭停止）；
//   - 补重装四个规则库首槽：从节点期间规则库更新任务由角色门停跑，版本行
//     可能残留「auto_update 开、next_update 空」形态——不重装则 NextSlotFn
//     永不到期，升主节点静默停更，只能靠重启恢复。
//
// 只在这一处增删收尾步骤：两条升主路径分头维护会漏项（对账升主曾漏掉两项）。
func applyPromoteTaskSideEffects() {
	SyncBusinessTaskDrivers()
	RearmSecurityLibrarySlots()
}

// WakeCertWaitingCAForEnqueuedJob 已知任务入队成功时的唤醒。
// 不重查 certJobsActive：队列可能在本调用前已快速失败并把状态置 failed，
// 但「入队成功」本身即真实工作——重查会把刚入队的工作误判为无活而漏唤醒。
func WakeCertWaitingCAForEnqueuedJob() {
	te := TaskEngine()
	if te == nil {
		return
	}
	te.RearmLoop("cert-waiting-ca", true)
}

func clusterSyncStatusMirror() string {
	te := TaskEngine()
	if te == nil || te.IsMaster() || syncLifecycleHalted == nil || !syncLifecycleHalted() {
		return ""
	}
	return string(TaskStatusFailed)
}

// clusterSyncDaemonRun 集群同步 daemon 的 Run 体（从 InitTaskEngine 的描述符
// 闭包抽出，便于对「引擎句柄固定」契约直接钉测）。
// 先固定引擎句柄再读角色——StopTaskEngine 在
// engine.Stop() 的 drain 超时后置全局 taskEngine=nil，daemon goroutine 若在
// 超时后首次进入 Run，裸读全局会 nil 解引用 panic（同族 cert-renewal-scan /
// cert-waiting-ca 已按 固定句柄）。句柄为空=引擎已停机/换代
// 直接退出，不得把「无引擎」误判成从节点去拉起同步生命周期。
func clusterSyncDaemonRun(rc taskengine.RunContext) error {
	te := TaskEngine()
	if te == nil {
		return nil
	}
	if te.IsMaster() {
		return masterSyncServingLifecycleRun(rc)
	}
	return daemonLifecycleRun(rc, syncLifecycleStart, syncLifecycleStop)
}

// StopTaskEngine 进程退出收尾：先原子摘除全局代际（后台读取方立即看到
// nil，不再触达正在 drain 的实例），再停引擎并等待角色对账 goroutine 退出
// （绑定本代的 done 信号；超时仅告警——关停等待不得被后台 DB 读无限拖住）。
func StopTaskEngine() {
	te := taskEnginePtr.Swap(nil)
	if te == nil {
		return
	}
	te.Stop()
	if done := roleReconcilerDoneFor(te); done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			log.Printf("WARNING: services: 任务引擎角色对账未在关停等待期内退出（后台 goroutine 随进程回收）")
		}
	}
}

// RearmSecurityLibrarySlots 幂等重装四个规则库首槽。
// 配置导入/还原提交后调用（引擎装配期已过）：导入包可能携带「auto_update
// 开启但 next_update 为空」的行——不重装则 NextSlotFn 永不到期，只能靠重启
// 恢复。已有槽的行、开关关闭的行一律不动；不重启引擎、不动运行中 Run。
func RearmSecurityLibrarySlots() {
	armSecurityLibraryFirstSlots()
	// 业务侧重排槽后清空引擎槽消费水位（显式复位入口）：导入包可能重写
	// next_update，旧 schedDoneSlot/失败退避会继续压住新预约。
	if te := TaskEngine(); te != nil {
		for _, id := range []string{"threat", "crs", "ip2region", "crawlerbot-update"} {
			te.ResetScheduleProgress(id)
		}
	}
}

// SecurityVersionImportSentinel 标记配置导入为「未导入版本表且导入前无行」
// 临时插入的占位版本串。写侧在 handlers（导入事务插入 + 提交后 CAS 删除），
// 读侧自愈在 armSecurityLibraryFirstSlots——单源常量，两侧不得各写一份字面量。
const SecurityVersionImportSentinel = "__lazy_balancer_import_seed__"

// healSecurityVersionImportSentinels 启动期修复导入哨兵行崩溃残留：把
// version=SecurityVersionImportSentinel 的行改写为内置种子版本并重新打开
// auto_update（与「未导入=零行，由 rearm 补真实种子」的终态一致）。幂等：
// 非哨兵行零改动；读/写失败仅告警（下次启动重试，不阻断启动）。
func healSecurityVersionImportSentinels() {
	if db.DB == nil {
		return
	}
	for _, tc := range []struct{ table, seedVersion string }{
		{"security_crs_version", CRSBundledVersion},
		{"security_ip2region_version", "unknown"},
	} {
		if _, err := db.DB.Exec(`UPDATE `+tc.table+` SET version=?, auto_update=TRUE WHERE id=1 AND version=?`, tc.seedVersion, SecurityVersionImportSentinel); err != nil {
			Logf("warn", "启动自愈：%s 导入哨兵行改写失败: %v", tc.table, err)
		}
	}
}

// armSecurityLibraryFirstSlots 四个规则库首槽武装
// auto_update 开且 next_update 空的行写入下一排程槽（versionTableNextSlot/
// threatNextSlot 与既有排程写侧同函数同口径）。已有槽的行、开关关闭的行
// 一律不动；武装失败仅告警不阻断启动（下一排程保存路径会自愈）。
func armSecurityLibraryFirstSlots() {
	if db.DB == nil {
		return
	}
	now := time.Now().UTC()
	// 版本表两族（CRS/IP2Region）：单行表——行可能尚未由管理器种子
	//（ensureCRSVersionRow 在管理器初始化时执行，时序晚于本函数），先补行再补槽。
	for _, tc := range []struct{ table, seedVersion string }{
		{"security_crs_version", CRSBundledVersion},
		{"security_ip2region_version", "unknown"},
	} {
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO `+tc.table+` (id, version, auto_update) VALUES (1, ?, TRUE)`, tc.seedVersion); err != nil {
			Logf("warn", "首槽武装：%s 种子行写入失败: %v", tc.table, err)
			continue
		}
		var autoUpdate int
		var nextUpdate string
		if err := db.DB.QueryRow(`SELECT COALESCE(auto_update,1), COALESCE(next_update,'') FROM `+tc.table+` WHERE id=1`).Scan(&autoUpdate, &nextUpdate); err != nil {
			continue
		}
		if autoUpdate != 1 || nextUpdate != "" {
			continue
		}
		if _, err := db.DB.Exec(`UPDATE `+tc.table+` SET next_update=? WHERE id=1`, versionTableNextSlot(tc.table, now)); err != nil {
			Logf("warn", "首槽武装：%s 写入 next_update 失败: %v", tc.table, err)
		}
	}
	// 威胁源族：三行源表，仅武装启用更新的源
	ArmThreatFirstSlots()
	armCrawlerFirstSlots()
}

// ArmThreatFirstSlots 威胁源首槽武装：开启业务或逐源启用时，空 next_update
// 的启用源写入威胁排程槽，避免 NextSlotFn 永不到期。
// 只武装注册表内的源（与读侧槽域同源）：注册表外启用行的槽没有任何推进
// 写点，武装它会让读侧「最早槽」被排除后仍留下无意义的惰性槽，并与启动期
// 清理互相抵消（清空→武装补回→下次启动再清空）。
func ArmThreatFirstSlots() {
	if db.DB == nil {
		// 同族 DB 入口的 nil 守卫：装配缺失时静默返回（无调度可武装），
		// 不得 panic 到调用方（handlers/security_threat、services/threatupdate）。
		return
	}
	if !ThreatAutoUpdateEnabled() {
		return
	}
	nameClause, args := sourceNameSetClause("name", threatSourceRegistryNames(), false)
	args = append([]any{threatNextSlot(time.Now().UTC())}, args...)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE update_enabled=1 AND COALESCE(next_update,'')=''`+nameClause, args...); err != nil {
		Logf("warn", "首槽武装：security_threat_sources 写入 next_update 失败: %v", err)
	}
}
