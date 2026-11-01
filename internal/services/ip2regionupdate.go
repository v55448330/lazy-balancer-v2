package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/taskengine"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	ip2regionService "github.com/lionsoul2014/ip2region/binding/golang/service"

	"lazy-balancer-v2/internal/db"
)

var ErrIP2RegionUpdateRunning = errors.New("IP2Region 更新任务正在进行中")

// errIP2RegionReload 标记「安装后内存热换失败」：此时磁盘已是新库
// 而内存 searcher 仍是旧库，run() 须走与 reloader 失败相同的回滚路径，不得按
// 普通安装失败直接落库（磁盘/内存/DB 会三方分叉）。
var errIP2RegionReload = errors.New("重载 ip2region 内存索引失败")

type IP2RegionUpdateStatus string

const (
	IP2RegionStatusIdle        IP2RegionUpdateStatus = "idle"
	IP2RegionStatusChecking    IP2RegionUpdateStatus = "checking"
	IP2RegionStatusDownloading IP2RegionUpdateStatus = "downloading"
	IP2RegionStatusInstalling  IP2RegionUpdateStatus = "installing"
	IP2RegionStatusReloading   IP2RegionUpdateStatus = "reloading"
	IP2RegionStatusSuccess     IP2RegionUpdateStatus = "success"
	IP2RegionStatusFailed      IP2RegionUpdateStatus = "failed"
	// IP2RegionStatusSkipped：起点角色复查中止的正常语义
	// 终态——镜像 CRS 侧。
	IP2RegionStatusSkipped IP2RegionUpdateStatus = "skipped"
	// IP2RegionStatusCancelled 用户主动取消，与 task_runs cancelled 同口径。
	IP2RegionStatusCancelled IP2RegionUpdateStatus = "cancelled"
)

// IP2RegionUpdateManager runs ip2region xdb updates single-flight and persists
// terminal state in security_ip2region_version.
type IP2RegionUpdateManager struct {
	mu      sync.Mutex
	running bool
	state   ip2RegionTaskState
	runDone chan struct{}

	// bakCreated 标记本次运行已创建 ip2region.xdb.bak（镜像 CRS 的
	// CRSUpdateManager.overridesBakCreated/rulesBakCreated，crsinstall.go 的
	// downloadAndInstall/restoreBackupInLock）：rollbackXDB 只消费本
	// 运行创建的 bak——跨运行崩溃窗口（rename 成功后、reloader 前崩溃）残留的
	// 陈旧 .bak 是旧 xdb 唯一副本，非本运行创建时视为无需回滚，不得消费。
	// 每次 run() 开始时重置，downloadAndInstall 备份成功后置位。
	bakCreated bool

	// installCommitted 标记本次运行的安装段已落盘（xdb 已 rename、版本行/
	// sidecar 已写）。取消发生在安装段之后、重载之前时必须按「未重载即未生效」
	// 回滚到同代基线（与 CRS 的 observeCancelAfterSwap 同构）——否则任务显示
	// 已取消而磁盘/版本行已是新库、Caddy 仍按旧库执行。run() 开始时重置，
	// downloadAndInstall 安装段完成后置位。
	installCommitted bool

	// prevVersion 记录安装锁段读出的事件前版本行值：版本行与
	// sidecar 随安装段（wafFileMu 互斥区）写入新 tag，重载失败且磁盘已还原
	// 旧 xdb 时（run() restored 分支）行与 sidecar 必须回滚到本值——否则
	// 「磁盘旧/行新」三方分叉。每次成功安装锁段内刷新。
	prevVersion string
	// newXdbSha 本次安装新工件的 sha256：rollback 全败时 fail-open
	// 必须验证 live 仍是该工件（普通文件 + 摘要一致 + validate 通过）方可认 success。
	newXdbSha string

	reloader       func() error
	fetchLatestTag func(ctx context.Context) (tag string, err error)
	// runCancel 取消当前运行中的下载阶段（任务监控手动取消，v2.3.4）：
	// 用户取消路径携带 ErrUserCancelled 原因，取消终态据此推进排程槽。
	runCancel   context.CancelCauseFunc
	downloadXDB func(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error

	// downloadXDBV6 是 IPv6 数据源的下载缝（单任务双源形态：同一 tag 同一
	// 任务内先后下载 v4+v6，v6 失败不拖垮 v4 安装）。测试重定向与 v4 缝同形。
	downloadXDBV6 func(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error

	// v6BakCreated 标记本次运行已创建 ip2region_v6.xdb.bak（与 bakCreated
	// 同口径：回滚永不消费 v6 bak——v6 安装成功即同 tag 有效内容，重载失败
	// 回滚只还原 v4；v6 bak 仅供崩溃窗口恢复，成功路径清理）。
	v6BakCreated bool

	// v6InstallAttempted/v6InstallSucceeded/v6InstallError 记录本次运行 v6
	// 源的安装段结果（运行 goroutine 私有，仅成功路径持 mu 读）：
	// attempted=false=本轮未尝试（关闭/已最新）；失败不反噬 v4 的 success。
	v6InstallAttempted bool
	v6InstallSucceeded bool
	v6InstallError     string

	// slots 本运行「排程槽未推进」的原因：排程不可读（写路径严格读排程失败）
	// 或状态行写入失败（槽随之未落地）。与 CRS 族共用同一记录器实现
	// （versionTableSlotRecorder）；Run 体把本轮按失败返回给任务引擎——成功轮
	// 不推进槽却回 success 会被引擎记入本槽消费水位，此后同一槽永不再投递
	// （该族自动更新静默停摆，没有下一轮可以自愈）。每次运行起点清空。
	slots versionTableSlotRecorder
}

var (
	ip2RegionUpdateManager     *IP2RegionUpdateManager
	ip2RegionUpdateManagerOnce sync.Once
)

func newIP2RegionUpdateManager(reloader func() error) *IP2RegionUpdateManager {
	return &IP2RegionUpdateManager{
		reloader:       reloader,
		fetchLatestTag: defaultFetchIP2RegionLatestTag,
		downloadXDB:    defaultDownloadIP2RegionXDB,
		downloadXDBV6:  defaultDownloadIP2RegionXDBV6,
		state:          ip2RegionTaskState{status: IP2RegionStatusIdle},
	}
}

// InitIP2RegionUpdateManager initializes the singleton with the Caddy reloader.
func InitIP2RegionUpdateManager(reloader func() error) {
	ip2RegionUpdateManagerOnce.Do(func() {
		ip2RegionUpdateManager = newIP2RegionUpdateManager(reloader)
		ensureIP2RegionVersionRow()
	})
}

func GetIP2RegionUpdateManager() *IP2RegionUpdateManager {
	return ip2RegionUpdateManager
}

func ResetIP2RegionUpdateManagerForTest() {
	ip2RegionUpdateManager = nil
	ip2RegionUpdateManagerOnce = sync.Once{}
}

// SetIP2RegionAutoUpdate toggles the auto-update flag without touching the
// stored version; a missing row is seeded with the fallback version.
func SetIP2RegionAutoUpdate(enabled bool) error {
	return setVersionTableAutoUpdate("security_ip2region_version", "IP2Region", "unknown", "ip2region", enabled)
}

func ensureIP2RegionVersionRow() {
	// IP 库自动更新默认 ON——与 CRS 种子及 schema DEFAULT TRUE 对齐
	//（此前种子 FALSE 与 schema 默认矛盾；过期 xdb 同样引发地域策略
	// 误拦/漏拦）。
	ensureVersionTableRow("security_ip2region_version", "unknown", "ip2region update")
}

func currentIP2RegionVersion() string {
	var version string
	if err := db.DB.QueryRow("SELECT version FROM security_ip2region_version WHERE id=1").Scan(&version); err != nil || version == "" {
		return "unknown"
	}
	return version
}

// ip2RegionCurrentVersionForRun 安装前版本判定的测试缝；生产恒指向 currentIP2RegionVersion。
var ip2RegionCurrentVersionForRun = currentIP2RegionVersion

// StartUpdate begins an async update; only one may run at a time. 返回本次 run
// 的完成通道：调度器 rearm 须等待该捕获通道而非
// 回读现行 m.runDone，防手动更新插队覆盖后的错等与误判。手动调用方可忽略。
// rc 语义同 CRS（RunID>0=引擎已记跳自记；Operator 审计归人）。
// currentTrigger 当前在途运行触发源（StartUpdate 落 m.state.trigger）——
// successAfterReloadFailOpen 等无 trigger 形参路径读此（排程槽生命周期门控用）。
func (m *IP2RegionUpdateManager) currentTrigger() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.trigger
}

func (m *IP2RegionUpdateManager) StartUpdate(trigger string, rc *taskengine.RunContext) (chan struct{}, error) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil, ErrIP2RegionUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	m.state = ip2RegionTaskState{status: IP2RegionStatusChecking, trigger: trigger, startedAt: time.Now().UTC()}
	// 可取消 ctx 与 running 同临界区登记（镜像 CRS）——StartUpdate
	// 返回后立刻 CancelRunning 必须命中，不得读到未登记的 runCancel 静默放行。
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
				Logf("error", "ip2region update: run panicked: %v\n%s", r, debug.Stack())
				m.fail(fmt.Errorf("更新任务内部异常（已拦截进程级崩溃）: %v", r))
			}
		}()
		m.runWithContext(runCtx, trigger, rc)
	}()
	return done, nil
}

func (m *IP2RegionUpdateManager) IsRunning() bool {
	return versionTableTaskIsRunning(&m.mu, &m.running)
}

func (m *IP2RegionUpdateManager) setStage(status IP2RegionUpdateStatus, message string) {
	m.mu.Lock()
	m.state.status = status
	m.state.message = message
	m.mu.Unlock()
	level := "INFO"
	switch status {
	case IP2RegionStatusFailed:
		level = "ERROR"
	case IP2RegionStatusSkipped, IP2RegionStatusCancelled:
		// 跳过/用户取消均为非故障中止，使用 WARN。
		level = "WARN"
	}
	WriteIP2RegionUpdateLog(level, string(status), message)
}

// run 同步执行一次更新（测试/内部直调路径）：自建可取消 ctx 并登记
// runCancel（镜像 CRS 的  形态）。
func (m *IP2RegionUpdateManager) run(trigger string, rc *taskengine.RunContext) {
	runCtx, runCancel := context.WithCancelCause(updateRunBaseContext(rc))
	defer runCancel(nil)
	m.mu.Lock()
	m.runCancel = runCancel
	m.mu.Unlock()
	m.runWithContext(runCtx, trigger, rc)
}

// runWithContext 是更新管线本体；runCtx 生命周期归调用方。
func (m *IP2RegionUpdateManager) runWithContext(runCtx context.Context, trigger string, rc *taskengine.RunContext) {
	operator := "system"
	if rc != nil && rc.Operator != "" {
		operator = rc.Operator
	}
	// 任务自记审计：手动/自动同一审计（用户裁定 2026-09-29）。defer 基准=
	// 内存 state（曾读 DB 行，slave 早退路径不写行导致
	// 「更新成功<上轮消息>」+task_runs success 双假；CRS 内存基准即正确形）。
	defer func() {
		m.mu.Lock()
		status, message := string(m.state.status), m.state.message
		m.mu.Unlock()
		// 状态中文归一（曾混英文 status token，与 threat 族口径不一）。
		// 中间阶段三档也必须映射——任何早退/异常形态读到中间状态时不得回落
		// 成英文 token（panic 路径由下方 recover 先落定 failed，此处是兜底）。
		statusLabel := map[string]string{
			string(IP2RegionStatusSuccess): "成功", string(IP2RegionStatusFailed): "失败",
			string(IP2RegionStatusSkipped): "跳过", string(IP2RegionStatusCancelled): "已取消",
			string(IP2RegionStatusIdle): "空闲", string(IP2RegionStatusChecking): "检测中",
			string(IP2RegionStatusDownloading): "下载中", string(IP2RegionStatusInstalling): "安装中",
			string(IP2RegionStatusReloading): "重载中",
		}[status]
		if statusLabel == "" {
			statusLabel = status
		}
		detail := fmt.Sprintf("更新%s（触发：%s）%s", statusLabel, trigger, message)
		switch status {
		case string(IP2RegionStatusFailed):
			// 资源名用归一表规范名「IP数据库」——旧名
			// 「IP2Region数据库」属归一表旧值，写入即被下次启动迁移重写。
			RecordAuditLog(operator, "更新失败", "IP数据库", detail, "")
		case string(IP2RegionStatusCancelled):
			RecordAuditLog(operator, "取消", "IP数据库", detail, "")
		default:
			RecordAuditLog(operator, "更新", "IP数据库", detail, "")
		}
	}()

	// 单写方：task_runs 由引擎统一记录。
	// runCtx 派生自 rc.Ctx（镜像 CRS 侧）——引擎 demote
	// 中止（SetRole 取消在途 Scheduled）随 rc.Ctx 传播；nil rc 回退 Background。
	// ctx 由调用方（StartUpdate/run）预建。
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	// 每次运行起点清空「排程槽未推进」状态：上一轮的读失败不得让本轮成功
	// 轮仍被引擎判失败（读恢复后必须立即自愈）。
	m.slots.set(nil, ip2RegionUpdateLogFamily)

	// 函数内 recover：本 defer 注册在上方审计 defer 之后，恢复先于审计执行
	// ——panic 轮先落定 failed 终态，审计读到终态（此前 goroutine 层 recover
	// 在审计 defer 之后才运行，审计读到 downloading/installing/reloading 等
	// 中间阶段，记成「更新」+英文 token，且此后不再有「更新失败」审计）。
	// 外层 goroutine 的 recover 退化为兜底（defer 自身 panic 等形态）。
	defer func() {
		if r := recover(); r != nil {
			Logf("error", "ip2region update: run panicked: %v\n%s", r, debug.Stack())
			m.fail(fmt.Errorf("更新任务内部异常（已拦截进程级崩溃）: %v", r))
		}
	}()

	// 起点角色复查：与 CRS 更新同一 demote 竞态窗口——tick 越过
	// is_master 守卫后节点被降级时，从节点上的 in-flight 更新必须立即终止。
	// NULL 兜底归一为 1，与 IsMaster/readonly 写闸/
	// 调度器 tick 的 COALESCE(is_master,1) 同口径（NULL 视为主节点）。
	if isMaster, roleErr := RoleOf(context.Background(), db.DB); roleErr != nil {
		// 角色读取失败（DB 瞬断/脏行）≠从节点——按失败落定（task_runs/任务
		// 监控可见），不得静默跳过（err!=nil||!isMaster 把 DB 故障
		// 当从节点）。
		m.fail(fmt.Errorf("角色读取失败，无法判定本节点是否主节点，已中止 IP2Region 更新: %w", roleErr))
		m.advanceSlotIfAuto(trigger)
		return
	} else if !isMaster {
		// 从节点中止是正常跳过语义，镜像 CRS——内存终态 + 更新日志/审计
		// 留痕（「更新跳过」），不写版本表（从节点只读不变量：版本行由集群
		// 同步治理），因此进程重启后 StatusSnapshot 会回退为存储行的 idle。
		m.syncInstalledVersionToState()
		m.setStage(IP2RegionStatusSkipped, "当前节点为从节点，终止 IP2Region 更新")
		return
	}

	// 每次运行重置：rollbackXDB 仅消费本运行创建的.bak；v6 源安装结果按轮
	// 重置（attempted=false=本轮未尝试）。
	m.bakCreated = false
	m.installCommitted = false
	m.v6BakCreated = false
	m.v6InstallAttempted = false
	m.v6InstallSucceeded = false
	m.v6InstallError = ""

	ensureIP2RegionVersionRow()
	runStartedAt := taskRunStartedAt(rc)
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET trigger=?, started_at=?, last_checked=?, finished_at=NULL WHERE id=1",
		trigger, runStartedAt, runStartedAt,
	); err != nil {
		Logf("error", "ip2region update: failed to mark start: %v", err)
	}

	m.setStage(IP2RegionStatusChecking, "查询最新 ip2region 版本")
	// 任务内重试（2026-09-25 用户裁定）：同 CRS 侧——耗尽才落定，排程槽不污染。
	var tag string
	err := runWithInTaskRetry(runCtx, func() error {
		var ferr error
		tag, ferr = m.fetchLatestTag(runCtx)
		if _, dbErr := db.DB.Exec("UPDATE security_ip2region_version SET last_checked=? WHERE id=1", runStartedAt); dbErr != nil {
			Logf("error", "ip2region update: failed to record last_checked: %v", dbErr)
		}
		return ferr
	}, func(nextAttempt int, wait time.Duration, rerr error) {
		WriteIP2RegionUpdateLog("WARN", "retry", fmt.Sprintf("查询 ip2region 最新版本失败: %v；等待 %s 重试，第 %d 次，共 %d 次", rerr, wait, nextAttempt, updateMaxAttempts))
	})
	if err != nil {
		// runCtx 取消且已非主节点=demote 在途中止——落 skipped
		// （与起点角色复查同语义），不走 fail（从节点中止非故障）。
		if master, known := updateRunRole(); runCtx.Err() != nil && known && !master {
			m.syncInstalledVersionToState()
			m.setStage(IP2RegionStatusSkipped, "节点已降级为从节点，终止 IP2Region 更新")
			return
		}
		if runCtx.Err() != nil {
			m.cancel(err, trigger, runCtx)
			return
		}
		m.fail(err)
		m.advanceSlotIfAuto(trigger)
		return
	}
	WriteIP2RegionUpdateLog("INFO", string(IP2RegionStatusChecking), fmt.Sprintf("最新版本 %s，当前版本 %s", tag, currentIP2RegionVersion()))

	// 与 CRS 同口径（crsupdate.go）——tag 不新于
	// current（cmp<=0）即按「已是最新」跳过，防上游 release 回退/删除时静默
	// 降级安装更旧 xdb；格式不可比（cmpErr!=nil）保持现行「不等即更新」行为。
	// 精确相等短路（与格式无关）并入既有跳过分支；不同且不可比较
	// 显式失败（不再隐含「必然更新」）。
	currentVersion := ip2RegionCurrentVersionForRun()
	cmp, cmpErr := CompareCRSVersions(tag, currentVersion)
	// 空 current（首装）永远走安装路径；`bundled`/`unknown` 是未写版本哨兵，
	// 同样允许从远端建立基线；不同且不可比较（非首装）显式失败。
	if cmpErr != nil && currentVersion != "" && !strings.EqualFold(currentVersion, "unknown") && !strings.EqualFold(currentVersion, "bundled") && tag != currentVersion {
		m.fail(fmt.Errorf("版本格式不可比较（远端 %q / 当前 %q），已中止更新以避免静默降级", tag, currentVersion))
		m.advanceSlotIfAuto(trigger)
		return
	}
	v4Current := tag == currentVersion || (cmpErr == nil && cmp <= 0)
	// v6 数据源货币性（单任务双源）：关闭=无需更新；开启时按 v6 版本行独立
	// 判定——v4 已最新但 v6 未装/落后（典型：用户刚开启 v6 开关）时仍要进
	// 安装段补齐 v6，否则「已是最新」短路会让 v6 永远装不上。
	v6Enabled := IsIP2RegionV6Enabled()
	v6VersionRow, v6verr := GetIP2RegionV6Version()
	if v6verr != nil && !errors.Is(v6verr, sql.ErrNoRows) {
		// 读故障按「非最新」处理会引发重复下载；按「最新」跳过会漏装。
		// 读故障先行落定（任务内重试已吸收瞬断，这里是持续故障），下轮自愈。
		m.fail(fmt.Errorf("读取 IPv6 版本行失败，已中止本轮更新: %w", v6verr))
		m.advanceSlotIfAuto(trigger)
		return
	}
	v6Current := !v6Enabled || v6VersionRow == tag
	if v4Current && v6Current {
		// （补正重写——首版实施脚本缺失落盘调用丢失）：已是最新也
		// 补写 .version sidecar——此前该分支提前 return 不写，崩溃遗留的 stale tag
		// 将无限期不愈（愈于下次「安装」而非下次「检查」）；幂等，写失败仅记日志。
		// v6 sidecar 同口径自愈（开启时）。
		if err := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", tag); err != nil {
			Logf("error", "ip2region update: failed to refresh .version sidecar at latest: %v", err)
		}
		if v6Enabled {
			if err := rewriteVersionIfMissingOrStale(ip2regionV6LivePath+".version", tag); err != nil {
				Logf("error", "ip2region update: failed to refresh v6 .version sidecar at latest: %v", err)
			}
		}
		WriteIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), "已是最新版本，无需更新")
		slotSQL, slotArgs, slotErr := versionTableSlotSuccessAssign("security_ip2region_version", trigger)
		if _, err := db.DB.Exec(
			// 排程槽：成功轮 auto/manual 同权、仅现存槽空/过期才推进——未来槽不回拨
			// （手动成功必须推进过期槽，否则引擎已消费而业务槽停滞，四族自动更新停摆）。
			// 排程不可读时槽保持原值，由调用方把本轮按失败上报（严格读单源留痕）。
			"UPDATE security_ip2region_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), consecutive_failures=0, "+slotSQL+" WHERE id=1",
			slotArgs...,
		); err != nil {
			// 状态行没落地=本轮对调度契约而言失败（排程槽同样未推进）：并入
			// 「槽未推进」通道，由 Run 体按失败返回（引擎退避重投，写成功即
			// 推进槽）。吞错按 success 收尾会让引擎消费过期槽而库里槽仍旧，
			// 该族自动更新再无自愈路径。
			slotErr = errors.Join(slotErr, fmt.Errorf("%w: 状态行写入失败: %w", errScheduleSlotNotAdvanced, err))
		}
		m.setSlotAdvanceError(slotErr)
		m.mu.Lock()
		m.state.status = IP2RegionStatusSuccess
		m.state.message = "已是最新版本"
		m.state.finishedAt = time.Now().UTC()
		// 同型补 version：内存态优先后 version
		// 此前在「已是最新」时退化为空串（CRS 侧已修，本侧漏同步）。
		m.state.version = currentIP2RegionVersion()
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	m.state.version = tag
	m.newXdbSha = ""
	m.mu.Unlock()

	var installErr error
	needV4, needV6 := !v4Current, v6Enabled && !v6Current
	installRetErr := runWithInTaskRetry(runCtx, func() error {
		installErr = m.downloadAndInstall(runCtx, tag, needV4, needV6)
		// errIP2RegionReload=内存热换失败（fail-open 回滚路径），非瞬断——不重试。
		if errors.Is(installErr, errIP2RegionReload) {
			return nil
		}
		return installErr
	}, func(nextAttempt int, wait time.Duration, rerr error) {
		WriteIP2RegionUpdateLog("WARN", "retry", fmt.Sprintf("下载安装 ip2region %s 失败: %v；等待 %s 重试，第 %d 次，共 %d 次", tag, rerr, wait, nextAttempt, updateMaxAttempts))
	})
	// 取消发生在 op 前时 installErr 仍 nil，但重试器已返回 ctx 错误。
	if installRetErr != nil && (installErr == nil || runCtx.Err() != nil) {
		installErr = installRetErr
	}
	if installErr == nil && runCtx.Err() != nil {
		installErr = runCtx.Err()
	}
	if installErr != nil && !errors.Is(installErr, errIP2RegionReload) {
		// 同上方 fetch 分支——demote 在途中止落 skipped（不回滚
		// 不重载：从节点保持只读不变量）。
		if master, known := updateRunRole(); runCtx.Err() != nil && known && !master {
			m.syncInstalledVersionToState()
			m.setStage(IP2RegionStatusSkipped, "节点已降级为从节点，终止 IP2Region 更新")
			return
		}
		if runCtx.Err() != nil {
			m.rollbackAfterCancel()
			m.cancel(installErr, trigger, runCtx)
			return
		}
		m.fail(fmt.Errorf("安装 ip2region xdb 失败: %w", installErr))
		m.advanceSlotIfAuto(trigger)
		return
	}

	// 安装返回与重载之间的取消观察点：取消必须按「未重载即未生效」回滚，
	// 不得让磁盘/版本行停在新库而任务显示已取消（Caddy 仍按旧库执行）。
	if runCtx.Err() != nil {
		m.rollbackAfterCancel()
		m.cancel(runCtx.Err(), trigger, runCtx)
		return
	}

	m.setStage(IP2RegionStatusReloading, "重载 Caddy 配置")
	// 安装后内存热换失败视同 reloader 失败进入同一回滚路径（磁盘已是
	// 新库、内存仍是旧库，直接按 failed 落库会重演三方分叉）；此时不再调用
	// reloader，直接回滚。memSwitched 记录内存 searcher 是否已切到新库，供
	// fail-open 的 message 注明「内存未切换、重启后生效」。
	reloadErr := installErr
	memSwitched := installErr == nil
	// nil reloader 守卫——镜像 CRS 侧（crsinstall.go 的
	// swapCRSTreeFromStaging 内 reloader nil 守卫 / crsupdate.go 的
	// restoreAfterInstallError 同口径）：包内直构（测试/未来重构）注入
	// nil 时此前会 panic；生产唯一注入点 cmd/server/main.go 的 InitCRSUpdateManager
	// 恒非 nil。nil 语义与
	// CRS 一致：不尝试重载、不记审计、视为成功。
	if reloadErr == nil && m.reloader != nil {
		reloadErr = m.reloader()
		recordSystemReloadAudit("ip2region_update", reloadErr)
	}
	if reloadErr != nil {
		// needV4=false 的轮次（仅 v6 变更）：v4 从未离位，磁盘/内存本就一致，
		// 无回滚语义——dist 回退会把在役 v4 错误降级为镜像旧库。v6 新库已落盘
		// （有效内容），面板内存 searcher 已随安装热换；仅 Caddy 停留旧配置，
		// 待下次成功重载收敛。
		if !needV4 {
			m.fail(fmt.Errorf("重载 Caddy 配置失败: %w（IPv6 库已落盘，待下次成功重载生效）", reloadErr))
			m.advanceSlotIfAuto(trigger)
			return
		}
		// 回滚旧 xdb 并再次重载（镜像 CRS fail() 路径）：reloader 失败
		// 时磁盘还原到更新前状态，避免「磁盘已是新库、DB 记录旧版本+failed」的
		// 长期不一致；还原后内存热换失败时旧 searcher 保持服役、磁盘已是基线
		//若安装阶段热换曾成功，内存 searcher 以新数据滞后，在下
		// 次更新安装或重启后收敛（无周期性 reload；Caddy 侧 geoip 强制随
		// reloader 重试收敛），不影响磁盘/DB 一致性。回滚或重试失败仅记录，
		// 不改变失败落库。
		restored, distRestore, rbErr := m.rollbackXDB()
		switch {
		case rbErr != nil:
			// 回滚升级链全败时 fail-open **必须**验证 live 仍是本次
			// 新工件（普通文件 + sha 等于新工件 + validate 通过）；否则按失败
			// 落库并回写旧版本（不得把未验证的字节认成「已生效」）。
			Logf("error", "ip2region update: rollback xdb failed: %v", rbErr)
			if m.failOpenPreconditionHolds() {
				m.successAfterReloadFailOpen(tag, reloadErr, rbErr, memSwitched)
			} else {
				Logf("error", "ip2region update: fail-open rejected: live xdb is not the validated new artifact; recording failure with previous version")
				m.restorePreviousVersionRow()
				m.fail(reloadErr)
				m.advanceSlotIfAuto(trigger)
			}
			return
		case restored && distRestore:
			// dist 基线不是「更新前版本」——不得冒称 prevVersion。
			// rollbackXDB 已在同一 wafFileMu 临界区写保守标识 bundled
			//（=镜像内置基线哨兵，下次更新不被「已是最新」短路；不是 unknown）。
			if m.reloader != nil {
				rErr := m.reloader()
				recordSystemReloadAudit("ip2region_update", rErr)
				if rErr != nil {
					Logf("error", "ip2region update: reload after dist rollback failed: %v", rErr)
				}
			}
			m.fail(reloadErr)
			m.advanceSlotIfAuto(trigger)
			return
		case restored:
			// 磁盘已还原旧 xdb——安装段（锁内）写入的新版本行与
			// sidecar 由 rollbackXDB 在同一 wafFileMu 临界区回滚到
			// prevVersion，否则「磁盘旧/行新」三方分叉（导出侧读新 tag
			// 配旧 xdb）。回滚失败仅记日志：fail() 落 failed 状态行，
			// 下次成功更新/启动对账自愈。
			// nil reloader 守卫——镜像本函数上方
			if m.reloader != nil {
				rErr := m.reloader()
				recordSystemReloadAudit("ip2region_update", rErr)
				if rErr != nil {
					Logf("error", "ip2region update: reload after rollback failed: %v", rErr)
				}
			}
			if errors.Is(reloadErr, errIP2RegionReload) {
				m.fail(reloadErr)
			} else {
				m.fail(fmt.Errorf("重载 Caddy 配置失败: %w", reloadErr))
			}
			m.advanceSlotIfAuto(trigger)
			return
		default:
			// bakCreated==false（全新部署首次更新，无旧 live
			// 可备份）且 dist 也缺失，无任何「更新前基线」可回退。但 live 必须
			// 仍是本次已验证的新工件才可按成功落库（与 rbErr 分支同门）。
			if m.failOpenPreconditionHolds() {
				m.successAfterReloadFailOpen(tag, reloadErr, nil, memSwitched)
			} else {
				Logf("error", "ip2region update: fail-open rejected: live xdb is not the validated new artifact; recording failure")
				m.restorePreviousVersionRow()
				m.fail(reloadErr)
				m.advanceSlotIfAuto(trigger)
			}
			return
		}
	}
	// 只清理本运行创建的备份（与 rollbackXDB 的 bakCreated 口径、
	// 「本运行创建才可消费/清理」统一）——fresh-install（live
	// 不存在→本轮未建备份）时磁盘上的陈旧 .bak 是崩溃现场唯一恢复副本，
	// 成功路径删除会无谓销毁它。v6 bak 同口径（v6 bak 不参与回滚，仅供
	// 崩溃窗口恢复；成功即同 tag 有效内容，清理）。
	if m.bakCreated {
		os.Remove(ip2regionLivePath + ".bak")
	}
	if m.v6BakCreated {
		os.Remove(ip2regionV6LivePath + ".bak")
	}

	slotSQL, slotArgs, slotErr := versionTableSlotSuccessAssign("security_ip2region_version", trigger)
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET version=?, updated_at=datetime('now'), update_status='success', message='', finished_at=datetime('now'), consecutive_failures=0, "+slotSQL+" WHERE id=1",
		append([]any{tag}, slotArgs...)...,
	); err != nil {
		// 同「已是最新」分支：状态行没落地即本轮失败（槽也未推进），走同一
		// 「槽未推进」通道让引擎退避重投。
		slotErr = errors.Join(slotErr, fmt.Errorf("%w: 状态行写入失败: %w", errScheduleSlotNotAdvanced, err))
	}
	m.setSlotAdvanceError(slotErr)
	if err := SetIP2RegionVersion(tag); err != nil {
		Logf("error", "ip2region update: failed to store version: %v", err)
	}
	// v6 源终态落库：本次安装段尝试过 v6（needV6）时按结果写——成功=版本行
	// +sidecar+源状态 success；失败已在安装段记 failed（不反噬 v4 的 success）。
	// 未尝试（关闭或已最新）不动 v6 状态。v6 版本行写失败仅留痕（下次成功
	// 更新/启动种子同步自愈）。
	if m.v6InstallAttempted {
		if m.v6InstallSucceeded {
			if err := SetIP2RegionV6Version(tag); err != nil {
				Logf("error", "ip2region update: failed to store v6 version: %v", err)
			}
			SetIP2RegionV6SourceStatus("success", "")
			if err := rewriteVersionIfMissingOrStale(ip2regionV6LivePath+".version", tag); err != nil {
				Logf("error", "ip2region update: failed to write v6 .version sidecar: %v", err)
			}
			WriteIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), fmt.Sprintf("IPv6 库已更新到 %s", tag))
		} else {
			SetIP2RegionV6SourceStatus("failed", m.v6InstallError)
			WriteIP2RegionUpdateLog("WARN", string(IP2RegionStatusSuccess), fmt.Sprintf("IPv6 库更新失败（不影响 IPv4 库）: %s", m.v6InstallError))
		}
	}
	// 主节点补写.version sidecar——waffiles_sync 的
	// BuildWafFileRef（ref.IP2RegionTag）与从节点 rewriteVersionIfMissingOrStale
	// 都假设它存在。 后首写已随安装段（wafFileMu 互斥区）完成，此处
	// 为幂等补写（安装段写失败时的自愈网，同 tag 命中即跳过重写）。
	if err := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", tag); err != nil {
		Logf("error", "ip2region update: failed to write .version sidecar: %v", err)
	}
	m.mu.Lock()
	v6Summary := m.v6InstallMessageLocked()
	m.state.status = IP2RegionStatusSuccess
	m.state.message = v6Summary
	m.state.version = tag
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), fmt.Sprintf("ip2region 已更新到 %s", tag))
}

// v6InstallMessageLocked 汇总 v6 源的本次结果进任务 message（v4 成功为主语义）：
// 未尝试=空；成功=空（详情进更新日志）；失败=保留旧库并注明。调用方必须
// 已持 m.mu（字段只由运行 goroutine 写、状态读侧持 mu 读 state.message，
// 本函数只在运行 goroutine 的持锁段内取值）。
func (m *IP2RegionUpdateManager) v6InstallMessageLocked() string {
	if !m.v6InstallAttempted {
		return ""
	}
	if m.v6InstallSucceeded {
		return ""
	}
	return "IPv6 库更新失败（保留原库，不影响 IPv4）: " + m.v6InstallError
}

// advanceSlotIfAuto 落定推进排程槽（失败/取消路径）：仅 auto 触发且现存槽
// 空/过期才推进（委托 advanceVersionSlotIfDue 的「未来槽不污染」门）——手动轮
// 失败由引擎退避重投同一槽，业务不抢先推进（手动**成功**按 schedule.go 成功门
// 推进，不经过本函数）。
func (m *IP2RegionUpdateManager) advanceSlotIfAuto(trigger string) error {
	if trigger != "auto" {
		return nil
	}
	return advanceVersionSlotIfDue("security_ip2region_version")
}

// backupIP2RegionXDB 备份 live xdb：优先硬链接（同目录同文件系统零拷贝，
// 免去 ~11MB 全量读+写+两次 fsync 在 wafFileMu 内的锁占用；.bak 只被本节
// 回滚以 rename/只读复制消费，硬链接共享 inode 不影响语义——安装段用 rename
// 换目录项，旧 inode 由 .bak 继续引用）。硬链接失败（跨设备/不支持）回退
// 整文件复制（与 WriteThreatIplistCompiled 的 .fast 备份同一升级链）。
func backupIP2RegionXDB(src, dst string) error {
	if err := osLink(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

// syncInstalledVersionToState 终态（失败/取消/跳过）把 state.version 归位为
// 已安装版本：与 CRS 侧同形——run 安装前写入远端 tag，失败/取消
// 后不复位会让 status 端点把未安装的版本当作当前版本返回。
// 读故障与「读取到空值」在这里都归「unknown」，但故障必须留痕（该字段只服务
// status 展示，权威值在版本行；写回路径不得复刻此折叠，见 downloadAndInstall）。
func (m *IP2RegionUpdateManager) syncInstalledVersionToState() {
	installed, err := GetIP2RegionVersion()
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			Logf("warn", "ip2region update: 终态读取已安装版本失败（status 显示 unknown）: %v", err)
		}
		installed = ""
	}
	if installed == "" {
		installed = "unknown"
	}
	m.mu.Lock()
	m.state.version = installed
	m.mu.Unlock()
}

// rollbackAfterCancel 取消归因收尾：若本次运行的安装段已落盘但尚未重载，
// 按「未重载即未生效」回滚到同代基线（xdb 文件 + 版本行/sidecar；无本运行
// 基线时回落到 dist 并写保守标识 bundled）——与 CRS 的
// observeCancelAfterSwap 同构，避免「已取消但库其实换了、Caddy 仍按旧库」
// 的三方分叉。安装未提交（下载期取消）时为零操作，保留既有磁盘状态。
func (m *IP2RegionUpdateManager) rollbackAfterCancel() {
	if !m.installCommitted {
		return
	}
	m.installCommitted = false
	// rollbackXDB 在同一 wafFileMu 临界区内完成文件还原 + 版本行/sidecar
	// 回写（restored→prevVersion，dist 回退→bundled 哨兵）。
	if _, _, err := m.rollbackXDB(); err != nil {
		Logf("error", "ip2region update: 取消后回滚 xdb 失败（下次成功更新自愈）: %v", err)
	}
}

// cancel 记录取消终态：保留既有工件/快照，不增加连续失败计数。
// 排程槽：**用户取消自动轮**与失败同源——本槽显式放弃，预约推进到紧邻下一
// 排程槽（引擎侧取消时已消费本槽，业务不推进则该库自动更新静默停摆）。
// demote/导入排空/进程停止的取消不推进（引擎侧同样不消费槽，恢复后补跑）。
func (m *IP2RegionUpdateManager) cancel(cause error, trigger string, runCtx context.Context) {
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET update_status='cancelled', message=?, finished_at=datetime('now') WHERE id=1",
		cause.Error(),
	); err != nil {
		Logf("error", "ip2region update: failed to record cancellation: %v", err)
	}
	if userCancelledRun(runCtx) {
		// advanceSlotIfAuto 自带「仅 auto、仅空/过期槽」门；失败显式上报重试。
		m.setSlotAdvanceError(m.advanceSlotIfAuto(trigger))
	}
	m.syncInstalledVersionToState()
	m.mu.Lock()
	m.state.status = IP2RegionStatusCancelled
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteIP2RegionUpdateLog("WARN", string(IP2RegionStatusCancelled), cause.Error())
}

func (m *IP2RegionUpdateManager) fail(cause error) {
	// 连续失败计数 +1（失败趋势可观测；操作审计由 run 的 defer 单记——
	// 收敛后内联首败审计已撤）。
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET update_status='failed', message=?, finished_at=datetime('now'), consecutive_failures=consecutive_failures+1 WHERE id=1",
		cause.Error(),
	); err != nil {
		Logf("error", "ip2region update: failed to record failure: %v", err)
	}
	m.syncInstalledVersionToState()
	m.mu.Lock()
	m.state.status = IP2RegionStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteIP2RegionUpdateLog("ERROR", string(IP2RegionStatusFailed), cause.Error())
}

// downloadAndInstall downloads, validates and atomically swaps in the new xdb.
// 单任务双源形态（类似爬虫地址库多源）：needV4/needV6 按两源各自的货币性
// 传入——v4 段语义逐字保持（下载/校验/备份/rename/版本行/热换/回滚链），
// v6 段独立健康门且**失败不反噬 v4**（源状态分列落库，WARN 留痕，任务按 v4
// 结果定性）。重载失败回滚只还原 v4 基线；v6 安装成功即同 tag 有效内容，
// 保留在盘（Caddy 侧待下次成功重载生效）。
func (m *IP2RegionUpdateManager) downloadAndInstall(parent context.Context, tag string, needV4, needV6 bool) error {
	m.setStage(IP2RegionStatusDownloading, fmt.Sprintf("下载 %s", tag))
	stagingDir := filepath.Join(filepath.Dir(ip2regionLivePath), ".staging")
	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("清理 staging 目录: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("创建 staging 目录: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(stagingDir); err != nil {
			Logf("error", "ip2region update: failed to clean staging dir: %v", err)
		}
	}()

	// 每族独立 15min 下载预算（v4 既有口径不变；v6 约 35MB 同窗口），互不挤占。
	var staged, stagedV6 string
	if needV4 {
		ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
		staged = filepath.Join(stagingDir, "ip2region_v4.xdb")
		err := m.downloadXDBLogged(ctx, tag, staged)
		cancel()
		if err != nil {
			return fmt.Errorf("下载 ip2region xdb: %w", err)
		}
	}
	if needV6 {
		ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
		stagedV6 = filepath.Join(stagingDir, "ip2region_v6.xdb")
		err := m.downloadXDBV6Logged(ctx, tag, stagedV6)
		cancel()
		if err != nil {
			// v6 下载失败：记源状态后继续 v4 安装（v6 辅助源不拖垮主源）。
			m.v6InstallAttempted = true
			m.v6InstallSucceeded = false
			m.v6InstallError = fmt.Sprintf("下载失败: %v", err)
			SetIP2RegionV6SourceStatus("failed", m.v6InstallError)
			Logf("warn", "ip2region update: IPv6 库下载失败（继续 IPv4 安装）: %v", err)
			stagedV6 = ""
		}
	}

	m.setStage(IP2RegionStatusInstalling, "校验并安装数据库")
	// v4 校验：needV4 时校验 staged 新工件（既有口径）；否则校验 live 现库
	// （v4 未离位，热换 searcher 以在役内容重建——仅 v6 变更的轮次仍要热换
	// 面板 searcher 以挂载新 v6 库）。v6 侧：staged 成功用 staged（新库随
	// 热换即刻在役）；下载/校验失败回落当前 attach 路径（保留在役 v6 服务，
	// 缺失/损坏由 attach 侧健康门降级为禁用）。
	v4Source := staged
	if !needV4 {
		v4Source = ip2regionLivePath
	}
	v6ForSearcher := stagedV6
	if v6ForSearcher == "" {
		v6ForSearcher = ip2RegionV6PathForAttach()
	}
	validatedSearcher, err := openValidatedIP2RegionSearcherForUpdate(v4Source, v6ForSearcher)
	if err != nil {
		if needV4 {
			return fmt.Errorf("校验 ip2region xdb: %w", err)
		}
		// v6 附加失败（stagedV6 已在 openIP2RegionV6Config 内降级为 nil——
		// 此分支实为 live v4 校验失败，与 v4 缺失/损坏同形，按失败落定。
		return fmt.Errorf("校验在役 ip2region xdb: %w", err)
	}
	searcherInstalled := false
	defer func() {
		if !searcherInstalled {
			validatedSearcher.Close()
		}
	}()
	if needV4 {
		// 记录新工件摘要，供回滚全败时 fail-open 前置校验。
		if sum, sumErr := sha256File(staged); sumErr == nil {
			m.newXdbSha = sum
		} else {
			m.newXdbSha = ""
		}
		// TOFU 完整性基线在格式验证成功之后记录：验证前的坏工件留下基线
		// 会让下次同 tag 好下载误报。I/O 类记录失败不阻断安装；mismatch 必须中止
		// 安装并保留旧基线。
		if ierr := recordDownloadIntegrity(ip2RegionXDBBaselineKey(tag), staged, "IP数据库"); ierr != nil {
			if errors.Is(ierr, errDownloadIntegrityMismatch) {
				return ierr
			}
			Logf("error", "ip2region update: failed to record download integrity: %v", ierr)
		}
	}
	if stagedV6 != "" {
		// v6 显式校验门（与 v4 的 openValidatedIP2RegionSearcherForUpdate 同
		// 强度）：双协议 searcher 构造对损坏 v6 是「降级禁用」语义（不报错），
		// 安装段必须独立显性校验——不合格工件到此拒装并记源失败，绝不 rename
		// 进 live（否则损坏 v6 会在役且源状态误报 success）。
		if verr := validateIP2RegionV6XDB(stagedV6); verr != nil {
			m.v6InstallAttempted = true
			m.v6InstallSucceeded = false
			m.v6InstallError = fmt.Sprintf("校验失败: %v", verr)
			SetIP2RegionV6SourceStatus("failed", m.v6InstallError)
			Logf("warn", "ip2region update: IPv6 库校验失败（拒绝安装，继续 IPv4 安装）: %v", verr)
			stagedV6 = ""
		}
	}
	if stagedV6 != "" {
		// v6 TOFU 基线（独立键，与 v4 基线互不覆盖）。mismatch 拒装 v6
		//（记源状态，v4 不受影响）；I/O 类记录失败降级为留痕。
		if ierr := recordDownloadIntegrity(ip2RegionXDBOriginURLFor("v6", tag), stagedV6, "IP数据库"); ierr != nil {
			if errors.Is(ierr, errDownloadIntegrityMismatch) {
				m.v6InstallAttempted = true
				m.v6InstallSucceeded = false
				m.v6InstallError = fmt.Sprintf("完整性校验失败: %v", ierr)
				SetIP2RegionV6SourceStatus("failed", m.v6InstallError)
				Logf("warn", "ip2region update: IPv6 库完整性基线不匹配（拒绝安装，继续 IPv4 安装）: %v", ierr)
				stagedV6 = ""
			} else {
				Logf("error", "ip2region update: failed to record v6 download integrity: %v", ierr)
			}
		}
	}

	// 1.2：rename 前备份旧 xdb，reloader 失败时可回滚（镜像 CRS 的
	// restoreBackup 路径），与 CRS 更新侧保持对称。
	// 备份+rename 是 wafFileMu 互斥的安装文件段（网络下载在锁外
	// staging 先行；内存热换在锁外）——与 lbbak 导入直写/集群同步落盘串行，
	// 杜绝撕裂 xdb 与元数据瞬时错位。v4 与 v6 的备份/rename/版本写入同处
	// 一个临界区：导出读相位只看到「全旧代」或「全新代」，不发布混合代。
	// 安装前读取版本行：读故障不得折叠成 "unknown" 哨兵继续安装——
	// 重载失败回滚时会把真实 tag 覆写成哨兵（非空故通过 prevVersion 门），
	// 版本溯源丢失且下轮按哨兵重装。读故障按安装失败落定（任务内重试可吸收
	// 瞬时 DB 故障）；行缺失（ErrNoRows）等价「无既有版本」，留空串让回滚
	// 不写版本行。与 GetIP2RegionVersion 的错误语义同源（读故障 vs 行缺失）。
	// 仅 needV4 时读取（v4 未离位的轮次无回滚语义，见下方 reloadErr 分支）。
	if needV4 {
		prevVersion, verr := GetIP2RegionVersion()
		if verr != nil && !errors.Is(verr, sql.ErrNoRows) {
			return fmt.Errorf("读取安装前 IP2Region 版本行: %w", verr)
		}
		m.prevVersion = prevVersion
	}
	liveBak := ip2regionLivePath + ".bak"
	wafFileMu.Lock()
	if needV4 {
		if _, err := os.Stat(ip2regionLivePath); err == nil {
			if err := backupIP2RegionXDB(ip2regionLivePath, liveBak); err != nil {
				wafFileMu.Unlock()
				return fmt.Errorf("备份旧 ip2region xdb: %w", err)
			}
			m.bakCreated = true
		}
		if err := osRename(staged, ip2regionLivePath); err != nil {
			// 安装未发生：仅清理本运行创建的备份（——无 bakCreated 守
			// 卫时 fresh-install 会删除跨运行的陈旧 .bak，而该备份是崩溃现场唯一
			// 恢复副本；陈旧 bak 本就不会被 rollback 消费）。
			if m.bakCreated {
				os.Remove(liveBak)
			}
			wafFileMu.Unlock()
			return fmt.Errorf("安装 ip2region xdb: %w", err)
		}
		// rename 后同步父目录项（与 writeFileAtomicSynced 同口径）——掉电
		// 窗口内未持久化的目录项会让重启看到旧/缺失的 live 文件。同步失败
		// 无法回退已完成的 rename，仅记错误（持久性降级，非功能性失败）。
		if err := syncParentDir(ip2regionLivePath); err != nil {
			Logf("error", "ip2region update: 安装段父目录同步失败（掉电持久性降级）: %v", err)
		}
		// 版本行与.version sidecar 收进安装段同一互斥
		// 区——此前在锁外 run() 成功路径，写相位中段（xdb 已换、行/sidecar 未写）
		// 导出侧（BuildWafFileBundle/BuildWafFileRef 读相位持同一锁）可打出「文件
		// 新/行旧」偏斜并沿 waf_files 通道扩散。单行 UPDATE+小文件原子写毫秒级，
		// 与段内 rename 同量级，不新增锁内长阻塞。写失败仅记日志：run() 成功路径
		// 稍后重写全量行与 sidecar，重载失败 restored 分支用 prevVersion 回滚
		// （prevVersion 已在进入互斥段前按「读故障 vs 行缺失」语义取好）。
		if _, err := db.DB.Exec(
			"UPDATE security_ip2region_version SET version=?, updated_at=datetime('now') WHERE id=1",
			tag,
		); err != nil {
			Logf("error", "ip2region update: 安装段写入版本行失败（稍后重写）: %v", err)
		}
		if err := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", tag); err != nil {
			Logf("error", "ip2region update: 安装段写入 .version sidecar 失败（稍后重写）: %v", err)
		}
		// 安装段已落盘（xdb 已 rename、版本行/sidecar 已写）：此后到重载之间的
		// 取消必须回滚到同代基线，见 installCommitted 契约。
		m.installCommitted = true
	}
	if stagedV6 != "" {
		// v6 安装段（同一临界区）：备份旧 v6 → rename → sidecar。失败记源
		// 状态后继续（不回滚 v4 已完成的 rename——v4 段自身已一致）。
		v6Bak := ip2regionV6LivePath + ".bak"
		if _, err := os.Stat(ip2regionV6LivePath); err == nil {
			if err := backupIP2RegionXDB(ip2regionV6LivePath, v6Bak); err != nil {
				m.recordV6InstallFailureLocked(fmt.Errorf("备份旧 IPv6 库: %w", err))
			} else {
				m.v6BakCreated = true
			}
		}
		if !m.v6InstallAttempted {
			if err := osRename(stagedV6, ip2regionV6LivePath); err != nil {
				if m.v6BakCreated {
					os.Remove(v6Bak)
				}
				m.recordV6InstallFailureLocked(fmt.Errorf("安装 IPv6 库: %w", err))
			} else {
				if err := syncParentDir(ip2regionV6LivePath); err != nil {
					Logf("error", "ip2region update: v6 安装段父目录同步失败（掉电持久性降级）: %v", err)
				}
				if err := rewriteVersionIfMissingOrStale(ip2regionV6LivePath+".version", tag); err != nil {
					// sidecar 写失败不回退已完成的 rename（下次成功更新/启动
					// 种子同步自愈）；集群 ref 的 v6 tag 读自 sidecar，缺失按
					// 「主端未声明 v6」处理，不阻塞 v4 通道。
					Logf("error", "ip2region update: 安装段写入 v6 .version sidecar 失败（稍后重写）: %v", err)
				}
				m.v6InstallAttempted = true
				m.v6InstallSucceeded = true
			}
		}
	}
	wafFileMu.Unlock()
	// rename 后内存热换失败不得静默吞掉——磁盘已是新库而内存仍是旧
	// 库，必须按安装失败处理（sentinel 标记），由 run() 走与 reloader 失败相同
	// 的回滚路径。Reload 失败时旧 searcher 保持服役（ip2region.go Reload 语义）。
	// needV4=false 的轮次无 v4 回滚语义（v4 未离位，dist 回退会错误降级 v4），
	// 由 run() 的 reloadErr 分支按「无需回滚」处理。
	if err := reloadIP2RegionSearcher(validatedSearcher); err != nil {
		if !needV4 {
			return fmt.Errorf("%w: %v（IPv6 库已落盘，待下次成功重载生效）", errIP2RegionReload, err)
		}
		return fmt.Errorf("%w: %v", errIP2RegionReload, err)
	}
	searcherInstalled = true
	return nil
}

// recordV6InstallFailureLocked 记录 v6 安装段失败（调用方须持 wafFileMu——
// 仅字段写入，锁口径与安装段一致便于内联调用）。
func (m *IP2RegionUpdateManager) recordV6InstallFailureLocked(cause error) {
	m.v6InstallAttempted = true
	m.v6InstallSucceeded = false
	m.v6InstallError = cause.Error()
	SetIP2RegionV6SourceStatus("failed", m.v6InstallError)
	Logf("warn", "ip2region update: IPv6 库安装段失败（继续 IPv4 安装）: %v", cause)
}

// downloadXDBLogged 包装下载 seam 写更新日志（口径同 CRS 的
// downloadTarballLogged）：开始行携带完整来源 URL（含 GitHub 加速代理前缀，
// 代理取值经 github_proxy_url 白名单），
// 已知时附预计大小；进度行按 10%/5MB 节流步进；完成行记录落盘
// 字节与耗时。stage 沿用下载阶段的 downloading。
func (m *IP2RegionUpdateManager) downloadXDBLogged(ctx context.Context, tag, destPath string) error {
	return m.downloadXDBLoggedFamily(ctx, "v4", tag, destPath)
}

// downloadXDBV6Logged 是 IPv6 数据源的下载日志包装（与 v4 同形，URL/族名
// 不同——进度行可区分两源）。
func (m *IP2RegionUpdateManager) downloadXDBV6Logged(ctx context.Context, tag, destPath string) error {
	return m.downloadXDBLoggedFamily(ctx, "v6", tag, destPath)
}

func (m *IP2RegionUpdateManager) downloadXDBLoggedFamily(ctx context.Context, family, tag, destPath string) error {
	logLine := func(message string) { WriteIP2RegionUpdateLog("INFO", string(IP2RegionStatusDownloading), message) }
	startedAt := time.Now()
	progress := newDownloadProgressLogger(ip2RegionXDBSourceURLFor(family, tag), logLine)
	var err error
	if family == "v4" {
		err = m.downloadXDB(ctx, tag, destPath, progress)
	} else {
		err = m.downloadXDBV6(ctx, tag, destPath, progress)
	}
	if err != nil {
		return err
	}
	logDownloadCompletion(logLine, destPath, startedAt)
	return nil
}

// rollbackXDB 将本次更新前备份的旧 xdb 还原到 live 路径并热换内存 searcher
// （1.2，镜像 CRS 的 restoreBackup）。返回 restored=true 表示磁盘已
// 回到「更新前基线」，调用方按 failed+旧版本落库即磁盘/DB 一致；restored=false
// 且 err=nil 表示无任何基线可用，由调用方按 fail-open 处理。
//
// 基线优先级：本运行创建的 .bak > dist 发行版副本。陈旧 .bak（跨运行崩溃窗口
// 的保全副本）永不消费；bakCreated==false 时回退到 ip2regionDistPath
// ——全新部署首次更新无旧 live 可备份，dist 即「更新前状态」的权威副本。dist
// 也缺失时不做任何改动，返回 restored=false。
//
// .bak 还原升级链：rename 失败（非权限类的瞬时故障，如偶发 IO
// 错误）不等于基线丢失——.bak 仍在磁盘，升级为 copyFile 还原；权限类失败
// （目录不可写）下 copyFile 需要同一目录的写权限、必然同败，会直接落到 dist
// 回退；全部失败才返回 error，由调用方走 fail-open（DB 必须跟随实际状态，
// 不得记 failed+旧版本重演三方分叉）。
//
// 任一级的磁盘还原一旦成功即「该级成功」，内存热换失败不再升级
// rename 会消费 .bak，升级后 copy 级必然失败、dist 必然执行，而 dist 是镜像
// 捆绑的旧版本，会覆盖已正确还原的更新前基线——磁盘(dist 旧版)≠DB(failed+
// 旧版本)分叉且基线不可恢复。热换失败只记 warn 并返回 restored=true：Reload
// 失败时旧 searcher 保持服役、磁盘已还原为基线；若安装阶段热换曾成功，内存
// searcher 以新数据滞后，在下次更新安装或重启后收敛（无周期性 reload；
// Caddy 侧 geoip 强制随 reloader 重试收敛）。dist 级同口径
// dist copy 成功后磁盘=dist 基线，fail-open 前提「磁盘已是新库」不成立，
// 热换失败同样 warn + restored=true；仅 dist copy 本身失败（磁盘未动、仍
// 是新库）才返回 error，由调用方走 fail-open。
func (m *IP2RegionUpdateManager) rollbackXDB() (restored bool, distRestore bool, err error) {
	// 回滚三件套（文件还原 + 版本行/sidecar 回写）收在同一 wafFileMu 临界区内，
	// 与安装段同构：读相位（BuildWafFileRef/BuildWafFileBundle）只看到旧代或
	// 新代，不会打出「xdb 旧/行新」或「xdb 新/sidecar 旧」的混合代沿
	// lbbak/集群通道扩散。内存热换（reloadIP2RegionSearcher）与调用方的
	// reloader 一律留在锁外。
	wafFileMu.Lock()
	restored, distRestore, err = m.rollbackFilesLocked()
	if err == nil {
		switch {
		case distRestore:
			m.writeDistRollbackMarkersLocked()
		case restored:
			m.restorePreviousVersionRowLocked()
		}
	}
	wafFileMu.Unlock()
	if restored || distRestore {
		searcher, openErr := openValidatedIP2RegionSearcher(ip2regionLivePath)
		if openErr != nil {
			Logf("error", "ip2region update: reload after rollback failed (%v); disk baseline restored; keeping the current searcher", openErr)
		} else if rErr := reloadIP2RegionSearcher(searcher); rErr != nil {
			searcher.Close()
			// 磁盘已是基线，热换失败不得反转回滚结论：旧 searcher 保持服役；
			// 若安装阶段热换曾成功，内存 searcher 以新数据滞后，在下次更新或重启收敛。
			Logf("error", "ip2region update: reload after rollback failed (%v); disk baseline restored; if the install-time hot-swap succeeded, the in-memory searcher lags until the next update install or restart (Caddy-side geoip converges with the reloader)", rErr)
		}
	}
	return restored, distRestore, err
}

// rollbackFilesLocked 文件级回滚（调用方须持 wafFileMu）：.bak 的
// rename/copy 两级与 dist 回退三级升级链。
func (m *IP2RegionUpdateManager) rollbackFilesLocked() (restored bool, distRestore bool, err error) {
	if m.bakCreated {
		bak := ip2regionLivePath + ".bak"
		if _, err := os.Stat(bak); err == nil {
			if renameErr := osRename(bak, ip2regionLivePath); renameErr == nil {
				return true, false, nil
			} else {
				Logf("error", "ip2region update: rename bak to live failed (%v), trying copy restore (permission-class failures will fall through to dist)", renameErr)
			}
			if copyErr := copyFile(bak, ip2regionLivePath); copyErr == nil {
				// copy 还原不消费 .bak：磁盘还原成功后清理，与 rename 消费语
				// 义对齐，避免残留陈旧副本干扰后续运行判断。
				if rErr := os.Remove(bak); rErr != nil {
					Logf("error", "ip2region update: failed to remove bak after copy restore: %v", rErr)
				}
				return true, false, nil
			} else {
				Logf("error", "ip2region update: copy restore from bak failed: %v", copyErr)
			}
		}
	}
	if _, err := os.Stat(ip2regionDistPath); err != nil {
		return false, false, nil
	}
	if _, statErr := os.Stat(ip2regionLivePath); statErr == nil {
		// dist 回退前提：live 仍为普通文件；目录/缺失形态不得 copyFile 覆盖。
		if info, ierr := os.Stat(ip2regionLivePath); ierr != nil || info.IsDir() {
			return false, false, fmt.Errorf("回退到发行版前 live xdb 形态异常: %v", ierr)
		}
	}
	if err := copyFile(ip2regionDistPath, ip2regionLivePath); err != nil {
		return false, false, fmt.Errorf("回退到发行版 ip2region xdb: %w", err)
	}
	return true, true, nil
}

// failOpenPreconditionHolds 校验 fail-open 前置：live 为普通文件、
// 摘要等于本次新工件、且 validateIP2RegionXDB 通过。
func (m *IP2RegionUpdateManager) failOpenPreconditionHolds() bool {
	info, err := os.Lstat(ip2regionLivePath)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if m.newXdbSha == "" {
		return false
	}
	sum, err := sha256File(ip2regionLivePath)
	if err != nil || sum != m.newXdbSha {
		return false
	}
	return validateIP2RegionXDB(ip2regionLivePath) == nil
}

// restorePreviousVersionRow 回写事件前版本行与 sidecar（失败仅日志）。
// 行与 sidecar 在同一 wafFileMu 临界区内完成——读相位不会看到「文件旧/标签新」。
func (m *IP2RegionUpdateManager) restorePreviousVersionRow() {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	m.restorePreviousVersionRowLocked()
}

// restorePreviousVersionRowLocked 是调用方已持 wafFileMu 的实现。
//
// 无可回写的既有版本（行缺失或 version 为空串）时不得冒称任何 tag：磁盘已还原为
// 更新前字节，版本行/sidecar 若停留在安装段写入的新 tag，就是「磁盘旧 / 行新」，
// 且下一轮 tag == currentVersion 会命中「已是最新」短路——磁盘上的旧库再也不会
// 被替换（自愈通道永久关闭，GeoIP 按旧库判决而面板显示新版本）。与 dist 回退
// 分支同构写保守标识 bundled：「版本不可知」只有一种表达，下次远端数值 tag 可
// 重新建立基线。
func (m *IP2RegionUpdateManager) restorePreviousVersionRowLocked() {
	if m.prevVersion == "" {
		m.writeDistRollbackMarkersLocked()
		return
	}
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET version=?, updated_at=datetime('now') WHERE id=1", m.prevVersion); err != nil {
		Logf("error", "ip2region update: 回滚版本行失败（下次成功更新自愈）: %v", err)
	}
	if err := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", m.prevVersion); err != nil {
		Logf("error", "ip2region update: 回滚 .version sidecar 失败（下次成功更新自愈）: %v", err)
	}
}

// writeDistRollbackMarkers dist 回退后写保守标识 bundled（已装载内置库，
// 版本不可知；不得冒称 prevVersion），下次远端数值 tag 可建立基线。
// 行与 sidecar 同 wafFileMu 临界区，与 restorePreviousVersionRow 同构。
// 「更新前版本不可知」（行缺失或版本为空串的回滚）复用同一标识——两种形态
// 的事实相同：磁盘上的库不是任何已知 tag，版本行不得声称是。
func (m *IP2RegionUpdateManager) writeDistRollbackMarkers() {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	m.writeDistRollbackMarkersLocked()
}

// writeDistRollbackMarkersLocked 是调用方已持 wafFileMu 的实现。
func (m *IP2RegionUpdateManager) writeDistRollbackMarkersLocked() {
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET version='bundled', updated_at=datetime('now') WHERE id=1"); err != nil {
		Logf("error", "ip2region update: 写入 dist 回退标识失败: %v", err)
	}
	if err := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", "bundled"); err != nil {
		Logf("error", "ip2region update: 写入 dist 回退 sidecar 失败: %v", err)
	}
}

// successAfterReloadFailOpen 在「reloader 失败但无任何回退基线」时按成功落库
// 磁盘已是新库，DB 记录 success+新 tag 让三方一致；
// message 保留 reloader 错误以便排查 Caddy 侧问题，审计同样记成功但附带上该
// 警告。落库前与 restored 分支对称补一次 reloader 重试：重试成功
// 则 Caddy 即刻追上新库、按无警告成功落库；仍失败则在 message 中注明 Caddy
// 侧 GeoIP 停留在旧库、待下次任意成功重载后生效。rbErr 非 nil（回滚升级链全
// 部失败）时 message 还须携带回滚失败根因——仅进组件日志会让运维
// 误判为纯重载问题。memSwitched=false（安装热换失败）时 message 还
// 须注明内存 searcher 未切换、重启后生效——否则 DB 记 success 而内存仍是旧库，
// 重启前无任何可见痕迹。
func (m *IP2RegionUpdateManager) successAfterReloadFailOpen(tag string, reloadErr, rbErr error, memSwitched bool) {
	warn := ""
	// 同上 nil 守卫（非生产路径；语义与 CRS 一致：nil=跳过）。
	var rErr error
	if m.reloader != nil {
		rErr = m.reloader()
		recordSystemReloadAudit("ip2region_update", rErr)
	}
	if rErr != nil {
		Logf("error", "ip2region update: fail-open reload retry failed: %v", rErr)
		warn = fmt.Sprintf("已生效，但重载 Caddy 配置失败: %v（Caddy 侧待下次重载生效）", reloadErr)
	} else {
		Logf("info", "ip2region update: fail-open reload retry succeeded, caddy caught up to %s", tag)
	}
	if rbErr != nil {
		if warn != "" {
			warn += "；"
		}
		warn += fmt.Sprintf("回滚旧库失败: %v", rbErr)
	}
	if !memSwitched {
		if warn != "" {
			warn += "；"
		}
		warn += "内存 searcher 未切换，重启后生效"
	}
	// 触发来源单次快照：成功门两次绑定同一值（两次读取间不得出现翻转）。
	trigger := m.currentTrigger()
	slotSQL, slotArgs, slotErr := versionTableSlotSuccessAssign("security_ip2region_version", trigger)
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET version=?, updated_at=datetime('now'), update_status='success', message=?, finished_at=datetime('now'), consecutive_failures=0, "+slotSQL+" WHERE id=1",
		append([]any{tag, warn}, slotArgs...)...,
	); err != nil {
		// fail-open 成功同属成功轮：状态行没落地即本轮失败（槽也未推进），
		// 并入同一通道让引擎退避重投。
		slotErr = errors.Join(slotErr, fmt.Errorf("%w: 状态行写入失败: %w", errScheduleSlotNotAdvanced, err))
	}
	m.setSlotAdvanceError(slotErr)
	if err := SetIP2RegionVersion(tag); err != nil {
		Logf("error", "ip2region update: failed to store version: %v", err)
	}
	// fail-open 成功同样补写 sidecar（与 success() 同因）。
	if err := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", tag); err != nil {
		Logf("error", "ip2region update: failed to write .version sidecar: %v", err)
	}
	m.mu.Lock()
	m.state.status = IP2RegionStatusSuccess
	m.state.message = warn
	m.state.version = tag
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	WriteIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), fmt.Sprintf("ip2region 已更新到 %s（%s）", tag, warn))
}

// openValidatedIP2RegionSearcherForUpdate 让更新用例测量完整装载次数；
// 生产默认与统一校验入口一致（显式双路径：v4 必选、v6 可选附加）。
var openValidatedIP2RegionSearcherForUpdate = openValidatedIP2RegionSearcherDual

// openValidatedIP2RegionSearcherDual 是「可装载」统一校验入口的显式双路径
// 变体：v4 结构自检 + 探针搜索 + panic 收敛（openValidatedIP2RegionSearcher
// 同强度），v6 路径非空时经独立健康门附加（损坏 v6 降级禁用，不影响 v4）。
func openValidatedIP2RegionSearcherDual(v4Path, v6Path string) (searcher *ip2regionService.Ip2Region, err error) {
	defer func() {
		if r := recover(); r != nil {
			if searcher != nil {
				searcher.Close()
				searcher = nil
			}
			Logf("error", "ip2region: probe search panicked on %s: %v\n%s", v4Path, r, debug.Stack())
			err = fmt.Errorf("探针搜索触发内部异常（文件损坏）: %v", r)
		}
	}()
	return openIP2RegionSearcherDual(v4Path, v6Path)
}

// validateIP2RegionXDB opens the staged xdb and performs a probe search.
// recover 兜底：结构自检门只覆盖已知布局（头/向量索引/段索引指针），绑定库
// 对内容缓冲区的其余无边界切片（段数据 dataPtr 带外等）仍以 panic 呈现
// ——校验必须把 panic 转成错误并留堆栈，绝不让待安装工件崩溃进程。
func validateIP2RegionXDB(path string) error {
	searcher, err := openValidatedIP2RegionSearcher(path)
	if err != nil {
		return fmt.Errorf("校验 ip2region xdb: %w", err)
	}
	searcher.Close()
	return nil
}

// CancelRunning 取消当前运行中的更新（下载阶段中断）。无运行中任务返回 false。
// 调用方只有用户取消通道（引擎 CancelHook／前端取消入口）——取消原因标记为
// ErrUserCancelled，取消终态据此把排程槽推进到下一槽。
func (m *IP2RegionUpdateManager) CancelRunning() bool {
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
