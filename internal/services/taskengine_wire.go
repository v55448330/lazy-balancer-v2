package services

// 任务引擎接线（v2.0 四类型标准）：Kind 决定调度/记录/日志——零 flag。
// 定时(4)：NextSlotFn 排程槽驱动，Run 纯业务（无到期检查）
// 常驻(3)：Run 阻塞自管理循环，引擎仅管生命周期
// 循环(8)：IntervalFn 固定间隔，每轮独立执行+记录
// 触发(1)：仅手动/代码触发
// cert-waiting-ca：默认调度关闭——cert-renewal-scan 入队时唤醒，全部终态自动停。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

var taskEngine *taskengine.Engine

// configLoadRerun 系统配置载入手动重载钩子（main 注入：DB 渲染→强制应用）。
// operator 透传（L1-66-03）：手动重载归因操作者，启动 BootSync 传空。
var configLoadRerun func(operator string) error

// SetConfigLoadRerun 注入手动重载实现。
func SetConfigLoadRerun(fn func(operator string) error) { configLoadRerun = fn }

// B（第 65 轮后裁定·完全标准化）：常驻服务真实生命周期挂钩——daemon Run
// start→阻塞→deferred stop，调度开关/角色翻转即真实启停服务。
var (
	syncLifecycleStart, syncLifecycleStop                 func()
	certIssuanceLifecycleStart, certIssuanceLifecycleStop func()
)

// SetSyncLifecycleHooks 注入集群同步真实启停（main: syncService.Start/Stop）。
func SetSyncLifecycleHooks(start, stop func()) { syncLifecycleStart, syncLifecycleStop = start, stop }

// SetCertIssuanceLifecycleHooks 注入证书签发真实启停（main: lifecycle.StartACME/StopACME）。
func SetCertIssuanceLifecycleHooks(start, stop func()) {
	certIssuanceLifecycleStart, certIssuanceLifecycleStop = start, stop
}

// daemonLifecycleRun 常驻生命周期包装：start→阻塞 ctx→stop（nil 挂钩=测试
// 环境空载体回退）。stop 恒执行（deferred）——StopLoop/角色翻转即真实停服。

func daemonLifecycleRun(rc taskengine.RunContext, start, stop func()) error {
	if start != nil {
		start()
	}
	<-rc.Ctx.Done()
	if stop != nil {
		stop()
	}
	return nil
}

// certJobsActiveFn 测试缝（F-L4-68-01 竞态序列注入用）；生产=certJobsActive。
var certJobsActiveFn = certJobsActive

// TaskEngine 返回全局引擎实例（未初始化返回 nil——测试环境）。
func TaskEngine() *taskengine.Engine { return taskEngine }

// parseUTCSlot 解析 DB 存的 UTC 排程串为 time.Time（crsTimeLayout 与
// RFC3339 双形态——与 localDisplayUTC 同口径）。
func parseUTCSlot(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{crsTimeLayout, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// slotCoveredByRun 排程槽是否已被一次执行覆盖（task_runs 存在 started_at≥槽
// 的行——started_at 按配置时区落库，槽统一转同格式比较）。
func slotCoveredByRun(taskID string, slot time.Time) bool {
	if db.DB == nil || slot.IsZero() {
		return false
	}
	var n int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=? AND started_at >= ?`,
		taskID, slot.In(CurrentLocation()).Format("2006-01-02 15:04:05")).Scan(&n)
	return n > 0
}

// coveredSlotStepPast 已覆盖的过去槽步进到排程配置的下一未来槽；未覆盖原样
// 返回（停机追补保留）。U1-P2-2 修复：失败不推进 next_update（2026-09-25
// 裁定保持）时引擎不重触发——感知在引擎侧，管理器与三钉测试零改动。
func coveredSlotStepPast(taskID, table string, slot time.Time) time.Time {
	if slot.IsZero() || slot.After(time.Now()) || !slotCoveredByRun(taskID, slot) {
		return slot
	}
	days, hhmm := versionTableSchedule(table)
	return NextScheduledSlot(time.Now(), days, hhmm, CurrentLocation())
}

func crsNextSlotAware() time.Time {
	return coveredSlotStepPast("crs", "security_crs_version", parseUTCSlot(GetCRSUpdateManager().NextScheduledSlot()))
}

func ip2regionNextSlotAware() time.Time {
	return coveredSlotStepPast("ip2region", "security_ip2region_version", parseUTCSlot(GetIP2RegionUpdateManager().NextScheduledSlot()))
}

// InitTaskEngine 建引擎、恢复孤儿运行、注册全部 16 任务并启动默认循环。
// TASK-L8（第 69 轮）：非幂等——调用方保证单次装配；重复调用前须先
// StopTaskEngine（否则旧 scheduleLoop goroutine 泄漏、双引擎双写 task_runs）。
// 测试环境须先 db.Initialize。
func InitTaskEngine(watchdogAdminURL, runtimeLogFile string) *taskengine.Engine {
	taskengine.SetLocation(CurrentLocation())
	logsDir := "/app/logs"
	if runtimeLogFile != "" {
		logsDir = filepath.Dir(runtimeLogFile)
	}
	tasksLogDir := filepath.Join(logsDir, "tasks")
	_ = os.MkdirAll(tasksLogDir, 0755)
	taskengine.SetLogDir(tasksLogDir)
	taskEngine = taskengine.NewEngine(taskengine.Options{})
	// 角色种子（v2.0 角色门前置）：按 DB 角色初始化——从节点不瞬启
	// master-only daemon（否则 boot 行噪音：启动→SetRole 停止）。
	// U1-P2-1 修复：曾在此前多建一个引擎（种子落在被弃实例上失效+泄漏）。
	var roleMaster int
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&roleMaster); err == nil {
		taskEngine.SetRole(roleMaster == 1)
	}
	_ = taskEngine.RecoverOrphans()

	// ============ 循环（8）============

	// 看门狗：60s 一致性检查（漂移/恢复+小时级心跳——一致轮不逐轮记录）
	watchdogAdminURLValue = watchdogAdminURL
	taskEngine.Register(taskengine.Descriptor{
		ID:          "config-watchdog",
		Family:      "system",
		Name:        "配置漂移看门狗",
		Description: "每 60 秒比对运行中 Caddy 配置与数据库期望配置，漂移时面板横幅告警（恢复经手动重启）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 60 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			WatchdogCheckOnce()
			return nil
		},
	})

	// 运行日志清理：每日
	logFile := runtimeLogFile
	taskEngine.Register(taskengine.Descriptor{
		ID:          "log-cleanup",
		Family:      "system",
		Name:        "日志清理与轮转",
		Description: "清理超保留期的应用日志轮转副本（app.log.*）；统一清理任务日志（tasks/*.log：超保留期删除、超大小上限轮转保一份）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			if logFile != "" {
				res := RuntimeLogCleanupOnce(logFile)
				months := 3
				if database := db.GetDB(); database != nil {
					var m int
					if err := database.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&m); err == nil && m >= 1 {
						months = m
					}
				}
				summary := fmt.Sprintf("日志清理完成：应用日志副本删除 %d 个（保留 %d 月，无过期为 0）；%s", res.AppRemoved, months, res.TaskLogs.Summary())
				// F-L3-68-01（第 68 轮审计）：daemon 停机时的 waf-audit 兜底
				// 动作如实进任务日志（2026-10-01 用户裁定：清理了哪个文件
				// 必须可见）；无动作时不加尾段，日志行形态不变。
				if len(res.WafAudit) > 0 {
					summary += "；waf-audit 兜底：" + strings.Join(res.WafAudit, "、")
				}
				TaskLogf("log-cleanup", "cleanup", "%s", summary)
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID:          "audit-retention",
		Family:      "system",
		Name:        "审计日志保留清理",
		Description: "按「审计保留月数」配置删除 audit 库过期操作日志（基础设置可调）；并清理 90 天前的任务运行历史（task_runs）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			auditDeleted := CleanupAuditLogs()
			runsDeleted := taskengine.PurgeTaskRuns(90)
			TaskLogf("audit-retention", "cleanup", "清理完成：审计日志 %d 条、任务运行历史 %d 行（无过期数据时为 0）", auditDeleted, runsDeleted)
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID:          "security-events-retention",
		Family:      "system",
		Name:        "安全事件保留清理",
		Description: "按保留期配置删除 metrics 库中过期的安全事件记录",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			deleted := SecurityEventsRetentionCleanupOnce()
			TaskLogf("security-events-retention", "cleanup", "安全事件保留清理完成：删除 %d 条（保留期与条数上限，无过期为 0）", deleted)
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-renewal-scan", Family: "certificates", Name: "证书续期扫描",
		Description: "扫描全部证书配置的到期时间，临期证书自动入队续签；入队时唤醒 CA 等待补扫",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			CertRenewalScanOnce()
			// 入队即唤醒 CA 等待补扫（默认调度关闭——有活自动开启）
			if certJobsActiveFn() {
				taskEngine.StartLoop("cert-waiting-ca")
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-reconcile", Family: "certificates", Name: "证书状态对账",
		Description: "核对证书文件与数据库状态一致性，修复中断任务残留的中间态",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { CertReconcileOnce(); return nil },
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-manual-poll", Family: "certificates", Name: "手动证书任务轮询",
		Description: "处理手工触发或重试的证书任务",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 10 * time.Minute },
		Run:        func(rc taskengine.RunContext) error { CertManualCheckOnce(); return nil },
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-waiting-ca", Family: "certificates", Name: "CA 等待补扫",
		Description: "证书任务在途时的兜底补扫：CA 冷却到期重排、滞留 queued 重入队、断链部署重试重建。默认调度关闭——续期扫描入队时自动开启，全部终态自动停止",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 30 * time.Second },
		StatusFn: func() string {
			if certJobsActiveFn() {
				return "running"
			}
			if te := TaskEngine(); te != nil && te.IsRunning("cert-waiting-ca") {
				return "idle"
			}
			return "stopped"
		},
		NextSlotFn: func() time.Time { // 有等待任务时展示最近 CA 可用时间
			var at string
			if err := db.DB.QueryRow(`SELECT COALESCE(MIN(NULLIF(ca_available_after,'')),'') FROM cert_jobs WHERE status='waiting_ca'`).Scan(&at); err != nil {
				return time.Time{}
			}
			return parseUTCSlot(at)
		},
		Run: func(rc taskengine.RunContext) error {
			if !certJobsActiveFn() {
				// 全部终态——自动关闭调度（回到默认关闭态）。
				// F-L4-68-01（第 68 轮）：StopLoop 后复检——首查（T0）到停调度
				// 之间的入队（T1）若经入队侧 StartLoop 先落地，会被本次 StopLoop
				// 覆盖成「任务活跃但调度已停」死态；复检捕获则重新拉回（复检
				// 之后的新入队由入队侧 StartLoop 承担，窗口闭合）。
				taskEngine.StopLoop("cert-waiting-ca")
				if certJobsActiveFn() {
					taskEngine.StartLoop("cert-waiting-ca")
					return nil
				}
				TaskLogf("cert-waiting-ca", "idle", "证书任务全部终态，自动停止补扫")
				return nil
			}
			CertWaitingCATickOnce()
			return nil
		},
	})

	// ============ 常驻（3）============

	// 安全事件摄取：自管理 2s 尾读循环（引擎仅管生命周期）
	taskEngine.Register(taskengine.Descriptor{
		ID:          "security-events-ingestion",
		Family:      "system",
		Name:        "安全事件采集",
		Description: "尾读 coraza WAF 审计日志并摄取为安全事件（安全总览/事件页的数据源），含审计日志轮转跟随",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run:         func(rc taskengine.RunContext) error { return runIngestionLoop(rc.Ctx) },
	})

	// 证书签发：daemonLifecycleRun 真实生命周期挂钩（StartACME/StopACME——
	// 队列+证书 worker+active 指针随调度开关/角色启停；幂等守卫吸收角色链
	// 双调用）。RunsOn=MasterOnly：从节点禁签发——daemon 不在从节点启动
	// （promote 经 SetRole 自动拉起），状态显示实态（从节点=空闲）。
	taskEngine.Register(taskengine.Descriptor{
		ID:          "cert-issuance",
		Family:      "certificates",
		Name:        "证书签发",
		Description: "ACME 证书签发队列——含新签发与续签（由证书任务队列调度，活跃任务显示为动态行；仅主节点运行，从节点只读镜像）",
		Category:    "证书",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleMasterOnly,
		Run: func(rc taskengine.RunContext) error {
			// B 完全标准化：真实生命周期挂钩（StartACME/StopACME 语义——队列+
			// 证书 worker+active 指针；幂等守卫吸收角色链双调用）
			return daemonLifecycleRun(rc, certIssuanceLifecycleStart, certIssuanceLifecycleStop)
		},
		StatusFn: func() string {
			var n int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE status NOT IN ('issued','failed','disabled')`).Scan(&n); err == nil && n > 0 {
				return "running"
			}
			return ""
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
	taskEngine.Register(taskengine.Descriptor{
		ID:                "cluster-sync",
		Family:            "cluster",
		Name:              "集群同步",
		Description:       "集群同步服务：从节点按配置间隔轮询主节点快照并增量回放；主节点巡检集群服务面（节点在线/版本滞后）。启停真实生效",
		Category:          "集群",
		Kind:              taskengine.KindDaemon,
		RunsOn:            taskengine.RoleAny,
		RestartOnRoleFlip: true,
		Run: func(rc taskengine.RunContext) error {
			if taskEngine.IsMaster() {
				return masterSyncServingLifecycleRun(rc)
			}
			return daemonLifecycleRun(rc, syncLifecycleStart, syncLifecycleStop)
		},
	})

	// ============ 定时（4）============

	taskEngine.Register(taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新",
		Description: "每日从 USTC/FireHOL/ET 三源下载恶意 IP 名单，聚合去重后写入威胁库文件并同步从节点——引用名单的安全策略据此拦截",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			if !ThreatAutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(earliestThreatNextUpdate())
		},
		EnabledFn: func() bool { return ThreatAutoUpdateEnabled() }, // 业务开关联动展示（关=已暂停）
		StatusFn: func() string {
			if m := GetThreatUpdateManager(); m != nil && m.StatusSnapshot().Running {
				return "running"
			}
			return ""
		},
		MasterOnly: true,
		CancelHook: func() bool { return GetThreatUpdateManager() != nil && GetThreatUpdateManager().CancelRunning() },
		ToggleFn:   SetThreatAutoUpdate,
		ToggleName: "威胁情报库自动更新",
		Run: func(rc taskengine.RunContext) error {
			m := GetThreatUpdateManager()
			if m == nil {
				return nil
			}
			// 引擎已在排程槽调用——直接执行（manager 内部自带总闸/单飞/到期源筛选）
			// TASK-L5：demote/中止语义（lastTaskOutcome=skipped）不再失真为 success——
			// 映射引擎 skipped 终态（ErrTaskSkipped 哨兵，task_runs CHECK 既有值）。
			if err := m.RunUpdate(rc.Trigger, &rc); err != nil {
				return err
			}
			if m.StatusSnapshot().Outcome == "skipped" {
				return taskengine.ErrTaskSkipped
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新",
		Description: "检查并更新 OWASP CoreRuleSet 规则集到最新版本（保留用户 overrides），供 WAF 拦截模式消费",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			// TASK-L1 同批：DB 直读不依赖管理器实例（EnabledFn :395-401 已同形态
			// DB 直读）——测试环境不建管理器，生产管理器初始化晚于引擎注册，
			// 管理器门会让首槽武装在窗口期读不到。
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_crs_version WHERE id=1").Scan(&en); err != nil || en != 1 {
				return time.Time{}
			}
			return coveredSlotStepPast("crs", "security_crs_version", parseUTCSlot(versionTableNextUpdate("security_crs_version")))
		},
		EnabledFn: func() bool { // 业务开关联动展示（关=已暂停；DB 直读——manager 未初始化窗口也正确）
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_crs_version WHERE id=1").Scan(&en); err != nil {
				return true
			}
			return en == 1
		},
		StatusFn: func() string {
			m := GetCRSUpdateManager()
			if m == nil {
				return ""
			}
			// F-L1-68-02（第 68 轮）：仅在途阶段映射 running——failed/skipped
			// 持久终态曾落入 running，任务监控恒显「运行中」。
			if IsActiveCRSStatus(m.StatusSnapshot().Status) {
				return "running"
			}
			return ""
		},
		MasterOnly: true,
		CancelHook: func() bool { m := GetCRSUpdateManager(); return m != nil && m.CancelRunning() },
		ToggleFn:   SetCRSAutoUpdate,
		ToggleName: "CRS 自动更新",
		Run: func(rc taskengine.RunContext) error {
			m := GetCRSUpdateManager()
			if m == nil {
				return nil
			}
			done, err := m.StartUpdate(rc.Trigger, &rc)
			if err != nil {
				return err
			}
			<-done
			if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusSkipped) {
				// TASK-L5：demote 中止落 skipped 终态而非 success
				return taskengine.ErrTaskSkipped
			}
			if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusFailed) {
				return fmt.Errorf("CRS 更新失败: %s", snap.Message)
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "ip2region", Family: "security", Name: "IP2Region 地理库更新",
		Description: "更新 IP 地理位置离线库（xdb），供 GeoIP 地域拦截与归属地展示使用",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			// TASK-L1 同批：DB 直读不依赖管理器实例（与 crs 同形）
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_ip2region_version WHERE id=1").Scan(&en); err != nil || en != 1 {
				return time.Time{}
			}
			return coveredSlotStepPast("ip2region", "security_ip2region_version", parseUTCSlot(versionTableNextUpdate("security_ip2region_version")))
		},
		EnabledFn: func() bool { // 业务开关联动展示（关=已暂停；DB 直读）
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_ip2region_version WHERE id=1").Scan(&en); err != nil {
				return true
			}
			return en == 1
		},
		StatusFn: func() string {
			var status string
			_ = db.DB.QueryRow("SELECT COALESCE(update_status,'') FROM security_ip2region_version WHERE id=1").Scan(&status)
			// F-L1-68-02（第 68 轮）：同 CRS——仅在途阶段映射 running，
			// failed/skipped 持久终态不再失真为「运行中」。
			if IsActiveIP2RegionStatus(status) {
				return "running"
			}
			return ""
		},
		MasterOnly: true,
		CancelHook: func() bool { return GetIP2RegionUpdateManager() != nil && GetIP2RegionUpdateManager().CancelRunning() },
		ToggleFn:   SetIP2RegionAutoUpdate,
		ToggleName: "IP2Region 自动更新",
		Run: func(rc taskengine.RunContext) error {
			m := GetIP2RegionUpdateManager()
			if m == nil {
				return nil
			}
			done, err := m.StartUpdate(rc.Trigger, &rc)
			if err != nil {
				return err
			}
			<-done
			if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusSkipped) {
				// TASK-L5：demote 中止落 skipped 终态而非 success
				return taskengine.ErrTaskSkipped
			}
			if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusFailed) {
				return fmt.Errorf("IP2Region 更新失败: %s", snap.Message)
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "auto-backup", Family: "backup", Name: "自动备份",
		Description: "按排程把全量配置打包为 lbbak 落盘 backup 目录（含 CRS/IP2Region/威胁库数据文件），保留份数自动清理",
		Category:    "备份", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly,
		NextSlotFn: func() time.Time {
			if t, ok := nextAutoBackupSlot(time.Now()); ok {
				return t
			}
			return time.Time{}
		},
		EnabledFn: func() bool { // 业务开关联动展示（备份未启用=已暂停）
			row, err := loadAutoBackupSettings()
			return err != nil || row.enabled
		},
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				exec := currentAutoBackupExecutor()
				if exec == nil {
					return errors.New("备份执行器未就绪")
				}
				return exec("manual", rc.Operator, rc.RunID)
			}
			return runAutoBackupScheduled(rc.RunID)
		},
	})

	// ============ 触发（1）============

	taskEngine.Register(taskengine.Descriptor{
		ID:          "startup:config-load",
		Family:      "startup",
		Name:        "系统配置载入",
		Description: "启动时从数据库装载运行态：规则库（CRS 种子/对账）→ 证书文件物化 → Caddy 配置渲染与应用（失败回退最后已知正确配置）。完成前面板不监听",
		Category:    "系统",
		Kind:        taskengine.KindOneshot,
		ManualRun:   true,
		BootSync:    true, // B1（第 65 轮后裁定）：启动执行=引擎同步触发（面板监听前完成）
		Run: func(rc taskengine.RunContext) error {
			// V1（第 67 轮）：caddy-restart=Caddy 崩溃自愈 watcher 经引擎调度
			// （曾 watcher 直调执行体绕过引擎——task_runs/单飞/日志双行）。
			if rc.Trigger != "manual" && rc.Trigger != "startup" && rc.Trigger != "caddy-restart" {
				return nil
			}
			if configLoadRerun == nil {
				return errors.New("配置重载未接线")
			}
			return configLoadRerun(rc.Operator) // 启动与手动同体（2026-09-29 裁定）；operator 归因（L1-66-03）
		},
	})

	// ============ 手动触发语义 + 默认调度启动 ============

	// 手动触发（定时/循环/触发允许；常驻无「立即执行」——启停即可）
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup", "log-cleanup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca", "startup:config-load"} {
		taskEngine.SetManualRun(id, true)
	}

	// 默认调度启动：
	// - 循环 8 个全启动（cert-waiting-ca 除外——默认关闭，续期扫描唤醒）
	// - 常驻 3 个全启动（系统启动即运行；关闭调度=启动也不运行）
	// - 定时 4 个启动排程（EnabledFn/NextSlotFn 内含开关判断）
	for _, id := range []string{
		"config-watchdog", "log-cleanup", "audit-retention", "security-events-retention",
		"cert-renewal-scan", "cert-reconcile", "cert-manual-poll",
		"security-events-ingestion", "cert-issuance", "cluster-sync",
		"threat", "crs", "ip2region", "auto-backup",
	} {
		taskEngine.StartLoop(id)
	}
	// TASK-L1（第 69 轮 P1）：首槽武装——引擎化前旧调度器首个 tick 才武装首槽
	//（auto_update 开且 next_update 空时写入下一排程槽）；引擎零槽恒不到期
	//（engine.go:725 零值槽 due=false）。引擎注册完成后对三安全库一次性武装：
	// 已有排程槽的行不受影响（空判据守门），仅全新安装/空槽行补写。
	armSecurityLibraryFirstSlots()
	// B1：BootSync 任务同步执行（startup:config-load——面板监听前完成，
	// 替代 main.go 直调+legacy startupPhase 记录旁路）
	taskEngine.RunBootSyncTasks()
	return taskEngine
}

// StopTaskEngine 进程退出收尾。
func StopTaskEngine() {
	if taskEngine != nil {
		taskEngine.Stop()
		taskEngine = nil
	}
}

// armSecurityLibraryFirstSlots 三安全库首槽武装（TASK-L1，第 69 轮 P1）：
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
	if ThreatAutoUpdateEnabled() {
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE update_enabled=1 AND COALESCE(next_update,'')=''`, threatNextSlot(now)); err != nil {
			Logf("warn", "首槽武装：security_threat_sources 写入 next_update 失败: %v", err)
		}
	}
}
