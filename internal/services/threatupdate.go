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
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
)

var wafDir = "/app/waf"

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

// ErrThreatUpdateFailed 任一源失败即整体失败（F-L1-68-01，第 68 轮）：失败终态
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
	mu            sync.Mutex
	running       bool
	runDone       chan struct{}
	schedulerStop chan struct{}
	schedulerDone chan struct{}
	// runCancel 取消当前运行中的下载阶段（任务监控手动取消，v2.3.4）。
	runCancel context.CancelFunc
	// lastCancelled 标记最近一次运行被手动取消（区分 failed）。
	lastCancelled bool
	// lastTrigger/lastFinishedAt 为任务级状态（status 端点 + 弹框展示）。
	lastTrigger     string
	lastStartedAt   string
	lastFinishedAt  string
	lastTaskOutcome string // success / failed / ""（未跑过）
}

// nil-until-init（镜像 CRS/IP2Region 管理器）：仅 main.go 初始化——集群
// promote/demote 路径的 SetMasterRole 在测试二进制中经 nil 守卫跳过，
// 不会把调度器（首轮即下载）带进无关测试。
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
	if threatUpdateManager != nil {
		threatUpdateManager.StopScheduler()
	}
	threatUpdateManager = &ThreatUpdateManager{}
}

func (m *ThreatUpdateManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

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
// ——ProjectionNeedForce（本轮渲染物化了证书文件，第 76 轮 CERT-1）与
// ProjectionFallback（发射面变化/运行配置不可读）均未证实收敛，调用方回退
// threatReloader 强制 /load 收敛（宁可一次重载，不欠引用方渲染收敛；强制
// 形态同时满足 R72 W1-1）。R59-P2 失败自愈标记（threatReloadPending）随之
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
	defer m.mu.Unlock()
	if m.running {
		return nil, ErrThreatUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	done := m.runDone
	go func() {
		defer close(done)
		m.run(trigger, rc)
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
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	m.run(trigger, rc)
	// F-L1-68-01（第 68 轮）：失败终态回传引擎（镜像 crs/ip2region wire Run
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
	rows, err := db.DB.Query(`SELECT id, name, url, COALESCE(next_update,''), COALESCE(consecutive_failures,0)
		FROM security_threat_sources
		WHERE update_enabled=1 AND name IN ('ustc','firehol_l1','et_compromised') ORDER BY id`)
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
		// 「从未失败」形态（consecutive_failures=0，第 55 轮 P3-2，用户裁
		// 定）：持续产不出条目的失败源按排程门控，不再每分钟整任务重跑。
		// v2.3.4 RDB 文件化：.iplist 文件缺失同此语义（哈希命中会跳过写
		// 文件，不补这条则升级后文件永不落地、严格渲染持续跳过策略）。
		if trigger != "manual" && nextUpdate != "" {
			isEmpty := threatListEmpty(s.name)
			gated := !isEmpty || consecutiveFailures > 0
			if gated {
				if due, err := time.Parse(crsTimeLayout, nextUpdate); err == nil && now.Before(due) {
					continue
				}
			}
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

// threatListEmpty 报告源是否「未装载」（排程到期判定用）。
// v2.3.4 RDB 文件化（稳态修复）：system 列表条目已迁至文件，DB entries=”
// 是**正常态**而非空信号——若按 DB 判空则每个调度 tick 都视为到期，主节点
// 每分钟空转更新（USTC 内容逐请求漂移 → .fast 每轮变化 → 从节点每轮
// 「已同步」刷屏）。判据改为文件物化状态：.iplist 缺失 = 未装载。
func threatListEmpty(source string) bool {
	return threatIplistMissing(source)
}

func (m *ThreatUpdateManager) run(trigger string, rc *taskengine.RunContext) {
	operator := "system"
	if rc != nil && rc.Operator != "" {
		operator = rc.Operator
	}
	// 任务自记审计（2026-09-29 用户裁定）：defer 在函数头注册（U2-P3-06——
	// 曾注册在源循环后，角色早退/源读取失败/零源路径零审计、「skipped」映射
	// 不可达）。
	defer func() {
		m.mu.Lock()
		outcome := m.lastTaskOutcome
		m.mu.Unlock()
		detail := fmt.Sprintf("更新%s（触发：%s）", map[string]string{
			"success": "成功", "failed": "失败", "cancelled": "已取消", "skipped": "跳过",
		}[outcome], trigger)
		if outcome == "failed" || outcome == "cancelled" {
			RecordAuditLog(operator, "更新失败", "威胁情报库", detail, "")
		} else {
			RecordAuditLog(operator, "更新", "威胁情报库", detail, "")
		}
	}()
	// 起点角色复查（第 59 轮 R59-P3，R54-N5 家族收敛）：调度器 tick 的 is_master
	// 守卫与更新启动之间存在 demote 竞态窗口——从节点继续执行会写
	// security_ip_lists 并触发重载，打破只读不变量。NULL 兜底归一为 1（同
	// crsupdate/ip2regionupdate 口径）。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		AppendThreatUpdateLog("WARN", "skipped", "当前节点为从节点，终止威胁情报库更新")
		m.mu.Lock()
		m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout) // 第 60 轮：早退同样落终态
		m.lastTaskOutcome = "skipped"
		m.mu.Unlock()
		return
	}
	// F-L2-68-01（第 68 轮）：runCtx 派生自 rc.Ctx（镜像 CRS/IP2Region 侧）——
	// 引擎 demote 中止（SetRole 取消在途 Scheduled）随 rc.Ctx 传播；nil rc
	// （测试/内部路径）回退 Background 保持旧语义。
	runBase := context.Background()
	if rc != nil && rc.Ctx != nil {
		runBase = rc.Ctx
	}
	runCtx, runCancel := context.WithCancel(runBase)
	// R63 单写方：task_runs 由引擎统一记录。
	m.mu.Lock()
	m.lastTrigger = trigger
	m.lastStartedAt = time.Now().UTC().Format(crsTimeLayout)
	m.lastCancelled = false
	m.runCancel = runCancel
	m.mu.Unlock()
	defer runCancel()
	sources, err := threatDueSources(trigger)
	finishWith := func(outcome string) {
		m.mu.Lock()
		m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
		m.lastTaskOutcome = outcome
		m.mu.Unlock()
	}
	if err != nil {
		Logf("error", "威胁情报库: 读取源列表失败: %v", err)
		finishWith("failed") // 第 59 轮 R59-P5：早退路径同样落终态，状态端点不失真
		return
	}
	if len(sources) == 0 {
		finishWith("success")
		return
	}
	AppendThreatUpdateLog("INFO", "checking", fmt.Sprintf("开始更新威胁情报库（%d 个启用源）", len(sources)))
	var changedIDs []int // 内容真实变化的名单 id（收敛分支的判定面）
	anyFailed := false
	cancelled := false
	demoted := false // F-L2-68-01：demote 在途中止标记（outcome=skipped，优先于 cancelled/failed）
	for _, source := range sources {
		if runCtx.Err() != nil {
			// F-L2-68-01：取消源分流——demote（角色已翻转）落 skipped（与起点
			// 角色复查同语义：从节点中止非故障）；主节点=手动取消 cancelled。
			if !updateRunStillMaster() {
				demoted = true
				AppendThreatUpdateLog("WARN", "skipped", "节点已降级为从节点，终止威胁情报库更新（已完成源的结果保留）")
			} else {
				cancelled = true
				AppendThreatUpdateLog("WARN", "cancelled", "威胁情报库更新已被手动取消（已完成源的结果保留）")
			}
			break
		}
		changed, failed := m.updateOneSource(runCtx, source, trigger)
		if changed {
			if id := threatListIDBySource(source.name); id > 0 {
				changedIDs = append(changedIDs, id)
			}
		}
		anyFailed = anyFailed || failed
	}
	// 中止点归一（F-L2-68-01）：末源在途取消时循环自然结束（无下一轮顶部
	// 检查）——补判一次取消源；demote 优先于源失败（中止非故障）。
	if !demoted && !cancelled && runCtx.Err() != nil {
		if updateRunStillMaster() {
			cancelled = true
		} else {
			demoted = true
		}
	}
	m.mu.Lock()
	m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
	if demoted {
		m.lastTaskOutcome = "skipped"
	} else if cancelled {
		m.lastTaskOutcome = "cancelled"
		m.lastCancelled = true
	} else if anyFailed {
		m.lastTaskOutcome = "failed"
	} else {
		m.lastTaskOutcome = "success"
	}
	m.mu.Unlock()
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
	if len(changedIDs) == 0 {
		AppendThreatUpdateLog("INFO", "unchanged", "全部源名单内容未变化，不重载 Caddy 配置")
	} else if threatProjectionRefresher == nil {
		// 未注册热路径（测试二进制/异常装配）：名单文件已更新，引用方投影
		// 由下次任意配置变更的全量渲染收敛。
		AppendThreatUpdateLog("WARN", "unchanged", "投影刷新器未注册，跳过热路径（引用方渲染由下次配置变更收敛）")
	} else if hot, rerr := threatProjectionRefresher(); rerr != nil || hot != ProjectionConverged {
		// fail-safe：投影刷新被拒（生成失败）/发射面变化/运行配置不可读/
		// 证书材料被物化（NeedForce，第 76 轮 CERT-1——重载回调为强制形态，
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

// threatListIDBySource 源名 → 内置名单 id（缺失=0）。
func threatListIDBySource(source string) int {
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, db.ThreatListNameBySource(source)).Scan(&id); err != nil {
		return 0
	}
	return id
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
	// 第 76 轮 SEC-2：引用面补全——除 ACL/信任引用外，CRS 排除 scope=ip/list
	// 条目的 ListRefs（emitScopedCRSExclusions 投影消费，SEC-1 后同为
	// @ipListFast 文件热感知面）与受信代理网段引用（global_config.
	// trusted_proxy_range_refs，tp.txt 投影消费，仅 trusted_proxy_enabled=1
	// 时渲染）都是渲染引用方；漏查会让「仅被这两面引用」的名单在写路径被
	// 资格门误判未引用→无谓回退全量链/全量重载（保守口径缺口）。查询/解析
	// 失败按「可能被引用」处理（P5-10 同口径）。
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
				// P5-10：解析失败按「可能被引用」处理（与查询失败同口径）。
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
		// R71-⑪（第 71 轮主审补漏）：迭代失败与查询/解析失败同口径——按被引用
		// 处理（fail-closed），漏查会跳过名单收敛致引用方渲染不收敛。
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
func (m *ThreatUpdateManager) updateOneSource(ctx context.Context, source threatSourceRow, trigger string) (bool, bool) {
	now := time.Now().UTC()
	nowStr := now.Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='running', message='', trigger=?, started_at=?, last_checked=?, updated_at=datetime('now') WHERE id=?`,
		trigger, nowStr, nowStr, source.id); err != nil {
		Logf("error", "威胁情报库: 标记源 %s 运行中失败: %v", source.name, err)
		return false, true
	}
	AppendThreatUpdateLog("INFO", "downloading", fmt.Sprintf("下载 %s（%s）", source.name, source.url))

	// 任务内重试（2026-09-25 用户裁定）：瞬断在当前任务内重试，耗尽才落定——
	// 失败退避不再改写排程槽（failSourceRow 写下一排程槽）。
	var entries []string
	var rawHash string
	err := runWithInTaskRetry(func() error {
		var derr error
		entries, rawHash, derr = downloadAndParseThreatSourceCtx(ctx, source)
		return derr
	}, func(nextAttempt int, wait time.Duration, rerr error) {
		AppendThreatUpdateLog("WARN", "retry", fmt.Sprintf("源 %s 下载失败: %v；等待 %s 重试，第 %d 次，共 %d 次", source.name, rerr, wait, nextAttempt, updateMaxAttempts))
	})
	finished := time.Now().UTC().Format(crsTimeLayout)
	if err != nil {
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
		// 名单行缺失（备份还原/异常清理）须穿透快速路径补建
		var listExists int
		err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, db.ThreatListNameBySource(source.name)).Scan(&listExists)
		switch {
		case err != nil:
			// F49-4：存在性判定失败不得按「存在」跳过（名单可能已缺失，
			// 跳过快照=拦截面静默为空）——记错并继续完整聚合/写库路径。
			Logf("error", "威胁情报库: 检查源 %s 内置名单存在性失败: %v", source.name, err)
		case listExists > 0 && threatIplistMissing(source.name):
			// RDB 文件化升级引导：名单行在但 .iplist 缺失（v2.3.3 升级、
			// 内容未变形态）——穿透快速路径照常写盘，否则文件永不落地。
			Logf("info", "威胁情报库: 源 %s 原始哈希一致但 .iplist 文件缺失，执行落盘（升级引导）", source.name)
		case listExists > 0:
			AppendThreatUpdateLog("INFO", "unchanged", fmt.Sprintf("源 %s 名单内容未变化（原始内容哈希一致），跳过解析写入", source.name))
			markSourceSuccess(source.id, len(entries), finished, trigger)
			return false, false
		}
	}

	// 聚合归一后写内置名单（内容未变化零写入——不重载、不 bump 集群版本）。
	merged := wafiplist.AggregateIPEntries(entries)
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
	markSourceSuccess(source.id, len(entries), finished, trigger, rawHash)
	return changed, false
}

// markSourceSuccess 源成功状态落库（版本/条数/退避清零/下一窗口 + 原始字节哈希）。
// 排程槽生命周期（2026-10-11 用户裁定）：仅 auto 且现存槽空/过期才推进——手动不动预约。
// rawHash 缺省=兼容旧调用形态【不写】raw_hash 列（第 55 轮 P3-1：无条件覆写
// 空串曾使快路径自我失效——缺省时动态剔除该列，保留上次慢路径哈希）。
func markSourceSuccess(id int, entryCount int, finished string, trigger string, rawHash ...string) {
	version := time.Now().UTC().Format("2006.01.02")
	next := threatNextSlot(time.Now().UTC())
	if len(rawHash) > 0 {
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='success', message='', entry_count=?, version=?, finished_at=?, `+threatSlotAdvanceSQL+`, consecutive_failures=0, raw_hash=?, updated_at=datetime('now') WHERE id=?`,
			entryCount, version, finished, trigger, next, rawHash[0], id); err != nil {
			Logf("error", "威胁情报库: 更新源成功状态失败: %v", err)
		}
	} else {
		// raw_hash 缺省（快路径内容未变）不覆写该列（第 55 轮 P3-1 修法）。
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='success', message='', entry_count=?, version=?, finished_at=?, `+threatSlotAdvanceSQL+`, consecutive_failures=0, updated_at=datetime('now') WHERE id=?`,
			entryCount, version, finished, trigger, next, id); err != nil {
			Logf("error", "威胁情报库: 更新源成功状态失败: %v", err)
		}
	}
	// 成功留痕（尾部共享，两分支同达，第 56 轮 P3-1 修法）：rawHash 分支=内容
	// 更新；无参分支=哈希一致跳过写入。原 P3-1 修复在 rawHash 分支加的 return
	// 切断了本段日志（真实更新零留痕），已撤除。
	// 源名仅用于日志，按 id 反查一次
	var name string
	_ = db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name)
	Logf("info", "威胁情报库: 源 %s 更新成功（%d 条，版本 %s）", name, entryCount, version)
	AppendThreatUpdateLog("INFO", "success", fmt.Sprintf("源 %s 更新成功（%d 条，版本 %s）", name, entryCount, version))
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
	// 名单行存在 + 哈希一致 → 未变化（名单行缺失即使哈希命中也须补建）
	var listExists int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, name).Scan(&listExists); err != nil {
		return false, fmt.Errorf("读内置名单失败: %w", err)
	}
	var storedHash string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_hash,'') FROM security_threat_sources WHERE name=?`, source).Scan(&storedHash); err != nil {
		return false, fmt.Errorf("读源哈希失败: %w", err)
	}
	// RDB 文件化：文件缺失时哈希命中不得跳过（升级引导——v2.3.3 升上来
	// 内容未变，但 .iplist/.fast 尚未落地，须照常写盘）。
	if listExists > 0 && storedHash == hash && storedHash != "" && !threatIplistMissing(source) {
		return false, nil
	}
	// RDB 文件化：条目写 .iplist 文件 + 编译 .fast，DB entries 恒空
	// L6-66-02：写+编译为 wafFileMu 互斥的原子文件相位（撕裂 .iplist 会让
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
		// 行缺失自愈补建
		if _, ierr := db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
			VALUES (?, ?, '恶意 IP', '', 1, datetime('now'), datetime('now'))`, name, threatListDescription(source)); ierr != nil {
			return false, fmt.Errorf("补建内置名单失败: %w", ierr)
		}
		// F49-P5-4：补建产生新 id
		Logf("warn", "威胁情报库: 内置名单 %q 已重建为新 id，原策略引用已失效，需重新绑定", name)
		RecordAuditLog("system", "重建", "威胁情报库", fmt.Sprintf("内置名单 %s 重建为新 id，原策略引用已失效，需重新绑定", name), "")
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
	for _, sl := range db.ThreatSystemLists {
		if sl.Source == source {
			return sl.Description
		}
	}
	return ""
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
	next := threatNextSlot(time.Now().UTC())
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', message=?, finished_at=?, `+threatSlotAdvanceSQL+`, updated_at=datetime('now') WHERE id=?`,
		cause.Error(), finished, trigger, next, id); err != nil {
		Logf("error", "威胁情报库: 失败状态落库失败: %v", err)
	}
	Logf("warn", "威胁情报库: 源更新失败: %v", cause)
}

// downloadAndParseThreatSource 下载并解析单源（format=plain）：
// 30s 超时、HTTP 200、body ≤16MB；空行与 #/; 注释跳过；可解析行比例 <50%
// 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
// 返回原始字节 sha256（两层哈希第一层快速路径，2026-09-24 用户裁定）：
// 原始一致即内容必然未变，调用方跳过聚合/写库；原始不同才走聚合规范哈希终判。
func downloadAndParseThreatSource(source threatSourceRow) ([]string, string, error) {
	return downloadAndParseThreatSourceCtx(context.Background(), source)
}

// downloadAndParseThreatSourceCtx 下载并解析单源（ctx 可被任务监控取消）。
func downloadAndParseThreatSourceCtx(parent context.Context, source threatSourceRow) ([]string, string, error) {
	ctx, cancel := context.WithTimeout(parent, threatDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "lazy-balancer-v2") // 第 59 轮 R59-P5：空 UA 可能被源拒绝/插页（对齐 crshttp 同口径）
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
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		total++
		if _, err := wafiplist.ParseIPEntry(line); err == nil {
			entries = append(entries, line)
		}
	}
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

// writeThreatIplist 将威胁库条目写为 .iplist 纯文本文件（原子写）。
// 格式：每行一个 IP/CIDR，供导出/调试/从节点编译。
func writeThreatIplist(path string, entries []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	content := strings.Join(entries, "\n") + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeThreatIplistCompiled 威胁库文件相位（L6-66-02）：.iplist 原子写 + .fast
// 编译在 wafFileMu 互斥段内完成——与 lbbak 导入直写、从节点 .fast 落盘串行，
// 杜绝并发写者下的撕裂读与半新半旧名单。错误文案与此前两段式返回保持一致。
func writeThreatIplistCompiled(path string, entries []string) error {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	if err := writeThreatIplist(path, entries); err != nil {
		return fmt.Errorf("写 .iplist 文件失败: %w", err)
	}
	if err := CompileFromIplistFile(path); err != nil {
		return fmt.Errorf("编译 .fast 失败: %w", err)
	}
	return nil
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
	// SEC-C-N3（第 71 轮）：补 running 门（对齐 CRS/IP2Region 同形）——
	// runCancel 一次运行后不清空，单查 cancel 会把已结束任务误报为可取消。
	if cancel == nil || !running {
		return false
	}
	cancel()
	return true
}
