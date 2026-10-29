package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ConfigDriftStatus 配置一致性看门狗的当前状态：数据库（唯一事实源）中应渲染的
// 规则与 Caddy 实际运行配置的比对结果。
type ConfigDriftStatus struct {
	Consistent bool     `json:"consistent"`
	Missing    []string `json:"missing"`    // 应渲染但运行配置缺失的规则（名称（caddy_id））
	Extra      []string `json:"extra"`      // 运行配置中存在但 DB 已不存在的规则路由
	Since      string   `json:"since"`      // 首次确认不一致的时间（UTC）
	CheckedAt  string   `json:"checked_at"` // 最近一轮完成检查的时间（UTC）
}

var (
	configDriftMu               sync.RWMutex
	configDriftStatus           = ConfigDriftStatus{Consistent: true}
	configDriftStreak           int
	configDriftCleanRounds      int  // 心跳窗口：连续「真实检查且一致」轮计数（60s 节拍 × 60 轮 ≈ 1h 一条心跳）
	configDriftSkipped          int  // 自上次真实检查以来的跳过轮数（未判定，不计入干净轮）。测试断言专用（生产无读者）——生产心跳文案只消费 configDriftHeartbeatSkipped；两窗口复位点不同，勿互替。
	configDriftHeartbeatSkipped int  // 自上次心跳以来的跳过轮数：仅用于心跳文案，与状态字段窗口分离。
	configDriftQueryWarned      bool // 规则数据读取失败首报留痕
	configDriftReadWarned       bool // 运行配置读取失败首报留痕
	// configDriftGeneration 每次 ResetConfigDrift 自增：取消轮的回滚快照携带
	// 代际，代际变化说明期间发生过角色复位，回滚必须放弃——否则降级前捕获的
	// 漂移态会被在途轮写回，从节点常亮陈旧横幅。
	configDriftGeneration uint64
	// configWatchdogMu/Cancel/Done 三个引擎化前残留
	// 死变量已删（StartConfigWatchdog/StopConfigWatchdog 随退役，零消费方）。
)

// ResetConfigDrift 角色切换时重置看门狗状态——曾漂移的主节点降级为从节点后，
// 内存中的陈旧漂移态必须清除（从节点不再运行检查，状态不会自行过期）。
func ResetConfigDrift() {
	configDriftMu.Lock()
	defer configDriftMu.Unlock()
	configDriftStatus = ConfigDriftStatus{Consistent: true}
	configDriftStreak = 0
	configDriftCleanRounds = 0
	configDriftSkipped = 0
	configDriftHeartbeatSkipped = 0
	configDriftQueryWarned = false
	configDriftReadWarned = false
	configDriftGeneration++
}

// CurrentConfigDrift 返回看门狗当前状态（GetCaddyStatus 等展示路径消费）。
func CurrentConfigDrift() ConfigDriftStatus {
	configDriftMu.RLock()
	defer configDriftMu.RUnlock()
	status := configDriftStatus
	status.Missing = append([]string(nil), configDriftStatus.Missing...)
	status.Extra = append([]string(nil), configDriftStatus.Extra...)
	return status
}

// configDriftSnapshot 单轮比对前的漂移状态快照（取消轮回滚用）。
type configDriftSnapshot struct {
	status     ConfigDriftStatus
	streak     int
	generation uint64
}

// snapshotConfigDrift 拷贝当前漂移状态与防抖计数（取消轮回滚基线）。
func snapshotConfigDrift() configDriftSnapshot {
	configDriftMu.RLock()
	defer configDriftMu.RUnlock()
	status := configDriftStatus
	status.Missing = append([]string(nil), configDriftStatus.Missing...)
	status.Extra = append([]string(nil), configDriftStatus.Extra...)
	return configDriftSnapshot{status: status, streak: configDriftStreak, generation: configDriftGeneration}
}

// restoreConfigDriftSnapshot 把漂移状态回滚到本轮之前——降级/停机取消的在途
// 轮不得把检查内部的状态转移（streak++/确认漂移）留在进程里。代际不一致说明
// 期间执行过 ResetConfigDrift（降级复位先于取消在途轮），回滚会覆写复位态，
// 此时必须放弃回滚。
func restoreConfigDriftSnapshot(snapshot configDriftSnapshot) {
	configDriftMu.Lock()
	defer configDriftMu.Unlock()
	if configDriftGeneration != snapshot.generation {
		// 轮中发生过降级复位：本轮在其后写入的簿记同样属于已失效的主节点
		// 视角，必须一并丢弃（只跳过回滚会留下本轮自己的 streak/漂移结论）。
		configDriftStatus = ConfigDriftStatus{Consistent: true}
		configDriftStreak = 0
		configDriftCleanRounds = 0
		configDriftSkipped = 0
		configDriftHeartbeatSkipped = 0
		// 首报留痕标志同权：复位后的下一次失败必须重新首报，残留的「已报过」
		// 会让首个诊断日志被静默（唯一线索丢失）。
		configDriftQueryWarned = false
		configDriftReadWarned = false
		return
	}
	configDriftStatus = snapshot.status
	configDriftStreak = snapshot.streak
}

// recordUndeterminedRoundLocked 记录一轮「未判定」簿记（调用方须持
// configDriftMu）：跳过计数 + 严格连续窗口打断。角色读取失败与比对跳过两条
// 路径必须同源——跳过轮不含任何证据，否则「漂移→跳过→漂移」会被当成两轮
// 连续证据而确认漂移。
func recordUndeterminedRoundLocked() {
	configDriftSkipped++
	configDriftHeartbeatSkipped++
	configDriftStreak = 0
}

// 配置一致性看门狗：主节点每 60s 比对「应渲染规则」与 Caddy 运行配置：不一致时
// 经系统日志 + 操作日志 + GetCaddyStatus（前端全局横幅）三通道告知，连续两轮不一致
// 才置状态（防配置应用窗口的瞬时误报）。从节点不运行——同步链路已有 drift 检测与
// 重载失败标记自愈覆盖。恢复由用户手动重启完成（横幅入口），不做自动重应用。
// 引擎化口径：60s 节拍由任务引擎 config-watchdog 族驱动
// （taskengine_wire.go 注册），停止随 StopTaskEngine 统一收尾；admin 地址由
// InitTaskEngine 装配时注入下方包级变量。
var watchdogAdminURLValue string

// configDriftCheckForTest 是单轮比对实现的测试缝（生产恒 nil）。panic 兜底
// 分支（运行日志 + 任务日志「检查异常（panic 已拦）」+ 错误包装）只有在比对
// 路径可注入 panic 时才可能被钉住——引擎 runGuarded 另有一层兜底，会掩盖本层
// 缺测。测试实现必须复位自身（t.Cleanup）。
var configDriftCheckForTest func(adminURL string) (bool, *configDriftEvent, error)

// WatchdogCheckOnce 单轮一致性检查（panic 留痕——看门狗是唯一消费者，
// goroutine 静默死亡是最坏形态；引擎 60s 节拍调用）。
// 主节点专属检测——从节点整轮短路（循环保持存活，
// 升主后自动生效；COALESCE(is_master,1) 口径与全仓一致）。此前从节点每轮
// 空跑簿记：心跳计数累积并逐小时发「配置一致」假心跳（从未真实检查）。
//
// 整轮未判定（规则/运行配置读取失败、Caddy 不可达）
// 返回错误并写业务摘要行——此前 checkConfigConsistency 的 (checked, err) 被
// 丢弃，本轮零业务日志且 task_runs 恒 success，任务监控无法区分「真实检查且
// 一致」与「整轮没查」（与同文件「跳过轮不构成一致证据」口径冲突）。引擎
// 通用行为不变：只有 Run 返回 error 才落 failed。
// 降级/停机窗口（BecomeSlave 的 SetRole(false) 取消在途 Periodic Run 的
// rc.Ctx）：在途轮不消费 ctx 会以旧主节点视角跑完，把漂移簿记/状态覆写到
// 已复位的漂移态上（复位→误报漂移窗口）。入口与比对出口各复核一次，
// 命中即整轮中止——零簿记、零心跳、零任务日志（与从节点整轮短路同口径）。
func WatchdogCheckOnce(ctx context.Context) (runErr error) {
	if db.DB == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	roleCtx := ctx
	if roleCtx == nil {
		roleCtx = context.Background()
	}
	isMaster, roleErr := RoleOf(roleCtx, db.DB)
	if roleErr != nil {
		// 降级/停机取消（BecomeSlave 的 SetRole(false) 取消在途轮）：取消不是
		// 角色读取失败——零簿记、零任务日志，与比对出口复核同口径，避免
		// 每次角色切换都留一条伪失败 task_run 与「角色读取已恢复」噪音。
		if ctx != nil && ctx.Err() != nil {
			return roleErr
		}
		// 看门狗角色读失败留痕：角色读失败=本轮未判定——计入跳过轮簿记（不宣称一致、
		// 不发假心跳，与下方 !checked 跳轮同口径），留痕并以错误返回，
		// 让 task_runs/任务监控可见（此前 return nil → 恒 success 掩盖 DB 异常）。
		// 状态转换口径（首报 warn + 恢复 info）：角色读取持久失败（is_master
		// 行损坏/库瞬断）时此前每 60s 一条裸 warn = 1440 行/天同一消息。
		if lvl := logStateTransition("config-watchdog-role", true); lvl != "" {
			Logf(lvl, "配置看门狗: 角色读取失败，本轮跳过: %v", roleErr)
		}
		configDriftMu.Lock()
		recordUndeterminedRoundLocked()
		configDriftMu.Unlock()
		TaskLogfWarn("config-watchdog", "skipped", "配置检查未完成：角色读取失败（%v），本轮未判定，不计入一致轮", roleErr)
		return fmt.Errorf("角色读取失败: %w", roleErr)
	}
	if lvl := logStateTransition("config-watchdog-role", false); lvl != "" {
		Logf(lvl, "配置看门狗：角色读取已恢复")
	}
	if !isMaster {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			Logf("error", "配置一致性看门狗：检查 panic: %v", r)
			TaskLogfWarn("config-watchdog", "check", "检查异常（panic 已拦，明细见运行日志）")
			// panic 轮没有任何判定证据，必须像其他未判定出口一样打断
			// 「连续两轮不一致」窗口，避免 panic 前后的两轮被拼成连续证据。
			configDriftMu.Lock()
			recordUndeterminedRoundLocked()
			configDriftMu.Unlock()
			runErr = fmt.Errorf("配置一致性检查 panic: %v", r)
		}
	}()
	driftSnapshot := snapshotConfigDrift()
	checkConsistency := checkConfigConsistencyDeferred
	if configDriftCheckForTest != nil {
		checkConsistency = configDriftCheckForTest
	}
	checked, driftEvent, checkErr := checkConsistency(watchdogAdminURLValue)
	// 比对出口复核：比对窗口期内降级/停机的在途轮不得落写簿记（防覆写
	// 复位态——入口复核只覆盖轮次开始前已取消的形态）。checkConfigConsistency
	// 内部会更新漂移状态（含防抖 streak 与确认转移），因此这里还必须把状态
	// 回滚到本轮之前：只跳过后续簿记不足以阻止「取消轮把 streak 推过防抖门
	// 从而确认漂移」。
	if ctx != nil && ctx.Err() != nil {
		restoreConfigDriftSnapshot(driftSnapshot)
		return ctx.Err()
	}
	// 对账留痕（运行日志 + 操作审计）在取消复核之后发射：审计是 append-only
	// 的事实源，回滚撤不回已落库的行——「配置漂移/配置恢复」必须与状态由
	// 同一判定点产出，否则取消轮会留下与横幅相反的结论。
	emitConfigDriftEvent(driftEvent)
	// 日志收敛（2026-10-03 裁定，「日志只记真实执行」延伸）：一致轮
	// 零逐轮行，每 configWatchdogHeartbeatRounds 轮（60s×60≈1h）一条心跳；
	// 漂移期逐轮漂移行与恢复事件照旧（task_runs 维持失败留痕不膨胀）。
	// 只有真实完成的检查轮才累加干净轮——整轮跳过（规则/运行配置
	// 读取失败、Caddy 不可达）不构成「一致」证据，此前会把跳过轮计入干净轮
	// 并发出「配置一致」假心跳。跳过轮单独计数并附在心跳文案里。
	configDriftMu.Lock()
	driftInProgress := configDriftStreak > 0
	switch {
	case !checked:
		// 严格「连续两轮」语义：跳过轮不含任何证据，必须打断连续窗口——
		// 否则「漂移→跳过→漂移」会被当作两轮连续证据而确认漂移。
		recordUndeterminedRoundLocked()
	case driftInProgress && configDriftStatus.Consistent:
		// 防抖轮（streak=1，状态仍为 Consistent）已观测到一轮不一致：
		// 它既不是「一致」证据，也必须清空本窗口——旧实现只是不计入
		// cleanRounds，窗口继续累计，随后凑满 60 个干净轮即写出「近 60 轮无
		// 漂移」的反事实心跳（漂移征兆落在窗口内）。重置后心跳窗口语义恢复为
		// 「自最近一次不一致观测以来连续无漂移」。
		configDriftCleanRounds = 0
		// 心跳文案的「期间跳过 N 轮」窗口与干净轮窗口同起点：不一致观测已
		// 重启干净轮窗口，跳过计数必须同步重启，否则恢复后的心跳会把漂移
		// 之前的跳过轮算进本窗口。
		configDriftHeartbeatSkipped = 0
	case configDriftStatus.Consistent:
		configDriftCleanRounds++
		configDriftSkipped = 0 // 字段口径为「自上次真实检查以来」；真实检查成功即开启新窗口。
	default:
		configDriftCleanRounds = 0
		configDriftSkipped = 0 // 漂移证据丢弃本窗口（恢复后重新累计）
		configDriftHeartbeatSkipped = 0
	}
	// 防抖轮（streak=1，状态仍为 Consistent）不是
	// 「一致」证据——它已经观测到一轮不一致。既不累加干净轮，也不得触发
	// 心跳，否则漂移起点恰落在第 60 个检查周期时会写出「配置一致」的反事实结论。
	rounds := configDriftCleanRounds
	skipped := configDriftHeartbeatSkipped
	heartbeat := checked && configDriftStatus.Consistent && !driftInProgress && rounds%configWatchdogHeartbeatRounds == 0
	if heartbeat {
		configDriftSkipped = 0 // 窗口关闭：跳过轮计数随心跳归零
		configDriftHeartbeatSkipped = 0
	}
	status := configDriftStatus
	status.Missing = append([]string(nil), configDriftStatus.Missing...)
	status.Extra = append([]string(nil), configDriftStatus.Extra...)
	configDriftMu.Unlock()
	switch {
	case !checked:
		// 跳过轮：不输出「一致」结论，也不再隐瞒「整轮没查」——写业务摘要行
		// 并按失败返回，让 task_runs 与任务监控可见。
		reason := "本轮未完成判定"
		if checkErr != nil {
			reason = checkErr.Error()
		}
		TaskLogfWarn("config-watchdog", "skipped", "配置检查未完成：%s（本轮未判定，不计入一致轮）", reason)
		if checkErr != nil {
			return fmt.Errorf("配置一致性检查未完成: %w", checkErr)
		}
		return errors.New("配置一致性检查未完成: " + reason)
	case heartbeat:
		if skipped > 0 {
			TaskLogf("config-watchdog", "check", "配置一致（心跳，近 60 轮有效检查无漂移；期间跳过 %d 轮未判定）", skipped)
		} else {
			TaskLogf("config-watchdog", "check", "配置一致（心跳，近 60 轮无漂移）")
		}
	case status.Consistent:
		return nil
	default:
		TaskLogf("config-watchdog", "check", "配置漂移：缺失 %d 条 / 多余 %d 条（自 %s）", len(status.Missing), len(status.Extra), status.Since)
	}
	return nil
}

// checkConfigConsistency 单轮真实比对，返回本轮是否真正完成判定（checked）：
// false=整轮跳过（规则读取失败/Caddy 运行配置不可读），调用方不得据此记
// 「一致」簿记。直接调用方（一次性诊断/测试）沿用「立即留痕」语义；生产看门狗
// 走 checkConfigConsistencyDeferred，把留痕推迟到取消复核之后。
func checkConfigConsistency(adminURL string) (checked bool, err error) {
	checked, event, err := checkConfigConsistencyDeferred(adminURL)
	emitConfigDriftEvent(event)
	return checked, err
}

// checkConfigConsistencyDeferred 执行比对并返回待发射的对账事件（nil=无结论）。
// 调用方在取消复核之后才能 emit——降级/停机取消的在途轮不得留下与已复位
// 状态相反的审计/运行日志。
func checkConfigConsistencyDeferred(adminURL string) (checked bool, event *configDriftEvent, err error) {
	if db.DB == nil {
		return false, nil, nil
	}
	// 角色门单层化——内层「非主节点跳过」门删除，
	// 由唯一生产调用方 WatchdogCheckOnce 外层门承担短路+簿记语义（双层
	// 背靠背同一句 is_master 查询曾每轮白打一次主库；外层若删会双条 warn）。
	expected, err := expectedRenderedRules()
	if err != nil {
		// 锁内只改状态（configDriftQueryWarned），日志在锁外输出
		// ——审计/日志落盘慢（轮转 writer、stdout 背压）时不得连带阻塞读者
		// （GetCaddyStatus → CurrentConfigDrift RLock），与 updateConfigDrift
		// 「锁内只改状态」铁律一致。
		configDriftMu.Lock()
		shouldWarn := !configDriftQueryWarned
		configDriftQueryWarned = true
		configDriftMu.Unlock()
		if shouldWarn {
			Logf("warn", "配置一致性看门狗：读取规则失败（本轮起跳过检查）: %v", err)
		}
		return false, nil, err
	}
	running, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		// Caddy 不可达由 GetCaddyStatus 的 status 通道报告；但「配置超解析上限/
		// 解析失败」会让看门狗永久静默——须留痕（首次失败告警，恢复后复位）。
		// 超限（与瞬时读失败不同——不会自愈）单独留痕文案。同样锁外输出。
		tooLarge := errors.Is(err, errCaddyAdminConfigTooLarge)
		configDriftMu.Lock()
		shouldWarn := !configDriftReadWarned
		configDriftReadWarned = true
		configDriftMu.Unlock()
		if shouldWarn {
			if tooLarge {
				Logf("warn", "配置一致性看门狗：运行配置超过 %d 字节上限，漂移检测无法进行（本轮起跳过，直至配置缩回上限内）: %v", caddyAdminConfigMaxBytes, err)
			} else {
				Logf("warn", "配置一致性看门狗：读取运行配置失败（本轮起跳过检查）: %v", err)
			}
		}
		return false, nil, err
	}
	configDriftMu.Lock()
	configDriftQueryWarned = false
	configDriftReadWarned = false
	configDriftMu.Unlock()
	event = updateConfigDrift(diffExpectedMissing(expected, running), diffRunningExtra(expected, running))
	return true, event, nil
}

// expectedRenderedRules 计算应出现在运行配置中的规则：启用中且至少有一个启用上游，
// 并排除渲染侧有意跳过的三类，否则会被误报为「缺失」：
//
//	TCP+动态 DNS 逐规则跳过、同端口多 TCP 整组拒绝；
//	HTTP+TLS 规则在 caddy.go 渲染门因「无可用证书（manual 材料缺失 /
//	  ACME 无域匹配且未过期证书）」整条 fail-closed 跳过。看门狗必须消费同一判据，
//	  否则 ACME 首签窗口（或证书过期窗口）连续两轮即误报配置漂移、全局横幅常亮。
//
// 返回 caddy_id → 规则名称。
func expectedRenderedRules() (map[string]string, error) {
	// 发布谓词单源 publishableRulesSQLPredicate（caddy.go）：启用 ∧ 存在启用
	// 上游——与渲染侧 Go 跳过（hasEnabledUpstream）恒等，禁止另写第三份。
	rows, err := db.DB.Query(`SELECT caddy_id, name, protocol, COALESCE(dynamic_dns,0), listen_port,
		IIF(enable_tls IN ('1',1),1,0), COALESCE(tls_source,'manual'), COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(domain,'')
		FROM lb_rules WHERE ` + publishableRulesSQLPredicate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ruleRow struct {
		caddyID    string
		name       string
		protocol   string
		dynamicDNS bool
		listenPort int
		enableTLS  int
		tlsSource  string
		tlsCert    string
		tlsKey     string
		domain     string
	}
	var all []ruleRow
	hasACMEHTTPTLS := false
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.caddyID, &r.name, &r.protocol, &r.dynamicDNS, &r.listenPort,
			&r.enableTLS, &r.tlsSource, &r.tlsCert, &r.tlsKey, &r.domain); err != nil {
			return nil, err
		}
		if r.protocol == "http" && r.enableTLS == 1 && r.tlsSource == "acme_dns" {
			hasACMEHTTPTLS = true
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 与 caddy.go 渲染门同源：ACME 候选查询 + selectCertificate（域匹配/有效期/
	// 可解析性）。证书候选只服务于 enabled+TLS+acme 规则，无此类规则时零查询。
	acmeCerts := make(map[string][]CertificateCandidate)
	// 本轮 ACME 候选证书 Leaf 去重缓存（PEM 内容 → 解析结果）。
	leafCache := make(map[string]*x509.Certificate)
	if hasACMEHTTPTLS {
		certRows, certErr := db.DB.Query(acmeCertCandidatesQuery)
		if certErr != nil {
			return nil, fmt.Errorf("读取 ACME 证书候选失败: %w", certErr)
		}
		for certRows.Next() {
			var ruleID string
			var id int64
			var domain, status, certPEM, keyPEM string
			var updatedAt float64
			if scanErr := certRows.Scan(&ruleID, &id, &domain, &status, &certPEM, &keyPEM, &updatedAt); scanErr != nil {
				closeErr := certRows.Close()
				return nil, fmt.Errorf("解析 ACME 证书候选失败: %w", errors.Join(scanErr, closeErr))
			}
			// 行装配与预解析单源（NewCertificateCandidate）：同一证书挂在多条
			// 规则下（certRows 逐规则返回）时按 PEM 内容在本轮内复用解析结果——
			// 60s 节拍的固定 X.509 解析开销随候选数×规则数增长。
			acmeCerts[ruleID] = append(acmeCerts[ruleID], NewCertificateCandidate(id, domain, status, certPEM, keyPEM, updatedAt, leafCache))
		}
		if rowsErr := certRows.Err(); rowsErr != nil {
			closeErr := certRows.Close()
			return nil, fmt.Errorf("遍历 ACME 证书候选失败: %w", errors.Join(rowsErr, closeErr))
		}
		if closeErr := certRows.Close(); closeErr != nil {
			return nil, fmt.Errorf("关闭 ACME 证书候选结果集失败: %w", closeErr)
		}
	}
	selectionNow := time.Now()
	certReady := func(r ruleRow) bool {
		if r.enableTLS != 1 {
			return true
		}
		switch r.tlsSource {
		case "manual":
			return r.tlsCert != "" && r.tlsKey != ""
		case "acme_dns":
			_, ok := selectCertificate(acmeCerts[r.caddyID], r.domain, selectionNow)
			return ok
		default:
			// 渲染层 availableCerts 只认 manual/acme_dns；其他形态无证可载，
			// 同 caddy.go 门一并跳过。
			return false
		}
	}

	// 渲染侧的同端口多 TCP 判定作用于动态 DNS/证书过滤之前的 TCP 集合——
	// 统计口径与 caddy.go 分组前一致（TLS 过滤只作用于 HTTP 规则）。
	tcpPorts := make(map[int]int)
	for _, r := range all {
		if r.protocol == "tcp" && !r.dynamicDNS {
			tcpPorts[r.listenPort]++
		}
	}
	expected := make(map[string]string)
	for _, r := range all {
		if r.protocol == "tcp" && (r.dynamicDNS || tcpPorts[r.listenPort] > 1) {
			continue
		}
		if r.protocol == "http" && !certReady(r) {
			continue
		}
		expected[r.caddyID] = r.name
	}
	return expected, nil
}

// configWatchdogHeartbeatRounds 一致轮心跳间隔：60s 节拍 × 60 轮 = 每小时一条
// 「配置一致」心跳。
const configWatchdogHeartbeatRounds = 60

// runningRuleRouteIDs 从 Caddy 运行配置收集全部顶层路由 @id（http 与 layer4
// 两类服务器）。**不过滤前缀**：比对口径必须与渲染口径恒等——渲染侧
// `@id = rule.CaddyID` 无前缀假定，导入门也只要求字母表（[a-z0-9_-]），
// 非 lb_ 前缀的合法规则（如 web1）同样会出现在运行配置里；在此过滤会让
// 看门狗把它们永久判为「缺失」并常亮漂移横幅。lb_ 前缀仅保留给
// RunningConfigHasRuleRoutes/ForeignRunningRuleRoutes 的「疑似本产品路由」
// 启发式（它们在调用侧自行过滤）。
// 读取/上限/状态分类统一委托 ReadAdminConfigBody（caddy.go）——
// 32MB+1 超限探测、非 2xx 显式错误、超限返回 errCaddyAdminConfigTooLarge，
// 与 GetConfig/getRunningConfigBytes 同源；裸 LimitReader 会让「超限」与
// 「瞬时读失败」不可区分，超大部署漂移检测长期静默。
func runningRuleRouteIDs(adminURL string) (map[string]bool, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(adminURL, "/") + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ReadAdminConfigBody(resp)
	if err != nil {
		return nil, err
	}
	var config map[string]interface{}
	// 解析保持与旧实现同容忍度：json.Decoder 只消费第一个顶层值（尾随字节/
	// 多余闭合符被忽略），json.Unmarshal 则要求整份字节恰为一个值。Caddy admin
	// 契约外尾随内容不应把「运行配置可读」降级为「读取失败」——看门狗与启动
	// 守卫的探针宁可沿用既有容忍面（只统一读取上限/状态分类，未收紧
	// 解析语义）。
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&config); err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	apps, _ := config["apps"].(map[string]interface{})
	for _, appName := range []string{"http", "layer4"} {
		app, _ := apps[appName].(map[string]interface{})
		servers, _ := app["servers"].(map[string]interface{})
		for _, srv := range servers {
			// 形状异常（带外 /load 或版本漂移）不得 panic——一律
			// comma-ok 断言跳过。
			srvObj, ok := srv.(map[string]interface{})
			if !ok {
				continue
			}
			routes, ok := srvObj["routes"].([]interface{})
			if !ok {
				continue
			}
			for _, route := range routes {
				routeObj, ok := route.(map[string]interface{})
				if !ok {
					continue
				}
				if id, ok := routeObj["@id"].(string); ok && id != "" {
					ids[id] = true
				}
			}
		}
	}
	return ids, nil
}

// RunningConfigHasRuleRoutes 报告 Caddy 运行配置是否仍含规则路由（lb_ 前缀
// @id）——启动「0 规则应用」守卫的探测面：空库实例启动时若运行
// 配置仍带规则路由，极可能是数据目录/Admin 地址误配，不得把空配置 /load
// 进去。admin 不可达返回错误，调用方按「无正向证据」放行（保持既有行为）。
func RunningConfigHasRuleRoutes(adminURL string) (has bool, err error) {
	// 导出入口兜底 recover——运行配置是外部输入（Caddy admin 可能被
	// 其他实例/版本写入），解析 panic 不得带崩启动守卫调用方。
	defer func() {
		if r := recover(); r != nil {
			has = false
			err = fmt.Errorf("运行配置解析 panic: %v", r)
		}
	}()
	ids, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		return false, err
	}
	// 本守卫只关心「疑似本产品规则路由」：历史数据与误指实例探针均以
	// lb_ 前缀识别（非 lb_ 的 @id 可能来自其他 Caddy 写入方，不构成
	// 「本实例曾应用规则」的证据）。
	for id := range ids {
		if strings.HasPrefix(id, "lb_") {
			return true, nil
		}
	}
	return false, nil
}

// ForeignRunningRuleRoutes 返回运行配置中不被本库规则认领的规则路由 @id
// （2026-09-25 漂移根因 C 加固）：host 网络下默认 admin 地址（localhost:2019）
// 无鉴权共享，外来实例（dev/e2e 误指）会把自身配置 /load 进本实例 Caddy——
// 启动应用前以此检出「非本库规则路由」并响亮留痕（09-18 多余路由、09-24
// 清空路由两次实证事故）。子路由（lb_x_path_0 等）归主规则认领，不计外来。
// admin 不可达返回错误，调用方按「无正向证据」跳过告警（与看门狗同口径）。
func ForeignRunningRuleRoutes(adminURL string, ownIDs map[string]bool) (foreign []string, err error) {
	// 同上——导出入口兜底 recover（外部输入解析 panic 不得带崩启动守卫）。
	defer func() {
		if r := recover(); r != nil {
			foreign = nil
			err = fmt.Errorf("运行配置解析 panic: %v", r)
		}
	}()
	running, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		return nil, err
	}
	own := make(map[string]string, len(ownIDs))
	for id := range ownIDs {
		own[id] = id
	}
	claimed := claimedRoutePrefixes(own)
	for routeID := range running {
		// 只把 lb_ 前缀 @id 视为「规则路由」（外来实例误指探针的启发式面）：
		// 非 lb_ 的 @id 既可能是导入的非前缀规则（本库 caddy_id 可合法不带
		// 前缀），也可能来自其他 Caddy 写入方——两类都不构成外来实例证据，
		// 在此一律跳过，避免导入合法规则后每次启动都响亮误报。
		if !strings.HasPrefix(routeID, "lb_") {
			continue
		}
		if !routeClaimedByAny(routeID, claimed) {
			foreign = append(foreign, routeID)
		}
	}
	sort.Strings(foreign)
	return foreign, nil
}

func diffExpectedMissing(expected map[string]string, running map[string]bool) []string {
	var missing []string
	for caddyID, name := range expected {
		if !running[caddyID] {
			missing = append(missing, fmt.Sprintf("%s（%s）", name, caddyID))
		}
	}
	// map 遍历顺序随机——状态切片直接进横幅/审计文本会造成展示抖动；
	// 排序保证同一集合的检查结果稳定（missing 按「名称（id）」字典序）。
	sort.Strings(missing)
	return missing
}

func diffRunningExtra(expected map[string]string, running map[string]bool) []string {
	var extra []string
	claimed := claimedRoutePrefixes(expected)
	for routeID := range running {
		// 子路由（lb_x_redirect / lb_x_path_0 等，caddy.go tagRuleRoute 系）属于其
		// 主规则——仅当没有任何期望规则认领该 @id 时才计为多余（// 精确匹配会把每条 HTTPS 跳转/路径规则的子路由误报为多余）。
		if !routeClaimedByAny(routeID, claimed) {
			extra = append(extra, routeID)
		}
	}
	sort.Strings(extra) // 同上，顺序稳定
	return extra
}

// claimedRoutePrefixes预建路由认领前缀集合：每个期望
// @id 收录其自身与 "<id>_" 两种形态，供 routeClaimedByAny 单次 O(1)/O(len)
// 判定——替代原先每 routeID 全量扫描期望集合的 O(running×expected)。行为
// 等价于 `routeID == caddyID || strings.HasPrefix(routeID, caddyID+"_")`。
func claimedRoutePrefixes(expected map[string]string) map[string]struct{} {
	set := make(map[string]struct{}, len(expected)*2)
	for caddyID := range expected {
		set[caddyID] = struct{}{}
		set[caddyID+"_"] = struct{}{}
	}
	return set
}

// routeClaimedByAny 判定 routeID 是否被某个期望 @id 认领：精确命中集合，或
// routeID 以某期望 @id+"_" 为前缀（子路由归属主规则）。claimed 由
// claimedRoutePrefixes 预建。
func routeClaimedByAny(routeID string, claimed map[string]struct{}) bool {
	if _, ok := claimed[routeID]; ok {
		return true
	}
	for i := 1; i < len(routeID); i++ {
		if routeID[i] == '_' {
			if _, ok := claimed[routeID[:i+1]]; ok {
				return true
			}
		}
	}
	return false
}

// configDriftEvent 一轮比对产生的对账留痕（运行日志 + 操作审计）。状态转移与
// 留痕分离：取消轮只能回滚内存状态，撤不回已落盘的审计行，因此留痕必须由
// 调用方在取消复核之后发射；nil = 本轮无结论（一致稳态或防抖首轮）。
type configDriftEvent struct {
	recovered bool
	detail    string
}

// emitConfigDriftEvent 发射对账留痕。调用方必须已完成取消复核——审计是
// append-only 的会计事实，无法随状态回滚。
func emitConfigDriftEvent(event *configDriftEvent) {
	switch {
	case event == nil:
		return
	case event.recovered:
		Logf("info", "配置一致性看门狗：运行配置与规则数据已恢复一致")
		RecordAuditLog("system", "配置恢复", "Caddy配置", "运行配置与规则数据已恢复一致", "")
	default:
		Logf("error", "配置一致性看门狗：%s", event.detail)
		RecordAuditLog("system", "配置漂移", "Caddy配置", event.detail, "")
	}
}

// updateConfigDrift 写入一轮比对结果。锁内只更新状态，锁外零 I/O：审计库
// busy（30s busy_timeout）时持有 configDriftMu 会阻塞读者（GetCaddyStatus 的
// CurrentConfigDrift）。待写留痕以事件返回，由调用方在确认本轮未被取消后
// 经 emitConfigDriftEvent 发射。
func updateConfigDrift(missing, extra []string) *configDriftEvent {
	drifted := len(missing) > 0 || len(extra) > 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	// 展示/审计文本顺序稳定。
	sort.Strings(missing)
	sort.Strings(extra)
	// 待写事件（nil=无结论）——锁外发射。
	var event *configDriftEvent
	configDriftMu.Lock()
	if !drifted {
		if !configDriftStatus.Consistent {
			event = &configDriftEvent{recovered: true}
		}
		configDriftStreak = 0
		configDriftStatus = ConfigDriftStatus{Consistent: true, CheckedAt: now}
	} else {
		configDriftStreak++
		if configDriftStatus.Consistent && configDriftStreak < 2 {
			configDriftStatus.CheckedAt = now
		} else {
			if configDriftStatus.Consistent {
				event = &configDriftEvent{detail: formatDriftDetail(missing, extra)}
				configDriftStatus = ConfigDriftStatus{Consistent: false, Since: now}
			}
			configDriftStatus.Missing = missing
			configDriftStatus.Extra = extra
			configDriftStatus.CheckedAt = now
		}
	}
	configDriftMu.Unlock()
	return event
}

// 漂移文案单源（横幅 GetCaddyStatus 与看门狗审计共用）——
// 此前两处各自拼接「缺失规则路由/多余规则路由」，跨包维护两份。展示上限
// 防止规则数很大时 60s 轮询响应与 audit_log.detail 无界增长。
const (
	driftDisplayMaxEntries = 20
	driftDisplayMaxRunes   = 512
)

// FormatDriftRoutes 生成「缺失规则路由: …；多余规则路由: …」正文（一致时
// 空串）。每条列表最多展示 driftDisplayMaxEntries 项，整体截断到
// driftDisplayMaxRunes 个字符。
func FormatDriftRoutes(missing, extra []string) string {
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, "缺失规则路由: "+formatDriftRouteList(missing))
	}
	if len(extra) > 0 {
		parts = append(parts, "多余规则路由: "+formatDriftRouteList(extra))
	}
	joined := strings.Join(parts, "；")
	runes := []rune(joined)
	if len(runes) > driftDisplayMaxRunes {
		return string(runes[:driftDisplayMaxRunes]) + "…"
	}
	return joined
}

func formatDriftRouteList(items []string) string {
	display := items
	suffix := ""
	if len(items) > driftDisplayMaxEntries {
		display = items[:driftDisplayMaxEntries]
		suffix = fmt.Sprintf("…（共 %d 条）", len(items))
	}
	return strings.Join(display, "、") + suffix
}

func formatDriftDetail(missing, extra []string) string {
	return "运行配置与规则数据不一致（" + FormatDriftRoutes(missing, extra) + "），请重启服务恢复"
}
