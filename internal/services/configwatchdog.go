package services

import (
	"encoding/json"
	"fmt"
	"io"
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
	Missing    []string `json:"missing"` // 应渲染但运行配置缺失的规则（名称（caddy_id））
	Extra      []string `json:"extra"`   // 运行配置中存在但 DB 已不存在的规则路由
	Since      string   `json:"since"`   // 首次确认不一致的时间（UTC）
	CheckedAt  string   `json:"checked_at"`
	// SkippedRounds 自上次真实检查以来未能判定的轮数（规则读取失败/Caddy
	// 不可达整轮跳过）——U12-F02：跳过轮不构成「一致」证据，心跳文案附此计数。
	SkippedRounds int `json:"skipped_rounds,omitempty"`
}

var (
	configDriftMu          sync.RWMutex
	configDriftStatus      = ConfigDriftStatus{Consistent: true}
	configDriftStreak      int
	configDriftCleanRounds int  // R66 心跳窗口：连续「真实检查且一致」轮计数（60s 节拍 × 60 轮 ≈ 1h 一条心跳）
	configDriftSkipped     int  // U12-F02：自上次真实检查以来的跳过轮数（未判定，不计入干净轮）
	configDriftQueryWarned bool // 规则数据读取失败首报留痕
	configDriftReadWarned  bool // 运行配置读取失败首报留痕
	// LBS-B-D1（第 69 轮）：configWatchdogMu/Cancel/Done 三个引擎化前残留
	// 死变量已删（StartConfigWatchdog/StopConfigWatchdog 随 M2 退役，零消费方）。
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
	configDriftQueryWarned = false
	configDriftReadWarned = false
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

// 配置一致性看门狗：主节点每 60s 比对「应渲染规则」与 Caddy 运行配置：不一致时
// 经系统日志 + 操作日志 + GetCaddyStatus（前端全局横幅）三通道告知，连续两轮不一致
// 才置状态（防配置应用窗口的瞬时误报）。从节点不运行——同步链路已有 drift 检测与
// 重载失败标记自愈覆盖。恢复由用户手动重启完成（横幅入口），不做自动重应用。
// LBS-B-D1（第 69 轮）引擎化口径：60s 节拍由任务引擎 config-watchdog 族驱动
// （taskengine_wire.go 注册），停止随 StopTaskEngine 统一收尾；admin 地址由
// InitTaskEngine 装配时注入下方包级变量。
var watchdogAdminURLValue string

// WatchdogCheckOnce 单轮一致性检查（panic 留痕——看门狗是唯一消费者，
// goroutine 静默死亡是最坏形态；引擎 60s 节拍调用）。
// L1-P4-2（第 67 轮审计）：主节点专属检测——从节点整轮短路（循环保持存活，
// 升主后自动生效；COALESCE(is_master,1) 口径与全仓一致）。此前从节点每轮
// 空跑簿记：心跳计数累积并逐小时发「配置一致」假心跳（从未真实检查）。
func WatchdogCheckOnce() {
	if db.DB == nil {
		return
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		if err != nil {
			// 查询失败与「非主节点」同为跳过，失败留痕（第 55 轮 P5 标准——
			// 静默吞错会掩盖 DB 异常）。
			Logf("warn", "配置看门狗: 读取集群角色失败，本轮跳过: %v", err)
		}
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				Logf("error", "配置一致性看门狗：检查 panic: %v", r)
				TaskLogf("config-watchdog", "check", "检查异常（panic 已拦，明细见运行日志）")
			}
		}()
		checked, _ := checkConfigConsistency(watchdogAdminURLValue)
		// R66 日志收敛（2026-10-03 裁定，R65「日志只记真实执行」延伸）：一致轮
		// 零逐轮行，每 configWatchdogHeartbeatRounds 轮（60s×60≈1h）一条心跳；
		// 漂移期逐轮漂移行与恢复事件照旧（task_runs 维持失败留痕不膨胀）。
		// U12-F02：只有真实完成的检查轮才累加干净轮——整轮跳过（规则/运行配置
		// 读取失败、Caddy 不可达）不构成「一致」证据，此前会把跳过轮计入干净轮
		// 并发出「配置一致」假心跳。跳过轮单独计数并附在心跳文案里。
		configDriftMu.Lock()
		if !checked {
			configDriftSkipped++
		} else if configDriftStatus.Consistent {
			configDriftCleanRounds++
		} else {
			configDriftCleanRounds = 0
			configDriftSkipped = 0 // 漂移证据丢弃本窗口（恢复后重新累计）
		}
		rounds := configDriftCleanRounds
		skipped := configDriftSkipped
		heartbeat := checked && configDriftStatus.Consistent && rounds%configWatchdogHeartbeatRounds == 0
		if heartbeat {
			configDriftSkipped = 0 // 窗口关闭：跳过轮计数随心跳归零
		}
		configDriftStatus.SkippedRounds = configDriftSkipped
		status := configDriftStatus
		status.Missing = append([]string(nil), configDriftStatus.Missing...)
		status.Extra = append([]string(nil), configDriftStatus.Extra...)
		configDriftMu.Unlock()
		switch {
		case !checked:
			return // 跳过轮不输出「一致」结论
		case heartbeat:
			if skipped > 0 {
				TaskLogf("config-watchdog", "check", "配置一致（心跳，近 60 轮有效检查无漂移；期间跳过 %d 轮未判定）", skipped)
			} else {
				TaskLogf("config-watchdog", "check", "配置一致（心跳，近 60 轮无漂移）")
			}
		case status.Consistent:
			return
		default:
			TaskLogf("config-watchdog", "check", "配置漂移：缺失 %d 条 / 多余 %d 条（自 %s）", len(status.Missing), len(status.Extra), status.Since)
		}
	}()
}

// checkConfigConsistency 单轮真实比对，返回本轮是否真正完成判定（checked）：
// false=整轮跳过（规则读取失败/Caddy 运行配置不可读），调用方不得据此记
// 「一致」簿记（U12-F02）。
func checkConfigConsistency(adminURL string) (checked bool, err error) {
	if db.DB == nil {
		return false, nil
	}
	// LBS-B-R1（第 69 轮）：角色门单层化——内层「非主节点跳过」门删除，
	// 由唯一生产调用方 WatchdogCheckOnce 外层门承担短路+簿记语义（双层
	// 背靠背同一句 is_master 查询曾每轮白打一次主库；外层若删会双条 warn）。
	expected, err := expectedRenderedRules()
	if err != nil {
		configDriftMu.Lock()
		if !configDriftQueryWarned {
			configDriftQueryWarned = true
			Logf("warn", "配置一致性看门狗：读取规则失败（本轮起跳过检查）: %v", err)
		}
		configDriftMu.Unlock()
		return false, err
	}
	running, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		// Caddy 不可达由 GetCaddyStatus 的 status 通道报告；但「配置超解析上限/
		// 解析失败」会让看门狗永久静默——须留痕（首次失败告警，恢复后复位）。
		configDriftMu.Lock()
		if !configDriftReadWarned {
			configDriftReadWarned = true
			Logf("warn", "配置一致性看门狗：读取运行配置失败（本轮起跳过检查）: %v", err)
		}
		configDriftMu.Unlock()
		return false, err
	}
	configDriftMu.Lock()
	configDriftQueryWarned = false
	configDriftReadWarned = false
	configDriftMu.Unlock()
	updateConfigDrift(diffExpectedMissing(expected, running), diffRunningExtra(expected, running))
	return true, nil
}

// expectedRenderedRules 计算应出现在运行配置中的规则：启用中且至少有一个启用上游，
// 并排除渲染侧有意跳过的两类（与 caddy.go:1949-1974 同口径——TCP+动态 DNS 逐规则
// 跳过、同端口多 TCP 整组拒绝），否则这两类规则会被误报为「缺失」（R37 F-1）。
// 返回 caddy_id → 规则名称。
func expectedRenderedRules() (map[string]string, error) {
	rows, err := db.DB.Query(`SELECT caddy_id, name, protocol, COALESCE(dynamic_dns,0), listen_port FROM lb_rules WHERE enabled=1
		AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=lb_rules.caddy_id AND IIF(u.enabled IN ('1',1),1,0)=1)`)
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
	}
	var all []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.caddyID, &r.name, &r.protocol, &r.dynamicDNS, &r.listenPort); err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 渲染侧的同端口多 TCP 判定作用于动态 DNS 过滤之后的集合——统计口径保持一致。
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
		expected[r.caddyID] = r.name
	}
	return expected, nil
}

// configWatchdogHeartbeatRounds 一致轮心跳间隔：60s 节拍 × 60 轮 = 每小时一条
// 「配置一致」心跳（R66 收敛——一致轮不再逐轮记录）。
const configWatchdogHeartbeatRounds = 60

// maxAdminConfigBytes 看门狗读取 Caddy 运行配置的解码上限——LB44-4 家族口径
// 32MB（与 caddy.go:210/565/780 同源；U8-P4-2 对齐，原先 4MB 上限使 >4MB 配置
// 漂移检测永久静默而 apply 仍工作至 32MB）。
const maxAdminConfigBytes = 32 << 20

// runningRuleRouteIDs 从 Caddy 运行配置收集规则路由 @id（lb_ 前缀），
// 覆盖 http 与 layer4 两类服务器。
func runningRuleRouteIDs(adminURL string) (map[string]bool, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(adminURL, "/") + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin status %d", resp.StatusCode)
	}
	var config map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAdminConfigBytes)).Decode(&config); err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	apps, _ := config["apps"].(map[string]interface{})
	for _, appName := range []string{"http", "layer4"} {
		app, _ := apps[appName].(map[string]interface{})
		servers, _ := app["servers"].(map[string]interface{})
		for _, srv := range servers {
			// U12-F03：形状异常（带外 /load 或版本漂移）不得 panic——一律
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
				if id, ok := routeObj["@id"].(string); ok && strings.HasPrefix(id, "lb_") {
					ids[id] = true
				}
			}
		}
	}
	return ids, nil
}

// RunningConfigHasRuleRoutes 报告 Caddy 运行配置是否仍含规则路由（lb_ 前缀
// @id）——启动「0 规则应用」守卫的探测面（F49-15）：空库实例启动时若运行
// 配置仍带规则路由，极可能是数据目录/Admin 地址误配，不得把空配置 /load
// 进去。admin 不可达返回错误，调用方按「无正向证据」放行（保持既有行为）。
func RunningConfigHasRuleRoutes(adminURL string) (has bool, err error) {
	// U12-F03：导出入口兜底 recover——运行配置是外部输入（Caddy admin 可能被
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
	return len(ids) > 0, nil
}

// ForeignRunningRuleRoutes 返回运行配置中不被本库规则认领的规则路由 @id
// （2026-09-25 漂移根因 C 加固）：host 网络下默认 admin 地址（localhost:2019）
// 无鉴权共享，外来实例（dev/e2e 误指）会把自身配置 /load 进本实例 Caddy——
// 启动应用前以此检出「非本库规则路由」并响亮留痕（09-18 多余路由、09-24
// 清空路由两次实证事故）。子路由（lb_x_path_0 等）归主规则认领，不计外来。
// admin 不可达返回错误，调用方按「无正向证据」跳过告警（与看门狗同口径）。
func ForeignRunningRuleRoutes(adminURL string, ownIDs map[string]bool) (foreign []string, err error) {
	// U12-F03：同上——导出入口兜底 recover（外部输入解析 panic 不得带崩启动守卫）。
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
	// U12-F14：map 遍历顺序随机——状态切片直接进横幅/审计文本会造成展示抖动；
	// 排序保证同一集合的检查结果稳定（missing 按「名称（id）」字典序）。
	sort.Strings(missing)
	return missing
}

func diffRunningExtra(expected map[string]string, running map[string]bool) []string {
	var extra []string
	claimed := claimedRoutePrefixes(expected)
	for routeID := range running {
		// 子路由（lb_x_redirect / lb_x_path_0 等，caddy.go tagRuleRoute 系）属于其
		// 主规则——仅当没有任何期望规则认领该 @id 时才计为多余（R36 WD-1：
		// 精确匹配会把每条 HTTPS 跳转/路径规则的子路由误报为多余）。
		if !routeClaimedByAny(routeID, claimed) {
			extra = append(extra, routeID)
		}
	}
	sort.Strings(extra) // U12-F14：同上，顺序稳定
	return extra
}

// claimedRoutePrefixes（SVC-C1，第 73 轮）预建路由认领前缀集合：每个期望
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
// claimedRoutePrefixes 预建（SVC-C1）。
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

// updateConfigDrift 写入一轮比对结果。U12-F07：锁内只更新状态并拷贝待写
// 内容，日志/审计落库移到 Unlock 之后——审计库 busy（30s busy_timeout）时
// 持有 configDriftMu 会阻塞读者（GetCaddyStatus 的 CurrentConfigDrift）。
func updateConfigDrift(missing, extra []string) {
	drifted := len(missing) > 0 || len(extra) > 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	// 展示/审计文本顺序稳定（U12-F14：调用方若传未排序切片也不抖动）。
	sort.Strings(missing)
	sort.Strings(extra)
	// 待写动作（0=无, 1=恢复, 2=漂移）——锁外执行。
	pendingIO := 0
	detail := ""
	configDriftMu.Lock()
	if !drifted {
		if !configDriftStatus.Consistent {
			pendingIO = 1
		}
		configDriftStreak = 0
		configDriftStatus = ConfigDriftStatus{Consistent: true, CheckedAt: now, SkippedRounds: configDriftStatus.SkippedRounds}
	} else {
		configDriftStreak++
		if configDriftStatus.Consistent && configDriftStreak < 2 {
			configDriftStatus.CheckedAt = now
		} else {
			if configDriftStatus.Consistent {
				detail = formatDriftDetail(missing, extra)
				pendingIO = 2
				configDriftStatus = ConfigDriftStatus{Consistent: false, Since: now, SkippedRounds: configDriftStatus.SkippedRounds}
			}
			configDriftStatus.Missing = missing
			configDriftStatus.Extra = extra
			configDriftStatus.CheckedAt = now
		}
	}
	configDriftMu.Unlock()

	switch pendingIO {
	case 1:
		Logf("info", "配置一致性看门狗：运行配置与规则数据已恢复一致")
		RecordAuditLog("system", "配置恢复", "Caddy配置", "运行配置与规则数据已恢复一致", "")
	case 2:
		Logf("error", "配置一致性看门狗：%s", detail)
		RecordAuditLog("system", "配置漂移", "Caddy配置", detail, "")
	}
}

func formatDriftDetail(missing, extra []string) string {
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, "缺失规则路由: "+strings.Join(missing, "、"))
	}
	if len(extra) > 0 {
		parts = append(parts, "多余规则路由: "+strings.Join(extra, "、"))
	}
	return "运行配置与规则数据不一致（" + strings.Join(parts, "；") + "），请重启服务恢复"
}
