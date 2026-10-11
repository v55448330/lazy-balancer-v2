package services

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

func resetConfigWatchdogForTest(t *testing.T) {
	t.Helper()
	configDriftMu.Lock()
	configDriftStatus = ConfigDriftStatus{Consistent: true}
	configDriftStreak = 0
	configDriftCleanRounds = 0
	configDriftMu.Unlock()
	t.Cleanup(func() {
		configDriftMu.Lock()
		configDriftStatus = ConfigDriftStatus{Consistent: true}
		configDriftStreak = 0
		configDriftCleanRounds = 0
		configDriftMu.Unlock()
	})
}

func fakeCaddyWithRoutes(t *testing.T, configJSON string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(configJSON))
	}))
	t.Cleanup(server.Close)
	return server
}

const emptyCaddyConfig = `{"apps":{"http":{"servers":{"http_80":{"listen":[":80"],"routes":[{"handle":[{"handler":"static_response"}]}]}}}}}`

func TestConfigWatchdog_flagsMissingRoutesAfterTwoCycles(t *testing.T) {
	// Given：DB 有启用规则+启用上游，Caddy 运行配置为空（零规则路由）
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_missing", false)
	resetConfigWatchdogForTest(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)

	// When：首轮检查
	checkConfigConsistency(server.URL)

	// Then：首轮只计数不告警（防应用窗口误报）
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("first cycle must not flag drift, got %+v", drift)
	}

	// When：第二轮检查
	checkConfigConsistency(server.URL)

	// Then：连续两轮不一致 → 置漂移状态并点名缺失规则
	drift := CurrentConfigDrift()
	if drift.Consistent || len(drift.Missing) != 1 || drift.Missing[0] != "lb_watchdog_missing（lb_watchdog_missing）" {
		t.Fatalf("drift=%+v, want missing lb_watchdog_missing", drift)
	}
}

func TestConfigWatchdog_recoversWhenRoutesReturn(t *testing.T) {
	// Given：先进入漂移状态
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_recover", false)
	resetConfigWatchdogForTest(t)
	empty := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	checkConfigConsistency(empty.URL)
	checkConfigConsistency(empty.URL)
	if CurrentConfigDrift().Consistent {
		t.Fatalf("precondition: drift must be flagged")
	}

	// When：运行配置恢复（路由回来了）
	full := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_watchdog_recover","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	checkConfigConsistency(full.URL)

	// Then：状态恢复一致
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("drift=%+v, want consistent after routes return", drift)
	}
}

// L1-P4-2（第 67 轮审计）：从节点 WatchdogCheckOnce 整轮短路——看门狗是主节点
// 专属检测，从节点零心跳簿记、零任务日志（此前从节点每轮空跑：cleanRounds 累积
// 并逐小时发「配置一致」假心跳，升主前从未真实检查）。循环保持存活，升主后自动
// 恢复真实检查。
func TestConfigWatchdog_slaveSkipsWholeRound(t *testing.T) {
	// Given 从节点角色 + 一条主节点必报漂移的启用规则 + 空运行配置
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	seedGenerationRule(t, database, "lb_watchdog_slave_round", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })
	// When 从节点连打两轮心跳窗口（120 轮）
	for range 2 * configWatchdogHeartbeatRounds {
		WatchdogCheckOnce()
	}

	// Then 零任务日志（无假心跳）+ 心跳计数零累积 + 零漂移态（整轮短路）
	if data, err := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		t.Fatalf("从节点应零任务日志行, got %q", data)
	}
	configDriftMu.Lock()
	rounds := configDriftCleanRounds
	configDriftMu.Unlock()
	if rounds != 0 {
		t.Fatalf("从节点心跳计数应零累积, got %d", rounds)
	}
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("从节点不得置漂移态, got %+v", drift)
	}

	// 回归形状：升主后同一循环恢复真实检查（空运行配置两轮置漂移态）
	if _, err := database.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	WatchdogCheckOnce()
	WatchdogCheckOnce()
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatal("升主后应恢复真实检查（两轮不一致置漂移态）")
	}
}

func TestConfigWatchdog_subRoutesBelongToParentRule(t *testing.T) {
	// Given：运行配置含子路由 @id（lb_x_redirect / lb_x_path_0）——R36 WD-1 误报场景
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_sub", false)
	resetConfigWatchdogForTest(t)
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_443":{"listen":[":443"],"routes":[{"@id":"lb_watchdog_sub","handle":[{"handler":"reverse_proxy"}]},{"@id":"lb_watchdog_sub_redirect","handle":[{"handler":"static_response"}]},{"@id":"lb_watchdog_sub_path_0","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)

	// When：两轮检查
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：子路由归属主规则，不误报
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("sub-routes must not be flagged as extra, got %+v", drift)
	}
}

func TestConfigWatchdog_orphanRouteStillFlagged(t *testing.T) {
	// Given：运行配置含 DB 中不存在的规则路由（真正的多余）
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_real", false)
	resetConfigWatchdogForTest(t)
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_watchdog_real","handle":[]},{"@id":"lb_deleted_rule","handle":[]}]}}}}}`)

	// When
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：孤儿路由被点名
	drift := CurrentConfigDrift()
	if drift.Consistent || len(drift.Extra) != 1 || drift.Extra[0] != "lb_deleted_rule" {
		t.Fatalf("drift=%+v, want extra lb_deleted_rule", drift)
	}
}

func TestConfigWatchdog_tcpDynamicDNSAndSamePortNotFlagged(t *testing.T) {
	// Given：TCP+动态 DNS 规则与同端口多 TCP 规则——渲染侧有意跳过，看门狗不应误报
	_, database := newClusterTestService(t)
	seedTCPWatchdogRule(t, database, "lb_tcp_dyndns", 9501, true)
	seedTCPWatchdogRule(t, database, "lb_tcp_multi_a", 9502, false)
	seedTCPWatchdogRule(t, database, "lb_tcp_multi_b", 9502, false)
	seedGenerationRule(t, database, "lb_http_normal", false)
	resetConfigWatchdogForTest(t)
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_http_normal","handle":[]}]}}}}}`)

	// When
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：只有正常渲染的 HTTP 规则在期望集合内，跳过类规则不误报缺失
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("render-skipped TCP rules must not be flagged, got %+v", drift)
	}
}

func seedTCPWatchdogRule(t *testing.T, database *sql.DB, ruleID string, listenPort int, dynamicDNS bool) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,dynamic_dns)
		VALUES (?,?,'tcp','',?,'weighted_round_robin',1,?)`, ruleID, ruleID, listenPort, dynamicDNS); err != nil {
		t.Fatalf("seed tcp rule %s: %v", ruleID, err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,'tcp')", ruleID); err != nil {
		t.Fatalf("seed tcp upstream %s: %v", ruleID, err)
	}
}

// R66 日志收敛（2026-10-03 裁定，R65「日志只记真实执行」延伸到常驻循环任务）：
// 一致轮不再逐轮写「配置一致」，收敛为每 60 轮（60s×60≈1h）一条心跳；漂移/
// 恢复事件留痕不变。设计变更披露：R62 SPEC 的「每轮一行结论」对一致轮不再
// 成立（task_logf_pin_test.go 的接线钉已同步迁移到心跳形态）。
func TestConfigWatchdog_heartbeatGatesConsistentRounds(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)

	// 心跳计数（零日志轮文件尚不存在——直调 WatchdogCheckOnce 无引擎 [start]/
	// [done] 记账行，文件由首条 TaskLogf 创建）。
	heartbeats := func() int {
		data, err := os.ReadFile(taskengine.TaskLogPath("config-watchdog"))
		if err != nil {
			return 0
		}
		return strings.Count(string(data), "配置一致")
	}

	// Given/When：连续两轮一致（admin 不可达跳过检查、状态维持初始一致——与
	// 引擎空轮同形）。Then：零结论行（原每轮一行）。
	WatchdogCheckOnce()
	WatchdogCheckOnce()
	if got := heartbeats(); got != 0 {
		t.Fatalf("一致轮结论行=%d, want 0（已收敛为心跳）", got)
	}

	// When：第 3-60 轮。Then：第 60 轮恰发一条心跳，无漂移行。
	for i := 3; i <= 60; i++ {
		WatchdogCheckOnce()
	}
	log := readTaskLog(t, "config-watchdog")
	if got := strings.Count(log, "配置一致（心跳，近 60 轮无漂移）"); got != 1 {
		t.Fatalf("心跳行=%d, want 1（第 60 轮一条）: %q", got, log)
	}
	if strings.Contains(log, "配置漂移") {
		t.Fatalf("一致轮不得出现漂移行: %q", log)
	}

	// 心跳周期重复：61-119 轮静默，第 120 轮第二条。
	for i := 61; i <= 119; i++ {
		WatchdogCheckOnce()
	}
	if got := heartbeats(); got != 1 {
		t.Fatalf("第 61-119 轮心跳应仍为 1 条, got %d", got)
	}
	WatchdogCheckOnce()
	if got := heartbeats(); got != 2 {
		t.Fatalf("第 120 轮应有第二条心跳, got %d", got)
	}
}

// 心跳窗口诚实性：漂移把窗口清零——恢复后须重新积满 60 轮一致才发下一条
// 心跳；漂移期逐轮漂移行与恢复序列行为不变（仅原漂移防抖首轮的「配置一致」
// 行随一致轮收敛消失——该轮本就是未确认轮）。
func TestConfigWatchdog_heartbeatWindowResetsOnDrift(t *testing.T) {
	_, database := newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	seedGenerationRule(t, database, "lb_hb_drift", false)
	oldURL := watchdogAdminURLValue
	empty := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = empty.URL
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })

	// 两轮漂移：第 2 轮置漂移态，逐轮漂移行照旧；一致轮零行。
	WatchdogCheckOnce()
	WatchdogCheckOnce()
	log := readTaskLog(t, "config-watchdog")
	if got := strings.Count(log, "配置漂移"); got != 1 {
		t.Fatalf("漂移行=%d, want 1（防抖首轮静默，置漂移轮起逐轮留痕）: %q", got, log)
	}
	if strings.Contains(log, "配置一致") {
		t.Fatalf("漂移期不得出现心跳行: %q", log)
	}

	// 恢复：恢复轮起重新计数——第 59 轮仍静默，第 60 轮发一条心跳。
	full := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_hb_drift","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	watchdogAdminURLValue = full.URL
	WatchdogCheckOnce() // 恢复轮（窗口 1/60）
	for i := 2; i <= 59; i++ {
		WatchdogCheckOnce()
	}
	if got := strings.Count(readTaskLog(t, "config-watchdog"), "配置一致"); got != 0 {
		t.Fatalf("恢复后第 59 轮仍应静默, got %d 条心跳", got)
	}
	WatchdogCheckOnce()
	if got := strings.Count(readTaskLog(t, "config-watchdog"), "配置一致"); got != 1 {
		t.Fatalf("恢复后第 60 轮应发一条心跳, got %d", got)
	}
}
