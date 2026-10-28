package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func resetConfigWatchdogForTest(t *testing.T) {
	t.Helper()
	// 复位含心跳窗口/跳过计数与首报留痕标志（原漏 configDriftSkipped
	// 与两枚 warn 标志——跨用例残留会让「失败首报」断言失真）。
	reset := func() {
		configDriftMu.Lock()
		configDriftStatus = ConfigDriftStatus{Consistent: true}
		configDriftStreak = 0
		configDriftCleanRounds = 0
		configDriftSkipped = 0
		configDriftHeartbeatSkipped = 0
		configDriftQueryWarned = false
		configDriftReadWarned = false
		configDriftMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// currentSkippedRounds 读包内「自上次真实检查以来的跳过轮数」。
// 该计数不随状态结构导出（无外部消费方），仅供包内簿记断言。
func currentSkippedRounds() int {
	configDriftMu.RLock()
	defer configDriftMu.RUnlock()
	return configDriftSkipped
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

// 从节点 WatchdogCheckOnce 整轮短路——看门狗是主节点
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
		WatchdogCheckOnce(context.Background())
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
	WatchdogCheckOnce(context.Background())
	WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatal("升主后应恢复真实检查（两轮不一致置漂移态）")
	}
}

func TestConfigWatchdog_subRoutesBelongToParentRule(t *testing.T) {
	// Given：运行配置含子路由 @id（lb_x_redirect / lb_x_path_0）——误报场景
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

// 日志收敛（2026-10-03 裁定，「日志只记真实执行」延伸到常驻循环任务）
// 一致轮不再逐轮写「配置一致」，收敛为每 60 轮（60s×60≈1h）一条心跳；漂移/
// 恢复事件留痕不变。设计变更披露： SPEC 的「每轮一行结论」对一致轮不再
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

	// Given：可达的 Caddy（空配置）+ 空规则库 → 真实检查且一致（自此
	// 跳过轮不计入干净轮，心跳必须由真实检查轮驱动）。
	oldURL := watchdogAdminURLValue
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })

	// When：连续两轮一致。Then：零结论行（原每轮一行）。
	WatchdogCheckOnce(context.Background())
	WatchdogCheckOnce(context.Background())
	if got := heartbeats(); got != 0 {
		t.Fatalf("一致轮结论行=%d, want 0（已收敛为心跳）", got)
	}

	// When：第 3-60 轮。Then：历史恰发一条心跳，无漂移行。
	for i := 3; i <= 60; i++ {
		WatchdogCheckOnce(context.Background())
	}
	log := readTaskLog(t, "config-watchdog")
	if got := strings.Count(log, "配置一致（心跳，近 60 轮无漂移）"); got != 1 {
		t.Fatalf("心跳行=%d, want 1（历史一条）: %q", got, log)
	}
	if strings.Contains(log, "配置漂移") {
		t.Fatalf("一致轮不得出现漂移行: %q", log)
	}

	// 心跳周期重复：61-119 轮静默，历史第二条。
	for i := 61; i <= 119; i++ {
		WatchdogCheckOnce(context.Background())
	}
	if got := heartbeats(); got != 1 {
		t.Fatalf("第 61-119 轮心跳应仍为 1 条, got %d", got)
	}
	WatchdogCheckOnce(context.Background())
	if got := heartbeats(); got != 2 {
		t.Fatalf("历史应有第二条心跳, got %d", got)
	}
}

func TestConfigWatchdog_heartbeatRetainsSkippedCountAcrossCleanWindow(t *testing.T) {
	// Given one undetermined round followed by 60 real, consistent checks.
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = "http://127.0.0.1:1"
	WatchdogCheckOnce(context.Background())
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	for range configWatchdogHeartbeatRounds {
		WatchdogCheckOnce(context.Background())
	}

	// Then the public since-last-check counter is zero, while the heartbeat's
	// independent since-last-heartbeat window still reports the skipped round.
	if got := currentSkippedRounds(); got != 0 {
		t.Fatalf("status skipped rounds=%d, want 0 after real checks", got)
	}
	log := readTaskLog(t, "config-watchdog")
	if !strings.Contains(log, "期间跳过 1 轮未判定") {
		t.Fatalf("heartbeat lost its skipped-round window: %q", log)
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

	// 两轮漂移：历史置漂移态，逐轮漂移行照旧；一致轮零行。
	WatchdogCheckOnce(context.Background())
	WatchdogCheckOnce(context.Background())
	log := readTaskLog(t, "config-watchdog")
	if got := strings.Count(log, "配置漂移"); got != 1 {
		t.Fatalf("漂移行=%d, want 1（防抖首轮静默，置漂移轮起逐轮留痕）: %q", got, log)
	}
	if strings.Contains(log, "配置一致") {
		t.Fatalf("漂移期不得出现心跳行: %q", log)
	}

	// 恢复：恢复轮起重新计数——历史仍静默，历史发一条心跳。
	full := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_hb_drift","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	watchdogAdminURLValue = full.URL
	WatchdogCheckOnce(context.Background()) // 恢复轮（窗口 1/60）
	for i := 2; i <= 59; i++ {
		WatchdogCheckOnce(context.Background())
	}
	if got := strings.Count(readTaskLog(t, "config-watchdog"), "配置一致"); got != 0 {
		t.Fatalf("恢复后历史仍应静默, got %d 条心跳", got)
	}
	WatchdogCheckOnce(context.Background())
	if got := strings.Count(readTaskLog(t, "config-watchdog"), "配置一致"); got != 1 {
		t.Fatalf("恢复后历史应发一条心跳, got %d", got)
	}
}

// 整轮跳过（Caddy 不可达）不构成「一致」证据——连续 120 轮跳过零
// 「配置一致」心跳，干净轮零累积，跳过轮单独计数（原实现把跳过轮计入干净轮
// 并发假心跳）。
func TestConfigWatchdog_skippedRoundsDoNotEmitHeartbeat(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	watchdogAdminURLValue = "http://127.0.0.1:1" // 不可达：每轮整轮跳过
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })

	for range 2 * configWatchdogHeartbeatRounds {
		WatchdogCheckOnce(context.Background())
	}

	if data, err := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); err == nil && strings.Contains(string(data), "配置一致") {
		t.Fatalf("跳过轮不得输出一致心跳: %q", string(data))
	}
	configDriftMu.Lock()
	rounds, skipped := configDriftCleanRounds, configDriftSkipped
	configDriftMu.Unlock()
	if rounds != 0 {
		t.Fatalf("跳过轮累积干净轮=%d, want 0", rounds)
	}
	if skipped != 2*configWatchdogHeartbeatRounds {
		t.Fatalf("跳过轮计数=%d, want %d", skipped, 2*configWatchdogHeartbeatRounds)
	}
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("跳过轮不得置漂移态: %+v", drift)
	}
	if got := currentSkippedRounds(); got != 2*configWatchdogHeartbeatRounds {
		t.Fatalf("跳过轮计数=%d, want %d", got, 2*configWatchdogHeartbeatRounds)
	}
}

// 防抖轮（streak=1、状态仍是 Consistent）不得被当作
// 干净轮——漂移起点恰落在第 60 个检查周期时，原实现会写出「配置一致（心跳）」这一
// 与事实相反的结论，并虚增干净轮计数。
func TestConfigWatchdog_debounceRoundDoesNotCountOrHeartbeat(t *testing.T) {
	// Given：已累积 59 个干净轮，且本轮将观测到第一轮不一致（防抖）
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_debounce", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	configDriftMu.Lock()
	configDriftCleanRounds = configWatchdogHeartbeatRounds - 1
	configDriftMu.Unlock()
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	// 运行配置为空 → 本轮不一致（streak=1，状态仍 Consistent）
	watchdogAdminURLValue = fakeCaddyWithRoutes(t, emptyCaddyConfig).URL

	// When：第 60 个检查周期（防抖轮）
	WatchdogCheckOnce(context.Background())

	// Then：不写心跳，干净轮归零（防抖轮已观测到不一致：既不是一致证据，
	// 也不得让窗口跨过它继续累计——否则凑满 60 个干净轮即发出「近 60 轮无漂移」
	// 的反事实心跳）
	if data, err := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); err == nil && strings.Contains(string(data), "配置一致") {
		t.Fatalf("防抖轮不得输出「配置一致」心跳: %q", string(data))
	}
	configDriftMu.RLock()
	rounds, streak := configDriftCleanRounds, configDriftStreak
	configDriftMu.RUnlock()
	if rounds != 0 {
		t.Fatalf("干净轮=%d, want 0（防抖不一致轮清空窗口）", rounds)
	}
	if streak != 1 {
		t.Fatalf("防抖 streak=%d, want 1", streak)
	}

	// 回归形状：确认漂移后恢复（第二轮不一致 → 状态翻 false，干净轮归零）
	WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatalf("第二轮不一致应置漂移态: %+v", drift)
	}
	configDriftMu.RLock()
	roundsAfterDrift := configDriftCleanRounds
	configDriftMu.RUnlock()
	if roundsAfterDrift != 0 {
		t.Fatalf("漂移态干净轮=%d, want 0", roundsAfterDrift)
	}
}

func TestConfigWatchdog_successfulCheckResetsSkippedRounds(t *testing.T) {
	// Given two undetermined rounds followed by a real, consistent check.
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = "http://127.0.0.1:1"
	WatchdogCheckOnce(context.Background())
	WatchdogCheckOnce(context.Background())
	if got := currentSkippedRounds(); got != 2 {
		t.Fatalf("setup skipped rounds=%d, want 2", got)
	}
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL

	// When a real check succeeds.
	WatchdogCheckOnce(context.Background())

	// Then the counter defined as "since the last real check" returns to zero,
	// while the successful round still advances the clean-round window.
	if got := currentSkippedRounds(); got != 0 {
		t.Fatalf("skipped rounds after real consistent check=%d, want 0", got)
	}
	configDriftMu.RLock()
	cleanRounds := configDriftCleanRounds
	configDriftMu.RUnlock()
	if cleanRounds != 1 {
		t.Fatalf("clean rounds=%d, want 1", cleanRounds)
	}

	// And a later skipped round is counted from this new real-check boundary.
	watchdogAdminURLValue = "http://127.0.0.1:1"
	WatchdogCheckOnce(context.Background())
	if got := currentSkippedRounds(); got != 1 {
		t.Fatalf("skipped rounds after new failure=%d, want 1", got)
	}
}

// 漂移证据必须连续：一轮未判定（规则/Caddy 读取失败）本身不含证据，
// 不得让「漂移→跳过→漂移」跨过它拼成两轮证据而确认漂移。
func TestConfigWatchdog_skippedRoundBreaksDriftStreak(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_streak", false)
	resetConfigWatchdogForTest(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	driftServer := fakeCaddyWithRoutes(t, emptyCaddyConfig)

	// 第一轮不一致（防抖：只计数不置状态）
	watchdogAdminURLValue = driftServer.URL
	WatchdogCheckOnce(context.Background())
	// 一轮未判定（Caddy 不可达）
	watchdogAdminURLValue = "http://127.0.0.1:1"
	WatchdogCheckOnce(context.Background())
	// 再一轮不一致：与首轮之间隔了未知轮，不构成连续证据
	watchdogAdminURLValue = driftServer.URL
	WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("漂移→跳过→漂移不是连续两轮证据，不得确认漂移: %+v", drift)
	}
	configDriftMu.RLock()
	streak := configDriftStreak
	configDriftMu.RUnlock()
	if streak != 1 {
		t.Fatalf("streak=%d, want 1（跳过轮必须打断连续窗口）", streak)
	}

	// 第四轮仍不一致 → 此时才是连续两轮有效证据
	WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatalf("连续两轮有效不一致应确认漂移: %+v", drift)
	}
}

// 心跳文案的「期间跳过 N 轮」窗口与干净轮窗口同起点：一轮不一致观测
// 已清空干净轮窗口，跳过计数必须同步重启——否则恢复后的心跳会把漂移之前的
// 跳过轮算进「近 60 轮」窗口。
func TestConfigWatchdog_heartbeatSkippedWindowRestartsAtDriftObservation(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_hb_window", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })

	// 一轮未判定（跳过轮）
	watchdogAdminURLValue = "http://127.0.0.1:1"
	WatchdogCheckOnce(context.Background())
	// 一轮不一致观测（防抖）
	driftServer := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = driftServer.URL
	WatchdogCheckOnce(context.Background())

	configDriftMu.RLock()
	cleanRounds, heartbeatSkipped := configDriftCleanRounds, configDriftHeartbeatSkipped
	configDriftMu.RUnlock()
	if cleanRounds != 0 || heartbeatSkipped != 0 {
		t.Fatalf("不一致观测须重启心跳窗口: clean=%d heartbeatSkipped=%d, want 0/0", cleanRounds, heartbeatSkipped)
	}

	// 第二轮不一致 → 确认漂移；恢复后积满心跳窗口，心跳不得携带漂移前的跳过轮
	WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatalf("连续两轮不一致应确认漂移: %+v", drift)
	}
	full := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_watchdog_hb_window","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	watchdogAdminURLValue = full.URL
	for range configWatchdogHeartbeatRounds {
		WatchdogCheckOnce(context.Background())
	}
	log := readTaskLog(t, "config-watchdog")
	if !strings.Contains(log, "配置一致（心跳，近 60 轮无漂移）") {
		t.Fatalf("恢复后满窗口应发无跳过计数的历史心跳: %q", log)
	}
	if strings.Contains(log, "期间跳过") {
		t.Fatalf("不一致观测之前的跳过轮不得计入心跳窗口: %q", log)
	}
}

// 非 lb_ 前缀的合法 caddy_id（v2 导入字母表允许，如 web1）必须与渲染口径
// 恒等：看门狗比对不得按前缀过滤运行配置 @id，否则导入规则后每轮都误报
// 「缺失」并常亮全局漂移横幅（重启也不会恢复）。
func TestConfigWatchdog_nonLbPrefixedRuleNotFlaggedAsDrift(t *testing.T) {
	newClusterTestService(t)
	ResetConfigDrift()
	t.Cleanup(ResetConfigDrift)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold)
		VALUES ('web1','web1','','http','web1.example.test',18081,'weighted_round_robin',1,10,2,3,2)`); err != nil {
		t.Fatalf("seed non-prefixed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('web1','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_18081":{"routes":[{"@id":"web1","handle":[]}]}}}}}`)

	for i := range 2 {
		checked, err := checkConfigConsistency(server.URL)
		if err != nil || !checked {
			t.Fatalf("round %d: checked=%v err=%v", i+1, checked, err)
		}
		if status := CurrentConfigDrift(); !status.Consistent {
			t.Fatalf("round %d: 非 lb_ 前缀规则被误报漂移: %+v", i+1, status)
		}
	}
	// 启动守卫的启发式面保持不变：非 lb_ @id 不进入外来路由告警。
	foreign, err := ForeignRunningRuleRoutes(server.URL, map[string]bool{"web1": true})
	if err != nil {
		t.Fatalf("ForeignRunningRuleRoutes: %v", err)
	}
	if len(foreign) != 0 {
		t.Fatalf("非 lb_ 前缀路由不得被判为外来: %v", foreign)
	}
	if hasRoutes, err := RunningConfigHasRuleRoutes(server.URL); err != nil || hasRoutes {
		t.Fatalf("启动守卫只认 lb_ 前缀: hasRoutes=%v err=%v", hasRoutes, err)
	}
}

// 畸形运行配置形状不得 panic，且合法路由照常提取。
func TestRunningRuleRouteIDs_toleratesMalformedShapes(t *testing.T) {
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"s":{"routes":["str",{"@id":"lb_x"},{"@id":123},null]}},"other":"not-a-map"},"layer4":"bad"}}`)

	hasRoutes, err := RunningConfigHasRuleRoutes(server.URL)
	if err != nil {
		t.Fatalf("RunningConfigHasRuleRoutes: %v", err)
	}
	if !hasRoutes {
		t.Fatal("lb_x 应被识别为规则路由")
	}
	foreign, err := ForeignRunningRuleRoutes(server.URL, map[string]bool{})
	if err != nil {
		t.Fatalf("ForeignRunningRuleRoutes: %v", err)
	}
	if len(foreign) != 1 || foreign[0] != "lb_x" {
		t.Fatalf("foreign=%v, want [lb_x]", foreign)
	}
}

// 同一集合的漂移 diff 结果顺序稳定（map 遍历随机不得驱动展示抖动）。
func TestConfigDriftDiffOrderIsStable(t *testing.T) {
	expected := map[string]string{}
	running := map[string]bool{}
	for i := range 20 {
		id := fmt.Sprintf("lb_rule_%02d", i)
		expected[id] = "name-" + id
		if i%2 == 1 {
			running[id] = true
		} else {
			running[fmt.Sprintf("lb_extra_%02d", i)] = true
		}
	}
	firstMissing := diffExpectedMissing(expected, running)
	firstExtra := diffRunningExtra(expected, running)
	if !sort.StringsAreSorted(firstMissing) {
		t.Fatalf("missing 未排序: %v", firstMissing)
	}
	if !sort.StringsAreSorted(firstExtra) {
		t.Fatalf("extra 未排序: %v", firstExtra)
	}
	for range 10 {
		if !slices.Equal(firstMissing, diffExpectedMissing(expected, running)) {
			t.Fatalf("missing 顺序抖动: %v vs %v", firstMissing, diffExpectedMissing(expected, running))
		}
		if !slices.Equal(firstExtra, diffRunningExtra(expected, running)) {
			t.Fatalf("extra 顺序抖动: %v vs %v", firstExtra, diffRunningExtra(expected, running))
		}
	}
}

// syncLogBuffer 并发安全的日志缓冲（updateConfigDrift 在另一个 goroutine 里写日志）。
type syncLogBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// 审计库被外部写锁占住（RecordAuditLog 阻塞）时，看门狗不得持
// configDriftMu 等 I/O——读者 CurrentConfigDrift 必须立即可返回。
func TestUpdateConfigDrift_releasesLockBeforeAuditIO(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	dataDir := t.TempDir()
	oldAudit := db.AuditDB
	if err := db.InitializeAuditDB(dataDir); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	auditHandle := db.AuditDB
	t.Cleanup(func() {
		_ = auditHandle.Close()
		db.AuditDB = oldAudit
	})

	locker, err := sql.Open("sqlite", filepath.Join(dataDir, "lazy-balancer-audit.db")+"?_txlock=immediate&_pragma=busy_timeout(30000)")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := locker.Begin()
	if err != nil {
		t.Fatalf("begin locker tx: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO audit_log (username, action, resource) VALUES ('locker','持有','写锁')`); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}

	logs := captureStandardLog(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		emitConfigDriftEvent(updateConfigDrift([]string{"lb_x"}, nil)) // 首轮只计数（无事件）
		emitConfigDriftEvent(updateConfigDrift([]string{"lb_x"}, nil)) // 置漂移 + 审计落库（被写锁阻塞）
	}()
	t.Cleanup(func() {
		_ = tx.Rollback()
		_ = locker.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("updateConfigDrift 在解除审计库写锁后未返回")
		}
	})

	// 等到「运行配置与规则数据不一致」日志出现（置态已完成、卡在审计写入前）。
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "运行配置与规则数据不一致") {
		if time.Now().After(deadline) {
			t.Fatalf("未观察到漂移日志（前置未达成）: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitForStableCond(t, time.Second, 5, func() bool { return strings.Contains(logs.String(), "运行配置与规则数据不一致") })

	probe := make(chan ConfigDriftStatus, 1)
	go func() { probe <- CurrentConfigDrift() }()
	select {
	case st := <-probe:
		if st.Consistent {
			t.Fatalf("前置：应已置漂移态, got %+v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CurrentConfigDrift 在审计库 busy 时被 configDriftMu 阻塞（锁内 I/O）")
	}
}

// 整轮未判定必须上报失败。此前 WatchdogCheckOnce
// 丢弃 checkConfigConsistency 的 (checked, err)，Caddy 不可达/运行配置读取失败
// 时本轮零业务日志、task_runs 恒 success，任务监控无法区分「真实检查且一致」
// 与「整轮没查」（与同文件「跳过轮不构成一致证据」口径冲突）。
func TestConfigWatchdog_uncheckedRoundFailsTaskRun(t *testing.T) {
	// Given：引擎已装配（DB 初始化、任务日志目录已注入）+ Caddy admin 不可达
	newTaskLogDir(t)
	resetConfigWatchdogForTest(t)
	te := newWireTestEngine(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = "http://127.0.0.1:1"

	// When：经引擎真实 Run 体执行一轮（Caddy 不可达 → 本轮无法判定）
	err := te.Trigger("config-watchdog", "manual", "")

	// Then：运行返回错误，task_runs 落 failed（不是 success）
	if err == nil {
		t.Fatal("整轮未判定必须返回错误（否则 task_runs 恒 success，监控看不到跳过）")
	}
	var status string
	if qerr := db.DB.QueryRow(`SELECT status FROM task_runs WHERE task_id='config-watchdog' ORDER BY id DESC LIMIT 1`).Scan(&status); qerr != nil {
		t.Fatalf("read task run status: %v", qerr)
	}
	if status != "failed" {
		t.Fatalf("task_runs.status=%q, want failed（跳过轮须在任务面可见）", status)
	}

	// And：任务日志有业务摘要行，说明本轮未完成判定
	logText := readTaskLog(t, "config-watchdog")
	if !strings.Contains(logText, "配置检查未完成") {
		t.Fatalf("任务日志缺少未判定摘要行:\n%s", logText)
	}
}

// 反向形状：真实完成的检查轮仍返回 nil（不得把「一致」误报为失败）。
func TestConfigWatchdog_checkedRoundSucceeds(t *testing.T) {
	newTaskLogDir(t)
	resetConfigWatchdogForTest(t)
	te := newWireTestEngine(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = server.URL

	if err := te.Trigger("config-watchdog", "manual", ""); err != nil {
		t.Fatalf("真实完成的一致轮必须成功: %v", err)
	}
}

// 看门狗角色读取持久失败必须按状态转换留痕（首报一次 + 恢复 info）：此前
// 每 60s 一条裸 warn＝1440 行/天同一消息，加速应用日志轮转并淹没真实信号。
func TestConfigWatchdog_roleReadFailureLogsOnceAndRecovers(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	isolateMetricsState(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = fakeCaddyWithRoutes(t, emptyCaddyConfig).URL
	logs := captureStandardLog(t)

	// When：角色读取连续两轮失败
	originalDB, originalCurrent := db.DB, db.GetDB()
	swapBrokenDB(t)
	for range 2 {
		if err := WatchdogCheckOnce(context.Background()); err == nil {
			t.Fatal("角色读取失败必须让本轮返回错误（task_runs failed）")
		}
	}
	if count := strings.Count(logs.String(), "角色读取失败"); count != 1 {
		t.Fatalf("角色读取失败日志次数=%d, want 1（状态转换去重）: %s", count, logs.String())
	}

	db.DB = originalDB
	db.SetDB(originalCurrent)
	for range 2 {
		if err := WatchdogCheckOnce(context.Background()); err != nil {
			t.Fatalf("角色读取恢复后的检查失败: %v", err)
		}
	}
	if count := strings.Count(logs.String(), "角色读取已恢复"); count != 1 {
		t.Fatalf("角色读取恢复日志次数=%d, want 1（恢复首报，持续健康不重复）: %s", count, logs.String())
	}
}

// 看门狗持锁期间不得做日志 I/O：日志落盘慢（轮转 writer/stdout 背压）时
// 读接口（GetCaddyStatus → CurrentConfigDrift RLock）会被连带阻塞。
func TestConfigWatchdog_doesNotHoldDriftLockDuringLogIO(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	// 运行配置不可解析 → 读失败分支（该分支历史上在锁内 Logf）
	watchdogAdminURLValue = fakeCaddyWithRoutes(t, "not-a-config").URL
	writer := &blockingLogWriter{marker: "读取运行配置失败", entered: make(chan struct{}), release: make(chan struct{})}
	originalWriter := log.Writer()
	log.SetOutput(writer)
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
		writer.unblock()
	})

	done := make(chan struct{})
	go func() {
		_ = WatchdogCheckOnce(context.Background())
		close(done)
	}()
	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("未进入读失败日志写入（夹具失效）")
	}

	// Then：日志写入阻塞中，状态读者必须仍能取得快照
	read := make(chan struct{})
	go func() {
		_ = CurrentConfigDrift()
		close(read)
	}()
	select {
	case <-read:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("日志 I/O 阻塞时仍持有 configDriftMu → CurrentConfigDrift 被阻塞")
	}
	writer.unblock()
	<-done
}

// blockingLogWriter 在写入含 marker 的首行时阻塞，直到 unblock（模拟日志
// 落盘慢/背压）；其他行直接放行。
type blockingLogWriter struct {
	marker  string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingLogWriter) Write(p []byte) (int, error) {
	if w.marker != "" && strings.Contains(string(p), w.marker) {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(p), nil
}

func (w *blockingLogWriter) unblock() {
	select {
	case <-w.release:
	default:
		close(w.release)
	}
}
