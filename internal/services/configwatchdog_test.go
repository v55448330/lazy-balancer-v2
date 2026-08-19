package services

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func resetConfigWatchdogForTest(t *testing.T) {
	t.Helper()
	configDriftMu.Lock()
	configDriftStatus = ConfigDriftStatus{Consistent: true}
	configDriftStreak = 0
	configDriftMu.Unlock()
	t.Cleanup(func() {
		configDriftMu.Lock()
		configDriftStatus = ConfigDriftStatus{Consistent: true}
		configDriftStreak = 0
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

func TestConfigWatchdog_skipsOnSlave(t *testing.T) {
	// Given：从节点角色
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	seedGenerationRule(t, database, "lb_watchdog_slave", false)
	resetConfigWatchdogForTest(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)

	// When
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：从节点不告警（同步链路覆盖）
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("slave must not flag drift, got %+v", drift)
	}
	_ = db.DB
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
