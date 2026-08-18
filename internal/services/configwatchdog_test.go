package services

import (
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
