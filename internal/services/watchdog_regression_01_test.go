package services

// 渲染门同源的「HTTP+TLS 证书可用性」判据，否则 ACME 首签窗口/证书过期窗口
// 的 fail-closed 跳过会被误报为配置漂移（连续两轮即全局横幅常亮）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	watchdogEmptyConfig  = `{"apps":{"http":{"servers":{}}}}`
	watchdogRoutedConfig = `{"apps":{"http":{"servers":{"http_18443":{"routes":[{"@id":"lb_l7watch","handle":[]}]}}}}}`
)

// watchTestRule 播种一条启用 HTTPS+ACME 的 HTTP 规则（无证书任务）。
func watchTestRule(t *testing.T, domain string, port int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		enable_tls,tls_source,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold)
		VALUES ('lb_l7watch','l7-watch','','http',?,?,'weighted_round_robin',1,1,'acme_dns',10,2,3,2)`, domain, port); err != nil {
		t.Fatalf("seed watch rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_l7watch','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed watch upstream: %v", err)
	}
}

func setWatchCertJob(t *testing.T, certPEM, keyPEM, domain string) {
	t.Helper()
	if _, err := db.DB.Exec(`DELETE FROM cert_jobs WHERE rule_id='lb_l7watch'`); err != nil {
		t.Fatalf("clear cert job: %v", err)
	}
	if certPEM == "" {
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_l7watch',?,'issued',?,?)`, domain, certPEM, keyPEM); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
}

func watchAdminServer(t *testing.T, config *atomic.Value) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(config.Load().(string)))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestWatchdogMatchesTLSCertificateRenderGate(t *testing.T) {
	newClusterTestService(t)
	ResetConfigDrift()
	t.Cleanup(ResetConfigDrift)

	const domain = "l7-watch.example.test"
	watchTestRule(t, domain, 18443)
	emptyConfig := watchdogEmptyConfig
	routedConfig := watchdogRoutedConfig
	var adminConfig atomic.Value
	adminConfig.Store(emptyConfig)
	admin := watchAdminServer(t, &adminConfig)

	runRound := func(name string) {
		t.Helper()
		checked, err := checkConfigConsistency(admin.URL)
		if err != nil {
			t.Fatalf("%s: check failed: %v", name, err)
		}
		if !checked {
			t.Fatalf("%s: round must be a real check, got skipped", name)
		}
		if status := CurrentConfigDrift(); !status.Consistent {
			t.Fatalf("%s: no drift expected, status=%+v", name, status)
		}
	}
	expectedContains := func(want bool) {
		t.Helper()
		expected, err := expectedRenderedRules()
		if err != nil {
			t.Fatalf("expectedRenderedRules: %v", err)
		}
		if _, ok := expected["lb_l7watch"]; ok != want {
			t.Fatalf("expected rendered contains=%v, want %v (set=%v)", ok, want, expected)
		}
	}

	// 形状 1（目标）：无证书任务（ACME 首签窗口）——渲染 fail-closed 跳过，
	// 运行配置无该路由，看门狗必须视为一致（连续两轮也不漂移）。
	expectedContains(false)
	runRound("no certificate round 1")
	runRound("no certificate round 2")

	// 形状 2（畸形）：过期证书同样不可选——继续不漂移。
	expiredPEM, expiredKey := certificatePairForDomains(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), domain)
	setWatchCertJob(t, expiredPEM, expiredKey, domain)
	expectedContains(false)
	runRound("expired certificate")

	// 形状 3（目标）：有效证书 + 运行配置已发布该规则 → 一致，且规则进入期望集。
	validPEM, validKey := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), domain)
	setWatchCertJob(t, validPEM, validKey, domain)
	adminConfig.Store(routedConfig)
	expectedContains(true)
	runRound("certificate ready")
	runRound("certificate ready round 2")

	// 形状 4（回归，不得放宽漂移检测）：证书就绪但运行配置缺该路由——连续两轮
	// 后必须仍报缺失（证明只排除了「无证书」一类，不吞真实漂移）。
	adminConfig.Store(emptyConfig)
	for i := range 2 {
		if checked, err := checkConfigConsistency(admin.URL); err != nil || !checked {
			t.Fatalf("missing route round %d: checked=%v err=%v", i+1, checked, err)
		}
	}
	status := CurrentConfigDrift()
	if status.Consistent {
		t.Fatalf("ready TLS rule missing from running config must drift: %+v", status)
	}
	if len(status.Missing) != 1 || !strings.Contains(status.Missing[0], "lb_l7watch") {
		t.Fatalf("missing list must name lb_l7watch: %+v", status.Missing)
	}

	// 恢复形状：路由回归 → 一致；随后证书移除（运行配置同步移除）→ 再次一致。
	adminConfig.Store(routedConfig)
	if checked, err := checkConfigConsistency(admin.URL); err != nil || !checked {
		t.Fatalf("recovery round: checked=%v err=%v", checked, err)
	}
	if status := CurrentConfigDrift(); !status.Consistent {
		t.Fatalf("recovered config must be consistent: %+v", status)
	}
	setWatchCertJob(t, "", "", domain)
	adminConfig.Store(emptyConfig)
	expectedContains(false)
	runRound("certificate removed")
}

// 形状补齐：manual 源但证书/私钥为空（带外坏行）——渲染门 fail-closed 跳过,
// 看门狗必须同判据（同一发布谓词 + certReady），不得把它判为「缺失」。
func TestWatchdogSkipsManualTLSRuleWithoutMaterial(t *testing.T) {
	newClusterTestService(t)
	ResetConfigDrift()
	t.Cleanup(ResetConfigDrift)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		enable_tls,tls_source,tls_cert,tls_key,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold)
		VALUES ('lb_l7manual','l7-manual','','http','manual-watch.example.test',18444,'weighted_round_robin',1,1,'manual','','',10,2,3,2)`); err != nil {
		t.Fatalf("seed manual rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_l7manual','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed manual upstream: %v", err)
	}

	expected, err := expectedRenderedRules()
	if err != nil {
		t.Fatalf("expectedRenderedRules: %v", err)
	}
	if _, ok := expected["lb_l7manual"]; ok {
		t.Fatalf("manual 空材料规则不得进入期望集: %v", expected)
	}

	var adminConfig atomic.Value
	adminConfig.Store(`{"apps":{"http":{"servers":{}}}}`)
	admin := watchAdminServer(t, &adminConfig)
	for i := range 2 {
		checked, checkErr := checkConfigConsistency(admin.URL)
		if checkErr != nil || !checked {
			t.Fatalf("round %d: checked=%v err=%v", i+1, checked, checkErr)
		}
		if status := CurrentConfigDrift(); !status.Consistent {
			t.Fatalf("round %d: manual 空材料规则不得造成漂移: %+v", i+1, status)
		}
	}
}

// 保证 emptyConfig/routedConfig 是合法 JSON（防手误拼写使读取分支静默跳过）。
func TestWatchdogFixturesAreValidJSON(t *testing.T) {
	for _, shape := range []string{watchdogEmptyConfig, watchdogRoutedConfig} {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(shape), &parsed); err != nil {
			t.Fatalf("invalid fixture %s: %v", shape, err)
		}
	}
}

// 发布谓词钉测试：看门狗期望集=「启用 ∧ 存在启用上游」——
// 与渲染侧 Go 跳过（零启用上游 warn+continue）恒等。谓词改为共享常量
// publishableRulesSQLPredicate 后，本测试钉死两消费层语义不漂移。
func TestExpectedRenderedRules_publishablePredicate(t *testing.T) {
	newClusterTestService(t)
	seed := func(stmt string, args ...any) {
		t.Helper()
		if _, err := db.DB.Exec(stmt, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,enable_tls) VALUES
		('lb_pub_yes','publishable','http',18081,1,0),
		('lb_pub_noups','no enabled upstream','http',18082,1,0),
		('lb_pub_disabled','disabled','http',18083,0,0)`)
	seed(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES
		('lb_pub_yes','127.0.0.1',9001,1),
		('lb_pub_noups','127.0.0.1',9002,0),
		('lb_pub_disabled','127.0.0.1',9003,1)`)

	expected, err := expectedRenderedRules()
	if err != nil {
		t.Fatalf("expectedRenderedRules: %v", err)
	}
	if _, ok := expected["lb_pub_yes"]; !ok {
		t.Fatalf("enabled rule with enabled upstream must be publishable: %v", expected)
	}
	for _, id := range []string{"lb_pub_noups", "lb_pub_disabled"} {
		if _, ok := expected[id]; ok {
			t.Fatalf("%s must not be publishable: %v", id, expected)
		}
	}
}
