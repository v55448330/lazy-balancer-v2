package services

// 库值唯一真相（批 1+2）渲染侧钉测：
//
// 类型①值型列（schema DEFAULT + 启动回填报证库恒有效）渲染直读贯通——
// 库值是多少就发射多少（哨兵值验证无写死替换）；库值无效（<=0，仅可能来自
// 带外直写/旧备份绕过导入门）→ 渲染显性报错（fail-visible），不再回退写死
// 常量。类型②省略型（0=不发射该 key，继承 Caddy 引擎默认）保持不变。
//
// 批 3（2026-10-15）扩展：安全策略值列 anomaly_threshold（①）/rate_limit_rps
// （①，条件消费）/rate_limit_burst（②省略型）/block_status_code（②省略型，
// 0=跟随默认 403）与 global_config.cert_expiry_days（①）。
//
// 反兜底机制钉测见 render_anti_fallback_scan_test.go。

import (
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// truthRule 构造健康检查族全哨兵值的 HTTP 规则（interval=37/timeout=13/
// unhealthy=5/healthy=4——全部偏离默认值，任何写死兜底都会被识破）。
func truthRule(caddyID string) SingleRuleConfig {
	return SingleRuleConfig{
		CaddyID:                       caddyID,
		Protocol:                      "http",
		Domain:                        "truth.test",
		ListenPort:                    8099,
		Strategy:                      "weighted_round_robin",
		HealthCheckInterval:           37,
		HealthCheckTimeout:            13,
		HealthCheckUnhealthyThreshold: 5,
		HealthCheckHealthyThreshold:   4,
		TCPTryDuration:                3000,
		TCPTryInterval:                777,
		// 模拟库值唯一真相下的全局值（类型①恒有效）；规则级 0=跟随全局。
		GlobalRequestBodyMaxSizeMB: 128,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.9.10", Port: 9000, Weight: 1, Protocol: "http", Enabled: true},
		},
	}
}

func TestRenderDBTruth_HealthCheckSentinelPassThrough(t *testing.T) {
	stubSecurityLibsAvailable(t)
	rule := truthRule("lb-truth-hc")
	rule.EnableActiveHealthCheck = true

	_, mainRoute, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generateHTTPRouteObjects: %v", err)
	}
	proxy := findHandlerInChain(t, mainRoute, "reverse_proxy")
	if proxy == nil {
		t.Fatalf("no reverse_proxy handler: %v", handlerNames(t, mainRoute))
	}
	hc, _ := proxy["health_checks"].(map[string]interface{})
	if hc == nil {
		t.Fatalf("no health_checks: %v", proxy)
	}
	passive, _ := hc["passive"].(map[string]interface{})
	if passive["fail_duration"] != "111s" { // 37s × 3：库值 37 贯通
		t.Fatalf("passive fail_duration=%v, want 111s (interval sentinel 37)", passive["fail_duration"])
	}
	if passive["max_fails"] != 5 {
		t.Fatalf("passive max_fails=%v, want 5 (unhealthy sentinel)", passive["max_fails"])
	}
	active, _ := hc["active"].(map[string]interface{})
	if active == nil {
		t.Fatalf("no active health_checks: %v", hc)
	}
	if active["interval"] != "37s" || active["timeout"] != "13s" {
		t.Fatalf("active interval/timeout=%v/%v, want 37s/13s", active["interval"], active["timeout"])
	}
	if active["passes"] != 4 || active["fails"] != 5 {
		t.Fatalf("active passes/fails=%v/%v, want 4/5", active["passes"], active["fails"])
	}
}

func TestRenderDBTruth_TryIntervalSentinelPassThrough(t *testing.T) {
	rule := truthRule("lb-truth-try")
	_, mainRoute, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generateHTTPRouteObjects: %v", err)
	}
	proxy := findHandlerInChain(t, mainRoute, "reverse_proxy")
	lb, _ := proxy["load_balancing"].(map[string]interface{})
	if lb["try_interval"] != "777ms" {
		t.Fatalf("HTTP try_interval=%v, want 777ms (库值直读)", lb["try_interval"])
	}

	rule.Protocol = "tcp"
	tcpServer, err := buildTCPServer(rule)
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	routes := tcpServer["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	handle := route["handle"].([]interface{})[0].(map[string]interface{})
	tcpLB := handle["load_balancing"].(map[string]interface{})
	if tcpLB["try_interval"] != "777ms" {
		t.Fatalf("TCP try_interval=%v, want 777ms (库值直读)", tcpLB["try_interval"])
	}
}

func TestRenderDBTruth_ZeroRuleColumnsFailVisible(t *testing.T) {
	stubSecurityLibsAvailable(t)
	// health_check_timeout/healthy_threshold 仅在主动健康检查启用时被消费
	//（passive 形态不读这两个值）——打靶这两列时开启 EnableActiveHealthCheck。
	cases := []struct {
		name   string
		active bool
		mutate func(r *SingleRuleConfig)
		hint   string
	}{
		{"health_check_interval", false, func(r *SingleRuleConfig) { r.HealthCheckInterval = 0 }, "健康检查间隔"},
		{"health_check_timeout", true, func(r *SingleRuleConfig) { r.HealthCheckTimeout = 0 }, "健康检查超时"},
		{"health_check_unhealthy_threshold", false, func(r *SingleRuleConfig) { r.HealthCheckUnhealthyThreshold = 0 }, "失败阈值"},
		{"health_check_healthy_threshold", true, func(r *SingleRuleConfig) { r.HealthCheckHealthyThreshold = 0 }, "恢复阈值"},
		{"tcp_try_interval", false, func(r *SingleRuleConfig) { r.TCPTryInterval = 0 }, "重试间隔"},
	}
	for _, tc := range cases {
		t.Run("http/"+tc.name, func(t *testing.T) {
			rule := truthRule("lb-truth-zero")
			rule.EnableActiveHealthCheck = tc.active
			tc.mutate(&rule)
			_, _, err := generateHTTPRouteObjects(rule)
			if err == nil {
				t.Fatalf("%s=0 must fail render generation (fail-visible), got nil error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("error %q missing hint %q", err.Error(), tc.hint)
			}
		})
	}
	for _, tc := range cases {
		if tc.name == "tcp_try_interval" {
			continue
		}
		t.Run("tcp/"+tc.name, func(t *testing.T) {
			rule := truthRule("lb-truth-zero")
			rule.Protocol = "tcp"
			rule.EnableActiveHealthCheck = tc.active
			tc.mutate(&rule)
			_, err := buildTCPServer(rule)
			if err == nil {
				t.Fatalf("tcp %s=0 must fail render generation (fail-visible), got nil error", tc.name)
			}
		})
	}
	t.Run("tcp/tcp_try_interval", func(t *testing.T) {
		rule := truthRule("lb-truth-zero")
		rule.Protocol = "tcp"
		rule.TCPTryInterval = 0
		_, err := buildTCPServer(rule)
		if err == nil {
			t.Fatal("tcp tcp_try_interval=0 must fail render generation (fail-visible), got nil error")
		}
	})
}

func TestRenderDBTruth_ZeroGlobalColumnsFailVisible(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-truth-global", false)

	cases := []struct {
		column string
		hint   string
	}{
		{"request_body_max_size_mb", "请求体大小"},
		{"http_read_timeout", "读取超时"},
		{"http_write_timeout", "写入超时"},
		{"http_idle_timeout", "空闲超时"},
		{"caddy_log_size_mb", "日志轮转大小"},
	}
	for _, tc := range cases {
		t.Run(tc.column, func(t *testing.T) {
			// 复位五列默认值（前序子测试的置 0 会跨子测试泄漏），再单独打靶目标列。
			if _, err := database.Exec(`UPDATE global_config SET request_body_max_size_mb=128, http_read_timeout=60, http_write_timeout=60, http_idle_timeout=120, caddy_log_size_mb=100`); err != nil {
				t.Fatalf("reset globals: %v", err)
			}
			if _, err := database.Exec("UPDATE global_config SET " + tc.column + "=0"); err != nil {
				t.Fatalf("zero column: %v", err)
			}
			generated := generateCaddyConfigFromStore(database)
			message, ok := generated[caddyConfigGenerationErrorKey].(string)
			if !ok {
				t.Fatalf("%s=0 must fail generation (fail-visible), got config keys %v", tc.column, configKeys(generated))
			}
			if !strings.Contains(message, tc.hint) {
				t.Fatalf("generation error %q missing hint %q", message, tc.hint)
			}
		})
	}
}

func configKeys(config map[string]interface{}) []string {
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	return keys
}

func TestRenderDBTruth_GlobalTimeoutsDirectEmit(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-truth-timeouts", false)

	assertServerTimeouts := func(wantRead, wantWrite, wantIdle string) {
		t.Helper()
		generated := generateCaddyConfigFromStore(database)
		if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("generation failed: %s", message)
		}
		apps := generated["apps"].(map[string]interface{})
		httpApp := apps["http"].(map[string]interface{})
		server := httpApp["servers"].(map[string]interface{})["http_8080"].(map[string]interface{})
		if got := server["read_timeout"]; got != wantRead {
			t.Fatalf("read_timeout=%v, want %v", got, wantRead)
		}
		if got := server["write_timeout"]; got != wantWrite {
			t.Fatalf("write_timeout=%v, want %v", got, wantWrite)
		}
		if got := server["idle_timeout"]; got != wantIdle {
			t.Fatalf("idle_timeout=%v, want %v", got, wantIdle)
		}
	}

	// fresh 库 DEFAULT（60/60/120）恒发射——不再「0=省略」；非 0 哨兵贯通。
	if _, err := database.Exec("UPDATE global_config SET http_read_timeout=90, http_write_timeout=45, http_idle_timeout=300"); err != nil {
		t.Fatalf("set sentinels: %v", err)
	}
	assertServerTimeouts("90s", "45s", "300s")
	if _, err := database.Exec("UPDATE global_config SET http_read_timeout=60, http_write_timeout=60, http_idle_timeout=120"); err != nil {
		t.Fatalf("reset defaults: %v", err)
	}
	assertServerTimeouts("60s", "60s", "120s")
}

func TestRenderDBTruth_KeepaliveOmissionSemanticsUnchanged(t *testing.T) {
	// 类型②省略型回归钉：upstream_keepalive_timeout 0=省略（继承 Caddy/Go
	// Transport 默认 2 分钟，R72 用户裁定）——本批治理不改其语义。
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-truth-keepalive", false)

	assertKeepalive := func(want string, wantAbsent bool) {
		t.Helper()
		generated := generateCaddyConfigFromStore(database)
		if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("generation failed: %s", message)
		}
		apps := generated["apps"].(map[string]interface{})
		httpApp := apps["http"].(map[string]interface{})
		server := httpApp["servers"].(map[string]interface{})["http_8080"].(map[string]interface{})
		routes := server["routes"].([]interface{})
		var proxy map[string]interface{}
		for _, r := range routes {
			route := r.(map[string]interface{})
			if chain, ok := route["handle"].([]interface{}); ok {
				for _, h := range chain {
					hm := h.(map[string]interface{})
					if hm["handler"] == "reverse_proxy" {
						proxy = hm
					}
				}
			}
		}
		if proxy == nil {
			t.Fatal("no reverse_proxy handler")
		}
		transport, _ := proxy["transport"].(map[string]interface{})
		keepalive, exists := transport["keep_alive"]
		if wantAbsent {
			if exists {
				t.Fatalf("keep_alive must be omitted for value 0, got %v", keepalive)
			}
			return
		}
		ka, _ := keepalive.(map[string]interface{})
		if ka["idle_timeout"] != want {
			t.Fatalf("keep_alive idle_timeout=%v, want %v", ka["idle_timeout"], want)
		}
	}

	// 全局 0 + 规则 0 → 省略（无 transport.keep_alive）。
	if _, err := database.Exec("UPDATE global_config SET upstream_keepalive_timeout=0"); err != nil {
		t.Fatalf("zero keepalive: %v", err)
	}
	assertKeepalive("", true)
	// 全局 90 → 贯通（needsTransport 由 keepalive 值触发）。
	if _, err := database.Exec("UPDATE global_config SET upstream_keepalive_timeout=90"); err != nil {
		t.Fatalf("set keepalive: %v", err)
	}
	assertKeepalive("90s", false)
}

// —— 批 3：安全策略值列 + global_config.cert_expiry_days ——

func TestRenderDBTruth_SecurityAnomalyThresholdSentinelPassThrough(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-truth-sec", false)
	result, err := database.Exec(`INSERT INTO security_policies (name,mode,anomaly_threshold,enabled) VALUES ('truth-sec','blocking',13,1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb-truth-sec',?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	route := findRouteByID(t, httpRoutesFromServer(t, generated, "http_8080"), "lb-truth-sec")
	if route == nil {
		t.Fatal("rule route missing")
	}
	waf := findChainHandler(t, route, "waf")
	if waf == nil {
		t.Fatal("no waf handler")
	}
	directives, _ := waf["directives"].(string)
	if !strings.Contains(directives, `id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=13`) {
		t.Fatalf("库值 13 必须直读贯通发射 id:900（无 >0 守卫、无写死 5）:\n%s", directives)
	}
}

func TestRenderDBTruth_SecurityAnomalyThresholdInvalidFailVisible(t *testing.T) {
	stubSecurityLibsAvailable(t)
	cases := []struct {
		name  string
		reset string
	}{
		{"zero", "UPDATE security_policies SET anomaly_threshold=0 WHERE name='truth-sec'"},
		{"null", "UPDATE security_policies SET anomaly_threshold=NULL WHERE name='truth-sec'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			seedGenerationRule(t, database, "lb-truth-sec0", false)
			result, err := database.Exec(`INSERT INTO security_policies (name,mode,anomaly_threshold,enabled) VALUES ('truth-sec','blocking',5,1)`)
			if err != nil {
				t.Fatalf("seed policy: %v", err)
			}
			policyID, _ := result.LastInsertId()
			if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb-truth-sec0',?)`, policyID); err != nil {
				t.Fatalf("bind policy: %v", err)
			}
			if _, err := database.Exec(tc.reset); err != nil {
				t.Fatalf("dirty column: %v", err)
			}

			generated := generateCaddyConfigFromStore(database)
			message, ok := generated[caddyConfigGenerationErrorKey].(string)
			if !ok {
				t.Fatalf("anomaly_threshold=%s must fail generation (fail-visible), got config keys %v", tc.name, configKeys(generated))
			}
			if !strings.Contains(message, "异常阈值") {
				t.Fatalf("generation error %q missing hint 异常阈值", message)
			}
		})
	}
}

func TestRenderDBTruth_RateLimitRPSSentinelPassThrough(t *testing.T) {
	// 哨兵 777/55 全程偏离默认——任何写死替换都会被识破。
	handler, err := buildRateLimitHandler("lb-truth-rl", &models.SecurityPolicy{ID: 9, RateLimitEnabled: true, RateLimitRPS: 777, RateLimitBurst: 55})
	if err != nil {
		t.Fatalf("buildRateLimitHandler: %v", err)
	}
	zones, _ := handler["rate_limits"].(map[string]interface{})
	sec, _ := zones["lb-truth-rl-p9-sec"].(map[string]interface{})
	if sec == nil || sec["max_events"] != 777+55 {
		t.Fatalf("sec zone max_events=%v, want 832 (rps 777 + burst 55 库值贯通)", sec["max_events"])
	}
	minz, _ := zones["lb-truth-rl-p9-min"].(map[string]interface{})
	if minz == nil || minz["max_events"] != 777*60 {
		t.Fatalf("min zone max_events=%v, want 46620 (rps 777 库值贯通)", minz["max_events"])
	}
}

func TestRenderDBTruth_RateLimitBurstZeroOmissionSemantics(t *testing.T) {
	// 类型②省略型回归钉：burst=0 → 单窗口（无 -min zone），max_events=rps 原值。
	handler, err := buildRateLimitHandler("lb-truth-rl0", &models.SecurityPolicy{ID: 3, RateLimitEnabled: true, RateLimitRPS: 777})
	if err != nil {
		t.Fatalf("buildRateLimitHandler: %v", err)
	}
	zones, _ := handler["rate_limits"].(map[string]interface{})
	if len(zones) != 1 {
		t.Fatalf("burst=0 must emit exactly one zone (省略语义), got %v", zones)
	}
	zone, _ := zones["lb-truth-rl0-p3"].(map[string]interface{})
	if zone == nil || zone["max_events"] != 777 {
		t.Fatalf("single zone max_events=%v, want 777", zone["max_events"])
	}
}

func TestRenderDBTruth_RateLimitEnabledZeroRPSFailVisible(t *testing.T) {
	stubSecurityLibsAvailable(t)
	for name, rps := range map[string]int{"zero": 0, "negative": -5} {
		t.Run(name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			seedGenerationRule(t, database, "lb-truth-rlv", false)
			result, err := database.Exec(`INSERT INTO security_policies (name,mode,rate_limit_enabled,rate_limit_rps,enabled) VALUES ('truth-rl','off',1,?,1)`, rps)
			if err != nil {
				t.Fatalf("seed policy: %v", err)
			}
			policyID, _ := result.LastInsertId()
			if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb-truth-rlv',?)`, policyID); err != nil {
				t.Fatalf("bind policy: %v", err)
			}

			generated := generateCaddyConfigFromStore(database)
			message, ok := generated[caddyConfigGenerationErrorKey].(string)
			if !ok {
				t.Fatalf("enabled=1 + rate_limit_rps=%d must fail generation (fail-visible, 根除静默不限流), got config keys %v", rps, configKeys(generated))
			}
			if !strings.Contains(message, "限流") || !strings.Contains(message, "rate_limit_rps") {
				t.Fatalf("generation error %q missing hints 限流/rate_limit_rps", message)
			}
		})
	}
}

func TestRenderDBTruth_BlockStatusCodeZeroFollowsDefault403(t *testing.T) {
	// 类型②省略型回归钉：0=未设置，跟随默认 403（static_response 必须显式
	// 状态码，省略以默认值替换实现——反兜底白名单 Ruling 披露）。
	route := buildBlockPageAttributionRoute(483, nil, "<html>bp</html>", 0, "")
	resp := route["handle"].([]interface{})[0].(map[string]interface{})
	if resp["status_code"] != 403 {
		t.Fatalf("block_status_code=0 must render 403 (跟随默认), got %v", resp["status_code"])
	}
	// 非零哨兵贯通（503=写侧白名单合法值）。
	route = buildBlockPageAttributionRoute(483, nil, "<html>bp</html>", 503, "")
	resp = route["handle"].([]interface{})[0].(map[string]interface{})
	if resp["status_code"] != 503 {
		t.Fatalf("block_status_code=503 must pass through, got %v", resp["status_code"])
	}
}

func TestRenderDBTruth_CertExpiryDaysInvalidLogsExplicitError(t *testing.T) {
	// 类型①值型列：库值无效（带外直写，正常已被启动回填收敛）不得静默降级——
	// 显性 error 留痕后按 CERT42-5 读故障族口径取默认 30。
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=-5 WHERE id=1"); err != nil {
		t.Fatalf("dirty cert_expiry_days: %v", err)
	}
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if got := GetCertExpiryThreshold(); got != 30 {
		t.Fatalf("GetCertExpiryThreshold=%d, want degraded 30", got)
	}
	if !strings.Contains(buf.String(), "cert_expiry_days") || !strings.Contains(buf.String(), "-5") {
		t.Fatalf("invalid cert_expiry_days must log explicit error with value, log=%q", buf.String())
	}
}

// G5（第 74 轮）：caddy_log_size_mb 哨兵贯通钉——批 1+2 只钉了 <=0 fail-visible
// （ZeroGlobalColumnsFailVisible），未钉「库值直发」方向。137 哨兵贯通到
// logging.logs.*.writer.roll_size_mb（任何写死 100 回流即被识破）。
func TestRenderDBTruth_LogSizeMB137SentinelPassThrough(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-truth-logsize", false)
	if _, err := database.Exec("UPDATE global_config SET caddy_log_size_mb=137"); err != nil {
		t.Fatalf("set sentinel: %v", err)
	}
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	logging, _ := generated["logging"].(map[string]interface{})
	logs, _ := logging["logs"].(map[string]interface{})
	def, _ := logs["default"].(map[string]interface{})
	writer, _ := def["writer"].(map[string]interface{})
	if got := writer["roll_size_mb"]; got != 137 {
		t.Fatalf("roll_size_mb=%v, want 137（库值直发，无写死 100 回流）", got)
	}
}
