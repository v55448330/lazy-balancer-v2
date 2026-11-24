package handlers

// 回归覆盖：
//   - 重试窗口；协议切换丢绑定；TCP 复制仅搬运 L4 合法 stage0/1 绑定；混合 TLS 冲突；管理端口；
//   - ACME 残留归一；TCP log_enabled 死配置的保存/导入归一。
// 所有断言基于真实 DB / HTTP 处理器行为。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func l7RuleFeatureInput(protocol string, duration, interval int) ruleFeatureInput {
	return ruleFeatureInput{
		Protocol: protocol, Strategy: "weighted_round_robin", ListenPort: 19800,
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		TCPTryDuration: duration, TCPTryInterval: interval,
	}
}

func TestTryWindow_requiresPositiveIntervalAtFieldGate(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		duration int
		interval int
		wantErr  string
	}{
		{"http duration>0 interval=0", "http", 3000, 0, "重试间隔"},
		{"tcp duration>0 interval=0", "tcp", 3000, 0, "重试间隔"},
		{"http duration>0 interval negative", "http", 3000, -1, "重试间隔"},
		{"tcp duration>0 interval negative", "tcp", 3000, -5, "重试"},
		// 回归形状：合法窗口、零窗口、HTTP NTLM -1 禁用态均保持放行。
		{"http valid window", "http", 3000, 250, ""},
		{"tcp valid window", "tcp", 3000, 250, ""},
		{"http zero window", "http", 0, 0, ""},
		{"tcp zero window", "tcp", 0, 0, ""},
		{"http NTLM disabled retry", "http", -1, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRuleFeatures(l7RuleFeatureInput(tc.protocol, tc.duration, tc.interval))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("duration=%d interval=%d must fail with %q, got %v", tc.duration, tc.interval, tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid retry window rejected: %v", err)
			}
		})
	}
}

func TestCreateRule_returnsFieldLevelError(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name string
		body string
	}{
		{"http", `{"name":"l7-try-http","protocol":"http","domain":"l7-try-http.test","listen_port":19802,
			"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
			"tcp_try_duration":3000,"tcp_try_interval":0,
			"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`},
		{"tcp", `{"name":"l7-try-tcp","protocol":"tcp","listen_port":19803,
			"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
			"tcp_try_duration":3000,"tcp_try_interval":0,
			"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			body := response.Body.String()
			if response.Code != http.StatusBadRequest {
				t.Fatalf("duration>0 interval=0 must 400, got %d %s", response.Code, body)
			}
			if !strings.Contains(body, "重试间隔") {
				t.Fatalf("field-level error must name 重试间隔: %s", body)
			}
			if strings.Contains(body, "Caddy 配置应用失败") {
				t.Fatalf("must fail before render/apply, got generic apply failure: %s", body)
			}
			var count int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name=?`, "l7-try-"+tc.name).Scan(&count); err != nil {
				t.Fatalf("count rule: %v", err)
			}
			if count != 0 {
				t.Fatalf("rejected rule must not persist (count=%d)", count)
			}
		})
	}
}

func l7SeedHTTPRuleWithBinding(t *testing.T, caddyID, domain string, port int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_interval,health_check_timeout,
		health_check_unhealthy_threshold,health_check_healthy_threshold,enabled)
		VALUES (?,?,'','http',?,?,'weighted_round_robin',10,2,3,2,1)`, caddyID, caddyID, domain, port); err != nil {
		t.Fatalf("seed rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream %s: %v", caddyID, err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,mode,enabled) VALUES ('l7-policy','stage1','blocking',1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("policy id: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, caddyID, policyID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
}

func l7BindingCount(t *testing.T, caddyID string) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?`, caddyID).Scan(&count); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	return count
}

func TestProtocolSwitchToTCPDropsSecurityBindings(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	l7SeedHTTPRuleWithBinding(t, "lb_l7switch", "l7-switch.test", 19820)
	// 回归对照：同协议 HTTP 编辑必须保留绑定。
	l7SeedHTTPRuleWithBinding(t, "lb_l7keep", "l7-keep.test", 19822)

	doUpdate := func(caddyID, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	rec := doUpdate("lb_l7keep", `{"protocol":"http","domain":"l7-keep.test","listen_port":19822,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-protocol HTTP update failed: %d %s", rec.Code, rec.Body.String())
	}
	if got := l7BindingCount(t, "lb_l7keep"); got != 1 {
		t.Fatalf("same-protocol update must keep bindings, got %d", got)
	}

	rec = doUpdate("lb_l7switch", `{"protocol":"tcp","listen_port":19821,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP→TCP update failed: %d %s", rec.Code, rec.Body.String())
	}
	if got := l7BindingCount(t, "lb_l7switch"); got != 0 {
		t.Fatalf("HTTP→TCP switch must drop inert security bindings, still %d", got)
	}
	var protocol string
	if err := db.DB.QueryRow(`SELECT protocol FROM lb_rules WHERE caddy_id='lb_l7switch'`).Scan(&protocol); err != nil {
		t.Fatalf("read protocol: %v", err)
	}
	if protocol != "tcp" {
		t.Fatalf("protocol=%q, want tcp", protocol)
	}
}

func TestV2ImportDropsBindingsForTCPRules(t *testing.T) {
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_l7imptcp", "name": "l7-import-tcp", "protocol": "tcp", "listen_port": 19825, "enabled": 1},
		},
		"upstreams": {
			{"rule_id": "lb_l7imptcp", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1, "protocol": "tcp"},
		},
		"security_policies": {
			{"id": 1, "name": "l7-import-policy", "policy_type": "stage1", "mode": "blocking", "enabled": 1},
		},
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_l7imptcp", "policy_id": 1},
		},
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	if got := l7BindingCount(t, "lb_l7imptcp"); got != 0 {
		t.Fatalf("TCP rule bindings must be dropped on import, still %d", got)
	}
	var policies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='l7-import-policy'`).Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policies != 1 {
		t.Fatalf("policy row must be preserved (got %d)", policies)
	}
	if !strings.Contains(response.Body.String(), "TCP") || !strings.Contains(response.Body.String(), "绑定") {
		t.Fatalf("import response must warn about dropped TCP bindings: %s", response.Body.String())
	}
}

func l7ConflictRows() []map[string]any {
	return []map[string]any{
		{"caddy_id": "lb_l7plain", "name": "l7-plain", "protocol": "http", "domain": "l7-plain.test", "listen_port": int64(19830), "enabled": int64(1), "enable_tls": int64(0)},
		{"caddy_id": "lb_l7tls", "name": "l7-tls", "protocol": "http", "domain": "l7-tls.test", "listen_port": int64(19830), "enabled": int64(1), "enable_tls": int64(1)},
	}
}

// TCP 复制按 L4 阶段 0/1 语义（契约 C4）搬运绑定：stage0/stage1 特征绑定
// 合法（buildTCPSecurityRoutes 消费）必须携带；含 G2（CC）/G3（WAF）特征
// 的绑定在 TCP 渲染链零效果，不得随复制放大（与编辑/启用/导入的
// pruneTCPUnsupportedBindings 收口同口径）。
func TestDuplicateTCPRuleCopiesOnlyL4SupportedBindings(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,listen_port,strategy,health_check_interval,health_check_timeout,
		health_check_unhealthy_threshold,health_check_healthy_threshold,enabled)
		VALUES ('lb_l7dup','l7-dup-tcp','','tcp',19826,'weighted_round_robin',10,2,3,2,1)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_l7dup','127.0.0.1',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed tcp upstream: %v", err)
	}
	stage0 := l4GateSeedPolicy(t, "l7-dup-stage0", true, false, false, false)
	stage1 := l4GateSeedPolicy(t, "l7-dup-stage1", false, true, false, false)
	g3 := l4GateSeedPolicy(t, "l7-dup-waf", false, false, false, true)
	g2 := l4GateSeedPolicy(t, "l7-dup-cc", false, false, true, false)
	for _, binding := range []struct {
		pid  int
		rank int
	}{{g3, 1}, {stage1, 2}, {g2, 3}, {stage0, 4}} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES ('lb_l7dup',?,?)`, binding.pid, binding.rank); err != nil {
			t.Fatalf("seed binding %d: %v", binding.pid, err)
		}
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_l7dup/duplicate", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s", response.Code, response.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name LIKE 'l7-dup-tcp%（副本）' LIMIT 1`).Scan(&copyID); err != nil {
		t.Fatalf("read duplicate rule: %v", err)
	}
	// 副本只保留 stage0/1 两条，且携带源 rank（源相对序 stage1→stage0，
	// 与 policy_id 序相反——丢 rank 会退化为 policy_id 序）。
	rows, err := db.DB.Query(`SELECT policy_id, rank FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY rank ASC, policy_id ASC`, copyID)
	if err != nil {
		t.Fatalf("read copy bindings: %v", err)
	}
	defer rows.Close()
	type copyBinding struct {
		pid  int
		rank int
	}
	var copied []copyBinding
	for rows.Next() {
		var b copyBinding
		if err := rows.Scan(&b.pid, &b.rank); err != nil {
			t.Fatalf("scan copy binding: %v", err)
		}
		copied = append(copied, b)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate copy bindings: %v", err)
	}
	want := []copyBinding{{stage1, 2}, {stage0, 4}}
	if len(copied) != len(want) {
		t.Fatalf("TCP duplicate bindings=%v, want stage0/1 only %v", copied, want)
	}
	for i := range want {
		if copied[i] != want[i] {
			t.Fatalf("TCP duplicate bindings=%v, want %v（G2/G3 不携带且保留 rank 序）", copied, want)
		}
	}
	if !strings.Contains(response.Body.String(), "2 条策略绑定") {
		t.Fatalf("success message must state carried bindings, body=%s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"caddy_id"`) {
		t.Fatalf("duplicate response missing caddy_id: %s", response.Body.String())
	}
}

func TestConflictMatrixDisablesPlaintextSideOfMixedTLSPort(t *testing.T) {
	rows := l7ConflictRows()
	conflicts := disableV2RuleConflicts(rows)
	if len(conflicts) != 1 {
		t.Fatalf("mixed TLS/plain port must yield exactly one disabled rule, got %#v", conflicts)
	}
	if conflicts[0].CaddyID != "lb_l7plain" {
		t.Fatalf("plaintext side must be disabled, got %s", conflicts[0].CaddyID)
	}
	if !strings.Contains(conflicts[0].Reason, "TLS 与明文") {
		t.Fatalf("conflict reason must explain TLS/plain mix: %s", conflicts[0].Reason)
	}
	if !backupRuleEnabled(rows[1]) {
		t.Fatal("TLS side must stay enabled (listener keeps serving TLS)")
	}

	// 回归：同 TLS 形态共存放行。
	sameTLS := l7ConflictRows()
	sameTLS[0]["enable_tls"] = int64(1)
	if conflicts := disableV2RuleConflicts(sameTLS); len(conflicts) != 0 {
		t.Fatalf("same-TLS coexistence must not conflict: %#v", conflicts)
	}

	// 回归：禁用中的明文规则不渲染，不构成混布冲突。
	disabledPlain := l7ConflictRows()
	disabledPlain[0]["enabled"] = int64(0)
	if conflicts := disableV2RuleConflicts(disabledPlain); len(conflicts) != 0 {
		t.Fatalf("disabled plaintext rule must not conflict: %#v", conflicts)
	}

	// 回归：同端口同域名冲突仍按既有矩阵禁用双方。
	duplicate := l7ConflictRows()
	duplicate[1]["domain"] = "l7-plain.test"
	if conflicts := disableV2RuleConflicts(duplicate); len(conflicts) != 2 {
		t.Fatalf("duplicate domain conflict must still disable both sides: %#v", conflicts)
	}
}

func TestV1ConflictMatrixDisablesPlaintextSide(t *testing.T) {
	rules := []convertedRule{
		{Name: "v1-plain", Protocol: "http", Domain: "v1-plain.test", ListenPort: 19831, Enabled: true},
		{Name: "v1-tls", Protocol: "http", Domain: "v1-tls.test", ListenPort: 19831, Enabled: true, EnableTLS: true},
	}
	conflicts := disableConvertedRuleConflicts(rules)
	if len(conflicts) != 1 || rules[0].Enabled {
		t.Fatalf("v1 plaintext side must be disabled, conflicts=%#v rules=%+v", conflicts, rules)
	}
	if !rules[1].Enabled {
		t.Fatal("v1 TLS side must stay enabled")
	}
}

func TestV2ImportDisablesPlaintextSideOfMixedPort(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	h := newBackupTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("l7-mix-tls.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_l7mixplain", "name": "l7-mix-plain", "protocol": "http", "domain": "l7-mix-plain.test",
				"listen_port": 19832, "enabled": 1, "enable_tls": 0},
			{"caddy_id": "lb_l7mixtls", "name": "l7-mix-tls", "protocol": "http", "domain": "l7-mix-tls.test",
				"listen_port": 19832, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": certPEM, "tls_key": keyPEM},
		},
		"upstreams": {
			{"rule_id": "lb_l7mixplain", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1},
			{"rule_id": "lb_l7mixtls", "host": "127.0.0.1", "port": 9002, "weight": 1, "enabled": 1},
		},
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var plainEnabled, tlsEnabled int
	if err := db.DB.QueryRow(`SELECT COALESCE(enabled,0) FROM lb_rules WHERE caddy_id='lb_l7mixplain'`).Scan(&plainEnabled); err != nil {
		t.Fatalf("read plaintext rule: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(enabled,0) FROM lb_rules WHERE caddy_id='lb_l7mixtls'`).Scan(&tlsEnabled); err != nil {
		t.Fatalf("read TLS rule: %v", err)
	}
	if plainEnabled != 0 || tlsEnabled != 1 {
		t.Fatalf("mixed port import enabled states plain=%d tls=%d, want 0/1", plainEnabled, tlsEnabled)
	}
	if !strings.Contains(response.Body.String(), "disabled_conflicts") || !strings.Contains(response.Body.String(), "TLS 与明文") {
		t.Fatalf("import response must report disabled plaintext conflict: %s", response.Body.String())
	}
}

func TestImportUsesProcessManagementPorts(t *testing.T) {
	cases := []struct {
		name      string
		panelPort int
		adminURL  string
		listen    int
	}{
		{"panel listen port", 19000, "", 19000},
		{"caddy admin port", 0, "http://127.0.0.1:19001", 19001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			if tc.panelPort > 0 {
				h.cfg.Port = tc.panelPort
			}
			if tc.adminURL != "" {
				h.cfg.CaddyAdminURL = tc.adminURL
			}
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"lb_rules": {
					{"caddy_id": "lb_l7mgmt", "name": "l7-mgmt", "protocol": "http", "domain": "l7-mgmt.test",
						"listen_port": tc.listen, "enabled": 1},
				},
				"upstreams": {
					{"rule_id": "lb_l7mgmt", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1},
				},
			})
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/config/validate", h.ValidateConfigImport)
			router.POST("/config/import", h.ImportConfigBackup)

			validateRequest := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
			validateRequest.Header.Set("Content-Type", "application/json")
			validateResponse := httptest.NewRecorder()
			router.ServeHTTP(validateResponse, validateRequest)
			if validateResponse.Code != http.StatusOK {
				t.Fatalf("preview status=%d body=%s", validateResponse.Code, validateResponse.Body.String())
			}
			if !strings.Contains(validateResponse.Body.String(), `"valid":false`) || !strings.Contains(validateResponse.Body.String(), "管理端口") {
				t.Fatalf("preview must reject process management port before import: %s", validateResponse.Body.String())
			}

			importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			importRequest.Header.Set("Content-Type", "application/json")
			importResponse := httptest.NewRecorder()
			router.ServeHTTP(importResponse, importRequest)
			if importResponse.Code != http.StatusBadRequest || !strings.Contains(importResponse.Body.String(), "管理端口") {
				t.Fatalf("import must reject process management port: %d %s", importResponse.Code, importResponse.Body.String())
			}
			var count int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_l7mgmt'`).Scan(&count); err != nil {
				t.Fatalf("count rules: %v", err)
			}
			if count != 0 {
				t.Fatalf("rejected import must not persist rule (count=%d)", count)
			}
		})
	}
}

func TestV1ImportUsesProcessManagementPorts(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.Port = 19000
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"l7-v1-mgmt","protocol":true,"listen":19000,"server_name":"l7-v1-mgmt.test","status":true,"upstream_list":[1]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}
		]}
	}`
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	router.POST("/config/import/v1", h.ImportV1Config)

	validateRequest := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
	validateRequest.Header.Set("Content-Type", "application/json")
	validateResponse := httptest.NewRecorder()
	router.ServeHTTP(validateResponse, validateRequest)
	if validateResponse.Code != http.StatusOK {
		t.Fatalf("v1 preview status=%d body=%s", validateResponse.Code, validateResponse.Body.String())
	}
	if !strings.Contains(validateResponse.Body.String(), `"valid":false`) || !strings.Contains(validateResponse.Body.String(), "管理端口") {
		t.Fatalf("v1 preview must reject process management port: %s", validateResponse.Body.String())
	}

	importRequest := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	importResponse := httptest.NewRecorder()
	router.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusBadRequest {
		t.Fatalf("v1 import must reject management port rule: %d %s", importResponse.Code, importResponse.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name='l7-v1-mgmt'`).Scan(&count); err != nil {
		t.Fatalf("count v1 rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected v1 import must not persist rule (count=%d)", count)
	}
}

func TestOBS_manualTLSResidualACMEReferenceNormalized(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	handler := newRuleFeatureTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("l7-manual.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	body := fmt.Sprintf(`{"name":"l7-manual","protocol":"http","domain":"l7-manual.test","listen_port":19845,
		"enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q,"acme_config_id":999,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, certPEM, keyPEM)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create manual TLS rule status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var acmeID int
	if err := db.DB.QueryRow(`SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE name='l7-manual'`).Scan(&acmeID); err != nil {
		t.Fatalf("read created acme_config_id: %v", err)
	}
	if acmeID != 0 {
		t.Fatalf("manual TLS create must clear residual acme_config_id, got %d", acmeID)
	}
	var sourceID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name='l7-manual'`).Scan(&sourceID); err != nil {
		t.Fatalf("read source id: %v", err)
	}
	// 直改 DB 制造存量残留，复制路径不得放大到副本。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=999 WHERE caddy_id=?`, sourceID); err != nil {
		t.Fatalf("seed residual acme_config_id: %v", err)
	}
	dupRequest := httptest.NewRequest(http.MethodPost, "/rules/"+sourceID+"/duplicate", nil)
	dupResponse := httptest.NewRecorder()
	router.ServeHTTP(dupResponse, dupRequest)
	if dupResponse.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s", dupResponse.Code, dupResponse.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name='l7-manual（副本）'`).Scan(&copyID); err != nil {
		t.Fatalf("read duplicate id: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?`, copyID).Scan(&acmeID); err != nil {
		t.Fatalf("read duplicate acme_config_id: %v", err)
	}
	if acmeID != 0 {
		t.Fatalf("manual TLS duplicate must not amplify residual acme_config_id, got %d", acmeID)
	}

	// 更新同族：存量 manual 行残留指向不存在配置的 acme_config_id，纯改名必须
	// 200 并自愈为 0（清理先于 ACME 引用门，否则 400 死端）。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		enable_tls,tls_source,tls_cert,tls_key,acme_config_id,health_check_interval,health_check_timeout,
		health_check_unhealthy_threshold,health_check_healthy_threshold)
		VALUES ('lb_l7manresid','l7-manual-resid','','http','l7-manual-resid.test',19847,'weighted_round_robin',1,
		1,'manual',?,?,12345,10,2,3,2)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed manual residual rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_l7manresid','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed residual upstream: %v", err)
	}
	updateRouter := gin.New()
	updateRouter.PUT("/rules/:caddy_id", handler.UpdateRule)
	updateRequest := httptest.NewRequest(http.MethodPut, "/rules/lb_l7manresid", strings.NewReader(`{"name":"l7-manual-resid-renamed"}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	updateRouter.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("manual residual update status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id='lb_l7manresid'`).Scan(&acmeID); err != nil {
		t.Fatalf("read updated acme_config_id: %v", err)
	}
	if acmeID != 0 {
		t.Fatalf("manual TLS update must clear residual acme_config_id, got %d", acmeID)
	}

	// 导入同族：备份行 manual + acme_config_id=999 → 事务归一为 0。
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_l7manualimp", "name": "l7-manual-import", "protocol": "http", "domain": "l7-manual-import.test",
				"listen_port": 19846, "enabled": 1, "enable_tls": 1, "tls_source": "manual",
				"tls_cert": certPEM, "tls_key": keyPEM, "acme_config_id": 999},
		},
		"upstreams": {
			{"rule_id": "lb_l7manualimp", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1},
		},
	})
	importRouter := gin.New()
	importRouter.POST("/config/import", h.ImportConfigBackup)
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	importResponse := httptest.NewRecorder()
	importRouter.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id='lb_l7manualimp'`).Scan(&acmeID); err != nil {
		t.Fatalf("read imported acme_config_id: %v", err)
	}
	if acmeID != 0 {
		t.Fatalf("manual TLS import must clear residual acme_config_id, got %d", acmeID)
	}
}

func TestOBS_tcpLogEnabledDeadConfigNormalized(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"l7-log-tcp","protocol":"tcp","listen_port":19840,"log_enabled":true,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create tcp rule status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var logEnabled int
	if err := db.DB.QueryRow(`SELECT COALESCE(log_enabled,0) FROM lb_rules WHERE name='l7-log-tcp'`).Scan(&logEnabled); err != nil {
		t.Fatalf("read log_enabled: %v", err)
	}
	if logEnabled != 0 {
		t.Fatalf("TCP log_enabled is dead config and must be zeroed on save, got %d", logEnabled)
	}

	// 导入同族：备份携带 TCP + log_enabled=1，事务归一后必须为 0。
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_l7logimp", "name": "l7-log-import", "protocol": "tcp", "listen_port": 19841, "enabled": 1, "log_enabled": 1},
		},
		"upstreams": {
			{"rule_id": "lb_l7logimp", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1, "protocol": "tcp"},
		},
	})
	importRouter := gin.New()
	importRouter.POST("/config/import", h.ImportConfigBackup)
	importRequest := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	importRequest.Header.Set("Content-Type", "application/json")
	importResponse := httptest.NewRecorder()
	importRouter.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(log_enabled,0) FROM lb_rules WHERE caddy_id='lb_l7logimp'`).Scan(&logEnabled); err != nil {
		t.Fatalf("read imported log_enabled: %v", err)
	}
	if logEnabled != 0 {
		t.Fatalf("imported TCP log_enabled must be normalized to 0, got %d", logEnabled)
	}
}
