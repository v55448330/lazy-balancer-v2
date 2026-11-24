package handlers

// NTLM 接管一致性：ntlm_compatible 列与渲染脱钩——渲染对该列零感知
// （caddy.go buildHTTPHandleChain 注释自述），真实 NTLM 行为由 UI 修改器
// （Rules.vue applyNtlmTakeover）落下的四列接管形态决定：
// tcp_try_duration=-1（禁用跨上游重试）/upstream_force_http1=1/
// proxy_flush_interval=-1（立即透传）/upstream_keepalive_timeout=300。
// 此前 API/导入/快照可绕过 UI 产「宣称 NTLM 实际非 NTLM」规则——保存
// （Create/Update/Duplicate）/启用（validateStoredRuleConfig）/导入
// （validateV2BackupRules）三链同门：ntlm=1 必须接管四列全齐，缺一 400；
// ntlm=0 不约束（UI restoreNtlmDefaults 已复位四列）。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// ntlmTakeoverColumns 是 UI 联动形态（applyNtlmTakeover）的库级表达。
const ntlmTakeoverColumnsJSON = `"tcp_try_duration":-1,"upstream_force_http1":1,"proxy_flush_interval":-1,"upstream_keepalive_timeout":300`

func TestValidateRuleFeatures_ntlmOn_requiresFullTakeoverColumns(t *testing.T) {
	fullTakeover := ruleFeatureInput{
		Protocol: "http", Strategy: "cookie", ListenPort: 18620,
		NTLMCompatible: 1, TCPTryDuration: -1, UpstreamForceHTTP1: 1,
		ProxyFlushInterval: -1, UpstreamKeepaliveTimeout: 300,
	}

	// 回归形状：UI 联动形态（四列全齐+ntlm=1）必须放行
	if err := validateRuleFeatures(fullTakeover); err != nil {
		t.Fatalf("full takeover shape must pass, got %v", err)
	}

	// 缺一即拒（逐列破坏）
	cases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"重试窗口未禁用", func(in *ruleFeatureInput) { in.TCPTryDuration = 0 }},
		{"未强制 HTTP/1.1", func(in *ruleFeatureInput) { in.UpstreamForceHTTP1 = 0 }},
		{"刷新间隔非立即透传", func(in *ruleFeatureInput) { in.ProxyFlushInterval = 0 }},
		{"keepalive 超时非 300", func(in *ruleFeatureInput) { in.UpstreamKeepaliveTimeout = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := fullTakeover
			tc.mutate(&input)
			err := validateRuleFeatures(input)
			if err == nil || !strings.Contains(err.Error(), "NTLM 接管需要同时设置") {
				t.Fatalf("err=%v, want rejection containing 接管文案", err)
			}
		})
	}

	// ntlm=0 不约束（四列任意合法值——restoreNtlmDefaults 复位为 0，API 显式值亦合法）
	off := ruleFeatureInput{
		Protocol: "http", Strategy: "weighted_round_robin", ListenPort: 18621,
		TCPTryDuration: 5000, TCPTryInterval: 250, ProxyFlushInterval: 100,
	}
	if err := validateRuleFeatures(off); err != nil {
		t.Fatalf("ntlm=0 must not be constrained by takeover gate, got %v", err)
	}
}

// 保存链 API 面：ntlm=1 + td=0（四列不齐）必须 400 且不落库。
func TestCreateRule_ntlmOn_missingTakeoverColumns_rejected(t *testing.T) {
	router := ntlmCreateRouter(t)

	response := serveJSON(t, router, http.MethodPost, "/rules", `{
		"name":"ntlm-half","protocol":"http","domain":"ntlm-half.example.test","listen_port":18622,
		"strategy":"cookie","ntlm_compatible":1,"tcp_try_duration":0,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "NTLM 接管需要同时设置") {
		t.Fatalf("create ntlm=1+td=0 status=%d body=%s, want 400 with 接管文案", response.Code, response.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name='ntlm-half'`).Scan(&stored); err != nil {
		t.Fatalf("count stored: %v", err)
	}
	if stored != 0 {
		t.Fatalf("rejected rule must not persist, found %d rows", stored)
	}
}

// 保存链 API 面回归：UI 联动形态（四列齐+ntlm=1）保存正常。
func TestCreateRule_ntlmOn_fullTakeoverColumns_accepted(t *testing.T) {
	router := ntlmCreateRouter(t)

	response := serveJSON(t, router, http.MethodPost, "/rules", `{
		"name":"ntlm-full","protocol":"http","domain":"ntlm-full.example.test","listen_port":18623,
		"strategy":"cookie","ntlm_compatible":1,`+ntlmTakeoverColumnsJSON+`,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`)

	if response.Code != http.StatusCreated {
		t.Fatalf("create full takeover status=%d body=%s, want 201", response.Code, response.Body.String())
	}
}

// 启用链存量门：直改 DB 的不一致行（ntlm=1+cookie 但 td=0）启用必须点名拒绝。
func TestValidateStoredRuleConfig_rejects_stored_ntlm_with_incomplete_takeover(t *testing.T) {
	newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,ntlm_compatible,tcp_try_duration,upstream_force_http1,proxy_flush_interval,upstream_keepalive_timeout,enabled)
		VALUES ('lb_ntlmhalf','half','http','half.example.test',18624,'cookie',1,0,1,-1,300,0)`); err != nil {
		t.Fatalf("seed stored rule: %v", err)
	}

	err := validateStoredRuleConfig(context.Background(), "lb_ntlmhalf")
	if err == nil || !strings.Contains(err.Error(), "NTLM 接管需要同时设置") {
		t.Fatalf("enable gate err=%v, want NTLM 接管 rejection for stored ntlm=1 + td=0", err)
	}
}

// 导入链同口径：备份行 ntlm=1 但接管四列不齐 → 整包 400；四列补齐 → 放行。
func TestValidateV2BackupRules_ntlmOn_requiresFullTakeoverColumns(t *testing.T) {
	tables := ruleTablesShared()
	rule := tables["lb_rules"][0]
	rule["strategy"] = "cookie"
	rule["ntlm_compatible"] = 1
	// 基础行四列全缺省（0）——不一致形态必须 400
	if err := validateV2BackupRules(tables); err == nil || !strings.Contains(err.Error(), "NTLM 接管需要同时设置") {
		t.Fatalf("import of inconsistent ntlm row err=%v, want rejection containing 接管文案", err)
	}

	// 回归：UI 联动形态（四列补齐）导入放行
	rule["tcp_try_duration"] = -1
	rule["upstream_force_http1"] = 1
	rule["proxy_flush_interval"] = -1
	rule["upstream_keepalive_timeout"] = 300
	if err := validateV2BackupRules(tables); err != nil {
		t.Fatalf("import of full takeover shape must pass, got %v", err)
	}
}
