package handlers

// LB40-2(第 40 轮):http→tcp 协议切换的零值化集合补 dynamic_dns/
// enable_dns_server/dns_server/dns_family 四字段——DNS 动态上游是 HTTP 语义,
// 残留会让 TCP 规则行携带永不消费的脏配置(快照/导出/审计随之放大)。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateRule_protocolSwitchToTCPZeroesDNSFields(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,dynamic_dns,enable_dns_server,dns_server,dns_family)
		VALUES ('lb_dnszero','dnszero','','http','dnszero.test',18580,'weighted_round_robin',1,1,1,'8.8.8.8:53','ipv6')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_dnszero','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	request := httptest.NewRequest(http.MethodPut, "/rules/lb_dnszero", strings.NewReader(`{"protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("switch to tcp: status=%d body=%s", response.Code, response.Body.String())
	}

	var dynamicDNS, enableDNSServer int
	var dnsServer, dnsFamily string
	if err := db.DB.QueryRow(`SELECT COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'') FROM lb_rules WHERE caddy_id='lb_dnszero'`).
		Scan(&dynamicDNS, &enableDNSServer, &dnsServer, &dnsFamily); err != nil {
		t.Fatal(err)
	}
	if dynamicDNS != 0 || enableDNSServer != 0 || dnsServer != "" || dnsFamily != "" {
		t.Fatalf("tcp switch must zero dns fields, got dynamic_dns=%d enable_dns_server=%d dns_server=%q dns_family=%q", dynamicDNS, enableDNSServer, dnsServer, dnsFamily)
	}
}

// LBH-A-L1（第 69 轮 P2）：http→tcp 协议切换不清上游 origin_domain——后端
// validateRulePayloadBeforeSave 对 TCP+origin_domain 硬 400，前端 TCP 下该列
// 不渲染（隐藏字段卡保存）。切换即弃置（与 host_header 同格归零）。
func TestUpdateRule_protocolSwitchToTCPZeroesOriginDomain(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_originzero','originzero','','http','ozero.test',18582,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES ('lb_originzero','up.test',80,1,1,'http','origin.test')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	request := httptest.NewRequest(http.MethodPut, "/rules/lb_originzero", strings.NewReader(`{"protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("switch to tcp must succeed（origin_domain 随切换弃置）: status=%d body=%s", response.Code, response.Body.String())
	}

	var originDomain string
	if err := db.DB.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_originzero'`).Scan(&originDomain); err != nil {
		t.Fatal(err)
	}
	if originDomain != "" {
		t.Fatalf("tcp switch must zero origin_domain, got %q", originDomain)
	}
}

// LB40-3(第 40 轮):路径规则上游 host:port 去重——主上游已有同口径判定
// (handlers.go hostPortSeen),路径规则缺位:同 host:port 双条目权重翻倍,
// 均衡语义静默漂移。
func TestPathRuleUpstreams_duplicateRejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := `{"name":"path-dup","protocol":"http","domain":"pathdup.test","listen_port":18581,"custom_routes_enabled":true,` +
		`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],` +
		`"path_rules":[{"path":"/a","match_type":"prefix","upstreams":[{"address":"Up.Test","port":9001},{"address":"up.test ","port":9001}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "重复") {
		t.Fatalf("duplicate path-rule upstream must 400, got %d %s", response.Code, response.Body.String())
	}
}

// LBH-A-U2（第 69 轮 P3）：CreateRule 的 TCP 归一顺位必须先于 TLS 来源/手动
// 证书材料校验（与 UpdateRule 同格）——此前 TCP+enable_tls:true+空/bogus
// tls_source 创建恒 400「启用 TLS 时必须选择证书来源」，同形态更新却归一放行
// 200，两入口对同一输入响应分叉。
func TestCreateRule_tcpNormalizationPrecedesTLSValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name string
		port int
		tls  string
	}{
		{"tcp-tls-empty-source", 18592, `"enable_tls":true,"tls_source":""`},
		{"tcp-tls-bogus-source", 18593, `"enable_tls":true,"tls_source":"bogus"`},
		{"tcp-tls-manual-garbage", 18594, `"enable_tls":true,"tls_source":"manual","tls_cert":"x","tls_key":"y"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given：TCP 创建载荷携带 TLS 死形态（UI 不发，API/MCP 直构可达）
			body := fmt.Sprintf(`{"name":%q,"protocol":"tcp","listen_port":%d,%s,`+
				`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,`+
				`"upstreams":[{"host":"10.0.0.1","port":9000,"enabled":true}]}`, tc.name, tc.port, tc.tls)
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then：归一（EnableTLS=false）先于 TLS 校验——放行且落库零 TLS 形态
			if response.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s, want 201（TCP 归一后 TLS 校验自然跳过，与 UpdateRule 同格）", response.Code, response.Body.String())
			}
			var enableTLS int
			var tlsSource string
			if err := db.DB.QueryRow(`SELECT IIF(enable_tls IN ('1',1),1,0), COALESCE(tls_source,'') FROM lb_rules WHERE name=?`, tc.name).
				Scan(&enableTLS, &tlsSource); err != nil {
				t.Fatal(err)
			}
			if enableTLS != 0 || tlsSource != "manual" {
				t.Fatalf("tcp create must normalize TLS fields, got enable_tls=%d tls_source=%q", enableTLS, tlsSource)
			}
		})
	}
}

// LBH-A-U1（第 69 轮 P3）：TCP 规则创建不得落库 HTTP 专属死配置字段族
// （host_header/health_check_path/enable_compress/compress_types/
// request_body_max_size_mb/upstream_keepalive_timeout/server_tokens_hidden）——
// TCP 渲染零消费（buildTCPServer/buildTCPProxyRoute 实证），携带即归一弃置
// （与 protocolChanged 归零同格），不随快照/导出/复制放大。
func TestCreateRule_tcpDropsHTTPOnlyFieldFamily(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	// Given：TCP 创建载荷显式携带全部七个 HTTP 专属字段
	body := `{"name":"tcp-family","protocol":"tcp","listen_port":18595,` +
		`"host_header":"dead.example","health_check_path":"/healthz",` +
		`"enable_compress":true,"compress_types":"zstd",` +
		`"request_body_max_size_mb":64,"upstream_keepalive_timeout":30,"server_tokens_hidden":1,` +
		`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
		`"upstreams":[{"host":"10.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：放行但七字段全部归一为零值
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	assertTCPRuleFamilyZeroed(t, "lb_rules 创建行", "name='tcp-family'")
}

// LBH-A-U1 同族：协议未变的 TCP 编辑同样归一（存量/导入残留的编辑自愈，
// 与 R62 C2-N1 的 TLS 归一/U3-1 阶段页归一同格）。
func TestUpdateRule_tcpEditHealsHTTPOnlyFieldFamily(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：存量 TCP 行携带死配置（修复前 API 直构/导入落库的形态）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		host_header,health_check_path,enable_compress,compress_types,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden)
		VALUES ('lb_tcpfam','tcpfam','','tcp','',18596,'weighted_round_robin',1,
		'legacy.example','/h',1,'gzip',32,15,2)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpfam','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：同协议编辑（纯改名，不携带该族字段——合并自存量）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcpfam", strings.NewReader(`{"name":"tcpfam-renamed","protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertTCPRuleFamilyZeroed(t, "lb_rules 编辑自愈", "caddy_id='lb_tcpfam'")
}

// LBH-A-N1（第 72 轮 P3）：NTLM 接管态（td=-1，方案 C 库级表达）随
// http→tcp 切换命中校验死端——指针合并（rules.go nil=沿用存量）把 -1 带进
// TCP 值域门（rule_features.go TCP 分支拒负值），400 指向用户从未提交的字段，
// UI 无自救路径。切换路径负值自愈归零（0=默认 5s 窗口）；非负间隔不受波及。
func TestUpdateRule_switchToTCPHealsNegativeTryDurationFromNTLMState(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：HTTP 行处于 NTLM 接管态（ntlm=1+cookie+td=-1）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,ntlm_compatible,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_ntlmsw','ntlmsw','','http','ntlm.test',18600,'cookie',1,1,-1,250)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_ntlmsw','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：切 TCP（不携带 td——合并自存量 -1）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_ntlmsw", strings.NewReader(`{"protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：200（修复前 400「重试时长不能为负数」死端）；td 自愈 0、非负 ti 原样保留
	if response.Code != http.StatusOK {
		t.Fatalf("switch to tcp: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryDuration, tryInterval, ntlm int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0), COALESCE(ntlm_compatible,0) FROM lb_rules WHERE caddy_id='lb_ntlmsw'`).
		Scan(&tryDuration, &tryInterval, &ntlm); err != nil {
		t.Fatal(err)
	}
	if tryDuration != 0 {
		t.Fatalf("td=%d, want 0 (NTLM 接管残留自愈)", tryDuration)
	}
	if tryInterval != 250 {
		t.Fatalf("ti=%d, want 250 (非负间隔不归零)", tryInterval)
	}
	if ntlm != 0 {
		t.Fatalf("ntlm_compatible=%d, want 0 (切换归零既有行为)", ntlm)
	}
}

// LBH-A-N1 同族第二面：直改 DB/导入残留的 TCP 行携带负值重试窗口——任意
// 同协议编辑（如改名）同样命中负值门 400。同协议编辑路径负值一并自愈归零
// （与 LBH-A-U1 死配置自愈同格）；非负值尊重 LB-02 指针合并契约
// （nil=沿用存量/显式值=尊重输入，rules_lb_fixes_test 钉测）。
func TestUpdateRule_tcpEditHealsNegativeTryWindowResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：直改 DB 的 TCP 行带 td=-1/ti=-1（修复前无 API 自救路径）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_tcpwin','tcpwin','','tcp','',18601,'weighted_round_robin',1,-1,-1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpwin','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：同协议编辑（纯改名，不携带重试窗口字段）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcpwin", strings.NewReader(`{"name":"tcpwin-renamed","protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：200 且负值残留归零
	if response.Code != http.StatusOK {
		t.Fatalf("tcp edit: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryDuration, tryInterval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_tcpwin'`).
		Scan(&tryDuration, &tryInterval); err != nil {
		t.Fatal(err)
	}
	if tryDuration != 0 || tryInterval != 0 {
		t.Fatalf("负值重试窗口未自愈: tcp_try_duration=%d tcp_try_interval=%d, want 0/0", tryDuration, tryInterval)
	}
}

// LBH-A-N1 同族（R-12 收敛）：DuplicateRule 把源行 td/ti 原样喂进
// validateRuleFeatures（rules.go 复制校验）——直改 DB 残留的负值 TCP 源行
// 复制即 400 死端（与编辑路径同形）；负值不放大到副本，非负窗口原样复制。
func TestDuplicateRule_tcpCopyHealsNegativeTryWindowResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// Given：直改 DB 的 TCP 行带 td=-1/ti=-1
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_tcpwindup','tcpwindup','','tcp','',18602,'weighted_round_robin',1,-1,-1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpwindup','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_tcpwindup/duplicate", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：201（修复前复制校验 400 死端）且副本窗口归零
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryDuration, tryInterval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE name='tcpwindup（副本）'`).
		Scan(&tryDuration, &tryInterval); err != nil {
		t.Fatalf("read copy: %v", err)
	}
	if tryDuration != 0 || tryInterval != 0 {
		t.Fatalf("副本负值窗口未归零: tcp_try_duration=%d tcp_try_interval=%d, want 0/0", tryDuration, tryInterval)
	}
}

// LBH-A-U1 同族：DuplicateRule 不把源 TCP 行的死配置放大到副本（与
// CreateRule/UpdateRule 归一同口径，A2-S2 归一块的家族补齐）。
func TestDuplicateRule_tcpCopyDropsHTTPOnlyFieldFamily(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// Given
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		host_header,health_check_path,enable_compress,compress_types,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden)
		VALUES ('lb_tcpdup','tcpdup','','tcp','',18597,'weighted_round_robin',1,
		'legacy.example','/h',1,'gzip',32,15,2)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpdup','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_tcpdup/duplicate", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	assertTCPRuleFamilyZeroed(t, "副本行", "name='tcpdup（副本）'")
}

// U04-07（第 78 轮 P4）：TCP 归一的 HTTP 专属字段清单补齐 TLSHTTPRedirect/
// Domain/UpstreamForceHTTP1——单一 tcpDeadFieldReset 清单由 Create/Update/
// Duplicate 共用（此前 Create 显式携带落库、Update/Duplicate 仅零散归零，
// 死配置随快照/导出/复制放大）。
func TestCreateRule_tcpDropsHTTPOnlyTransportFields(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := `{"name":"tcp-transport","protocol":"tcp","listen_port":18820,` +
		`"domain":"dead-transport.example","tls_http_redirect":true,"upstream_force_http1":1,` +
		`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
		`"upstreams":[{"host":"10.0.0.9","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	assertTCPDeadTransportFieldsZeroed(t, "创建行", "caddy_id IS NOT NULL AND name='tcp-transport'")
}

// U04-07 同族：协议未变化的 TCP 编辑同样归一（存量/导入残留的编辑自愈）。
func TestUpdateRule_tcpEditDropsHTTPOnlyTransportFields(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		tls_http_redirect,upstream_force_http1)
		VALUES ('lb_tcptransport','tcp-transport-upd','','tcp','dead-transport.example',18821,'weighted_round_robin',1,
		1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcptransport','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcptransport", strings.NewReader(`{"name":"tcp-transport-upd-renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertTCPDeadTransportFieldsZeroed(t, "编辑自愈", "caddy_id='lb_tcptransport'")
}

// U04-07 同族：DuplicateRule 不把源 TCP 行的 HTTP 专属传输字段放大到副本。
func TestDuplicateRule_tcpCopyDropsHTTPOnlyTransportFields(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		tls_http_redirect,upstream_force_http1)
		VALUES ('lb_tcptransportdup','tcp-transport-dup','','tcp','dead-transport.example',18822,'weighted_round_robin',1,
		1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcptransportdup','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/rules/lb_tcptransportdup/duplicate", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	assertTCPDeadTransportFieldsZeroed(t, "副本行", "name='tcp-transport-dup（副本）'")
}

// assertTCPDeadTransportFieldsZeroed 断言 TCP 行不携带 HTTP 专属传输字段。
func assertTCPDeadTransportFieldsZeroed(t *testing.T, label, where string) {
	t.Helper()
	var domain string
	var tlsHTTPRedirect, upstreamForceHTTP1 int
	if err := db.DB.QueryRow(`SELECT COALESCE(domain,''), IIF(tls_http_redirect IN ('1',1),1,0), COALESCE(upstream_force_http1,0)
		FROM lb_rules WHERE `+where).Scan(&domain, &tlsHTTPRedirect, &upstreamForceHTTP1); err != nil {
		t.Fatalf("%s readback: %v", label, err)
	}
	if domain != "" || tlsHTTPRedirect != 0 || upstreamForceHTTP1 != 0 {
		t.Fatalf("%s HTTP 专属传输字段未归一: domain=%q tls_http_redirect=%d upstream_force_http1=%d", label, domain, tlsHTTPRedirect, upstreamForceHTTP1)
	}
}

// assertTCPRuleFamilyZeroed 断言 lb_rules 中匹配 where 的行七字段全部为零值形态。
func assertTCPRuleFamilyZeroed(t *testing.T, label, where string) {
	t.Helper()
	var hostHeader, healthCheckPath, compressTypes string
	var enableCompress, bodyMax, keepalive, tokensHidden int
	if err := db.DB.QueryRow(`SELECT COALESCE(host_header,''), COALESCE(health_check_path,''),
		IIF(enable_compress IN ('1',1),1,0), COALESCE(compress_types,''),
		COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0)
		FROM lb_rules WHERE `+where).
		Scan(&hostHeader, &healthCheckPath, &enableCompress, &compressTypes, &bodyMax, &keepalive, &tokensHidden); err != nil {
		t.Fatalf("%s readback: %v", label, err)
	}
	if hostHeader != "" || healthCheckPath != "" || enableCompress != 0 || compressTypes != "" ||
		bodyMax != 0 || keepalive != 0 || tokensHidden != 0 {
		t.Fatalf("%s HTTP 专属死配置未归一: host_header=%q health_check_path=%q enable_compress=%d compress_types=%q body_max=%d keepalive=%d tokens_hidden=%d",
			label, hostHeader, healthCheckPath, enableCompress, compressTypes, bodyMax, keepalive, tokensHidden)
	}
}

func TestUpdateRule_httpEditDropsTCPOnlyFields(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_health_check_port,tcp_proxy_protocol)
		VALUES ('lb_http_tcpdead','http-tcpdead','','http','hdead.test',18583,'weighted_round_robin',1,99,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_http_tcpdead','up.test',80,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_http_tcpdead", strings.NewReader(`{"name":"http-tcpdead-renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("http edit status=%d body=%s", response.Code, response.Body.String())
	}
	var port, proxy int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0) FROM lb_rules WHERE caddy_id='lb_http_tcpdead'`).Scan(&port, &proxy); err != nil {
		t.Fatal(err)
	}
	if port != 0 || proxy != 0 {
		t.Fatalf("http edit must clear TCP-only fields, got port=%d proxy=%d", port, proxy)
	}
}
