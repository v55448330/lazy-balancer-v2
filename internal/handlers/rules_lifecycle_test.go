package handlers

// 规则生命周期 handler 族修复的回归钉测。
// 覆盖：TCP 自愈族（TCP 自愈清单扩面）、删除复核（DisableRule 放锁窗口
// 删除复核）、规则文本长度上限（name/description 长度门）、并发修改复核（UpdateRule 放锁
// 窗口并发修改复核）、提交后失败审计（五端点提交后失败审计）。

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedTCPRuleWithDeadHTTPOnlyConfig 播种带存量 HTTP 专属死值的 TCP 规则：
// proxy 超时族非零、custom_routes_enabled=1、dynamic_dns=1、strategy=cookie。
func seedTCPRuleWithDeadHTTPOnlyConfig(t *testing.T, caddyID, name string, listenPort int) {
	t.Helper()
	_, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,
		health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,
		enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,
		request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,
		enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,
		enable_compress,compress_types,enabled,created_by,host_header,log_enabled,
		custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,
		proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,
		dynamic_dns)
		VALUES (?,?,'',?,'',?,'cookie','',10,5,3,2,0,9001,0,5000,300,0,0,0,
		0,'manual',0,0,'','',0,1,'gzip',0,0,'',0,
		1,30,60,120,120,300,-1,15,1)`, caddyID, name, "tcp", listenPort)
	if err != nil {
		t.Fatalf("seed tcp dead-config rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'tcp')`, caddyID); err != nil {
		t.Fatalf("seed upstream for %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES (?,1,'prefix','/legacy')`, caddyID); err != nil {
		t.Fatalf("seed path rule for %s: %v", caddyID, err)
	}
}

// seedTestDNSProviderConfig 播种 DNS 提供商配置并返回 id（acme_dns 规则引用门要求）。
func seedTestDNSProviderConfig(t *testing.T) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns88','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed dns provider config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read dns provider id: %v", err)
	}
	return id
}

// readTCPHTTPOnlyDeadColumns 读取 TCP 死配置族终态。
func readTCPHTTPOnlyDeadColumns(t *testing.T, caddyID string) (strategy string, proxy [7]int, customRoutes, dynamicDNS, pathRuleCount int) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT COALESCE(strategy,''), COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0),
		COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
		COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(custom_routes_enabled,0), COALESCE(dynamic_dns,0)
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&strategy, &proxy[0], &proxy[1], &proxy[2], &proxy[3], &proxy[4], &proxy[5], &proxy[6],
		&customRoutes, &dynamicDNS); err != nil {
		t.Fatalf("read tcp dead columns: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id = ?`, caddyID).Scan(&pathRuleCount); err != nil {
		t.Fatalf("read path rules: %v", err)
	}
	return
}

func assertTCPDeadColumnsHealed(t *testing.T, caddyID string) {
	t.Helper()
	strategy, proxy, customRoutes, dynamicDNS, pathRuleCount := readTCPHTTPOnlyDeadColumns(t, caddyID)
	if strategy != "weighted_round_robin" {
		t.Fatalf("strategy=%q, want weighted_round_robin after TCP heal", strategy)
	}
	if proxy != [7]int{} {
		t.Fatalf("proxy timeouts=%v, want all zero after TCP heal", proxy)
	}
	if customRoutes != 0 || dynamicDNS != 0 {
		t.Fatalf("custom_routes_enabled=%d dynamic_dns=%d, want 0/0 after TCP heal", customRoutes, dynamicDNS)
	}
	if pathRuleCount != 0 {
		t.Fatalf("path_rules=%d, want 0 after TCP heal", pathRuleCount)
	}
}

func TestUpdateRule_toleratesNullStoredDescription(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_null_description", "before", "null-description.example.test", 18011, true, "manual", false)
	seedAuditUpstream(t, "lb_null_description")
	if _, err := db.DB.Exec("UPDATE lb_rules SET description=NULL WHERE caddy_id='lb_null_description'"); err != nil {
		t.Fatalf("seed null description: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_null_description", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update with NULL stored description status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var name, description string
	if err := db.DB.QueryRow("SELECT name,COALESCE(description,'') FROM lb_rules WHERE caddy_id='lb_null_description'").Scan(&name, &description); err != nil {
		t.Fatalf("read updated rule: %v", err)
	}
	if name != "after" || description != "" {
		t.Fatalf("updated rule name=%q description=%q, want after/empty", name, description)
	}
}

// TCP 自愈族：同协议 TCP 编辑自愈（存量死值不再让无关编辑恒 400 死端）。
func TestUpdateRule_tcpSameProtocolEditSelfHealsHTTPOnlyConfig(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleWithDeadHTTPOnlyConfig(t, "lb_tcp_heal", "tcp-heal", 17041)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcp_heal", strings.NewReader(`{"name":"healed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When：只改名字（未携带任何 HTTP 专属字段）
	router.ServeHTTP(response, request)

	// Then：200 且死配置族归零、残留路径规则删除
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertTCPDeadColumnsHealed(t, "lb_tcp_heal")
}

// TCP 自愈族：复制自愈（tcp+cookie / tcp+proxy 超时 / tcp+自定义路径的
// 存量行不再「复制即 400」；副本不放大死配置）。
func TestDuplicateRule_tcpSelfHealsHTTPOnlyConfig(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleWithDeadHTTPOnlyConfig(t, "lb_tcp_dup_heal", "tcp-dupsrc", 17042)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_dup_heal/duplicate", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：201，副本死配置族归零且未复制路径规则
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name='tcp-dupsrc（副本）'`).Scan(&copyID); err != nil {
		t.Fatalf("read duplicated rule: %v", err)
	}
	assertTCPDeadColumnsHealed(t, copyID)
}

// TCP 自愈族：Create 的显式携带仍由保存门 400 点名（请求值全部显式，无存量可愈）。
func TestCreateRule_tcpExplicitProxyTimeoutStillRejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"tcp-explicit","protocol":"tcp","listen_port":17043,"proxy_dial_timeout":5,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "代理超时") {
		t.Fatalf("create tcp with explicit proxy timeout status=%d body=%s, want 400 代理超时", response.Code, response.Body.String())
	}
}

// TCP 保存门契约：显式携带代理超时（含 -1 等负值）统一由 validateRuleFeatures
// TCP 分支 400 点名——此前负值被 Create 调用点静默归零绕过保存门（正值 400、
// 负值 201 落库的分叉），七列已从负值归零环剔除。
func TestCreateRule_tcpExplicitNegativeProxyTimeout(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"tcp-negative-proxy","protocol":"tcp","listen_port":17044,"enabled":false,
		"proxy_dial_timeout":-1,"proxy_response_header_timeout":-2,"proxy_read_timeout":-3,
		"proxy_write_timeout":-4,"proxy_stream_timeout":-5,"proxy_flush_interval":-1,"proxy_stream_close_delay":-7,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("create TCP with explicit negative proxy timeouts status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "TCP 规则不支持 HTTP 代理超时配置") {
		t.Fatalf("error body must name the TCP proxy timeout gate, got: %s", response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name='tcp-negative-proxy'`).Scan(&count); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected create must not persist a row, found %d", count)
	}
}

func TestValidateStoredRuleConfig_normalizesTCPDeadFields(t *testing.T) {
	newRuleFeatureTestHandlers(t)
	seedTCPRuleWithDeadHTTPOnlyConfig(t, "lb_tcp_enable_heal", "tcp-enable-heal", 17045)

	if err := validateStoredRuleConfig(t.Context(), "lb_tcp_enable_heal"); err != nil {
		t.Fatalf("stored TCP dead fields must be normalized before enable validation: %v", err)
	}
}

// lb_rules 五份列投影的全集机械断言钉测：UpdateRule 合并基线 SELECT / 主
// UPDATE SET 与 services.LbRuleInsertColumns() 全集对齐（豁免逐列注明）。
// 包初始化用同一判定函数 panic（fail-visible）；本用例负向变异验证「临时删列
// 必须 panic 且点名缺失列」。
func TestUpdateRuleColumnLists_parityWithInsertSpec(t *testing.T) {
	specSet, selectSet, setSet := updateRuleColumnParitySets()
	if gaps := updateRuleColumnParityGaps(specSet, selectSet, setSet); len(gaps) != 0 {
		t.Fatalf("UpdateRule 列投影全集断言失败: %v", gaps)
	}

	// 负向变异：基线 SELECT 临时删列 → 与 init 同一判定必须 panic 且点名。
	func() {
		defer func() {
			recovered := recover()
			if recovered == nil {
				t.Fatal("基线 SELECT 临时删列必须触发全集断言 panic")
			}
			if message := fmt.Sprint(recovered); !strings.Contains(message, "proxy_dial_timeout") {
				t.Fatalf("panic 未点名缺失列: %v", recovered)
			}
		}()
		mutated := make(map[string]bool, len(selectSet))
		for column := range selectSet {
			mutated[column] = true
		}
		delete(mutated, "proxy_dial_timeout")
		mustUpdateRuleColumnParity(specSet, mutated, setSet)
	}()
}

// 删除复核：DisableRule 放锁窗口内规则被并发删除 → 冲突中止且不写「禁用」审计。
func TestDisableRule_abortsWhenRuleDeletedInLockWindow(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_dis_window", "diswindow", "diswindow.example.test", 18001, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_dis_window")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	disableRuleLockWindowHook = func(caddyID string) {
		if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("delete rule in lock window: %v", err)
		}
	}
	t.Cleanup(func() { disableRuleLockWindowHook = nil })
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dis_window/disable", nil))

	// Then：409 中止；成功审计缺席
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "已被删除") {
		t.Fatalf("disable status=%d body=%s, want 409 已被删除", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='禁用' AND resource='负载规则' AND detail LIKE '%lb_dis_window%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read disable audit: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("禁用 success audit=%d, want 0 when rule deleted in lock window", auditCount)
	}
}

// 并发修改复核：UpdateRule 放锁窗口内规则被并发修改 → 409 + 审计「并发修改」，
// DB 保留他人已提交内容。
func TestUpdateRule_abortsWhenRuleConcurrentlyModifiedInLockWindow(t *testing.T) {
	// Given：manual TLS（orphanACME=true）打开证书取消窗口
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_upd_conc", "updconc", "updconc.example.test", 18002, true, "manual", false)
	seedAuditUpstream(t, "lb_upd_conc")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 1 {
			return
		}
		if _, err := db.DB.Exec("UPDATE lb_rules SET name='concurrent' WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("concurrent update in lock window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_upd_conc", strings.NewReader(`{"name":"mine"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：409 点名并发修改；DB 保留并发提交的 name；审计留痕
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "并发修改") {
		t.Fatalf("update status=%d body=%s, want 409 并发修改", response.Code, response.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id='lb_upd_conc'`).Scan(&name); err != nil {
		t.Fatalf("read rule name: %v", err)
	}
	if name != "concurrent" {
		t.Fatalf("rule name=%q, want concurrent（他人已提交内容不得被回退）", name)
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%并发修改%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read concurrency audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("并发修改中止必须落「更新失败」审计")
	}
}

// 并发修改复核：指纹复核的直接契约——未变不中止，变更即 409。
func TestAbortIfRuleConcurrentlyModified_detectsChange(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_fp", 17051)
	baseline, err := ruleMutationFingerprint(t.Context(), "lb_fp")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if abortIfRuleConcurrentlyModified(c, "lb_fp", baseline) {
		t.Fatal("unchanged rule must not abort")
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET name='changed' WHERE caddy_id='lb_fp'"); err != nil {
		t.Fatalf("mutate rule: %v", err)
	}
	if !abortIfRuleConcurrentlyModified(c, "lb_fp", baseline) {
		t.Fatal("changed rule must abort")
	}
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409", recorder.Code)
	}
}

func TestRuleMutationFingerprint_honorsContextCancellation(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedTCPRuleForZeroMerge(t, "lb_fp_cancel", 17052)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := ruleMutationFingerprint(ctx, "lb_fp_cancel")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fingerprint error=%v, want context.Canceled", err)
	}
}

// 规则文本长度上限：name/description 长度门（DDL 声明值 100/300 rune）。
func TestCreateRule_rejectsOverlongNameAndDescription(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{
			name:    "name over 100 runes",
			body:    fmt.Sprintf(`{"name":%q,"protocol":"http","domain":"long.example.test","listen_port":17061,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, strings.Repeat("名", 101)),
			wantMsg: "规则名称过长",
		},
		{
			name:    "description over 300 runes",
			body:    fmt.Sprintf(`{"name":"desc-long","description":%q,"protocol":"http","domain":"long2.example.test","listen_port":17062,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, strings.Repeat("述", 301)),
			wantMsg: "规则描述过长",
		},
	}
	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(tc.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.wantMsg) {
			t.Fatalf("%s: status=%d body=%s, want 400 %s", tc.name, response.Code, response.Body.String(), tc.wantMsg)
		}
	}
}

func TestUpdateRule_rejectsOverlongName(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_longname", "longname", "longname.example.test", 18003, true, "manual", false)
	seedAuditUpstream(t, "lb_longname")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_longname",
		strings.NewReader(fmt.Sprintf(`{"name":%q}`, strings.Repeat("名", 101))))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "规则名称过长") {
		t.Fatalf("update overlong name status=%d body=%s, want 400 规则名称过长", response.Code, response.Body.String())
	}
}

// 规则文本长度上限：副本名累积后缀截断到上限内（源名 100 rune → 基名截断保后缀）。
func TestDuplicateRule_truncatesCopyNameWithinLimit(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	sourceName := strings.Repeat("名", maxRuleNameRunes)
	seedTCPRuleForZeroMerge(t, "lb_dup_long", 17071)
	if _, err := db.DB.Exec("UPDATE lb_rules SET name=? WHERE caddy_id='lb_dup_long'", sourceName); err != nil {
		t.Fatalf("rename source: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_long/duplicate", nil))

	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var copyName string
	if err := db.DB.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id != 'lb_dup_long' ORDER BY rowid DESC LIMIT 1`).Scan(&copyName); err != nil {
		t.Fatalf("read copy name: %v", err)
	}
	if n := utf8.RuneCountInString(copyName); n > maxRuleNameRunes {
		t.Fatalf("copy name runes=%d, want <= %d", n, maxRuleNameRunes)
	}
	if !strings.HasSuffix(copyName, "（副本）") {
		t.Fatalf("copy name=%q must keep 副本 suffix", copyName)
	}
}

// 规则文本长度上限：复制路径同样拒绝超长描述（点名源规则）。
func TestDuplicateRule_rejectsOverlongDescription(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_dup_desc", 17072)
	if _, err := db.DB.Exec("UPDATE lb_rules SET description=? WHERE caddy_id='lb_dup_desc'", strings.Repeat("述", maxRuleDescriptionRunes+1)); err != nil {
		t.Fatalf("seed long description: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_desc/duplicate", nil))

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "规则描述过长") {
		t.Fatalf("duplicate overlong description status=%d body=%s, want 400 规则描述过长", response.Code, response.Body.String())
	}
}

func TestDuplicateRule_auditsFailureResponses(t *testing.T) {
	tests := []struct {
		name       string
		caddyID    string
		seed       func(*testing.T)
		wantStatus int
	}{
		{name: "missing source", caddyID: "lb_duplicate_missing", seed: func(*testing.T) {}, wantStatus: http.StatusNotFound},
		{name: "invalid source", caddyID: "lb_duplicate_invalid", seed: func(t *testing.T) {
			seedTCPRuleForZeroMerge(t, "lb_duplicate_invalid", 17073)
			if _, err := db.DB.Exec("UPDATE lb_rules SET description=? WHERE caddy_id='lb_duplicate_invalid'", strings.Repeat("述", maxRuleDescriptionRunes+1)); err != nil {
				t.Fatalf("seed invalid source: %v", err)
			}
		}, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newRuleFeatureTestHandlers(t)
			gin.SetMode(gin.TestMode)
			tt.seed(t)
			router := gin.New()
			router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+tt.caddyID+"/duplicate", nil))
			if response.Code != tt.wantStatus {
				t.Fatalf("duplicate status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantStatus)
			}
			var auditCount int
			if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
				WHERE action='复制失败' AND resource='负载规则' AND detail LIKE ?`, "%"+tt.caddyID+"%").Scan(&auditCount); err != nil {
				t.Fatalf("read duplicate failure audit: %v", err)
			}
			if auditCount != 1 {
				t.Fatalf("duplicate failure audit rows=%d, want 1", auditCount)
			}
		})
	}
}

// 提交后失败审计 行为钉：CreateRule 提交后入队失败（CA 队列未初始化）→ 500 + 「创建失败」审计。
func TestCreateRule_auditsEnqueueFailureWhenQueueInactive(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	acmeConfigID := seedTestDNSProviderConfig(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{"name":"acme-create","protocol":"http","domain":"acme-create.example.test","listen_port":18004,
		"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, acmeConfigID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "CA 队列未初始化") {
		t.Fatalf("create status=%d body=%s, want 500 CA 队列未初始化", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='创建失败' AND resource='负载规则' AND detail LIKE '%队列%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read create failure audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("创建入队失败必须落「创建失败」审计")
	}
}

// 提交后失败审计 行为钉：UpdateRule 提交后入队失败 → 500 + 「更新失败」审计。
func TestUpdateRule_auditsEnqueueFailureWhenQueueInactive(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	acmeConfigID := seedTestDNSProviderConfig(t)
	seedAuditRule(t, "lb_acme_upd", "acmeupd", "acmeupd.example.test", 18005, true, "manual", true)
	seedAuditUpstream(t, "lb_acme_upd")
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acme_upd",
		strings.NewReader(fmt.Sprintf(`{"tls_source":"acme_dns","acme_config_id":%d}`, acmeConfigID)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "CA 队列未初始化") {
		t.Fatalf("update status=%d body=%s, want 500 CA 队列未初始化", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%队列%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read update failure audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("更新入队失败必须落「更新失败」审计")
	}
}

// 提交后失败审计 行为钉：提交已成功、ACME 阶段读取证书任务失败 → 500 +
// 「更新失败」审计（含规则 id）。该分支此前只回滚不落审计，Explicit 策略下
// 整个「曾提交并已回滚」的事实完全缺席。
func TestUpdateRule_auditsCertJobReadFailureAfterCommit(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_acme_read_fail", "acmereadfail", "acmereadfail.example.test", 18007, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_acme_read_fail")
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=?,ca_provider_id=? WHERE caddy_id='lb_acme_read_fail'",
		seedR52CertificateConfig(t), providerID); err != nil {
		t.Fatalf("bind ACME references: %v", err)
	}

	probe := &prepareProbe{fail: func(query string, _ bool) error {
		if strings.Contains(query, "SELECT id,status,expires_at,COALESCE(ca_provider_id,0) FROM cert_jobs") {
			return errors.New("injected cert_jobs read failure")
		}
		return nil
	}}
	wrapHandlerDBWithProbe(t, probe)

	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acme_read_fail",
		strings.NewReader(`{"name":"acmereadfail-renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "读取证书任务失败") {
		t.Fatalf("status=%d body=%s, want 500 读取证书任务失败", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
		WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%读取证书任务失败%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read update failure audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("提交后读取证书任务失败必须恰落 1 条「更新失败」审计，实际 %d", auditCount)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log
		WHERE action='更新失败' AND resource='负载规则' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if !strings.Contains(detail, "lb_acme_read_fail") {
		t.Fatalf("审计明细必须点名规则 id: %q", detail)
	}
}

// 提交后失败审计 结构钉：五端点提交后失败分支的审计留痕数量下限（提交失败/入队
// 失败路径无法在 handler 层注入 DB commit 故障，按源码分支计数）。
// 注意：这是「最低数量」而非充分条件——新增/漏记分支可能不在计数覆盖面内，
// 分支集合等价由 TestRuleWriteFailureBranches_allAudited 承担。
func TestRuleFailurePathAudits_pinAllPostCommitBranches(t *testing.T) {
	src, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	body := string(src)
	cases := []struct {
		fn     string
		action string
		min    int
	}{
		{"func (h *Handlers) CreateRule(", "创建失败", 3},  // commit + qm nil + enqueue err
		{"func (h *Handlers) UpdateRule(", "更新失败", 3},  // commit + qm nil + enqueue err（并发修改另有 1 处）
		{"func (h *Handlers) DeleteRule(", "删除失败", 2},  // cancel timeout + commit
		{"func (h *Handlers) DisableRule(", "禁用失败", 1}, // commit
	}
	for _, tc := range cases {
		window := handlerFuncBody(body, tc.fn)
		if got := strings.Count(window, `recordAudit(c, "`+tc.action+`"`); got < tc.min {
			t.Fatalf("%s 失败审计 %s 次数=%d, want >= %d", tc.fn, tc.action, got, tc.min)
		}
	}
}

// 提交后失败审计 分支集合等价门：枚举五端点函数体内每个 5xx 候选
// （writeInternalError / c.JSON）。动态 status 无法在语法层证明一定是 4xx，
// 一律按 5xx 候选要求留痕；明确 2xx/3xx/4xx 与认证响应不纳入。断言其执行
// 路径上存在留痕调用——同块前序直呼 recordAudit / recordRuleWriteFailure，
// 或经由 fail* 闭包，或外层块的同一判据。新增失败分支漏记即红。
func TestRuleWriteFailureBranches_allAudited(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rules.go", nil, 0)
	if err != nil {
		t.Fatalf("parse rules.go: %v", err)
	}
	callName := func(call *ast.CallExpr) string {
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			return fun.Name
		case *ast.SelectorExpr:
			return fun.Sel.Name
		}
		return ""
	}
	// 只有语法层明确的非 5xx 状态才能排除；变量、函数返回值等动态状态
	// 一律保留为候选，防止 certEnqueueErrorResponse 等 4xx/5xx 联合分支漏审。
	nonServerStatusNames := map[string]bool{}
	for _, name := range []string{
		"StatusOK", "StatusCreated", "StatusAccepted", "StatusNonAuthoritativeInfo",
		"StatusNoContent", "StatusResetContent", "StatusPartialContent", "StatusMultiStatus",
		"StatusAlreadyReported", "StatusIMUsed", "StatusMultipleChoices", "StatusMovedPermanently",
		"StatusFound", "StatusSeeOther", "StatusNotModified", "StatusUseProxy", "StatusTemporaryRedirect",
		"StatusPermanentRedirect", "StatusBadRequest", "StatusUnauthorized", "StatusPaymentRequired",
		"StatusForbidden", "StatusNotFound", "StatusMethodNotAllowed", "StatusNotAcceptable",
		"StatusProxyAuthRequired", "StatusRequestTimeout", "StatusConflict", "StatusGone",
		"StatusLengthRequired", "StatusPreconditionFailed", "StatusRequestEntityTooLarge",
		"StatusRequestURITooLong", "StatusUnsupportedMediaType", "StatusRequestedRangeNotSatisfiable",
		"StatusExpectationFailed", "StatusTeapot", "StatusMisdirectedRequest", "StatusUnprocessableEntity",
		"StatusLocked", "StatusFailedDependency", "StatusTooEarly", "StatusUpgradeRequired",
		"StatusPreconditionRequired", "StatusTooManyRequests", "StatusRequestHeaderFieldsTooLarge",
		"StatusUnavailableForLegalReasons",
	} {
		nonServerStatusNames[name] = true
	}
	isServerErrorResponse := func(call *ast.CallExpr) bool {
		switch callName(call) {
		case "writeInternalError":
			return true
		case "JSON":
			if len(call.Args) == 0 {
				return false
			}
			switch status := call.Args[0].(type) {
			case *ast.BasicLit:
				if status.Kind != token.INT {
					return true
				}
				code, err := strconv.ParseInt(status.Value, 0, 32)
				return err != nil || code < 200 || code >= 500
			case *ast.SelectorExpr:
				return !nonServerStatusNames[status.Sel.Name]
			default:
				return true
			}
		}
		return false
	}
	// 自检分类器本身：成功、认证与明确客户端错误不得制造伪候选，
	// 动态 status 与明确 5xx 则必须进入分支审计。
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{"c.JSON(http.StatusOK, nil)", false},
		{"c.JSON(http.StatusCreated, nil)", false},
		{"c.JSON(http.StatusUnauthorized, nil)", false},
		{"c.JSON(http.StatusForbidden, nil)", false},
		{"c.JSON(http.StatusBadRequest, nil)", false},
		{"c.JSON(http.StatusNotFound, nil)", false},
		{"c.JSON(http.StatusConflict, nil)", false},
		{"c.JSON(200, nil)", false},
		{"c.JSON(404, nil)", false},
		{"c.JSON(500, nil)", true},
		{"c.JSON(http.StatusBadGateway, nil)", true},
		{"c.JSON(status, nil)", true},
	} {
		expr, err := parser.ParseExpr(tc.expr)
		if err != nil {
			t.Fatalf("parse classifier self-check %q: %v", tc.expr, err)
		}
		if got := isServerErrorResponse(expr.(*ast.CallExpr)); got != tc.want {
			t.Fatalf("5xx 候选分类自检 %s = %v, want %v", tc.expr, got, tc.want)
		}
	}
	// 仅收集本层语句内的 5xx（遇到嵌套块即止——嵌套块由下一层按同一判据评估，
	// 避免外层「有审计」错误地赦免内层新增的无审计分支）。
	directServerErrorCalls := func(stmt ast.Stmt) []*ast.CallExpr {
		var calls []*ast.CallExpr
		ast.Inspect(stmt, func(n ast.Node) bool {
			if _, inner := n.(*ast.BlockStmt); inner {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if ok && isServerErrorResponse(call) {
				calls = append(calls, call)
			}
			return true
		})
		return calls
	}
	handlerFuncs := map[string]bool{
		"CreateRule": true, "UpdateRule": true, "DeleteRule": true,
		"DisableRule": true, "EnableRule": true,
	}
	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !handlerFuncs[fn.Name.Name] {
			continue
		}
		// 本函数内定义的闭包（failEnableWithStatus/failEnable/failUpdateWithStatus 等）
		// 供「块内只调了 fail* 名字」时下钻验证：留痕必须真实存在于闭包链上。
		closureBodies := map[string]*ast.BlockStmt{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			ident, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			lit, ok := assign.Rhs[0].(*ast.FuncLit)
			if !ok {
				return true
			}
			closureBodies[ident.Name] = lit.Body
			return true
		})
		var closureAudits func(name string, seen map[string]bool) bool
		closureAudits = func(name string, seen map[string]bool) bool {
			body, ok := closureBodies[name]
			if !ok || seen[name] {
				return false
			}
			seen[name] = true
			var names []string
			ast.Inspect(body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					names = append(names, callName(call))
				}
				return true
			})
			for _, called := range names {
				if called == "recordAudit" || closureAudits(called, seen) {
					return true
				}
			}
			return false
		}
		// 直呼留痕调用（非 if 分支内）：只有无条件执行才支配后续 5xx。
		auditStatement := func(stmt ast.Stmt) bool {
			expr, ok := stmt.(*ast.ExprStmt)
			if !ok {
				return false
			}
			call, ok := expr.X.(*ast.CallExpr)
			if !ok {
				return false
			}
			name := callName(call)
			return name == "recordAudit" || name == "recordRuleWriteFailure" || closureAudits(name, map[string]bool{})
		}
		var walk func(block *ast.BlockStmt, auditPrefix []bool)
		walk = func(block *ast.BlockStmt, auditPrefix []bool) {
			audited := false
			for _, stmt := range block.List {
				covered := audited
				for _, ancestorAudited := range auditPrefix {
					covered = covered || ancestorAudited
				}
				for _, call := range directServerErrorCalls(stmt) {
					checked++
					if !covered {
						t.Errorf("%s: 5xx 响应缺少留痕（同块前序无审计，外层块的审计也不支配该分支）@ %s",
							fn.Name.Name, fset.Position(call.Pos()))
					}
				}
				if auditStatement(stmt) {
					audited = true
				}
				// 进入嵌套块时携带「截至该语句之前的无条件审计」状态。
				prefix := append(append([]bool{}, auditPrefix...), audited)
				ast.Inspect(stmt, func(n ast.Node) bool {
					if child, ok := n.(*ast.BlockStmt); ok {
						walk(child, prefix)
						return false
					}
					return true
				})
			}
		}
		walk(fn.Body, nil)
	}
	const minServerErrorCandidates = 20
	if checked < minServerErrorCandidates {
		t.Fatalf("仅枚举到 %d 个 5xx 候选，want >= %d——AST 锚点漂移（分支集合等价门失效）", checked, minServerErrorCandidates)
	}
}

// handlerFuncBody 截取 handler 函数体（到下一个顶格 func）。
func handlerFuncBody(body, anchor string) string {
	start := strings.Index(body, anchor)
	if start < 0 {
		return ""
	}
	rest := body[start+len(anchor):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// 列表投影派生断言：列表投影派生必须命中——列表列不含 tls_cert/tls_key 字样，且
// 实际列表查询不返回证书正文（派生失效时 strings.Replace 静默返回原文）。
func TestListRules_omitsTLSMaterialAndDerivationHits(t *testing.T) {
	if strings.Contains(lbRuleListColumns, "tls_cert") || strings.Contains(lbRuleListColumns, "tls_key") {
		t.Fatalf("lbRuleListColumns 仍含证书列字样——派生未命中: %q", lbRuleListColumns)
	}
	if !strings.Contains(lbRuleColumns, "COALESCE(tls_cert,''), COALESCE(tls_key,'')") {
		t.Fatal("lbRuleColumns 证书列字样缺失（派生锚点被改名）")
	}

	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_list_tls", 17081)
	// 直改 DB 写入证书正文（保存链会归一，故绕过链路模拟遗留行）。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_cert='CERT-BODY-MARKER', tls_key='KEY-BODY-MARKER' WHERE caddy_id='lb_list_tls'`); err != nil {
		t.Fatalf("seed tls material: %v", err)
	}
	router := gin.New()
	router.GET("/rules", handler.ListRules)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "CERT-BODY-MARKER") || strings.Contains(response.Body.String(), "KEY-BODY-MARKER") {
		t.Fatalf("列表响应泄露证书/私钥正文: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "lb_list_tls") {
		t.Fatal("列表响应缺少规则行（列序对齐被破坏）")
	}
}

// 治理默认值单源：治理默认值列绑定 db.Default* 常量（源码不得回流写死字面量）。
// 覆盖面=rule_features.go 的 lbRuleColumns + rules.go 的 UpdateRule 存量合并查询
// （读侧 COALESCE 默认值与 schema DEFAULT/写侧校验同源）。strategy/tls_source/
// compress_types 三处文本默认值在 db 包无常量，保持字面量（rules.go 查询注释说明）。
func TestLbRuleColumns_governedDefaultsBindConstants(t *testing.T) {
	src, err := os.ReadFile("rule_features.go")
	if err != nil {
		t.Fatalf("read rule_features.go: %v", err)
	}
	rulesSrc, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	for _, literal := range []string{
		"COALESCE(health_check_interval,10)",
		"COALESCE(health_check_timeout,2)",
		"COALESCE(health_check_unhealthy_threshold,3)",
		"COALESCE(health_check_healthy_threshold,2)",
		"COALESCE(tcp_try_interval,250)",
	} {
		for name, content := range map[string]string{"rule_features.go": string(src), "rules.go": string(rulesSrc)} {
			if strings.Contains(content, literal) {
				t.Fatalf("%s 仍含写死治理默认值 %q（应绑定 db.Default* 常量）", name, literal)
			}
		}
	}
	bindings := []struct {
		fragment string
		value    int
		constRef string
	}{
		{"COALESCE(health_check_interval,%d)", db.DefaultHealthCheckInterval, "db.DefaultHealthCheckInterval"},
		{"COALESCE(health_check_timeout,%d)", db.DefaultHealthCheckTimeout, "db.DefaultHealthCheckTimeout"},
		{"COALESCE(health_check_unhealthy_threshold,%d)", db.DefaultHealthCheckUnhealthyThreshold, "db.DefaultHealthCheckUnhealthyThreshold"},
		{"COALESCE(health_check_healthy_threshold,%d)", db.DefaultHealthCheckHealthyThreshold, "db.DefaultHealthCheckHealthyThreshold"},
		{"COALESCE(tcp_try_interval,%d)", db.DefaultTCPTryInterval, "db.DefaultTCPTryInterval"},
	}
	for _, binding := range bindings {
		want := fmt.Sprintf(binding.fragment, binding.value)
		if !strings.Contains(lbRuleColumns, want) {
			t.Fatalf("lbRuleColumns 缺少常量绑定后的列 %q", want)
		}
		// rules.go 的 UpdateRule 存量合并查询投影已收进 updateRuleBaselineSelectColumns
		// 单源表（fmt.Sprintf 常量绑定）——断言常量引用存在即可（绑定形态由表单源）。
		if !strings.Contains(string(rulesSrc), binding.constRef) {
			t.Fatalf("rules.go 缺少常量绑定 %q（UpdateRule 存量合并查询）", binding.constRef)
		}
	}
}

// 并发修改复核（DisableRule）：放锁取消窗口内并发启用/更新完整提交
// （指纹偏离本请求提交后的基线）→ 409 中止 + 审计「并发修改」，不再写
// 「禁用」成功审计（否则成功留痕与最终状态矛盾——启用侧重新入队的
// 任务已被本请求取消）。
func TestDisableRule_abortsWhenRuleConcurrentlyModifiedInLockWindow(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_dis_conc", "disconc", "disconc.example.test", 18011, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_dis_conc")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	disableRuleLockWindowHook = func(caddyID string) {
		// 模拟并发 EnableRule 提交（窗口内重新启用）
		if _, err := db.DB.Exec("UPDATE lb_rules SET enabled=1, updated_at=datetime('now') WHERE caddy_id=?", caddyID); err != nil {
			t.Errorf("re-enable rule in lock window: %v", err)
		}
	}
	t.Cleanup(func() { disableRuleLockWindowHook = nil })
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dis_conc/disable", nil))

	// Then：409 并发修改中止；规则保持他人提交的启用态；无「禁用」成功审计
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "并发修改") {
		t.Fatalf("disable status=%d body=%s, want 409 并发修改", response.Code, response.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_dis_conc'").Scan(&enabled); err != nil {
		t.Fatalf("read rule enabled: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("enabled=%d, want 1（他人已提交的启用不得被回退）", enabled)
	}
	var successAudit int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='禁用' AND resource='负载规则' AND detail LIKE '%lb_dis_conc%'`).Scan(&successAudit); err != nil {
		t.Fatalf("read disable audit: %v", err)
	}
	if successAudit != 0 {
		t.Fatalf("禁用 success audit=%d, want 0 when concurrently modified in lock window", successAudit)
	}
}

// DuplicateRule 的 5xx 分支必须保留底层 cause（运行日志 + 审计 detail），
// 响应仍是固定文案：否则复制入口 500 时只能看到「读取规则失败」，无法区分
// 连接/busy、schema 漂移、关联表损坏——排障必须复现或临时加日志。
func TestDuplicateRule_keepsUnderlyingCauseInAudit(t *testing.T) {
	for _, tc := range []struct{ name, table string }{
		{"读取规则失败", "lb_rules"},
		{"读取规则关联数据失败", "upstreams"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := newRuleFeatureTestHandlers(t)
			seedTCPRuleForZeroMerge(t, "lb_dup_cause", 17075)
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
			if _, err := db.DB.Exec("ALTER TABLE " + tc.table + " RENAME TO " + tc.table + "_broken"); err != nil {
				t.Fatalf("rename %s: %v", tc.table, err)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_cause/duplicate", nil))
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "no such table") {
				t.Fatalf("5xx 响应不得携带底层错误文本: %s", response.Body.String())
			}
			var detail string
			if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log
				WHERE action='复制失败' AND resource='负载规则' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
				t.Fatalf("read duplicate failure audit: %v", err)
			}
			if !strings.Contains(detail, tc.table+"_broken") && !strings.Contains(detail, "no such table") {
				t.Fatalf("审计 detail 丢失底层 cause: %q", detail)
			}
		})
	}
}

// UpdateRule 主 UPDATE 命中 0 行（放锁窗口内规则的并发删除）同样必须留痕：
// 409 是「用户操作被拒」里最需要解释的一类，此前只有版本冲突/并发中止有审计。
// RAISE(IGNORE) 触发器精确制造「行存在但更新 0 行」形态（先删行会让读取提前 404）。
func TestUpdateRule_zeroRowUpdateAuditsConflict(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_zero_upd", "zero-upd", "zero-upd.example.test", 18650, true, "manual", false)
	seedAuditUpstream(t, "lb_zero_upd")
	if _, err := db.DB.Exec(`CREATE TRIGGER ignore_lb_zero_upd_update BEFORE UPDATE ON lb_rules
		WHEN OLD.caddy_id='lb_zero_upd' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_zero_upd", strings.NewReader(`{"name":"renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（0 行更新不得当成成功）", response.Code, response.Body.String())
	}
	var blockedAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
		WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%lb_zero_upd%'`).Scan(&blockedAudits); err != nil {
		t.Fatalf("read blocked update audit: %v", err)
	}
	if blockedAudits != 1 {
		t.Fatalf("0 行更新阻断审计条数=%d, want 1", blockedAudits)
	}
}

// 并发指纹必须覆盖安全策略绑定：绑定写端点只改 security_policy_bindings、
// 不 bump lb_rules，指纹漏掉该表就会把放锁窗口内的绑定变更误判为「无人并发
// 修改」，随后 ACME 失败补偿会按请求前快照整体恢复运行配置，撤销他人刚生效
// 的防护（DB 保留绑定、运行面已回滚的分叉）。绑定-only 变更必须与规则行变更
// 同权触发既有 409 中止。
func TestRuleMutationFingerprint_tracksPolicyBindings(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_fp_bind", 17053)
	baseline, err := ruleMutationFingerprint(t.Context(), "lb_fp_bind")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES ('fp-bind','off','stage3',1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()

	// When：只新增绑定，lb_rules 行不变
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_fp_bind',?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}
	afterBind, err := ruleMutationFingerprint(t.Context(), "lb_fp_bind")
	if err != nil {
		t.Fatalf("fingerprint after bind: %v", err)
	}

	// Then：指纹变化并触发并发中止
	if afterBind == baseline {
		t.Fatal("绑定-only 变更必须改变规则指纹（否则补偿会回滚他人的绑定变更）")
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if !abortIfRuleConcurrentlyModified(c, "lb_fp_bind", baseline) {
		t.Fatal("绑定-only 变更必须触发并发修改中止")
	}
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409", recorder.Code)
	}

	// 解绑同样改变指纹，解除后回到基线（无绑定 vs 无绑定）
	if _, err := db.DB.Exec(`DELETE FROM security_policy_bindings WHERE rule_caddy_id='lb_fp_bind' AND policy_id=?`, policyID); err != nil {
		t.Fatalf("unbind policy: %v", err)
	}
	afterUnbind, err := ruleMutationFingerprint(t.Context(), "lb_fp_bind")
	if err != nil {
		t.Fatalf("fingerprint after unbind: %v", err)
	}
	if afterUnbind == afterBind {
		t.Fatal("解绑也必须改变指纹")
	}
	if afterUnbind != baseline {
		t.Fatal("解除全部绑定后指纹应回到基线（绑定行集为空）")
	}
}

// 存量上游行的「待归一 NULL 列」判据必须覆盖 origin_domain：读侧用
// COALESCE(origin_domain,”) 归一，但内容等价且 needsNormalize=false 时零写入，
// 于是旧可空表/带外写入留下的 NULL 在用户原样保存后仍然存在——导出与集群
// 快照继续携带 NULL，与 schema 的 NOT NULL DEFAULT ” 终态不一致。
func TestStoredUpstreamNullColumnsFlagsOriginDomainNull(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE upstream_null_probe (
		weight INTEGER, dynamic_dns INTEGER, enabled INTEGER, protocol TEXT, max_connections INTEGER, origin_domain TEXT)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	query := `SELECT ` + storedUpstreamNullColumnsSQL + ` FROM upstream_null_probe WHERE rowid = ?`
	insert := func(originDomain any) int64 {
		t.Helper()
		result, err := db.DB.Exec(`INSERT INTO upstream_null_probe (weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (1, 0, 1, 'http', 0, ?)`, originDomain)
		if err != nil {
			t.Fatalf("seed probe row: %v", err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("last insert id: %v", err)
		}
		return id
	}
	needsNormalize := func(id int64) int {
		t.Helper()
		var got int
		if err := db.DB.QueryRow(query, id).Scan(&got); err != nil {
			t.Fatalf("probe predicate: %v", err)
		}
		return got
	}

	nullOrigin := insert(nil)
	if got := needsNormalize(nullOrigin); got != 1 {
		t.Fatal("origin_domain IS NULL 必须判为待归一（否则原样保存后 NULL 永久保留）")
	}
	if got := needsNormalize(insert("")); got != 0 {
		t.Fatal("全部列非 NULL 的行不得判为待归一（会白白触发同步触发器）")
	}
	nullWeight := insert("")
	if _, err := db.DB.Exec(`UPDATE upstream_null_probe SET weight = NULL WHERE rowid = ?`, nullWeight); err != nil {
		t.Fatal(err)
	}
	if got := needsNormalize(nullWeight); got != 1 {
		t.Fatal("既有列（weight）判据不得回退")
	}
}
