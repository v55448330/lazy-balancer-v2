package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 路径规则上游地址写侧 trim——带前后空白的 " up.test " 会渲染成非法 dial。
func TestCreateRule_pathUpstreamAddressTrimmedOnWrite(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := `{"name":"path-trim","protocol":"http","domain":"pathtrim.test","listen_port":18840,"custom_routes_enabled":true,` +
		`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],` +
		`"path_rules":[{"path":"/a","match_type":"prefix","upstreams":[{"address":" up.test ","port":9001,"weight":1}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(upstreams_json,'') FROM path_rules WHERE rule_id=(SELECT caddy_id FROM lb_rules WHERE name='path-trim')`).Scan(&raw); err != nil {
		t.Fatalf("read path upstreams: %v", err)
	}
	if !strings.Contains(raw, `"address":"up.test"`) || strings.Contains(raw, `" up.test "`) {
		t.Fatalf("upstreams_json=%s, want address trimmed to up.test", raw)
	}
}

func TestValidateRuleFeatures_rejectsInvalidUpstreamForceHTTP1(t *testing.T) {
	base := ruleFeatureInput{
		Protocol: "http", Strategy: "weighted_round_robin", ListenPort: 18841,
		TCPTryInterval: 250, HealthCheckInterval: 10, HealthCheckTimeout: 2,
	}
	for _, invalid := range []int{2, -1, 9} {
		input := base
		input.UpstreamForceHTTP1 = invalid
		if err := validateRuleFeatures(input); err == nil {
			t.Fatalf("upstream_force_http1=%d must be rejected", invalid)
		}
	}
	for _, valid := range []int{0, 1} {
		input := base
		input.UpstreamForceHTTP1 = valid
		if err := validateRuleFeatures(input); err != nil {
			t.Fatalf("upstream_force_http1=%d must pass, got %v", valid, err)
		}
	}

	// API 面同门：HTTP 规则携带 2 保存必须 400 且不落库。
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_forceh1','forceh1','','http','forceh1.test',18842,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_forceh1','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_forceh1", strings.NewReader(`{"upstream_force_http1":2}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "upstream_force_http1") {
		t.Fatalf("status=%d body=%s, want 400 upstream_force_http1", response.Code, response.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(upstream_force_http1,0) FROM lb_rules WHERE caddy_id='lb_forceh1'`).Scan(&stored); err != nil {
		t.Fatalf("read stored value: %v", err)
	}
	if stored != 0 {
		t.Fatalf("rejected value persisted: %d", stored)
	}
}

// 200 + config_not_exists（排障误导）。
func TestGetRuleCaddyConfig_adminUnreachableReturns502(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb_admin_down','admin-down','','http','admin-down.test',18843,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	handler := &Handlers{caddyService: services.NewCaddyService("http://127.0.0.1:1")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/caddy-config", handler.GetRuleCaddyConfig)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_admin_down/caddy-config", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502（不得伪装成 config_not_exists）", response.Code, response.Body.String())
	}
}

func TestScanLbRules_nullEnableCompressReadsAsOff(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress)
		VALUES ('lb_nullcompress','null-compress','','http','null-compress.test',18844,'weighted_round_robin',1,NULL)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	rows, err := db.DB.Query(`SELECT ` + lbRuleListColumns + ` FROM lb_rules WHERE caddy_id='lb_nullcompress'`)
	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	rules, scanErr := scanLbRules(rows)
	closeErr := rows.Close()
	if scanErr != nil || closeErr != nil {
		t.Fatalf("scan rules: %v / close: %v", scanErr, closeErr)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(rules))
	}
	if rules[0].EnableCompress {
		t.Fatal("NULL enable_compress 读为 true，与渲染 IIF(NULL)=0 分裂")
	}
}

func TestEnableRule_postCommitFailureRestoresMetadataAndAudits(t *testing.T) {
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	handler, _, _ := newAuditRuleHandlers(t, 0)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO certificate_configs (id, name, dns_provider, dns_credentials, enabled) VALUES (1, 'test-dns', 'dnspod', '{}', 1)`); err != nil {
		t.Fatalf("seed acme config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (1,'le-test','letsencrypt','https://acme.test/directory',1)`); err != nil {
		t.Fatalf("seed ca provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
		enable_tls,tls_source,acme_config_id,ca_provider_id,updated_by)
		VALUES ('lb_enable_meta','enable-meta','','http','Enable.Example.Test',18550,'weighted_round_robin',0,
		1,'acme_dns',1,1,7)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_enable_meta','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_meta/enable", nil))

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "CA 队列未初始化") {
		t.Fatalf("status=%d body=%s, want 500 CA 队列未初始化", response.Code, response.Body.String())
	}
	var enabled int
	var domain string
	var updatedBy int
	if err := db.DB.QueryRow(`SELECT IIF(enabled IN ('1',1),1,0), COALESCE(domain,''), COALESCE(updated_by,0) FROM lb_rules WHERE caddy_id='lb_enable_meta'`).
		Scan(&enabled, &domain, &updatedBy); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("enabled=%d, want 0（补偿未恢复）", enabled)
	}
	if domain != "Enable.Example.Test" {
		t.Fatalf("domain=%q, want original Enable.Example.Test（规范化值未回滚）", domain)
	}
	if updatedBy != 7 {
		t.Fatalf("updated_by=%d, want 7（未生效的启用尝试不得覆盖操作者）", updatedBy)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='启用失败' AND detail LIKE '%lb_enable_meta%'`).Scan(&detail); err != nil {
		t.Fatalf("启用失败审计缺失: %v", err)
	}
}

// 回弹 DB 权威配置，且状态码保持 400（配置被拒）。
func TestValidateConfig_fallbackRestoresAuthoritativeConfigOnRejection(t *testing.T) {
	newBackupTestHandlers(t)
	var validateCalls, restoreCalls int
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			// 验证 /load 不再带 ?validate=true（真实加载）——按调用序分发：
			// 首次=验证（Caddy 拒绝），二次=回弹权威配置。
			if validateCalls == 0 {
				validateCalls++
				http.Error(w, "invalid config", http.StatusBadRequest)
			} else {
				restoreCalls++
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: fakeCaddy.URL}, caddyService: services.NewCaddyService(fakeCaddy.URL)}
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfig)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(`{"apps":{"http":{"servers":{}}}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（配置被 Caddy 拒绝）", response.Code, response.Body.String())
	}
	if validateCalls != 1 {
		t.Fatalf("validate /load calls=%d, want 1", validateCalls)
	}
	if restoreCalls != 1 {
		t.Fatalf("restore /load calls=%d, want 1（失败分支也必须回弹权威配置）", restoreCalls)
	}
}

// 500 而非伪装成「配置无效」400。
func TestValidateConfig_fallbackTransportError500_andRestores(t *testing.T) {
	newBackupTestHandlers(t)
	var loadCalls, restoreCalls int
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			// 验证 /load 不再带 ?validate=true——按调用序分发：首次=验证
			// （传输错误：劫持连接即闭），二次=回弹权威配置。
			loadCalls++
			if loadCalls == 1 {
				if hijacker, ok := w.(http.Hijacker); ok {
					conn, _, err := hijacker.Hijack()
					if err == nil {
						_ = conn.Close()
						return
					}
				}
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				restoreCalls++
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: fakeCaddy.URL}, caddyService: services.NewCaddyService(fakeCaddy.URL)}
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfig)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(`{"apps":{"http":{"servers":{}}}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（传输错误不得伪装成配置无效）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "运行配置已恢复") {
		t.Fatalf("body=%s, want 明示运行配置已恢复", response.Body.String())
	}
	if restoreCalls != 1 {
		t.Fatalf("restore /load calls=%d, want 1（传输错误同样必须回弹）", restoreCalls)
	}
}

// UpdateConfig 同收口——统一走 recoverCommittedViewAfterCommitFailure(tx)
// （回滚事务 + 已提交视图重渲染 /load + 投影/证书/LKG 回退；单点投影回滚
// 已不足以在恢复 /load 失败时回退 LKG）。以源码结构门锁定五个分支的收敛。
func TestRuleCommitFailureBranchesRestoreCommittedView(t *testing.T) {
	raw, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	source := string(raw)
	// 提交入口有两个等价形态：`tx.Commit()` 与测试缝单源 `commitTx(tx)`
	//（提交失败可注入，见 txCommitForTest）。分支断言必须两者都认，否则换
	// 入口即假红。
	needles := []string{"if err := tx.Commit(); err != nil {", "if err := commitTx(tx); err != nil {"}
	searchFrom := 0
	branches := 0
	for {
		nextIndex, nextNeedleLen := -1, 0
		for _, needle := range needles {
			if index := strings.Index(source[searchFrom:], needle); index >= 0 && (nextIndex < 0 || index < nextIndex) {
				nextIndex, nextNeedleLen = index, len(needle)
			}
		}
		if nextIndex < 0 {
			break
		}
		start := searchFrom + nextIndex
		searchFrom = start + nextNeedleLen
		// 分支体内（900 字节窗口，含中文注释）必须含已提交视图统一恢复；
		// DuplicateRule 不应用 Caddy 配置（副本默认禁用），无副作用，按专属
		// 日志文案豁免。
		windowEnd := start + 900
		if windowEnd > len(source) {
			windowEnd = len(source)
		}
		window := source[start:windowEnd]
		if strings.Contains(window, "DuplicateRule transaction commit failed") {
			continue
		}
		branches++
		if !strings.Contains(window, "recoverCommittedViewAfterCommitFailure(tx)") {
			t.Fatalf("第 %d 个 tx.Commit 失败分支缺少 recoverCommittedViewAfterCommitFailure(tx)（offset=%d）", branches, start)
		}
	}
	if branches != 5 {
		t.Fatalf("tx.Commit 失败分支=%d, want 5（Create/Update/Delete/Enable/Disable）", branches)
	}
}

func TestBatchRuleBlockPages_rejectsOverLimitRuleIDs(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/batch-block-pages", handler.BatchRuleBlockPages)

	ids := make([]string, 501)
	for i := range ids {
		ids[i] = "lb_over_" + strconv.Itoa(i)
	}
	payload, _ := json.Marshal(map[string]any{"rule_ids": ids})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules/batch-block-pages", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "500") {
		t.Fatalf("status=%d body=%s, want 400 上限提示", response.Code, response.Body.String())
	}
}
