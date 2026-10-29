package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type importRollbackHarness struct {
	handler       *Handlers
	certDir       string
	currentConfig func() string
	loadCalls     func() int
	failRestore   func()
}

func newImportRollbackHarness(t *testing.T) importRollbackHarness {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		waitImportCleanup()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 直换包级句柄必须同步复位 currentDB（契约，
		// 与 newBackupTestHandlers 同型）——否则 GetDB() 返回 nil/后台循环
		// 持有已关闭测试库，跨用例污染。
		db.SetDB(oldDB)
	})
	certDir := t.TempDir()
	restoreCertDir := services.SetCertDirForTest(certDir)
	t.Cleanup(restoreCertDir)

	var stateMu sync.Mutex
	currentConfig := `{"marker":"before-import"}`
	loads := 0
	rejectLoads := false
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/config/":
			stateMu.Lock()
			body := currentConfig
			// 2026-09-25 审计真实性改造配套：restore 失败注入——首次 GET（快照
			// 摄取）返回 before-import 后即漂移，restore 的同字节比对才会失败、
			// /load 真发并被 rejectLoads 拒绝（否则 restore 恒同字节短路不可达）。
			if rejectLoads {
				currentConfig = `{"marker":"drifted-after-snapshot"}`
			}
			stateMu.Unlock()
			_, _ = response.Write([]byte(body))
		case request.Method == http.MethodPost && request.URL.Path == "/load":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			stateMu.Lock()
			loads++
			if rejectLoads {
				stateMu.Unlock()
				response.WriteHeader(http.StatusInternalServerError)
				_, _ = response.Write([]byte("restore rejected"))
				return
			}
			currentConfig = string(body)
			stateMu.Unlock()
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	return importRollbackHarness{
		handler: &Handlers{
			cfg:            cfg,
			caddyService:   services.NewCaddyService(fakeCaddy.URL),
			clusterService: services.NewClusterService(db.DB, ""),
		},
		certDir: certDir,
		currentConfig: func() string {
			stateMu.Lock()
			defer stateMu.Unlock()
			return currentConfig
		},
		loadCalls: func() int {
			stateMu.Lock()
			defer stateMu.Unlock()
			return loads
		},
		failRestore: func() {
			stateMu.Lock()
			rejectLoads = true
			stateMu.Unlock()
		},
	}
}

func TestConfigImportEndpoints_distinguishUnreadableAndEmptyBodies(t *testing.T) {
	for _, endpoint := range []struct {
		name  string
		path  string
		mount func(*gin.Engine, *Handlers)
	}{
		{name: "validate", path: "/config/import/validate", mount: func(r *gin.Engine, h *Handlers) { r.POST("/config/import/validate", h.ValidateConfigImport) }},
		{name: "v1 import", path: "/config/import/v1", mount: func(r *gin.Engine, h *Handlers) { r.POST("/config/import/v1", h.ImportV1Config) }},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			router := gin.New()
			endpoint.mount(router, h)

			// Given a request body whose transport fails while being read.
			request := httptest.NewRequest(http.MethodPost, endpoint.path, iotest.ErrReader(errors.New("injected body read failure")))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			// Then the transport failure is reported as such, not as an empty backup.
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "读取失败") || !strings.Contains(response.Body.String(), "injected body read failure") {
				t.Fatalf("read error status=%d body=%s, want 400 with transport cause", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "内容为空") {
				t.Fatalf("read error was misreported as empty content: %s", response.Body.String())
			}

			// Regression: a successfully read empty body retains the empty-backup response.
			emptyRequest := httptest.NewRequest(http.MethodPost, endpoint.path, strings.NewReader(""))
			emptyRequest.Header.Set("Content-Type", "application/json")
			emptyResponse := httptest.NewRecorder()
			router.ServeHTTP(emptyResponse, emptyRequest)
			if emptyResponse.Code != http.StatusBadRequest || !strings.Contains(emptyResponse.Body.String(), "内容为空") {
				t.Fatalf("empty body status=%d body=%s, want empty-backup 400", emptyResponse.Code, emptyResponse.Body.String())
			}
		})
	}
}

func TestImportV1Config_rolls_back_when_certificate_materialization_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old_v1', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old_v1'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if oldRules != 1 {
		t.Fatalf("old rule count=%d, want 1", oldRules)
	}
}

// TestImportV1Config_multiDomainServerNameJoinsWithoutEmptySegments 钉 v1
// server_name 的拆分口径：nginx 导出形态以空格分隔、也见「逗号+空格」混合
// 形态——统一拆分后不得把逗号残留在段内落库出空段（"a.test,, b.test"）。
func TestImportV1Config_multiDomainServerNameJoinsWithoutEmptySegments(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"multi-domain","protocol":true,"listen":18443,"server_name":"a.test, b.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var domain string
	if err := db.DB.QueryRow(`SELECT domain FROM lb_rules WHERE name='multi-domain'`).Scan(&domain); err != nil {
		t.Fatalf("query imported rule: %v", err)
	}
	if domain != "a.test, b.test" {
		t.Fatalf("domain=%q, want %q（逐段剥逗号后拼接，无空段）", domain, "a.test, b.test")
	}
}

func TestImportV1Config_cleansDisappearedRuleMetricsAndLogs(t *testing.T) {
	// Given an old rule with metrics and log artifacts, plus unrelated global metrics.
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_stale_artifacts','old-rule','http',8080,1)`); err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []any{"lb_stale_artifacts", nil} {
		if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history
			(rule_id,timestamp,requests_total,requests_2xx,requests_3xx,requests_4xx,requests_5xx,bytes_in,bytes_out)
			VALUES (?,datetime('now'),1,1,0,0,0,10,20)`, ruleID); err != nil {
			t.Fatalf("seed metrics %v: %v", ruleID, err)
		}
	}
	oldRuleCleanup, oldCertCleanup := removeImportRuleLogFiles, removeImportCertJobLogFiles
	var ruleLogIDs, certLogIDs []string
	removeImportRuleLogFiles = func(ruleID string) error {
		ruleLogIDs = append(ruleLogIDs, ruleID)
		return nil
	}
	removeImportCertJobLogFiles = func(ruleID string) error {
		certLogIDs = append(certLogIDs, ruleID)
		return nil
	}
	t.Cleanup(func() {
		removeImportRuleLogFiles, removeImportCertJobLogFiles = oldRuleCleanup, oldCertCleanup
	})
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)

	// When replacing the old rules through a V1 import.
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	// 提交后产物清理已异步执行（响应不等清理）：等它结束再断言产物与调用集。
	waitImportCleanup()

	// Then only the disappeared rule's artifacts are removed.
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var staleMetrics, globalMetrics int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_history WHERE rule_id='lb_stale_artifacts'`).Scan(&staleMetrics); err != nil {
		t.Fatal(err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_history WHERE rule_id IS NULL`).Scan(&globalMetrics); err != nil {
		t.Fatal(err)
	}
	if staleMetrics != 0 || globalMetrics != 1 {
		t.Fatalf("metrics stale=%d global=%d, want 0/1", staleMetrics, globalMetrics)
	}
	if len(ruleLogIDs) != 1 || ruleLogIDs[0] != "lb_stale_artifacts" || len(certLogIDs) != 1 || certLogIDs[0] != "lb_stale_artifacts" {
		t.Fatalf("log cleanup rule=%v cert=%v, want old rule exactly once", ruleLogIDs, certLogIDs)
	}
}

func TestImportV1Config_removes_orphaned_path_rules(t *testing.T) {
	// Given：导入前存在规则及其路径规则，v1 导入覆盖后不得留下孤儿 path_rules
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enabled) VALUES ('lb_orphan_v1', 'old-rule', 'http', 'orphan.example.test', 8080, 1);
		INSERT INTO path_rules (rule_id, sort_order, match_type, path) VALUES ('lb_orphan_v1', 0, 'prefix', '/legacy/')`); err != nil {
		t.Fatalf("seed rule with path rules: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var pathRuleCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM path_rules").Scan(&pathRuleCount); err != nil {
		t.Fatalf("count path_rules: %v", err)
	}
	if pathRuleCount != 0 {
		t.Fatalf("orphaned path_rules count=%d, want 0", pathRuleCount)
	}
}

func TestImportV1Config_clears_security_policy_bindings(t *testing.T) {
	// Given：绑定表对 rule_caddy_id 无外键级联，v1 覆盖导入后
	// 不得残留指向已删除规则的悬挂绑定。
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enabled) VALUES ('lb_stale_binding', 'old-rule', 'http', 'stale.example.test', 8080, 1);
		INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_stale_binding', 1)`); err != nil {
		t.Fatalf("seed rule with policy binding: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var bindings int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings").Scan(&bindings); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if bindings != 0 {
		t.Fatalf("security_policy_bindings count=%d, want 0", bindings)
	}
}

func TestValidateConfigImport_rejects_disabled_v1_rule_with_out_of_range_port(t *testing.T) {
	tests := []struct {
		name       string
		listenPort int
		upstream   int
	}{
		{name: "zero listen port", listenPort: 0, upstream: 9000},
		{name: "listen port above maximum", listenPort: 65536, upstream: 9000},
		{name: "zero upstream port", listenPort: 8080, upstream: 0},
		{name: "upstream port above maximum", listenPort: 8080, upstream: 65536},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			backup := fmt.Sprintf(`{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"disabled","protocol":true,"listen":%d,"server_name":"disabled.example.test","status":false,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":%d,"weight":100}}]}}`, test.listenPort, test.upstream)
			router := gin.New()
			router.POST("/config/validate", h.ValidateConfigImport)
			request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			var envelope struct {
				Data importValidateResponse `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode validation response: %v", err)
			}
			if envelope.Data.Valid {
				t.Fatalf("validation accepted invalid disabled rule: %s", response.Body.String())
			}
		})
	}
}

func TestImportV1Config_skips_empty_domain_HTTP_rules(t *testing.T) {
	// Given：v1 备份中一条 HTTP 规则域名为空（无法创建的死规则），一条 HTTP 规则正常，一条 TCP 规则无域名
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"empty-domain","protocol":true,"listen":8441,"server_name":"","status":true,"upstream_list":[1]}},
			{"pk":2,"fields":{"proxy_name":"valid-rule","protocol":true,"listen":8442,"server_name":"valid.example.test","status":true,"upstream_list":[2]}},
			{"pk":3,"fields":{"proxy_name":"tcp-rule","protocol":false,"listen":8443,"server_name":"","status":true,"upstream_list":[3]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}},
			{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9002,"weight":100}},
			{"pk":3,"fields":{"status":true,"address":"127.0.0.1","port":9003,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：空域名 HTTP 规则跳过并告警，其余规则正常导入
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "域名为空") {
		t.Fatalf("import response missing skip warning: %s", response.Body.String())
	}
	var emptyDomainRules, importedRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name='empty-domain'").Scan(&emptyDomainRules); err != nil {
		t.Fatalf("count skipped rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name IN ('valid-rule','tcp-rule')").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if emptyDomainRules != 0 || importedRules != 2 {
		t.Fatalf("rules after import: empty-domain=%d imported=%d, want 0 skipped and 2 imported", emptyDomainRules, importedRules)
	}
}

func TestImportV1Config_requeues_original_non_terminal_jobs_after_rollback(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_requeue_v1','old-rule','http','old.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_requeue_v1','old.example.test','creating_order',999999)`); err != nil {
		t.Fatalf("seed original non-terminal job: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	block := make(chan struct{})
	acmeMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	t.Cleanup(func() { close(block); services.GetCAQueueManager().PauseAndDrain(); acmeMock.Close() })
	if _, err := db.DB.Exec("UPDATE ca_providers SET provider='letsencrypt', directory_url=? WHERE enabled=1", acmeMock.URL); err != nil {
		t.Fatalf("redirect ACME directory: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='acme@example.test' WHERE id=1"); err != nil {
		t.Fatalf("set ACME email: %v", err)
	}

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import unexpectedly succeeded: %s", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_requeue_v1'").Scan(&status); err != nil {
		t.Fatalf("read recovered original job: %v", err)
	}
	if status != "queued" && status != "creating_account" {
		t.Fatalf("recovered original job status=%q, want queued or creating_account (pipeline active)", status)
	}
}

func TestImportV1Config_reports_partial_failure_when_certificate_job_recovery_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：message 与 warnings 必须来自 importPartialSuccess* 单源（与 v2 出口
	// 同措辞）——「（部分完成）：」是主文案口径，「数据库已提交，但…」是 warning 口径。
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "配置已导入（部分完成）：证书任务恢复失败: requeue failed") ||
		!strings.Contains(response.Body.String(), "数据库已提交，但证书任务恢复失败: requeue failed") ||
		!strings.Contains(response.Body.String(), `"partial":true`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestImportV1Config_joins_import_and_certificate_job_recovery_failures(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	oldRequeue := requeueNonTerminalCertJobs
	requeueNonTerminalCertJobs = func() error { return errors.New("requeue failed") }
	t.Cleanup(func() { requeueNonTerminalCertJobs = oldRequeue })
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"bad","protocol":true,"listen":8443,"server_name":"bad.example","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "invalid certificate") || !strings.Contains(response.Body.String(), "requeue failed") {
		t.Fatalf("status=%d body=%s, want joined failures", response.Code, response.Body.String())
	}
}

func TestImportV1Config_restores_partial_certificate_materialization(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_old_v1_partial', 'old-rule', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	validCert, validKey, err := generateTestCert("v1-partial.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("generate valid certificate: %v", err)
	}
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"first-rule","protocol":true,"listen":8443,"server_name":"v1-partial.example.test","ssl":true,"ssl_cert":` + stringMustMarshal(t, validCert) + `,"ssl_key":` + stringMustMarshal(t, validKey) + `,"status":true,"upstream_list":[1]}},
			{"pk":2,"fields":{"proxy_name":"second-rule","protocol":true,"listen":9443,"server_name":"v1-invalid.example.test","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[2]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}},
			{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", harness.handler.ImportV1Config)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code == http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var oldRules, importedRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_old_v1_partial'").Scan(&oldRules); err != nil {
		t.Fatalf("count old rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id<>'lb_old_v1_partial'").Scan(&importedRules); err != nil {
		t.Fatalf("count imported rules: %v", err)
	}
	if oldRules != 1 || importedRules != 0 {
		t.Fatalf("rules after failed import: old=%d imported=%d", oldRules, importedRules)
	}
	entries, err := os.ReadDir(harness.certDir)
	if err != nil {
		t.Fatalf("read certificate directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("certificate directory contains %d files after rollback, want none", len(entries))
	}
	// loads=0：同字节短路（2026-09-25 审计真实性改造）——restore 目标=快照=
	// 当前运行配置（导入失败于证书验证、未触达 /load），恢复为成功空操作。
	if harness.loadCalls() != 0 || harness.currentConfig() != `{"marker":"before-import"}` {
		t.Fatalf("Caddy loads=%d config=%s, want 恢复为空操作（同字节短路）且运行态保持 before-import", harness.loadCalls(), harness.currentConfig())
	}
}

func TestImportV1Config_reports_import_and_runtime_restore_failures(t *testing.T) {
	// Given

	harness := newImportRollbackHarness(t)
	harness.failRestore()
	backup := `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"bad-cert","protocol":true,"listen":8443,"server_name":"bad.example","ssl":true,"ssl_cert":"invalid-cert","ssl_key":"invalid-key","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", harness.handler.ImportV1Config)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusInternalServerError || !strings.Contains(body, "invalid certificate") || !strings.Contains(body, "restore rejected") {
		t.Fatalf("status=%d body=%s, want joined import and restore errors", response.Code, body)
	}
	if strings.Contains(body, "已回滚") {
		t.Fatalf("response falsely claims rollback success: %s", body)
	}
}

func TestRestoreImportRuntime_reports_certificate_restore_failure(t *testing.T) {
	// Given
	harness := newImportRollbackHarness(t)
	snapshot := importRuntimeSnapshot{
		caddyConfig: map[string]interface{}{"marker": "before-import"},
		certFiles: services.CertFilesSnapshot{
			"../invalid": {},
		},
	}

	// When
	err := harness.handler.restoreImportRuntime(snapshot)

	// Then
	if err == nil || !strings.Contains(err.Error(), "非法的规则编号") {
		t.Fatalf("restore error=%v, want certificate restore failure", err)
	}
}

func stringMustMarshal(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal string: %v", err)
	}
	return string(data)
}

// 预览 has_waf_files 必须纳入威胁库名单条目——RDB 文件化后存在「仅威胁
// .iplist、无 CRS/xdb」的合法 lbbak，此前预览提示「不含规则库文件」而实际会
// 落盘名单文件（文案与真实能力不符）。

func a3CanonicalThreatURL(t *testing.T, source string) string {
	t.Helper()
	seed, ok := db.CanonicalThreatSource(source)
	if !ok {
		t.Fatalf("未登记的内置威胁源 %q", source)
	}
	return seed.URL
}

func TestPreviewHasWafFilesIncludesThreatOnlyLbbak(t *testing.T) {
	h := newBackupTestHandlers(t)
	overrideTestWafPaths(t)
	restore := services.OverrideThreatWafDirForTest(t.TempDir())
	t.Cleanup(restore)

	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_threat_sources": {{"name": "ustc", "display_name": "USTC", "url": a3CanonicalThreatURL(t, "ustc"), "format": "plain", "update_enabled": 1, "apply_enabled": 1}},
	}, Config: nil, Sections: nil, EmptyConfigIfNil: true})

	bundle := &services.WafFileBundle{ThreatFiles: []models.ThreatFileEntry{{Name: "ustc"}}}
	payload, err := buildLbbakPayloadWithThreatIplists([]byte(backup), bundle, map[string][]byte{"ustc": []byte("203.0.113.9\n")})
	if err != nil {
		t.Fatalf("build lbbak: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/validate", h.ValidateConfigImport)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import/validate", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/octet-stream")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data struct {
			Valid       bool `json:"valid"`
			HasWafFiles bool `json:"has_waf_files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode preview: %v body=%s", err, rec.Body.String())
	}
	if !response.Data.Valid {
		t.Fatalf("preview invalid: %s", rec.Body.String())
	}
	if !response.Data.HasWafFiles {
		t.Fatalf("has_waf_files=false, want true（仅含威胁库名单条目的合法 lbbak）: %s", rec.Body.String())
	}
}

// Given 拒绝路径（导入在证书校验阶段失败，运行配置未变）与运行时快照同字节。
// When restoreImportRuntime 回弹快照。
// Then 同字节短路（errSameConfig）视为恢复成功——不得把无副作用的空操作
// 变成「恢复运行配置失败」的假信号（响应/审计/失败横幅污染）。
func TestRestoreImportRuntime_sameConfigIsSuccessNoop(t *testing.T) {
	harness := newImportRollbackHarness(t)
	snapshot := importRuntimeSnapshot{caddyConfig: map[string]interface{}{"marker": "before-import"}}
	if err := harness.handler.restoreImportRuntime(snapshot); err != nil {
		t.Fatalf("同字节回弹应成功（同字节短路），got %v", err)
	}
	if harness.loadCalls() != 0 {
		t.Fatalf("同字节回弹不应触发 /load, got %d", harness.loadCalls())
	}
	if got := harness.currentConfig(); got != `{"marker":"before-import"}` {
		t.Fatalf("运行配置被改写: %s", got)
	}
}

// 413 文案必须从 maxConfigImportBytes 派生——测试把限额改小后仍称 128MB
// 属「断言照过、文案失真」，巡检会按错误上限排障。
func TestConfigImportLimitMessage_derivesFromConfiguredLimit(t *testing.T) {
	old := maxConfigImportBytes
	t.Cleanup(func() { maxConfigImportBytes = old })

	maxConfigImportBytes = 1 << 20
	if got, want := configImportLimitMessage(), "备份文件不能超过 1MB"; got != want {
		t.Fatalf("message=%q, want %q", got, want)
	}
	maxConfigImportBytes = 256 << 20
	if got, want := configImportLimitMessage(), "备份文件不能超过 256MB"; got != want {
		t.Fatalf("message=%q, want %q", got, want)
	}
	maxConfigImportBytes = 128 << 20
	if got, want := configImportLimitMessage(), "备份文件不能超过 128MB"; got != want {
		t.Fatalf("message=%q, want %q（生产默认值）", got, want)
	}
}

func TestImportV1ConfigSurvivesRequestCancellationAfterSessionStarts(t *testing.T) {
	h := newBackupTestHandlers(t)
	backup := `{"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":18443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}}`
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hookCalled := false
	configImportAfterSessionHook = func() {
		hookCalled = true
		cancel()
	}
	t.Cleanup(func() { configImportAfterSessionHook = nil })
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if !hookCalled {
		t.Fatal("v1 import must expose the same after-session cancellation point as v2")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want import to finish on session context", response.Code, response.Body.String())
	}
}
