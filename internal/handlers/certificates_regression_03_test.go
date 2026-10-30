package handlers

// （签发未入队不得伪装成功）。

import (
	"database/sql"
	"encoding/json"
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

// Given 一条 30 天 + 1 分钟到期的任务（阈值 30 天）。
// When 任务列表消费到期状态。
// Then 必须与 certinfo 列表同口径按天粒度判 expiring（修复前按完整时长比较 → valid）。
func TestListCertJobs_statusUsesSharedDayGranularity(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/jobs", h.ListCertJobs)
	if _, err := db.DB.Exec("UPDATE global_config SET cert_expiry_days=30 WHERE id=1"); err != nil {
		t.Fatalf("seed threshold: %v", err)
	}
	// 基准取 UTC 并按 UTC 格式化：SQLite datetime 文本经 connection 解析为 UTC，
	// 与截断口径测试同基准（本地格式化会引入 8 小时偏移）。
	now := time.Now().UTC()
	cases := []struct {
		name       string
		offset     time.Duration
		wantStatus string
	}{
		{name: "threshold+1m", offset: 30*24*time.Hour + time.Minute, wantStatus: "expiring"},
		// 31 天 + 1 小时：保证截断天数 > 30（恰好 31 天会被执行耗时压到 30）
		{name: "threshold+1d", offset: 31*24*time.Hour + time.Hour, wantStatus: "valid"},
		{name: "expired-1h", offset: -time.Hour, wantStatus: "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expires := now.Add(tc.offset)
			if _, err := db.DB.Exec(`INSERT OR REPLACE INTO cert_jobs (id,rule_id,domain,status,expires_at) VALUES (9201,'lb_status_probe','probe.test','issued',?)`,
				expires.Format("2006-01-02 15:04:05")); err != nil {
				t.Fatalf("seed job: %v", err)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/jobs?page=1&page_size=50", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			idx := strings.Index(body, `"rule_id":"lb_status_probe"`)
			if idx < 0 {
				t.Fatalf("seeded job missing from response")
			}
			if !strings.Contains(body[idx:], `"certificate_status":"`+tc.wantStatus+`"`) {
				t.Fatalf("offset=%v: certificate_status != %q (body=%s)", tc.offset, tc.wantStatus, body)
			}
		})
	}
}

// Given 一条 DNS 配置与一条引用它的规则尚不存在引用。
// When 删除配置的「引用查询 → DELETE」窗口内并发提交 UpdateRule 绑定该配置。
// Then 删除全程持 caddyOpMu（窗口内不可再取锁），并发绑定只能在删除完成后
// 进入校验并被拒（非 200）——引用检查与删除对规则写路径原子。
func TestDeleteCertificateConfig_holds_caddyOpMuAcrossReferenceCheckAndDelete(t *testing.T) {
	h := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'probe','dnspod','{}',1)`); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_tls,tls_source,acme_config_id) VALUES ('lb_delete_probe','probe','','http','probe.example.test',8080,'weighted_round_robin',1,0,'manual',0)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE("/configs/:id", h.DeleteCertificateConfig)
	router.PUT("/rules/:caddy_id", h.UpdateRule)

	oldHook := deleteCertificateConfigPreDeleteHook
	t.Cleanup(func() { deleteCertificateConfigPreDeleteHook = oldHook })
	hookRan := false
	earlyUpdate := make(chan int, 1)
	deleteCertificateConfigPreDeleteHook = func() {
		hookRan = true
		// 引用查询已完成、DELETE 尚未执行：caddyOpMu 必须仍被删除路径持有
		if h.caddyOpMu.TryLock() {
			h.caddyOpMu.Unlock()
			t.Error("删除路径在引用查询→DELETE 窗口未持 caddyOpMu")
		}
		go func() {
			body := `{"name":"probe","protocol":"http","domain":"probe.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":1}`
			request := httptest.NewRequest(http.MethodPut, "/rules/lb_delete_probe", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			earlyUpdate <- recorder.Code
		}()
		select {
		case <-earlyUpdate:
			t.Error("并发 UpdateRule 在删除临界区内完成")
		case <-time.After(150 * time.Millisecond):
		}
	}

	deleteResponse := httptest.NewRecorder()
	router.ServeHTTP(deleteResponse, httptest.NewRequest(http.MethodDelete, "/configs/1", nil))
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", deleteResponse.Code, deleteResponse.Body.String())
	}
	if !hookRan {
		t.Fatal("pre-delete 钩子未执行")
	}
	select {
	case code := <-earlyUpdate:
		if code == http.StatusOK {
			t.Fatalf("配置已删除后 UpdateRule 仍绑定成功（status=%d）——悬空引用", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UpdateRule 未在删除完成后结束")
	}
	var configs int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM certificate_configs WHERE id=1").Scan(&configs); err != nil {
		t.Fatal(err)
	}
	if configs != 0 {
		t.Fatalf("config 仍存在，删除未生效")
	}
}

// 证书清单按 (rule_id,domain) 聚合；同域不同规则不得折叠，
// 较新的 disabled 行不得遮蔽另一规则已签发证书。
func TestListCertificates_groupsByRuleAndDomain(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at) VALUES
		(1,'lb_issued','shared.example.test','issued',datetime('now','+30 days')),
		(2,'lb_disabled','shared.example.test','disabled',NULL),
		(3,'lb_other','other.example.test','issued',datetime('now','+60 days'))`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/certificates", h.ListCertificates)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			Certificates []struct {
				ID     int    `json:"id"`
				RuleID string `json:"rule_id"`
				Domain string `json:"domain"`
				Status string `json:"status"`
			} `json:"certificates"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Total != 3 || len(body.Data.Certificates) != 3 {
		t.Fatalf("total=%d len=%d body=%s, want three rule/domain rows", body.Data.Total, len(body.Data.Certificates), response.Body.String())
	}
	seen := map[string]string{}
	for _, cert := range body.Data.Certificates {
		seen[cert.RuleID] = cert.Status
	}
	if seen["lb_issued"] != "issued" || seen["lb_disabled"] != "disabled" || seen["lb_other"] != "issued" {
		t.Fatalf("rows=%v, want issued+disabled same-domain rows and unrelated row", seen)
	}
}

// 禁用规则的历史引用与零引用配置仍可正常禁用。
func TestUpdateCertificateConfig_disableReferenceGuard(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ruleEnabled int
		enableTLS   int
		seedRule    bool
		wantStatus  int
		wantEnabled bool
	}{
		{name: "enabled ACME reference", ruleEnabled: 1, enableTLS: 1, seedRule: true, wantStatus: http.StatusConflict, wantEnabled: true},
		{name: "disabled rule reference", ruleEnabled: 0, enableTLS: 1, seedRule: true, wantStatus: http.StatusOK, wantEnabled: false},
		// TLS 关闭的引用规则不消费 ACME 证书（签发/续期只服务 enable_tls=1）——
		// 禁用守卫点名它属误报，必须放行。
		{name: "TLS-off enabled rule reference", ruleEnabled: 1, enableTLS: 0, seedRule: true, wantStatus: http.StatusOK, wantEnabled: false},
		{name: "unreferenced", wantStatus: http.StatusOK, wantEnabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRuleFeatureTestHandlers(t)
			if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'guard','dnspod','{"mode":"tencent","secret_id":"id","secret_key":"key"}',1)`); err != nil {
				t.Fatalf("seed config: %v", err)
			}
			if tc.seedRule {
				if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_tls,tls_source,acme_config_id) VALUES ('lb_dns_guard','guard','','http','guard.example.test',8443,'weighted_round_robin',?,?,'acme_dns',1)`, tc.ruleEnabled, tc.enableTLS); err != nil {
					t.Fatalf("seed rule: %v", err)
				}
			}
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.PUT("/configs/:id", h.UpdateCertificateConfig)
			request := httptest.NewRequest(http.MethodPut, "/configs/1", strings.NewReader(`{"enabled":false}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			var enabled bool
			if err := db.DB.QueryRow(`SELECT enabled FROM certificate_configs WHERE id=1`).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			if enabled != tc.wantEnabled {
				t.Fatalf("enabled=%v, want %v", enabled, tc.wantEnabled)
			}
		})
	}
}

func TestUpdateCertificateConfig_serializesWithRuleWrites(t *testing.T) {
	h := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'lock','dnspod','{"mode":"tencent","secret_id":"id","secret_key":"key"}',1)`); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/configs/:id", h.UpdateCertificateConfig)
	request := httptest.NewRequest(http.MethodPut, "/configs/1", strings.NewReader(`{"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")

	h.caddyOpMu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		done <- response
	}()
	select {
	case response := <-done:
		h.caddyOpMu.Unlock()
		t.Fatalf("持 caddyOpMu 时更新仍完成：status=%d body=%s", response.Code, response.Body.String())
	case <-time.After(150 * time.Millisecond):
	}
	h.caddyOpMu.Unlock()
	select {
	case response := <-done:
		if response.Code != http.StatusOK {
			t.Fatalf("解锁后 status=%d body=%s, want 200", response.Code, response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("解锁后更新未完成")
	}
}

// Given GET 掩码形态下的三种回传。
// When 判定是否整体未改并合并。
// Then 仅「全部非空值均为哨兵且无空串」判整体未改；含空串走逐字段合并并
// 保留空串（显式清空语义），混合真实值同样走合并。
func TestMaskedDNSCredentials_threeShapes(t *testing.T) {
	stored := map[string]string{"app_id": "stored-id", "app_token": "stored-token"}

	// 形状 1：空字段 + 其余哨兵 → 不是整体掩码；空串保留（清空 app_id），哨兵取库值
	submitted := map[string]string{"app_id": "", "app_token": maskedDNSCredentialsSentinel}
	if isMaskedDNSCredentials(submitted) {
		t.Fatal("含空串的回传不得判整体未改（会吞掉显式清空）")
	}
	merged, err := mergeMaskedDNSCredentials(submitted, stored, true)
	if err != nil {
		t.Fatalf("merge shape1: %v", err)
	}
	if merged["app_id"] != "" || merged["app_token"] != "stored-token" {
		t.Fatalf("shape1 merged=%v, want app_id 空串保留 + app_token 取库值", merged)
	}

	// 形状 2：全空串 → 不是整体掩码；合并后全空串
	empty := map[string]string{"app_id": "", "app_token": ""}
	if isMaskedDNSCredentials(empty) {
		t.Fatal("全空串不得判整体未改（显式清空语义）")
	}
	merged, err = mergeMaskedDNSCredentials(empty, stored, true)
	if err != nil {
		t.Fatalf("merge shape2: %v", err)
	}
	if merged["app_id"] != "" || merged["app_token"] != "" {
		t.Fatalf("shape2 merged=%v, want 全空串保留", merged)
	}

	// 形状 3：混合真实值 → 真实值保留，哨兵字段取库值
	mixed := map[string]string{"app_id": "new-id", "app_token": maskedDNSCredentialsSentinel}
	if isMaskedDNSCredentials(mixed) {
		t.Fatal("含真实值不得判整体未改")
	}
	merged, err = mergeMaskedDNSCredentials(mixed, stored, true)
	if err != nil {
		t.Fatalf("merge shape3: %v", err)
	}
	if merged["app_id"] != "new-id" || merged["app_token"] != "stored-token" {
		t.Fatalf("shape3 merged=%v, want new-id + 库值 token", merged)
	}

	// 回归：全哨兵（GET 原样回传）仍判整体未改
	allMasked := map[string]string{"app_id": maskedDNSCredentialsSentinel, "app_token": maskedDNSCredentialsSentinel}
	if !isMaskedDNSCredentials(allMasked) {
		t.Fatal("全哨兵回传应判整体未改（编辑表单原样回传）")
	}
}

// Given 库中 tencent 凭证 + 前端回传「secret_id 空串 + secret_key 哨兵」。
// When PUT 更新配置。
// Then 不得静默返回 200「未修改」吞掉清空意图——走合并后凭证校验失败（400），库值不变。
func TestUpdateCertificateConfig_emptyFieldWithMaskNotSwallowed(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCertConfigRouter(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/configs", strings.NewReader(
		`{"name":"cfg","dns_provider":"dnspod","dns_credentials":{"mode":"tencent","secret_id":"id1","secret_key":"key1"},"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create config: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, "/certificates/configs/1", strings.NewReader(
		`{"dns_credentials":{"secret_id":"","secret_key":"***"}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code == http.StatusOK && strings.Contains(recorder.Body.String(), "unchanged") {
		t.Fatalf("含空串回传被吞为「未修改」（body=%s）——显式清空语义丢失", recorder.Body.String())
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（合并后凭证校验失败）", recorder.Code, recorder.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT dns_credentials FROM certificate_configs WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "id1") || !strings.Contains(stored, "key1") || strings.Contains(stored, "***") {
		t.Fatalf("stored=%s, want 原凭证保持不变且无掩码串", stored)
	}
}

// 签发未入队不得回 200「已创建 0 个任务」 ——

func seedIssueRule(t *testing.T, caddyID, domain string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES (?,?,'http',?,8443,1,1,'acme_dns')`, caddyID, caddyID, domain); err != nil {
		t.Fatalf("seed rule %s: %v", caddyID, err)
	}
}

func initIssueQueue(t *testing.T) *services.CAQueueManager {
	t.Helper()
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	return services.GetCAQueueManager()
}

// Given 证书签发队列已暂停。
// When 定向签发。
// Then 409 并点名「队列已暂停」，审计结果 skipped（不得 200 queued=0 伪装成功）。
func TestIssueCertificate_pausedQueueReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_paused_probe", "paused.example")
	qm.PauseAndDrain()
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_paused_probe"}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "暂停") {
		t.Fatalf("body=%s, want 点名「队列已暂停」", response.Body.String())
	}
	assertLatestCertificateAudit(t, "规则：lb_paused_probe", "已跳过")
}

// Given 规则处于删除/迁移屏障（blockedRules）。
// When 定向签发。
// Then 409 并点名屏障原因，审计结果 skipped。
func TestIssueCertificate_blockedRuleReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_blocked_probe", "blocked.example")
	token := qm.BlockJobsForRule("lb_blocked_probe")
	t.Cleanup(func() { qm.UnblockJobsForRule("lb_blocked_probe", token) })
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_blocked_probe"}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "屏障") {
		t.Fatalf("body=%s, want 点名规则屏障原因", response.Body.String())
	}
	assertLatestCertificateAudit(t, "规则：lb_blocked_probe", "已跳过")
}

// Given 既有任务仍在本队列在途执行（qm.IsJobActive），状态 creating_order 已超
// 重试守卫窗口（不会被 429 拦截）。
// When 再次定向签发。
// Then 200 + queued=0 + in_flight 归因（在途保留 200，但不得声称新建任务）。
func TestIssueCertificate_inFlightJobReturns200WithZeroQueued(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_inflight_probe", "inflight.example")
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at)
		VALUES ('lb_inflight_probe','inflight.example','creating_order','active',datetime('now','-10 minutes'))`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	qm.MarkJobRunningForTest("lb_inflight_probe", int(jobID))
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_inflight_probe"}`)))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（在途保留）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":0`) || !strings.Contains(response.Body.String(), `"in_flight":true`) {
		t.Fatalf("body=%s, want queued=0 + in_flight=true", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "执行中") {
		t.Fatalf("body=%s, want 在途文案", response.Body.String())
	}
	assertLatestCertificateAudit(t, "规则：lb_inflight_probe", "已跳过")
}

// Given 批量签发全部目标都在途（无冷却、无失败）。
// When all=true。
// Then 409（未创建任何任务不得 200），响应与审计给出跳过归因。
func TestIssueCertificate_batchAllSkippedReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_r78_batch", "r78-batch.example")
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at)
		VALUES ('lb_r78_batch','r78-batch.example','creating_order','active',datetime('now','-10 minutes'))`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, _ := result.LastInsertId()
	qm.MarkJobRunningForTest("lb_r78_batch", int(jobID))
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（全部跳过不得 200）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":0`) || !strings.Contains(response.Body.String(), `"skipped_in_flight":1`) {
		t.Fatalf("body=%s, want queued=0 + skipped_in_flight=1", response.Body.String())
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "已跳过")
}

// Given 任务的 CA 限流退避窗口未到期（waiting_ca + ca_available_after=+1h）。
// When 从规则列表「重新签发」（定向触发）。
// Then 与任务重试同一契约：429 + 剩余时长，任务状态与退避窗口原样保留；
// force=true 显式越过并留「手动越过 CA 冷却」审计。
func TestIssueCertificate_waitingCACoolingRequiresForce(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_ca_cooling", "ca-cooling.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,renewal_attempts,ca_available_after,updated_at)
		VALUES ('lb_ca_cooling','ca-cooling.example','waiting_ca',2,datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	// When：未带 force
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_ca_cooling"}`)))

	// Then：429 + 剩余时长；冷却窗口与重试预算均不得被触碰
	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "冷却未到期") {
		t.Fatalf("status=%d body=%s, want 429 冷却未到期", response.Code, response.Body.String())
	}
	var status string
	var attempts int
	var availableAfter sql.NullTime
	if err := db.DB.QueryRow("SELECT status, COALESCE(renewal_attempts,0), ca_available_after FROM cert_jobs WHERE rule_id=?", "lb_ca_cooling").
		Scan(&status, &attempts, &availableAfter); err != nil {
		t.Fatalf("read cooling job: %v", err)
	}
	if status != "waiting_ca" || attempts != 2 || !availableAfter.Valid {
		t.Fatalf("status=%q attempts=%d window=%v, want waiting_ca/2/未清空（不得静默重排）", status, attempts, availableAfter)
	}
	assertLatestCertificateAudit(t, "规则：lb_ca_cooling", "重试被阻止")

	// When：force=true（用户确认越过）
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue?force=true", strings.NewReader(`{"caddy_id":"lb_ca_cooling"}`)))

	// Then：受理 + 越过冷却留痕；真实队列执行（测试环境 CA 预检必败：
	// ACME email 未配置）按 B2 失败语义统一重新落 failed 并写入**新的**
	// 退避窗口——「越过冷却重排」与「重排后的真实失败」两个事实都要可见。
	if response.Code != http.StatusOK {
		t.Fatalf("force issue status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='触发签发' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("read issue audit: %v", err)
	}
	if !strings.Contains(detail, "手动越过 CA 冷却") {
		t.Fatalf("audit detail=%q, want 手动越过 CA 冷却留痕", detail)
	}
	// 轮询等待异步执行收敛（失败终态 + 次数 +1）——轮询窗口内未收敛按失败论。
	var refreshedStatus string
	var refreshed sql.NullTime
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := db.DB.QueryRow("SELECT status, COALESCE(renewal_attempts,0), ca_available_after FROM cert_jobs WHERE rule_id=?", "lb_ca_cooling").
			Scan(&refreshedStatus, &attempts, &refreshed); err != nil {
			t.Fatalf("read refreshed job: %v", err)
		}
		if refreshedStatus == "failed" && attempts >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status=%q attempts=%d, want force 重排后重新失败（failed/1+，B2 失败语义统一：真实执行失败写新退避窗口）", refreshedStatus, attempts)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !refreshed.Valid {
		t.Fatalf("ca_available_after=%v, want 非空（重新失败必须写新退避窗口，1h 阶梯第一档）", refreshed)
	}
}

// Given force 定向/批量签发已迁移冷却任务（changed=true），随后 provider 解析失败。
// When 签发入口返回 500。
// Then 两种失败审计都必须保留「手动越过 CA 冷却」；只有 changed=false 才不得记。
func TestIssueCertificate_forceFailureAuditKeepsCooldownOverride(t *testing.T) {
	for _, tc := range []struct {
		name string
		all  bool
	}{
		{name: "targeted"},
		{name: "batch", all: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			initIssueQueue(t)
			ruleID := "lb_force_failure_" + tc.name
			domain := "force-failure-" + tc.name + ".example"
			seedIssueRule(t, ruleID, domain)
			if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
				VALUES (?,?,'waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`, ruleID, domain); err != nil {
				t.Fatalf("seed cooling job: %v", err)
			}
			oldCreate := createOrRequeueCertJob
			createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, bool, error) {
				return 1, true, fmt.Errorf("provider resolution failed")
			}
			t.Cleanup(func() { createOrRequeueCertJob = oldCreate })
			router := gin.New()
			router.POST("/certificates/issue", h.IssueCertificate)
			body := `{"caddy_id":"` + ruleID + `"}`
			if tc.all {
				body = `{"all":true}`
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/certificates/issue?force=true", strings.NewReader(body)))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want 500 provider resolution failure", recorder.Code, recorder.Body.String())
			}
			var detail string
			if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='触发签发' AND resource='证书' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
				t.Fatalf("read issue failure audit: %v", err)
			}
			if !strings.Contains(detail, "手动越过 CA 冷却") {
				t.Fatalf("audit detail=%q, want 手动越过 CA 冷却（changed=true,error）", detail)
			}
		})
	}
}

// Given 批量签发中唯一目标处于 CA 限流退避窗口。
// When all=true（未带 force）。
// Then 409 且如实给出 skipped_waiting_ca 计数，任务不被重排。
func TestIssueCertificate_batchSkipsWaitingCACooling(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_ca_batch", "ca-batch.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
		VALUES ('lb_ca_batch','ca-batch.example','waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed batch cooling job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（全部因 CA 冷却跳过）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"skipped_waiting_ca":1`) || !strings.Contains(response.Body.String(), "冷却跳过 1 个") {
		t.Fatalf("body=%s, want skipped_waiting_ca=1 + 冷却跳过文案", response.Body.String())
	}
	var status string
	var availableAfter sql.NullTime
	if err := db.DB.QueryRow("SELECT status, ca_available_after FROM cert_jobs WHERE rule_id=?", "lb_ca_batch").Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read batch job: %v", err)
	}
	if status != "waiting_ca" || !availableAfter.Valid {
		t.Fatalf("status=%q window=%v, want waiting_ca 且退避窗口保留", status, availableAfter)
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "已跳过")
}

// Given 批量目标中一条处于 CA 冷却（force 越过）、一条域名非法（必然失败）。
// When all=true 且 force=true。
// Then 200 partial，且审计留痕「手动越过 CA 冷却」——批量各出口都必须携带
// 越权痕迹，不能只存在于全成功出口。
func TestIssueCertificate_batchForcePartialKeepsOverrideAudit(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_force_partial", "force-partial.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
		VALUES ('lb_force_partial','force-partial.example','waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	seedIssueRule(t, "lb_force_bad_domain", "bad domain.example")
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue?force=true", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 partial", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":1`) || !strings.Contains(response.Body.String(), `"failed":1`) {
		t.Fatalf("body=%s, want queued=1 + failed=1（partial）", response.Body.String())
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "手动越过 CA 冷却")
}

// Given 规则仍启用但证书任务行已 disabled（历史残留/脏快照）。
// When 批量 all=true / 定向重新签发。
// Then 批量按「已退役任务」单列（不得混入冷却计数），定向 409 给出可执行指引。
func TestIssueCertificate_disabledJobClassifiedAsRetired(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_retired", "retired.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
		VALUES ('lb_retired','retired.example','disabled',datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed retired job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	batch := httptest.NewRecorder()
	router.ServeHTTP(batch, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))
	if batch.Code != http.StatusConflict {
		t.Fatalf("batch status=%d body=%s, want 409（全部跳过）", batch.Code, batch.Body.String())
	}
	if !strings.Contains(batch.Body.String(), `"skipped_retired":1`) || !strings.Contains(batch.Body.String(), "已退役任务 1 个") {
		t.Fatalf("batch body=%s, want skipped_retired=1 + 已退役任务文案", batch.Body.String())
	}
	if strings.Contains(batch.Body.String(), "冷却跳过") {
		t.Fatalf("batch body=%s, 永久退役条件不得混入冷却计数", batch.Body.String())
	}

	directed := httptest.NewRecorder()
	router.ServeHTTP(directed, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_retired"}`)))
	if directed.Code != http.StatusConflict {
		t.Fatalf("directed status=%d body=%s, want 409", directed.Code, directed.Body.String())
	}
	if !strings.Contains(directed.Body.String(), "已退役的证书任务不能重试") || !strings.Contains(directed.Body.String(), "禁用再启用") {
		t.Fatalf("directed body=%s, want 不可重试 + 禁用再启用指引", directed.Body.String())
	}
}

// Given 批量快照已取（锁外），随后目标规则在取锁前被并发删除。
// When all=true 落到 upsert 的规则当前态闸。
// Then 全部失败且均为规则状态冲突 → 409「刷新后重试」（与定向同口径），
// 不得折成 500 服务器故障。
func TestIssueCertificate_batchAllConflictReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_conflict_batch", "conflict-batch.example")
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	// 快照钩子：目标快照完成后、取 caddyOpMu 之前触发——在此删除规则，
	// 确定性地制造「快照已取、规则在取锁前被删除」，不依赖墙钟 sleep。
	snapshotTaken := make(chan struct{})
	allowContinue := make(chan struct{})
	oldHook := issueCertificateBatchSnapshotHook
	issueCertificateBatchSnapshotHook = func() {
		close(snapshotTaken)
		<-allowContinue
	}
	t.Cleanup(func() { issueCertificateBatchSnapshotHook = oldHook })
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))
		done <- rec
	}()
	select {
	case <-snapshotTaken:
	case <-time.After(5 * time.Second):
		t.Fatal("批量签发目标快照未在超时内完成")
	}
	if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id='lb_conflict_batch'"); err != nil {
		close(allowContinue)
		t.Fatalf("delete rule in snapshot-to-lock window: %v", err)
	}
	close(allowContinue)

	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("批量签发请求未返回")
	}
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（全部规则状态冲突）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "规则状态已变更") || !strings.Contains(response.Body.String(), "刷新后重试") {
		t.Fatalf("body=%s, want 可行动冲突文案", response.Body.String())
	}
	// 审计详情必须渲染中文结果码：conflict 曾因 auditResultTextMap 与动态
	// 结果码清单双缺而落英文内部标识（界面显示「结果：conflict」）。
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='触发签发' AND resource='证书' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read issue audit detail: %v", err)
	}
	if !strings.Contains(detail, "结果：状态冲突") || strings.Contains(detail, "conflict") {
		t.Fatalf("审计详情=%q, want 结果：状态冲突 且不含英文码 conflict", detail)
	}
}

// seedDownloadedJobWithMaterial 播种部署生命周期 + 材料在库的任务行
// （updated_at 回拨 3 分钟避开 2 分钟重试冷却）。
func seedDownloadedJobWithMaterial(t *testing.T, ruleID, domain, status string) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,updated_at)
		VALUES (?,?,?,'CERT-PEM-MATERIAL','KEY-PEM-MATERIAL',datetime('now','+80 days'),datetime('now','-3 minutes'))`, ruleID, domain, status)
	if err != nil {
		t.Fatalf("seed downloaded job for %s: %v", ruleID, err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return jobID
}

// stubDeploymentRegistrar 注入部署重试登记缝（生产=RetryCertificateDeploymentNow），
// 记录 (jobID, ruleID) 且不真正执行部署，便于断言「只重排部署」。
func stubDeploymentRegistrar(t *testing.T) *[]string {
	t.Helper()
	old := certJobDeploymentRetryRegistrar
	registered := make([]string, 0, 2)
	certJobDeploymentRetryRegistrar = func(jobID int, ruleID string) error {
		registered = append(registered, fmt.Sprintf("%d:%s", jobID, ruleID))
		return nil
	}
	t.Cleanup(func() { certJobDeploymentRetryRegistrar = old })
	return &registered
}

// Given 目标处于部署生命周期（downloaded）且材料在库、规则启用。
// When 定向「重新签发」。
// Then 只触发重新部署（不重新签发）：任务状态保持 downloaded、部署窗口前移、
// 登记缝收到该任务——与证书任务重试入口同源（整轮重签会丢弃已签发证书）。
func TestIssueCertificate_downloadedJobTriggersRedeployNotReissue(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_redeploy", "redeploy.example")
	jobID := seedDownloadedJobWithMaterial(t, "lb_redeploy", "redeploy.example", "downloaded")
	registered := stubDeploymentRegistrar(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_redeploy"}`)))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "已触发重新部署（不重新签发）") || !strings.Contains(response.Body.String(), `"redeployed":true`) {
		t.Fatalf("body=%s, want 重新部署响应", response.Body.String())
	}
	var status string
	var availableAfter sql.NullTime
	if err := db.DB.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（不得转 queued 重签）", status)
	}
	if !availableAfter.Valid {
		t.Fatal("deployment_available_after 未前移（未登记立即部署）")
	}
	if want := fmt.Sprintf("%d:lb_redeploy", jobID); len(*registered) != 1 || (*registered)[0] != want {
		t.Fatalf("registrations=%v, want [%s]", *registered, want)
	}
	assertLatestCertificateAudit(t, "规则：lb_redeploy", "等待恢复部署")
}

// Given 批量目标全部处于部署生命周期且材料在库。
// When all=true。
// Then 全部只重排部署：响应单列 redeployed、任务保持 downloaded、审计同源。
func TestIssueCertificate_batchDownloadedJobsTriggerRedeploy(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_redeploy_a", "redeploy-a.example")
	seedIssueRule(t, "lb_redeploy_b", "redeploy-b.example")
	jobA := seedDownloadedJobWithMaterial(t, "lb_redeploy_a", "redeploy-a.example", "cleanup_dns")
	jobB := seedDownloadedJobWithMaterial(t, "lb_redeploy_b", "redeploy-b.example", "cleanup_warning")
	registered := stubDeploymentRegistrar(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"redeployed":2`) || !strings.Contains(response.Body.String(), "已触发重新部署 2 个（不重新签发）") {
		t.Fatalf("body=%s, want redeployed=2 + 不重新签发文案", response.Body.String())
	}
	if len(*registered) != 2 {
		t.Fatalf("registrations=%v, want 2", *registered)
	}
	for _, jobID := range []int64{jobA, jobB} {
		var status string
		var availableAfter sql.NullTime
		if err := db.DB.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
			t.Fatal(err)
		}
		if status != "downloaded" && status != "cleanup_dns" && status != "cleanup_warning" {
			t.Fatalf("job %d status=%q, want 保持部署生命周期", jobID, status)
		}
		if !availableAfter.Valid {
			t.Fatalf("job %d deployment_available_after 未前移", jobID)
		}
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "等待恢复部署")
}

// blockingDeploymentRegistrar 注入「登记立即部署时会等待在途部署回调退出」的
// 登记缝：首次登记会阻塞到测试放行（或 10s 兜底，避免失败分支泄漏 goroutine），
// 并记录 (jobID:ruleID)。
func blockingDeploymentRegistrar(t *testing.T) (registrations *[]string, entered <-chan struct{}, release func()) {
	t.Helper()
	old := certJobDeploymentRetryRegistrar
	recorded := make([]string, 0, 2)
	enteredCh := make(chan struct{}, 1)
	releaseCh := make(chan struct{})
	var releaseOnce bool
	certJobDeploymentRetryRegistrar = func(jobID int, ruleID string) error {
		recorded = append(recorded, fmt.Sprintf("%d:%s", jobID, ruleID))
		select {
		case enteredCh <- struct{}{}:
		default:
		}
		select {
		case <-releaseCh:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("部署登记等待在途回调超时")
		}
		return nil
	}
	t.Cleanup(func() {
		certJobDeploymentRetryRegistrar = old
		if !releaseOnce {
			close(releaseCh)
		}
	})
	return &recorded, enteredCh, func() {
		if releaseOnce {
			return
		}
		releaseOnce = true
		close(releaseCh)
	}
}

// assertCaddyOpMuFreeDuringRegistration 断言登记阻塞期间全局锁已释放：在途部署
// 回调需要 caddyOpMu 才能完成规则写/Caddy 应用，持锁登记会互等到 busy 超时。
func assertCaddyOpMuFreeDuringRegistration(t *testing.T, h *Handlers, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("部署登记未发生")
	}
	locked := make(chan struct{})
	go func() {
		h.caddyOpMu.Lock()
		close(locked)
	}()
	select {
	case <-locked:
		h.caddyOpMu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("部署登记期间 caddyOpMu 仍被持有（登记未移出临界区）")
	}
}

// Given 定向目标「只差部署」且该任务存在在途部署回调（登记会等待其退出）。
// When 定向签发触发重新部署。
// Then 登记不在 caddyOpMu 临界区内执行——登记阻塞期间全局锁可用（修复前此处
// 要等到 busy 超时），放行后响应仍是「已触发重新部署（不重新签发）」。
func TestIssueCertificate_redeployRegistrationRunsOutsideCaddyOpMu(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_lock_free", "lock-free.example")
	jobID := seedDownloadedJobWithMaterial(t, "lb_lock_free", "lock-free.example", "downloaded")
	registrations, entered, release := blockingDeploymentRegistrar(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_lock_free"}`)))
		done <- rec
	}()
	assertCaddyOpMuFreeDuringRegistration(t, h, entered)
	release()
	select {
	case response := <-done:
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "已触发重新部署（不重新签发）") || !strings.Contains(response.Body.String(), `"redeployed":true`) {
			t.Fatalf("body=%s, want 重新部署响应", response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("签发请求未返回")
	}
	if want := fmt.Sprintf("%d:lb_lock_free", jobID); len(*registrations) != 1 || (*registrations)[0] != want {
		t.Fatalf("registrations=%v, want [%s]", *registrations, want)
	}
	assertLatestCertificateAudit(t, "规则：lb_lock_free", "等待恢复部署")
}

// Given 批量目标全部「只差部署」且每个目标的登记都会等待在途部署回调退出。
// When all=true。
// Then 登记在锁外逐个执行（登记阻塞期间锁可用），放行后全部登记成功、
// redeployed 计数在登记后聚合，响应文案与审计语义不变。
func TestIssueCertificate_batchRedeployRegistrationRunsOutsideCaddyOpMu(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_lock_batch_a", "lock-batch-a.example")
	seedIssueRule(t, "lb_lock_batch_b", "lock-batch-b.example")
	jobA := seedDownloadedJobWithMaterial(t, "lb_lock_batch_a", "lock-batch-a.example", "downloaded")
	jobB := seedDownloadedJobWithMaterial(t, "lb_lock_batch_b", "lock-batch-b.example", "cleanup_dns")
	registrations, entered, release := blockingDeploymentRegistrar(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))
		done <- rec
	}()
	assertCaddyOpMuFreeDuringRegistration(t, h, entered)
	release()
	select {
	case response := <-done:
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"redeployed":2`) || !strings.Contains(response.Body.String(), "已触发重新部署 2 个（不重新签发）") {
			t.Fatalf("body=%s, want redeployed=2 + 不重新签发文案", response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批量签发请求未返回")
	}
	if len(*registrations) != 2 {
		t.Fatalf("registrations=%v, want 2", *registrations)
	}
	registered := make(map[string]bool, 2)
	for _, item := range *registrations {
		registered[item] = true
	}
	for _, want := range []string{fmt.Sprintf("%d:lb_lock_batch_a", jobA), fmt.Sprintf("%d:lb_lock_batch_b", jobB)} {
		if !registered[want] {
			t.Fatalf("registrations=%v, want 含 %s", *registrations, want)
		}
	}
	assertLatestCertificateAudit(t, "范围：全部 ACME 规则", "等待恢复部署")
}
