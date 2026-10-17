package handlers

// 第 78 轮 B 域切片：U06-F04（删除路径临界区）、U06-F07（掩码合并空串）、
// L04-01（签发未入队不得伪装成功）。

import (
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
	// 与 r67 截断口径测试同基准（本地格式化会引入 8 小时偏移）。
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
			if _, err := db.DB.Exec(`INSERT OR REPLACE INTO cert_jobs (id,rule_id,domain,status,expires_at) VALUES (9201,'lb_r78_status','r78.test','issued',?)`,
				expires.Format("2006-01-02 15:04:05")); err != nil {
				t.Fatalf("seed job: %v", err)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/jobs?page=1&page_size=50", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			idx := strings.Index(body, `"rule_id":"lb_r78_status"`)
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
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'r78','dnspod','{}',1)`); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_tls,tls_source,acme_config_id) VALUES ('lb_r78_delete','r78','','http','r78.example.test',8080,'weighted_round_robin',1,0,'manual',0)`); err != nil {
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
			body := `{"name":"r78","protocol":"http","domain":"r78.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":1}`
			request := httptest.NewRequest(http.MethodPut, "/rules/lb_r78_delete", strings.NewReader(body))
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
	merged, err := mergeMaskedDNSCredentials(submitted, stored)
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
	merged, err = mergeMaskedDNSCredentials(empty, stored)
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
	merged, err = mergeMaskedDNSCredentials(mixed, stored)
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

// —— L04-01：签发未入队不得回 200「已创建 0 个任务」 ——

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
	t.Cleanup(services.ResetCAQueueManagerForTest)
	return services.GetCAQueueManager()
}

// Given 证书签发队列已暂停。
// When 定向签发。
// Then 409 并点名「队列已暂停」，审计结果 skipped（不得 200 queued=0 伪装成功）。
func TestIssueCertificate_pausedQueueReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_r78_paused", "r78-paused.example")
	qm.PauseAndDrain()
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_r78_paused"}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "暂停") {
		t.Fatalf("body=%s, want 点名「队列已暂停」", response.Body.String())
	}
	assertLatestCertificateAudit(t, "规则：lb_r78_paused", "已跳过")
}

// Given 规则处于删除/迁移屏障（blockedRules）。
// When 定向签发。
// Then 409 并点名屏障原因，审计结果 skipped。
func TestIssueCertificate_blockedRuleReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_r78_blocked", "r78-blocked.example")
	token := qm.BlockJobsForRule("lb_r78_blocked")
	t.Cleanup(func() { qm.UnblockJobsForRule("lb_r78_blocked", token) })
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_r78_blocked"}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "屏障") {
		t.Fatalf("body=%s, want 点名规则屏障原因", response.Body.String())
	}
	assertLatestCertificateAudit(t, "规则：lb_r78_blocked", "已跳过")
}

// Given 既有任务仍在本队列在途执行（qm.IsJobActive），状态 creating_order 已超
// 重试守卫窗口（不会被 429 拦截）。
// When 再次定向签发。
// Then 200 + queued=0 + in_flight 归因（在途保留 200，但不得声称新建任务）。
func TestIssueCertificate_inFlightJobReturns200WithZeroQueued(t *testing.T) {
	h := newBackupTestHandlers(t)
	qm := initIssueQueue(t)
	seedIssueRule(t, "lb_r78_inflight", "r78-inflight.example")
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at)
		VALUES ('lb_r78_inflight','r78-inflight.example','creating_order','active',datetime('now','-10 minutes'))`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	qm.MarkJobRunningForTest("lb_r78_inflight", int(jobID))
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_r78_inflight"}`)))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（在途保留）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":0`) || !strings.Contains(response.Body.String(), `"in_flight":true`) {
		t.Fatalf("body=%s, want queued=0 + in_flight=true", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "执行中") {
		t.Fatalf("body=%s, want 在途文案", response.Body.String())
	}
	assertLatestCertificateAudit(t, "规则：lb_r78_inflight", "已跳过")
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
