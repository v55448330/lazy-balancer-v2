package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 阶段化安全流水线批 2 端点：
//   GET  /security/rules/:caddy_id/stage-stats（阶段计数 chip：阶段 1/3=24h
//        blocked 事件分桶，阶段 2=重载口径 429 按 host 映射回规则）
//   POST /security/policies/batch-bind（批量绑定：单事务单渲染，merge/replace）
//   POST /rules/batch-block-pages（批量阶段拦截页：单事务单渲染）

// newStageBatchTestHandlers 带 /load 计数器的 Caddy 桩——批量端点必须一次
// finishTxApply（单渲染），计数>1 即违反「单事务单渲染」契约。
func newStageBatchTestHandlers(t *testing.T) (*Handlers, *int) {
	t.Helper()
	initializeRuleFeatureTestDB(t)
	fullConfig := `{"apps":{"http":{"servers":{"http_8080":{"routes":[]}}}}}`
	loadCount := 0
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/config/") {
			_, _ = response.Write([]byte(fullConfig))
			return
		}
		if request.Method == http.MethodPost && (request.URL.Path == "/load" || request.URL.Path == "/config/") {
			_, _ = io.ReadAll(request.Body)
			loadCount++
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	cfg := &config.Config{CaddyAdminURL: fakeCaddy.URL}
	return &Handlers{
		cfg:            cfg,
		caddyService:   services.NewCaddyService(fakeCaddy.URL),
		clusterService: services.NewClusterService(db.DB, ""),
	}, &loadCount
}

func stageBatchRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies/batch-bind", h.BatchBindSecurityPolicies)
	router.POST("/rules/batch-block-pages", h.BatchRuleBlockPages)
	router.GET("/security/rules/:caddy_id/stage-stats", h.GetRuleStageStats)
	return router
}

func postStageJSON(t *testing.T, router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func seedStageBatchRules(t *testing.T) {
	t.Helper()
	for _, rule := range []struct{ id, protocol, domain string }{
		{"lb_b1", "http", "b1.example.test"},
		{"lb_b2", "http", "b2.example.test"},
		{"lb_b3", "http", "b3.example.test"},
		{"lb_bt", "tcp", ""},
	} {
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled) VALUES (?,?,?,?,?, 'weighted_round_robin', 1)`,
			rule.id, rule.id, rule.protocol, rule.domain, 8080); err != nil {
			t.Fatalf("seed rule %s: %v", rule.id, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES (?,?,9000,1,1)`, rule.id, "127.0.0.1"); err != nil {
			t.Fatalf("seed upstream %s: %v", rule.id, err)
		}
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (1,'bp-one','blocking',1),(2,'bp-two','detection',1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_block_pages (id,name,content) VALUES (7,'batch-page','<html>batch</html>')`); err != nil {
		t.Fatalf("seed block page: %v", err)
	}
}

func batchResult(t *testing.T, recorder *httptest.ResponseRecorder) (int, []map[string]any) {
	t.Helper()
	var payload struct {
		Code int `json:"code"`
		Data struct {
			Bound   int              `json:"bound"`
			Skipped []map[string]any `json:"skipped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode batch result: %v (body=%s)", err, recorder.Body.String())
	}
	return payload.Data.Bound, payload.Data.Skipped
}

func TestBatchBindSecurityPolicies_singleRenderAndShapes(t *testing.T) {
	// Given：3 条 http 规则 + 1 条 tcp 规则 + 2 条策略
	handler, loadCount := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	// When：merge 绑定（含一条 tcp 规则）
	response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3","lb_bt"],"policy_ids":[1],"mode":"merge"}`)

	// Then：bound=3、tcp 进 skipped、/load 恰好 1 次（单渲染）
	if response.Code != http.StatusOK {
		t.Fatalf("merge status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, skipped := batchResult(t, response)
	if bound != 3 || len(skipped) != 1 || skipped[0]["rule_id"] != "lb_bt" {
		t.Fatalf("merge bound=%d skipped=%v, want bound=3 skipped=[lb_bt]", bound, skipped)
	}
	if *loadCount != 1 {
		t.Fatalf("batch-bind must render once, got %d loads", *loadCount)
	}
	for _, ruleID := range []string{"lb_b1", "lb_b2", "lb_b3"} {
		var count int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id=1`, ruleID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("binding for %s missing (count=%d, err=%v)", ruleID, count, err)
		}
	}

	// When：replace——lb_b1 已有 [1]，替换为 [2]
	response = postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[2],"mode":"replace"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("replace status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var pids string
	if err := db.DB.QueryRow(`SELECT COALESCE(GROUP_CONCAT(policy_id),'') FROM security_policy_bindings WHERE rule_caddy_id='lb_b1'`).Scan(&pids); err != nil {
		t.Fatal(err)
	}
	if pids != "2" {
		t.Fatalf("replace must leave only policy 2, got [%s]", pids)
	}

	// When：merge 幂等（重复绑定已绑定策略）→ bound 照计、无重复行
	response = postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b2"],"policy_ids":[1,1,2],"mode":"merge"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("merge-idempotent status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, _ = batchResult(t, response)
	if bound != 1 {
		t.Fatalf("idempotent merge bound=%d, want 1", bound)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(GROUP_CONCAT(policy_id),'') FROM security_policy_bindings WHERE rule_caddy_id='lb_b2' ORDER BY policy_id`).Scan(&pids); err != nil {
		t.Fatal(err)
	}
	if pids != "1,2" {
		t.Fatalf("merge must union dedupe to [1,2], got [%s]", pids)
	}

	// When：超 8 条策略 → 400（2026-09-21 上限 5→8）；恰好 8 条 → 200；策略不存在 → 400
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (3,'bp-3','off',1),(4,'bp-4','off',1),(5,'bp-5','off',1),(6,'bp-6','off',1),(7,'bp-7','off',1),(8,'bp-8','off',1),(9,'bp-9','off',1)`); err != nil {
		t.Fatalf("seed policies 3-9: %v", err)
	}
	if response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[1,2,3,4,5,6,7,8,9],"mode":"merge"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("over-9 status=%d, want 400", response.Code)
	}
	response = postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b3"],"policy_ids":[1,2,3,4,5,6,7,8],"mode":"replace"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("exactly-8 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, _ = batchResult(t, response)
	if bound != 1 {
		t.Fatalf("exactly-8 bound=%d, want 1", bound)
	}
	var b3Count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_b3'`).Scan(&b3Count); err != nil || b3Count != 8 {
		t.Fatalf("exactly-8 binding count=%d (err=%v), want 8", b3Count, err)
	}
	if response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[999],"mode":"merge"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("dangling policy status=%d, want 400", response.Code)
	}
}

func TestBatchBindSecurityPolicies_dedupesRuleIDs(t *testing.T) {
	handler, loadCount := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)
	response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":[" lb_b1 ","lb_b1","lb_b1"],"policy_ids":[1],"mode":"replace"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	bound, skipped := batchResult(t, response)
	if bound != 1 || len(skipped) != 0 {
		t.Fatalf("duplicate rule ids bound=%d skipped=%v, want 1/0", bound, skipped)
	}
	if *loadCount != 1 {
		t.Fatalf("loads=%d, want 1", *loadCount)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "成功 1 条") {
		t.Fatalf("audit detail=%q, want deduped success count", detail)
	}
}

// merge 上限边界（2026-09-21 上限 5→8）：lb_b1 现有 6 条 + merge 2 条 = 8 → bound；
// 再 merge 1 条 = 9 → 该规则 skipped「合并后超过 8 条策略上限」且原绑定保留。
func TestBatchBindSecurityPolicies_mergeCapBoundary(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)
	for i := 3; i <= 9; i++ {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (?,?,?,1)`, i, fmt.Sprintf("cap-%d", i), "off"); err != nil {
			t.Fatalf("seed policy %d: %v", i, err)
		}
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) SELECT 'lb_b1', id FROM security_policies WHERE id<=6`); err != nil {
		t.Fatalf("seed 6 bindings: %v", err)
	}

	// When merge 至恰好 8 条
	response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[7,8],"mode":"merge"}`)

	// Then bound=1、绑定共 8 条
	if response.Code != http.StatusOK {
		t.Fatalf("merge-to-8 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, skipped := batchResult(t, response)
	if bound != 1 || len(skipped) != 0 {
		t.Fatalf("merge-to-8 bound=%d skipped=%v, want bound=1 skipped=0", bound, skipped)
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_b1'`).Scan(&count); err != nil || count != 8 {
		t.Fatalf("merge-to-8 binding count=%d (err=%v), want 8", count, err)
	}

	// When 再 merge 1 条 → 9 条唯一 → 规则级 skipped
	response = postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[9],"mode":"merge"}`)

	// Then 200（整体受理）但 lb_b1 skipped 且原 8 条绑定保留
	if response.Code != http.StatusOK {
		t.Fatalf("merge-to-9 status=%d body=%s, want 200 (rule-level skip)", response.Code, response.Body.String())
	}
	bound, skipped = batchResult(t, response)
	if bound != 0 || len(skipped) != 1 || skipped[0]["rule_id"] != "lb_b1" {
		t.Fatalf("merge-to-9 bound=%d skipped=%v, want bound=0 skipped=[lb_b1]", bound, skipped)
	}
	if reason, _ := skipped[0]["reason"].(string); !strings.Contains(reason, "合并后超过 8 条策略上限") {
		t.Fatalf("skip reason=%q, want containing 合并后超过 8 条策略上限", reason)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_b1'`).Scan(&count); err != nil || count != 8 {
		t.Fatalf("skipped rule must keep 8 bindings, got %d (err=%v)", count, err)
	}
}

func TestBatchRuleBlockPages_updatesAndSkips(t *testing.T) {
	// Given：2 条规则 + 拦截页 7；lb_ghost 不存在
	handler, loadCount := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	// When：批量设置阶段页（含一条不存在规则）
	response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_ghost"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)

	// Then：bound=2、ghost 进 skipped、两规则 4 列落库、/load 恰好 1 次
	if response.Code != http.StatusOK {
		t.Fatalf("batch-block-pages status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, skipped := batchResult(t, response)
	if bound != 2 || len(skipped) != 1 || skipped[0]["rule_id"] != "lb_ghost" {
		t.Fatalf("bound=%d skipped=%v, want bound=2 skipped=[lb_ghost]", bound, skipped)
	}
	if *loadCount != 1 {
		t.Fatalf("batch-block-pages must render once, got %d loads", *loadCount)
	}
	for _, ruleID := range []string{"lb_b1", "lb_b2"} {
		var s1id, s1status, s3id, s3status int
		if err := db.DB.QueryRow(`SELECT block_page_stage1_id,block_page_stage1_status,block_page_stage3_id,block_page_stage3_status FROM lb_rules WHERE caddy_id=?`, ruleID).
			Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
			t.Fatal(err)
		}
		if s1id != 7 || s1status != 403 || s3id != 7 || s3status != 503 {
			t.Fatalf("%s stage columns=(%d,%d,%d,%d), want (7,403,7,503)", ruleID, s1id, s1status, s3id, s3status)
		}
	}

	// When：悬空页 / 越界状态码 → 400
	if response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1"],"block_page_stage1_id":999}`); response.Code != http.StatusBadRequest {
		t.Fatalf("dangling page status=%d, want 400", response.Code)
	}
	if response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1"],"block_page_stage3_id":7,"block_page_stage3_status":418}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid status code status=%d, want 400", response.Code)
	}
}

func TestGetRuleStageStats_bucketsAndRateLimitMapping(t *testing.T) {
	// Given：规则 lb_ss（双域名）+ 24h 内 blocked 事件（id 2 / 14 / 800123 / 942100 /
	// 10005）+ 界外事件（logged / 25h 前）+ 指标桩 429 计数
	handler, _ := newStageBatchTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled) VALUES ('lb_ss','ss','http','ss.example.test,api.ss.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_ss','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}
	eventSeq := 0
	seedEvent := func(triggered, action, timeExpr string) {
		t.Helper()
		eventSeq++
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,rule_caddy_id,policy_id,client_ip,method,uri,event_type,rule_triggered,rule_msg,action,anomaly_score,rule_name,policy_name,transaction_id)
			VALUES (`+timeExpr+`,'lb_ss',1,'203.0.113.9','GET','/x','waf',?,'msg',?,0,'ss','p1',?)`, triggered, action, fmt.Sprintf("tx-%d", eventSeq)); err != nil {
			t.Fatalf("seed event %s/%s: %v", triggered, action, err)
		}
	}
	seedEvent("2", "blocked", "datetime('now','-1 hour')")
	seedEvent("14", "blocked", "datetime('now','-1 hour')") // 威胁情报库并入阶段 1（生产口径 {2,4,7,8,14}∪800xxx）
	seedEvent("800123", "blocked", "datetime('now','-2 hours')")
	seedEvent("800123", "blocked", "datetime('now','-3 hours')")
	seedEvent("942100", "blocked", "datetime('now','-1 hour')")
	seedEvent("10005", "blocked", "datetime('now','-1 hour')")
	seedEvent("2", "logged", "datetime('now','-1 hour')")           // 非 blocked 不计
	seedEvent("2", "blocked", "datetime('now','-25 hours')")        // 超 24h 窗不计
	seedEvent("949110", "blocked", "datetime('now','-30 minutes')") // 阶段 3 评分拦截
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="ss.example.test",method="GET",server="http_8080"} 7
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="api.ss.test",method="GET",server="http_8080"} 2
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="other.example.test",method="GET",server="http_8080"} 5
caddy_http_request_duration_seconds_count{code="200",handler="rate_limit",host="ss.example.test",method="GET",server="http_8080"} 100
`))
	}))
	t.Cleanup(metrics.Close)
	handler.cfg.CaddyMetricsURL = metrics.URL
	router := stageBatchRouter(handler)

	// When
	request := httptest.NewRequest(http.MethodGet, "/security/rules/lb_ss/stage-stats", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：阶段 1={2,4,7,8,14}∪800xxx=4（2/14/800123×2），阶段 3=其余=3
	// （942100/10005/949110），429=按域名映射 7+2=9（other.example.test 与
	// code=200 排除）
	if response.Code != http.StatusOK {
		t.Fatalf("stage-stats status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			Stage1    int     `json:"stage1_blocked_24h"`
			Stage3    int     `json:"stage3_blocked_24h"`
			Ratelimit float64 `json:"ratelimit_blocks_reload"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode stage-stats: %v (body=%s)", err, response.Body.String())
	}
	if payload.Data.Stage1 != 4 || payload.Data.Stage3 != 3 || payload.Data.Ratelimit != 9 {
		t.Fatalf("stage-stats=(%d,%d,%v), want (4,3,9)", payload.Data.Stage1, payload.Data.Stage3, payload.Data.Ratelimit)
	}
}

// 同域多端口：两条规则各自只认自己监听端口的 429 计数（按 host 求和会让每条
// chip 变成两条之和）；泛域名规则匹配子域 host（此前恒 0）。
func TestGetRuleStageStats_rateLimitCountsPerListenPort(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	for _, rule := range []struct {
		id, domain string
		port       int
	}{
		{"lb_port80", "shared.example.test", 80},
		{"lb_port443", "shared.example.test", 443},
		{"lb_wild", "*.wild.example.test", 8080},
	} {
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled) VALUES (?,?,?,?,?,'weighted_round_robin',1)`,
			rule.id, rule.id, "http", rule.domain, rule.port); err != nil {
			t.Fatal(err)
		}
	}
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="shared.example.test",method="GET",server="http_80"} 3
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="shared.example.test",method="GET",server="http_443"} 4
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="a.wild.example.test",method="GET",server="http_8080"} 5
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="wild.example.test",method="GET",server="http_8080"} 6
`))
	}))
	t.Cleanup(metrics.Close)
	handler.cfg.CaddyMetricsURL = metrics.URL
	router := stageBatchRouter(handler)

	readRatelimit := func(t *testing.T, ruleID string) float64 {
		t.Helper()
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/rules/"+ruleID+"/stage-stats", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", ruleID, response.Code, response.Body.String())
		}
		var payload struct {
			Data struct {
				Ratelimit float64 `json:"ratelimit_blocks_reload"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode %s: %v", ruleID, err)
		}
		return payload.Data.Ratelimit
	}

	if got := readRatelimit(t, "lb_port80"); got != 3 {
		t.Errorf("lb_port80 ratelimit=%v, want 3（不得累加 443 端口）", got)
	}
	if got := readRatelimit(t, "lb_port443"); got != 4 {
		t.Errorf("lb_port443 ratelimit=%v, want 4（不得累加 80 端口）", got)
	}
	// 泛域名只匹配子域：a.wild... = 5，裸域 6 不计（Caddy 通配域不含裸域）。
	if got := readRatelimit(t, "lb_wild"); got != 5 {
		t.Errorf("lb_wild ratelimit=%v, want 5（通配匹配子域、不含裸域）", got)
	}
}

func TestGetRuleStageStats_timingUsesConsistentSegmentsAndPositiveSamples(t *testing.T) {
	// Given：WAF 事件携带预检快照、3/5/12 防御性预检 ID、升级前 precheck_us=0
	// 的存量预检行，以及非数字触发 ID 和 24h 界外行。
	handler, _ := newStageBatchTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled) VALUES ('lb_timing','timing','http','',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	seedTiming := func(triggered, timeExpr string, durationUS, precheckUS int) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events
			(event_time,rule_caddy_id,client_ip,rule_triggered,action,duration_us,precheck_us)
			VALUES (`+timeExpr+`,'lb_timing','203.0.113.10',?,'blocked',?,?)`, triggered, durationUS, precheckUS); err != nil {
			t.Fatalf("seed timing event %q: %v", triggered, err)
		}
	}
	seedTiming("942100", "datetime('now','-1 hour')", 300, 40)
	seedTiming("10005", "datetime('now','-1 hour')", 100, 60)
	seedTiming("3", "datetime('now','-1 hour')", 20, 20)
	seedTiming("5", "datetime('now','-1 hour')", 40, 0)
	seedTiming("12", "datetime('now','-1 hour')", 60, 60)
	seedTiming("800123", "datetime('now','-1 hour')", 80, 80)
	seedTiming("2", "datetime('now','-1 hour')", 10, 0)
	seedTiming("949110", "datetime('now','-1 hour')", 500, 0)
	seedTiming("garbage", "datetime('now','-1 hour')", 900, 0)
	seedTiming("942100", "datetime('now','-25 hours')", 10000, 10000)

	// When
	response := httptest.NewRecorder()
	stageBatchRouter(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/security/rules/lb_timing/stage-stats", nil))

	// Then：预检均值使用所有正 precheck_us 快照（40/60/20/60/80）；WAF 均值只
	// 使用非预检段的正 duration_us（300/100/500/900）。零快照存量行不稀释，
	// 3/5/12 不得混入 WAF 桶。
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			PrecheckAvg     float64 `json:"precheck_avg_us"`
			PrecheckSamples int     `json:"precheck_samples"`
			WafAvg          float64 `json:"waf_avg_us"`
			WafSamples      int     `json:"waf_samples"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode timing stats: %v", err)
	}
	if payload.Data.PrecheckAvg != 52 || payload.Data.PrecheckSamples != 5 {
		t.Fatalf("precheck timing=(%v,%d), want (52,5); body=%s", payload.Data.PrecheckAvg, payload.Data.PrecheckSamples, response.Body.String())
	}
	if payload.Data.WafAvg != 450 || payload.Data.WafSamples != 4 {
		t.Fatalf("waf timing=(%v,%d), want (450,4); body=%s", payload.Data.WafAvg, payload.Data.WafSamples, response.Body.String())
	}
}

func TestGetRuleStageStats_nilMetricsDBReturnsFullZeroShape(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	// 规则存在性判定先于 MetricsDB 分支（未知规则一律 404）——零值面板用例
	// 必须钉在真实存在的规则上。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_nil','lb_nil','http','nil.example.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })
	router := stageBatchRouter(handler)
	request := httptest.NewRequest(http.MethodGet, "/security/rules/lb_nil/stage-stats", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	// 键存在 + 值为零：只查键存在会让零值面板漂移成任意占位值仍绿。
	for _, key := range []string{"stage1_blocked_24h", "stage3_blocked_24h", "stage_unattributed_24h", "ratelimit_blocks_reload", "precheck_avg_us", "precheck_samples", "waf_avg_us", "waf_samples"} {
		raw, ok := payload.Data[key]
		if !ok {
			t.Fatalf("nil MetricsDB fallback missing key %q: %s", key, response.Body.String())
		}
		var value float64
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("nil MetricsDB fallback key %q 不是数值: %s", key, raw)
		}
		if value != 0 {
			t.Fatalf("nil MetricsDB fallback key %q=%v, want 0（零值面板）", key, value)
		}
	}
}

// stage-stats 对不存在规则此前误归 500（message 借「规则不存在」
// 文案但 code 500）——ErrNoRows 分判 404 not_found；其余 DB 故障保持 500 且
// message 归位「阶段统计查询失败」。前端 RuleFlowDialog 对非 200 一律
// stats=null（catch 分支），404 化不改变前端表现。
func TestGetRuleStageStats_unknownRuleReturns404(t *testing.T) {
	t.Run("unknown rule", func(t *testing.T) {
		// Given：无 lb_rules 行的 caddy_id（metrics 查询空集照常成功）
		handler, _ := newStageBatchTestHandlers(t)
		router := stageBatchRouter(handler)

		// When
		request := httptest.NewRequest(http.MethodGet, "/security/rules/lb_absent/stage-stats", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusNotFound {
			t.Fatalf("unknown rule status=%d body=%s, want 404", response.Code, response.Body.String())
		}
		var payload struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode stage-stats: %v (body=%s)", err, response.Body.String())
		}
		if payload.Code != 404 || payload.Message != "规则不存在" {
			t.Fatalf("payload=(%d,%q), want (404,规则不存在)", payload.Code, payload.Message)
		}
	})

	t.Run("database failure stays 500", func(t *testing.T) {
		// Given：主库句柄关闭（metrics 库为独立句柄，首个查询照常成功，
		// 查询失败点落在 lb_rules 存在性检查——非 ErrNoRows 的 DB 故障）
		handler, _ := newStageBatchTestHandlers(t)
		router := stageBatchRouter(handler)
		if err := db.DB.Close(); err != nil {
			t.Fatalf("close main db: %v", err)
		}

		// When
		request := httptest.NewRequest(http.MethodGet, "/security/rules/lb_absent/stage-stats", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("db failure status=%d body=%s, want 500", response.Code, response.Body.String())
		}
		var payload struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode stage-stats: %v (body=%s)", err, response.Body.String())
		}
		if payload.Code != 500 || payload.Message != "阶段统计查询失败" {
			t.Fatalf("payload=(%d,%q), want (500,阶段统计查询失败)", payload.Code, payload.Message)
		}
	})
}

// 批量绑定端点的 rule_ids 数量上限。同族端点均有
// 上限（bindings/bulk=100、batch-block-pages=500），本端点此前无界——超大
// rule_ids 会在 BEGIN IMMEDIATE + caddyOpMu 内逐规则查询/写入，阻塞全部主库
// 配置写。判据按 normalizeRuleIDs 归一后集合计数（空白/重复 id 不占额度）。
func TestBatchBindSecurityPolicies_ruleIDLimit(t *testing.T) {
	handler, loadCount := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	ruleIDs := func(n int) []string {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("lb_limit_%03d", i)
		}
		return ids
	}
	body := func(ids []string) string {
		raw, err := json.Marshal(map[string]any{"rule_ids": ids, "policy_ids": []int{1}, "mode": "merge"})
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		return string(raw)
	}

	// 形状 1：归一后 101 条 → 400 整批拒绝，且不进入写路径（零 /load）
	response := postStageJSON(t, router, "/security/policies/batch-bind", body(ruleIDs(101)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("over-limit status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "100 条规则") {
		t.Fatalf("over-limit body=%s, want limit message", response.Body.String())
	}
	if *loadCount != 0 {
		t.Fatalf("rejected batch must not render caddy, got %d loads", *loadCount)
	}

	// 形状 2：原始 102 项（100 唯一 + 1 空白 + 1 重复）→ 归一后 100，边界通过
	ids := ruleIDs(100)
	ids = append(ids, "   ", ids[0])
	response = postStageJSON(t, router, "/security/policies/batch-bind", body(ids))
	if response.Code != http.StatusOK {
		t.Fatalf("boundary status=%d body=%s, want 200（上限按归一后集合判定）", response.Code, response.Body.String())
	}
	if *loadCount != 1 {
		t.Fatalf("boundary batch loads=%d, want 1", *loadCount)
	}
}

// 拦截页 PUT 必须是指针合并（与 UpdateRule 同域口径）：省略字段保留原值，
// 显式空串才清空。旧实现用值结构体全量替换——省略 description/content_type
// 会静默清空描述、并把自定义内容类型重置为默认 text/html。
func TestUpdateSecurityBlockPage_omittedFieldsPreserved(t *testing.T) {
	h, _ := newStageBatchTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)

	result, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, content_type, is_default, is_builtin) VALUES ('原名称','原描述','<h1>x</h1>','application/json; charset=utf-8','0','0')`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	id, _ := result.LastInsertId()

	// 只改 content：name/description/content_type 必须保留。
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/security/block-pages/%d", id), strings.NewReader(`{"content":"<h1>new</h1>"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var name, description, content, contentType string
	if err := db.DB.QueryRow(`SELECT name, description, content, content_type FROM security_block_pages WHERE id=?`, id).Scan(&name, &description, &content, &contentType); err != nil {
		t.Fatalf("read page: %v", err)
	}
	if name != "原名称" || description != "原描述" || contentType != "application/json; charset=utf-8" || content != "<h1>new</h1>" {
		t.Fatalf("merge semantics broken: name=%q desc=%q content=%q type=%q", name, description, content, contentType)
	}

	// 显式空串仍可清空（指针语义：省略=保留，显式零值=写入）。
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/security/block-pages/%d", id), strings.NewReader(`{"description":""}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("clear description status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT description FROM security_block_pages WHERE id=?`, id).Scan(&description); err != nil {
		t.Fatalf("read page: %v", err)
	}
	if description != "" {
		t.Fatalf("explicit empty description must clear, got %q", description)
	}
}

// 阶段统计的非数字 triggered（空串/垃圾串/带前缀 ID）必须归「未归因」桶，
// 不得冒充阶段 3（WAF）拦截——同域 categorizeAttack/attackFamilyClassOf 对
// 不可判定形态一律归「其他」。响应以 stage_unattributed 披露，合计口径不变。
func TestGetRuleStageStats_nonNumericTriggeredGoesUnattributed(t *testing.T) {
	h, _ := newStageBatchTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/rules/:caddy_id/stage-stats", h.GetRuleStageStats)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled) VALUES ('lb_stage_unattr','unattr','','http','',8090,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	seed := []struct {
		triggered string
		count     int
	}{
		{"garbage", 3}, // 非数字 → 未归因
		{"", 2},        // 空串 → 未归因
		{"942100", 5},  // 策略引擎（阶段 3）
		{"800005", 1},  // 地域预检精确段（阶段 1）
		{"429", 4},     // 限流：不计入阶段 chip（既有口径）
	}
	for _, row := range seed {
		for range row.count {
			if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (rule_caddy_id, client_ip, event_type, rule_triggered, action) VALUES ('lb_stage_unattr','203.0.113.9','waf',?,'blocked')`, row.triggered); err != nil {
				t.Fatalf("seed event %q: %v", row.triggered, err)
			}
		}
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/rules/lb_stage_unattr/stage-stats", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Stage1Blocked24h int `json:"stage1_blocked_24h"`
			Stage3Blocked24h int `json:"stage3_blocked_24h"`
			Unattributed     int `json:"stage_unattributed_24h"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, recorder.Body.String())
	}
	if payload.Data.Stage1Blocked24h != 1 || payload.Data.Stage3Blocked24h != 5 || payload.Data.Unattributed != 5 {
		t.Fatalf("stage split=%+v, want stage1=1 stage3=5 unattributed=5", payload.Data)
	}
	if payload.Data.Stage1Blocked24h+payload.Data.Stage3Blocked24h+payload.Data.Unattributed != 11 {
		t.Fatalf("合计口径变化（429 仍应排除）: %+v", payload.Data)
	}
}
