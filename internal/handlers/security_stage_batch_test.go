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
		clusterService: services.NewClusterService(db.DB, nil, ""),
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

	// When：超 5 条策略 → 400；策略不存在 → 400
	if response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[1,2,3,4,5,6],"mode":"merge"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("over-5 status=%d, want 400", response.Code)
	}
	if response := postStageJSON(t, router, "/security/policies/batch-bind",
		`{"rule_ids":["lb_b1"],"policy_ids":[999],"mode":"merge"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("dangling policy status=%d, want 400", response.Code)
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
	// Given：规则 lb_ss（双域名）+ 24h 内 blocked 事件（id 2 / 800123 / 942100 /
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
	seedEvent("800123", "blocked", "datetime('now','-2 hours')")
	seedEvent("800123", "blocked", "datetime('now','-3 hours')")
	seedEvent("942100", "blocked", "datetime('now','-1 hour')")
	seedEvent("10005", "blocked", "datetime('now','-1 hour')")
	seedEvent("2", "logged", "datetime('now','-1 hour')")           // 非 blocked 不计
	seedEvent("2", "blocked", "datetime('now','-25 hours')")        // 超 24h 窗不计
	seedEvent("949110", "blocked", "datetime('now','-30 minutes')") // 阶段 3 评分拦截
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

	// Then：阶段 1={2,4,7,8}∪800xxx=3，阶段 3=其余=3（942100/10005/949110），
	// 429=按域名映射 7+2=9（other.example.test 与 code=200 排除）
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
	if payload.Data.Stage1 != 3 || payload.Data.Stage3 != 3 || payload.Data.Ratelimit != 9 {
		t.Fatalf("stage-stats=(%d,%d,%v), want (3,3,9)", payload.Data.Stage1, payload.Data.Stage3, payload.Data.Ratelimit)
	}
}

// 占位防漂移：seedEvent 的时间表达式拼接必须保持常量形态（防 SQL 注入面，
// 本测试全部用例为字面量）。若未来参数化时间表达式，须改占位符绑定。
var _ = fmt.Sprintf
