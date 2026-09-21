package handlers

// U3-1(第 45 轮审计修复)：阶段页 4 列（block_page_stage1_id/status、
// block_page_stage3_id/status）仅 http 渲染消费，但多条写路径可把非零值
// 写进 TCP 规则行成为永不消费的死数据。本组测试钉住：
//   - UpdateRule 协议切换 http→tcp：4 列归零；tcp 编辑显式携带 → 归一 0
//   - CreateRule tcp：携带页引用 → 落库 0（http 携带 → 保留，回归）
//   - DuplicateRule tcp 源：副本 4 列 0（http 源复制携带，回归）
//   - BatchRuleBlockPages：tcp 规则跳过（与 batch-bind 同文案），仅 http UPDATE

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func stageColumnsByID(t *testing.T, caddyID string) (int, int, int, int) {
	t.Helper()
	var s1id, s1status, s3id, s3status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE caddy_id=?`, caddyID).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read stage columns for %s: %v", caddyID, err)
	}
	return s1id, s1status, s3id, s3status
}

func TestUpdateRule_tcpSwitchClearsStagePageColumns(t *testing.T) {
	// Given：http 规则（含上游）+ 两个拦截页行
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	// When：http 编辑携带 4 列阶段页
	response := putStageRule(t, router, `{
		"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,
		"block_page_stage1_id":7,"block_page_stage1_status":401,
		"block_page_stage3_id":8,"block_page_stage3_status":503
	}`)

	// Then：200 且落库（回归形状：http 保留）
	if response.Code != http.StatusOK {
		t.Fatalf("http update with stage pages status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if s1id, s1status, s3id, s3status := stagePageColumns(t); s1id != 7 || s1status != 401 || s3id != 8 || s3status != 503 {
		t.Fatalf("http stage columns=(%d,%d,%d,%d), want (7,401,8,503)", s1id, s1status, s3id, s3status)
	}

	// When：协议切换 http→tcp
	response = putStageRule(t, router, `{"protocol":"tcp"}`)

	// Then：200 且 4 列归零（TCP 不消费阶段页，死数据随切换清除）
	if response.Code != http.StatusOK {
		t.Fatalf("switch to tcp status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if s1id, s1status, s3id, s3status := stagePageColumns(t); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("tcp switch stage columns=(%d,%d,%d,%d), want all 0", s1id, s1status, s3id, s3status)
	}

	// When：tcp 规则编辑显式携带阶段页引用（最终协议归一形状）
	response = putStageRule(t, router, `{
		"protocol":"tcp","listen_port":8080,
		"block_page_stage1_id":7,"block_page_stage1_status":401,
		"block_page_stage3_id":8,"block_page_stage3_status":503
	}`)

	// Then：200 且仍全零（归一吞掉显式携带，TCP 无渲染消费面）
	if response.Code != http.StatusOK {
		t.Fatalf("tcp edit with stage pages status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if s1id, s1status, s3id, s3status := stagePageColumns(t); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("tcp explicit stage columns=(%d,%d,%d,%d), want all 0", s1id, s1status, s3id, s3status)
	}
}

func TestCreateRule_tcpNormalizesStagePages(t *testing.T) {
	// Given：两个拦截页行
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	// When：tcp 创建携带页引用
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"tcp-pages","protocol":"tcp","listen_port":8083,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],
		"block_page_stage1_id":7,"block_page_stage1_status":401,
		"block_page_stage3_id":8,"block_page_stage3_status":503
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：201 且落库 4 列全零
	if response.Code != http.StatusCreated {
		t.Fatalf("create tcp with stage pages status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	if s1id, s1status, s3id, s3status := stageColumnsByName(t, "tcp-pages"); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("created tcp stage columns=(%d,%d,%d,%d), want all 0", s1id, s1status, s3id, s3status)
	}

	// 回归：http 创建携带 → 保留
	request = httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"http-pages","protocol":"http","domain":"httppages.example.test","listen_port":8084,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],
		"block_page_stage1_id":7,"block_page_stage1_status":403,
		"block_page_stage3_id":8,"block_page_stage3_status":503
	}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create http with stage pages status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	if s1id, s1status, s3id, s3status := stageColumnsByName(t, "http-pages"); s1id != 7 || s1status != 403 || s3id != 8 || s3status != 503 {
		t.Fatalf("created http stage columns=(%d,%d,%d,%d), want (7,403,8,503)", s1id, s1status, s3id, s3status)
	}
}

func TestDuplicateRule_tcpClearsStagePages(t *testing.T) {
	// Given：tcp 源规则 + http 源规则，各配 4 列阶段页
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_tcppage", "tcp-page", 19095, false, "weighted_round_robin", false)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET block_page_stage1_id=7, block_page_stage1_status=401, block_page_stage3_id=8, block_page_stage3_status=503 WHERE caddy_id='lb_tcppage'`); err != nil {
		t.Fatalf("seed tcp stage columns: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress) VALUES ('lb_httppage','http-page','','http','httppage.example.test',19096,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httppage','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed http upstream: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET block_page_stage1_id=7, block_page_stage1_status=401, block_page_stage3_id=8, block_page_stage3_status=503 WHERE caddy_id='lb_httppage'`); err != nil {
		t.Fatalf("seed http stage columns: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// When：复制两条源规则
	for _, id := range []string{"lb_tcppage", "lb_httppage"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+id+"/duplicate", nil))
		if response.Code != http.StatusCreated && response.Code != http.StatusOK {
			t.Fatalf("duplicate %s status=%d body=%.200s, want 2xx", id, response.Code, response.Body.String())
		}
	}

	// Then：tcp 副本 4 列全零；http 副本携带（回归）
	if s1id, s1status, s3id, s3status := stageColumnsByName(t, "tcp-page（副本）"); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("tcp duplicate stage columns=(%d,%d,%d,%d), want all 0", s1id, s1status, s3id, s3status)
	}
	if s1id, s1status, s3id, s3status := stageColumnsByName(t, "http-page（副本）"); s1id != 7 || s1status != 401 || s3id != 8 || s3status != 503 {
		t.Fatalf("http duplicate stage columns=(%d,%d,%d,%d), want (7,401,8,503)", s1id, s1status, s3id, s3status)
	}
}

func stageColumnsByName(t *testing.T, name string) (int, int, int, int) {
	t.Helper()
	var s1id, s1status, s3id, s3status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE name=?`, name).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read stage columns for %s: %v", name, err)
	}
	return s1id, s1status, s3id, s3status
}

func TestBatchRuleBlockPages_skipsTcpRules(t *testing.T) {
	// Given：http 规则 lb_b1/b2/b3 + tcp 规则 lb_bt + 拦截页 7；lb_ghost 不存在
	handler, loadCount := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	// When：混合提交（http + tcp + ghost）
	response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_bt","lb_ghost"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)

	// Then：bound=1；tcp 与 ghost 各自 reason 进 skipped；tcp 行 4 列不动
	if response.Code != http.StatusOK {
		t.Fatalf("batch-block-pages status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, skipped := batchResult(t, response)
	if bound != 1 || len(skipped) != 2 {
		t.Fatalf("bound=%d skipped=%v, want bound=1 skipped=2 entries", bound, skipped)
	}
	if skipped[0]["rule_id"] != "lb_bt" || skipped[0]["reason"] != "TCP 规则不经过安全链" {
		t.Fatalf("skipped[0]=%v, want lb_bt/TCP 规则不经过安全链", skipped[0])
	}
	if skipped[1]["rule_id"] != "lb_ghost" || skipped[1]["reason"] != "规则不存在" {
		t.Fatalf("skipped[1]=%v, want lb_ghost/规则不存在", skipped[1])
	}
	if s1id, s1status, s3id, s3status := stageColumnsByID(t, "lb_bt"); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("tcp rule stage columns=(%d,%d,%d,%d), want untouched all 0", s1id, s1status, s3id, s3status)
	}
	if *loadCount != 1 {
		t.Fatalf("batch-block-pages must render once, got %d loads", *loadCount)
	}

	// 回归：全 http 提交照旧
	response = postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if response.Code != http.StatusOK {
		t.Fatalf("all-http batch status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, skipped = batchResult(t, response)
	if bound != 2 || len(skipped) != 0 {
		t.Fatalf("all-http bound=%d skipped=%v, want bound=2 skipped=0", bound, skipped)
	}
	for _, ruleID := range []string{"lb_b2", "lb_b3"} {
		if s1id, s1status, s3id, s3status := stageColumnsByID(t, ruleID); s1id != 7 || s1status != 403 || s3id != 7 || s3status != 503 {
			t.Fatalf("%s stage columns=(%d,%d,%d,%d), want (7,403,7,503)", ruleID, s1id, s1status, s3id, s3status)
		}
	}
}
