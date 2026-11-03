package handlers

// 阶段页 4 列（block_page_stage1_id/status、
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

func TestUpdateRule_stagePageColumnsNeverWritten(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	for _, body := range []string{
		`{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage1_id":7,"block_page_stage1_status":401,"block_page_stage3_id":8,"block_page_stage3_status":503}`,
		`{"protocol":"tcp"}`,
		`{"protocol":"tcp","listen_port":8080,"block_page_stage1_id":7,"block_page_stage1_status":401,"block_page_stage3_id":8,"block_page_stage3_status":503}`,
	} {
		response := putStageRule(t, router, body)
		if response.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if s1, s1s, s3, s3s := stagePageColumns(t); s1 != 0 || s1s != 0 || s3 != 0 || s3s != 0 {
			t.Fatalf("stage columns=(%d,%d,%d,%d), want all zero（写侧停写，任何协议都不写）", s1, s1s, s3, s3s)
		}
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
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
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

	// 回归：http 创建携带 → 同样落 0（写侧停写，2026-11 用户裁定）
	request = httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"http-pages","protocol":"http","domain":"httppages.example.test","listen_port":8084,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
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
	if s1id, s1status, s3id, s3status := stageColumnsByName(t, "http-pages"); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("created http stage columns=(%d,%d,%d,%d), want all 0（写侧停写）", s1id, s1status, s3id, s3status)
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
	if s1id, s1status, s3id, s3status := stageColumnsByName(t, "http-page（副本）"); s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("http duplicate stage columns=(%d,%d,%d,%d), want all 0（不继承停用功能死配置）", s1id, s1status, s3id, s3status)
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

func TestBatchRuleBlockPages_deprecatedSkipsTcpRules(t *testing.T) {
	handler, loadCount := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_bt","lb_ghost"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if response.Code != http.StatusOK {
		t.Fatalf("batch-block-pages status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, unchanged, skipped := batchResultAll(t, response)
	if bound != 0 || unchanged != 1 || len(skipped) != 2 {
		t.Fatalf("bound=%d unchanged=%d skipped=%v, want 0/1/2", bound, unchanged, skipped)
	}
	if skipped[0]["rule_id"] != "lb_bt" || skipped[0]["reason"] != "TCP 规则不经过安全链" {
		t.Fatalf("skipped[0]=%v", skipped[0])
	}
	if skipped[1]["rule_id"] != "lb_ghost" || skipped[1]["reason"] != "规则不存在" {
		t.Fatalf("skipped[1]=%v", skipped[1])
	}
	if *loadCount != 0 {
		t.Fatalf("停用端点不得触发渲染，got %d loads", *loadCount)
	}
	for _, id := range []string{"lb_b1", "lb_bt"} {
		if s1, s1s, s3, s3s := stageColumnsByID(t, id); s1 != 0 || s1s != 0 || s3 != 0 || s3s != 0 {
			t.Fatalf("%s stage columns=(%d,%d,%d,%d), want all zero", id, s1, s1s, s3, s3s)
		}
	}
}
