package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 阶段拦截页（规则级覆盖层，阶段化安全流水线批 2）：lb_rules 4 列
// block_page_stage1_id/block_page_stage1_status/block_page_stage3_id/
// block_page_stage3_status——规则可为阶段 1（IP 访问控制+地域拦截预检）与
// 阶段 3（WAF）各配拦截页+状态码，未配（0）=跟随策略（v2.3.1 逐策略归因
// 默认层）。写侧校验：page_id>0 须存在于 security_block_pages；status ∈
// {0,400,401,403,404,503}。Update 指针化（nil=保留合并，同 ca_provider_id 先例）。

func seedStagePageRule(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress) VALUES ('lb_stage','stage','','http','stage.example.test',8080,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_stage','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_block_pages (id,name,content) VALUES (7,'stage-one','<html>s1</html>'),(8,'stage-three','<html>s3</html>')`); err != nil {
		t.Fatalf("seed block pages: %v", err)
	}
}

func stagePageRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", h.CreateRule)
	router.PUT("/rules/:caddy_id", h.UpdateRule)
	return router
}

func putStageRule(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_stage", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func stagePageColumns(t *testing.T) (int, int, int, int) {
	t.Helper()
	var s1id, s1status, s3id, s3status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE caddy_id='lb_stage'`).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read stage page columns: %v", err)
	}
	return s1id, s1status, s3id, s3status
}

func TestUpdateRule_stageBlockPages_roundTrip(t *testing.T) {
	// Given：存量规则 + 两个拦截页
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	// When：PUT 携带 4 个阶段页字段
	response := putStageRule(t, router, `{
		"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,
		"block_page_stage1_id":7,"block_page_stage1_status":401,
		"block_page_stage3_id":8,"block_page_stage3_status":503
	}`)

	// Then：200 且读回一致
	if response.Code != http.StatusOK {
		t.Fatalf("update with stage pages status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	s1id, s1status, s3id, s3status := stagePageColumns(t)
	if s1id != 7 || s1status != 401 || s3id != 8 || s3status != 503 {
		t.Fatalf("stage page columns=(%d,%d,%d,%d), want (7,401,8,503)", s1id, s1status, s3id, s3status)
	}

	// When：仅改名（阶段页字段 nil=保留合并）
	response = putStageRule(t, router, `{"name":"stage-renamed","protocol":"http","domain":"stage.example.test","listen_port":8080}`)

	// Then：4 列保留
	if response.Code != http.StatusOK {
		t.Fatalf("rename-only update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	s1id, s1status, s3id, s3status = stagePageColumns(t)
	if s1id != 7 || s1status != 401 || s3id != 8 || s3status != 503 {
		t.Fatalf("stage page columns after nil-merge=(%d,%d,%d,%d), want preserved (7,401,8,503)", s1id, s1status, s3id, s3status)
	}
}

func TestRule_stageBlockPages_validation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	cases := []struct {
		name string
		body string
	}{
		{"dangling stage1 page", `{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage1_id":999}`},
		{"dangling stage3 page", `{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage3_id":999}`},
		{"stage1 status out of set", `{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage1_id":7,"block_page_stage1_status":418}`},
		{"stage3 status out of set", `{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage3_id":8,"block_page_stage3_status":500}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := putStageRule(t, router, tc.body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}

	// 创建路径同校验：悬空阶段页 → 400
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"stage-new","protocol":"http","domain":"stage-new.example.test","listen_port":8081,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],
		"block_page_stage3_id":999
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("create with dangling stage3 page status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestCreateRule_stageBlockPages_roundTrip(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t) // 只需拦截页行（规则行用另一 caddy_id 新建）
	router := stagePageRouter(handler)

	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"stage-created","protocol":"http","domain":"stage-created.example.test","listen_port":8082,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],
		"block_page_stage1_id":7,"block_page_stage1_status":403,
		"block_page_stage3_id":8
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create with stage pages status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var s1id, s1status, s3id, s3status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE domain='stage-created.example.test'`).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read created rule stage columns: %v", err)
	}
	if s1id != 7 || s1status != 403 || s3id != 8 || s3status != 0 {
		t.Fatalf("created stage columns=(%d,%d,%d,%d), want (7,403,8,0)", s1id, s1status, s3id, s3status)
	}
}
