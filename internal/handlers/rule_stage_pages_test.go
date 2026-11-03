package handlers

// 规则级阶段拦截页停用后的写侧钉测（2026-11 用户裁定：写侧停写、渲染链
// 零消费、DB 4 列保留）。本文件替代原「PUT/Create 往返 + 引用校验」钉：
// 四个字段现在被接受但一律忽略——请求 200/201、四列保持 0、无校验错误。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateRule_stageBlockPages_ignored(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	// When：PUT 携带 4 个阶段页字段（含悬空页/非法状态码）
	response := putStageRule(t, router, `{
		"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,
		"block_page_stage1_id":999,"block_page_stage1_status":418,
		"block_page_stage3_id":999,"block_page_stage3_status":500
	}`)

	// Then：200 且四列保持 0（写侧停写，不校验也不写入）。
	if response.Code != http.StatusOK {
		t.Fatalf("update with stage fields status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	s1id, s1status, s3id, s3status := stagePageColumns(t)
	if s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("stage page columns=(%d,%d,%d,%d), want all zero (feature removed)", s1id, s1status, s3id, s3status)
	}

	// 仅改名同样不触碰四列。
	response = putStageRule(t, router, `{"name":"stage-renamed","protocol":"http","domain":"stage.example.test","listen_port":8080}`)
	if response.Code != http.StatusOK {
		t.Fatalf("rename-only update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	s1id, s1status, s3id, s3status = stagePageColumns(t)
	if s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("stage page columns after rename=(%d,%d,%d,%d), want all zero", s1id, s1status, s3id, s3status)
	}
}

func TestRule_stageBlockPages_noValidation(t *testing.T) {
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
		{"stage1 status without page", `{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage1_status":503}`},
		{"stage3 status without page", `{"name":"stage","protocol":"http","domain":"stage.example.test","listen_port":8080,"block_page_stage3_status":403}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := putStageRule(t, router, tc.body)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200（四字段已忽略）", response.Code, response.Body.String())
			}
			if got := stagePageColumnsKey(t); got != "0|0|0|0" {
				t.Fatalf("stage page columns=%s, want 0|0|0|0", got)
			}
		})
	}

	// 创建路径同口径：悬空阶段页不再 400，落库四列为 0。
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"stage-new","protocol":"http","domain":"stage-new.example.test","listen_port":8081,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],
		"block_page_stage3_id":999
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create with dangling stage3 page status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var s1id, s1status, s3id, s3status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE domain='stage-new.example.test'`).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read created rule stage columns: %v", err)
	}
	if s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("created stage columns=(%d,%d,%d,%d), want all zero", s1id, s1status, s3id, s3status)
	}
}

func TestCreateRule_stageBlockPages_ignored(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedStagePageRule(t)
	router := stagePageRouter(handler)

	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"stage-created","protocol":"http","domain":"stage-created.example.test","listen_port":8082,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
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
	if s1id != 0 || s1status != 0 || s3id != 0 || s3status != 0 {
		t.Fatalf("created stage columns=(%d,%d,%d,%d), want all zero", s1id, s1status, s3id, s3status)
	}
}

// —— 与 rules_tcp_stagepages_test.go 共享的夹具（阶段页停用后仍用于「列保持
// 零」断言；原定义随旧行为钉删除，此处按共享契约恢复）——

// seedStagePageRule 播种 lb_stage（http，stage.example.test:8080）与拦截页 7/8。
func seedStagePageRule(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enabled)
		VALUES ('lb_stage','stage','http','stage.example.test',8080,'weighted_round_robin',10,2,3,2,1)`); err != nil {
		t.Fatalf("seed stage rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, enabled, protocol) VALUES ('lb_stage','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed stage rule upstream: %v", err)
	}
	for _, id := range []int{7, 8} {
		if _, err := db.DB.Exec(`INSERT INTO security_block_pages (id,name,content) VALUES (?, ?, '<html></html>')`, id, "page-"+strconv.Itoa(id)); err != nil {
			t.Fatalf("seed block page %d: %v", id, err)
		}
	}
}

// stagePageRouter 组装 PUT /rules/:caddy_id 与 POST /rules 两层路由。
func stagePageRouter(handler *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	router.POST("/rules", handler.CreateRule)
	return router
}

// putStageRule 对 lb_stage 发起一次 PUT。
func putStageRule(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_stage", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// stagePageColumns 读 lb_stage 的四列。
func stagePageColumns(t *testing.T) (int, int, int, int) {
	t.Helper()
	var s1id, s1status, s3id, s3status int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE caddy_id='lb_stage'`).
		Scan(&s1id, &s1status, &s3id, &s3status); err != nil {
		t.Fatalf("read stage page columns: %v", err)
	}
	return s1id, s1status, s3id, s3status
}

// stagePageColumnsKey 把四列拼成可比较键。
func stagePageColumnsKey(t *testing.T) string {
	t.Helper()
	s1id, s1status, s3id, s3status := stagePageColumns(t)
	return fmt.Sprintf("%d|%d|%d|%d", s1id, s1status, s3id, s3status)
}
