package handlers

// 拦截页 Content-Type（2026-09-25 用户裁定）：创建/编辑可选内容类型
// （默认 text/html; charset=utf-8，白名单=text/html、application/json、
// application/xml、text/plain，均含 charset=utf-8）；列表新增内容类型与
// 规则引用数（引用该页的规则去重计数=启用策略绑定 ∪ 规则级阶段覆盖）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func newBlockPageContentTypeRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/block-pages", h.ListSecurityBlockPages)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	return router
}

func blockPageRequest(t *testing.T, router *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, path, strings.NewReader(body)))
	return recorder
}

func TestCreateSecurityBlockPage_contentTypeStored(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)

	// When：以 application/json 创建
	recorder := blockPageRequest(t, router, http.MethodPost, "/security/block-pages",
		`{"name":"JSON 拦截页","content":"{\"error\":\"blocked\"}","content_type":"application/json; charset=utf-8"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}

	// Then：行内存储类型
	var ct string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE name='JSON 拦截页'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if ct != "application/json; charset=utf-8" {
		t.Fatalf("content_type=%q, want application/json; charset=utf-8", ct)
	}
}

func TestCreateSecurityBlockPage_defaultsToHTML(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)

	recorder := blockPageRequest(t, router, http.MethodPost, "/security/block-pages",
		`{"name":"默认类型页","content":"<html>x</html>"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var ct string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE name='默认类型页'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if ct != "text/html; charset=utf-8" {
		t.Fatalf("content_type=%q, want text/html; charset=utf-8", ct)
	}
}

func TestCreateSecurityBlockPage_rejectsUnknownContentType(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)

	recorder := blockPageRequest(t, router, http.MethodPost, "/security/block-pages",
		`{"name":"非法类型页","content":"x","content_type":"text/css"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（白名单外类型拒绝）", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateSecurityBlockPage_contentTypeUpdated(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('改类型页', '<html>x</html>', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := res.LastInsertId()

	recorder := blockPageRequest(t, router, http.MethodPut, fmt.Sprintf("/security/block-pages/%d", pageID),
		`{"name":"改类型页","description":"","content":"x","content_type":"text/plain; charset=utf-8"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var ct string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE id=?`, pageID).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if ct != "text/plain; charset=utf-8" {
		t.Fatalf("content_type=%q, want text/plain; charset=utf-8", ct)
	}
}

func TestUpdateSecurityBlockPage_rejectsUnknownContentType(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('非法改类页', '<html>x</html>', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := res.LastInsertId()

	recorder := blockPageRequest(t, router, http.MethodPut, fmt.Sprintf("/security/block-pages/%d", pageID),
		`{"name":"非法改类页","description":"","content":"x","content_type":"image/png"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

func TestListSecurityBlockPages_ruleRefCount(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)
	// Given：页面被 ①一条启用策略（绑定规则 lb_ra）②规则 lb_rb 的阶段 1 覆盖引用
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('引用统计页', '<html>x</html>', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, block_page_id, enabled) VALUES (901, '引用策略', ?, 1)`, pageID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_ra','ra','http','ra.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,block_page_stage1_id) VALUES ('lb_rb','rb','http','rb.test',8081,1,?)`, pageID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ra', 901)`); err != nil {
		t.Fatal(err)
	}

	recorder := blockPageRequest(t, router, http.MethodGet, "/security/block-pages", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", recorder.Code)
	}
	var payload struct {
		Data []struct {
			ID           int    `json:"id"`
			Name         string `json:"name"`
			ContentType  string `json:"content_type"`
			RuleRefCount int    `json:"rule_ref_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析列表响应: %v", err)
	}
	found := false
	for _, p := range payload.Data {
		if p.ID == int(pageID) {
			found = true
			if p.RuleRefCount != 2 {
				t.Fatalf("rule_ref_count=%d, want 2（lb_ra 策略绑定 ∪ lb_rb 阶段覆盖）", p.RuleRefCount)
			}
		}
	}
	if !found {
		t.Fatal("列表未包含新建页面")
	}
}
