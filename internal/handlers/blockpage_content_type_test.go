package handlers

// 拦截页 （2026-09-25 用户裁定）：创建/编辑可选内容类型
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
	"lazy-balancer-v2/internal/models"
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

func TestUpdateSecurityBlockPage_omittedContentTypeKeepsExisting(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, content_type, is_default) VALUES ('省略类型页', '{}', 'application/json; charset=utf-8', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := res.LastInsertId()

	// 指针合并语义：省略 content_type 是「不改」，不得回落默认 text/html。
	recorder := blockPageRequest(t, router, http.MethodPut, fmt.Sprintf("/security/block-pages/%d", pageID),
		`{"name":"省略类型页","content":"{\"ok\":true}"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var ct string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_type,'') FROM security_block_pages WHERE id=?`, pageID).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if ct != "application/json; charset=utf-8" {
		t.Fatalf("省略 content_type 后=%q, want 保留原值 application/json; charset=utf-8", ct)
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
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, content_type, is_default) VALUES ('引用统计页', '<html>x</html>', 'application/json; charset=utf-8', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	pageID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, block_page_id, enabled) VALUES (901, '引用策略', ?, 1)`, pageID); err != nil {
		t.Fatal(err)
	}
	// 禁用策略即使被绑定也不得计入 rule_ref_count（展示口径=生效引用）。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, block_page_id, enabled) VALUES (902, '禁用引用策略', ?, 0)`, pageID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_ra','ra','http','ra.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,block_page_stage1_id) VALUES ('lb_rb','rb','http','rb.test',8081,1,?)`, pageID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rc','rc','http','rc.test',8082,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ra', 901)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_rc', 902)`); err != nil {
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
				t.Fatalf("rule_ref_count=%d, want 2（lb_ra 策略绑定 ∪ lb_rb 阶段覆盖；禁用策略的 lb_rc 不计）", p.RuleRefCount)
			}
			if p.ContentType != "application/json; charset=utf-8" {
				t.Fatalf("列表 content_type=%q, want application/json; charset=utf-8（列表投影必须携带库值）", p.ContentType)
			}
		}
	}
	if !found {
		t.Fatal("列表未包含新建页面")
	}
}

func TestValidateBlockPagePayload_sharedContract(t *testing.T) {
	valid := models.SecurityBlockPage{Name: "page", Content: "<html>x</html>"}
	if err := validateBlockPagePayload(&valid); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if valid.ContentType != models.DefaultBlockPageContentType {
		t.Fatalf("empty content type=%q, want default %q", valid.ContentType, models.DefaultBlockPageContentType)
	}
	cases := []struct {
		name string
		page models.SecurityBlockPage
	}{
		{name: "empty name", page: models.SecurityBlockPage{Content: "x"}},
		{name: "long name", page: models.SecurityBlockPage{Name: strings.Repeat("名", securityNameMaxRunes+1), Content: "x"}},
		{name: "long description", page: models.SecurityBlockPage{Name: "page", Description: strings.Repeat("述", securityDescriptionMaxRunes+1), Content: "x"}},
		{name: "empty content", page: models.SecurityBlockPage{Name: "page"}},
		{name: "oversize content", page: models.SecurityBlockPage{Name: "page", Content: strings.Repeat("x", 64<<10+1)}},
		{name: "unknown content type", page: models.SecurityBlockPage{Name: "page", Content: "x", ContentType: "image/png"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page := tc.page
			if err := validateBlockPagePayload(&page); err == nil {
				t.Fatal("invalid payload must be rejected")
			}
		})
	}
}

// 响应模板双档（2026-11-12 用户裁定）：拦截页支持 HTML + JSON 两档——
// 创建/列表/更新全链路必须保留 json_content（编辑器唯一数据源；丢失即
// 「查看→保存」把 API 响应体写掉）。
func TestSecurityBlockPage_jsonContentRoundTrip(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBlockPageContentTypeRouter(t)
	create := map[string]any{
		"name": "双档页", "content": "<html>denied</html>",
		"json_content": `{"error":"denied-by-page"}`,
	}
	rec := postJSON(t, router, "/security/block-pages", create)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created.Data.ID

	var embedded string
	if err := db.DB.QueryRow(`SELECT COALESCE(json_content,'') FROM security_block_pages WHERE id=?`, id).Scan(&embedded); err != nil {
		t.Fatal(err)
	}
	if embedded != `{"error":"denied-by-page"}` {
		t.Fatalf("落库 json_content=%q", embedded)
	}

	// 列表回传（列表是编辑器唯一数据源）
	listRec := getRequest(t, router, "/security/block-pages")
	var listResp struct {
		Data []struct {
			ID          int    `json:"id"`
			JSONContent string `json:"json_content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range listResp.Data {
		if p.ID == id {
			found = true
			if p.JSONContent != `{"error":"denied-by-page"}` {
				t.Fatalf("列表 json_content=%q", p.JSONContent)
			}
		}
	}
	if !found {
		t.Fatal("列表未返回新建页面")
	}

	// 更新可清空 JSON 档（指针合并语义：显式空串才清空）
	putRec := putJSON(t, router, fmt.Sprintf("/security/block-pages/%d", id), map[string]any{"json_content": ""})
	if putRec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", putRec.Code, putRec.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(json_content,'') FROM security_block_pages WHERE id=?`, id).Scan(&embedded); err != nil {
		t.Fatal(err)
	}
	if embedded != "" {
		t.Fatalf("清空后 json_content=%q", embedded)
	}
}
