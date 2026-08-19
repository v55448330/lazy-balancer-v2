package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// newSecurityEntityRouter 注册自定义规则与拦截页面的读写路由，供 status_code 列
// 移除后的 CRUD 回归测试使用。与 newSecurityRouter 一样注入假的 Caddy 服务，
// 使 Create/Update 处理器末尾的 caddyApplyNote() 不会空指针。
func newSecurityEntityRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/custom-rules", h.ListSecurityCustomRules)
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
	router.GET("/security/block-pages", h.ListSecurityBlockPages)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	return router
}

func TestSecurityCustomRuleCRUD_withoutStatusColumn(t *testing.T) {
	// Given a database whose security_custom_rules table no longer has status_code
	setupSecurityPolicyTestDB(t)
	router := newSecurityEntityRouter(t)

	// When a rule is created without any status_code field
	recorder := postJSON(t, router, "/security/custom-rules", map[string]any{
		"name":        "无状态码规则",
		"description": "status_code 列已移除",
		"conditions":  []map[string]string{{"target": "uri", "operator": "contains", "pattern": "/admin"}},
		"action":      "block",
		"score":       5,
		"enabled":     true,
	})

	// Then the create succeeds and the list round-trips the rule without a status_code field
	if recorder.Code != http.StatusOK {
		t.Fatalf("create custom rule status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	list := getRequest(t, router, "/security/custom-rules")
	if list.Code != http.StatusOK {
		t.Fatalf("list custom rules status=%d body=%s", list.Code, list.Body.String())
	}
	var resp struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("custom rules len=%d, want 1: %s", len(resp.Data), list.Body.String())
	}
	if _, present := resp.Data[0]["status_code"]; present {
		t.Fatalf("custom rule still exposes status_code field: %s", list.Body.String())
	}
}

func TestCreateSecurityBlockPage_rejectsDefaultPage(t *testing.T) {
	// Given 系统已播种唯一的默认拦截页（is_default=1）
	setupSecurityPolicyTestDB(t)
	router := newSecurityEntityRouter(t)

	// When API 请求创建第二个默认拦截页
	recorder := postJSON(t, router, "/security/block-pages", map[string]any{
		"name":       "第二个默认页",
		"content":    "<h1>Access Denied</h1>",
		"is_default": true,
	})

	// Then 请求被 400 拒绝（R40 F3：第二个默认页不可编辑/不可删除，会产生死行），
	// 且默认页仍只有种子行
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create default block page status=%d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Message != "默认拦截页由系统管理，不允许创建" {
		t.Fatalf("message=%q, want 默认拦截页由系统管理，不允许创建", resp.Message)
	}
	var defaults int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaults); err != nil {
		t.Fatal(err)
	}
	if defaults != 1 {
		t.Fatalf("default block pages=%d, want 1 (seed only)", defaults)
	}
}

func TestSecurityBlockPageCRUD_withoutStatusColumn(t *testing.T) {
	// Given a database whose security_block_pages table no longer has status_code
	setupSecurityPolicyTestDB(t)
	router := newSecurityEntityRouter(t)

	// When a page is created without any status_code field
	recorder := postJSON(t, router, "/security/block-pages", map[string]any{
		"name":        "无状态码页面",
		"description": "status_code 列已移除",
		"content":     "<h1>Access Denied</h1>",
	})

	// Then the create succeeds and the list round-trips the page without a status_code field
	if recorder.Code != http.StatusOK {
		t.Fatalf("create block page status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	list := getRequest(t, router, "/security/block-pages")
	if list.Code != http.StatusOK {
		t.Fatalf("list block pages status=%d body=%s", list.Code, list.Body.String())
	}
	var resp struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	found := false
	for _, page := range resp.Data {
		if _, present := page["status_code"]; present {
			t.Fatalf("block page still exposes status_code field: %s", list.Body.String())
		}
		var name string
		if err := json.Unmarshal(page["name"], &name); err == nil && name == "无状态码页面" {
			found = true
		}
	}
	if !found {
		t.Fatalf("created block page missing from list: %s", list.Body.String())
	}
}
