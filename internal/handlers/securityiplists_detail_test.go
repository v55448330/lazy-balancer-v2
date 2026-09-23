package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// IP 列表弹框性能重构（v2.3.2）：列表接口不再内联 entries（大名单载荷瘦身），
// 新增单条详情端点供弹框按需拉取。
func TestListIPLists_omitsEntries_keepsCount(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('big-list', '恶意 IP', '[{"value":"10.0.0.1","remark":"a"},{"value":"10.0.0.2","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d", resp.Code)
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, row := range payload.Data {
		if row["name"] == "big-list" {
			found = row
		}
	}
	if found == nil {
		t.Fatal("big-list 行缺失")
	}
	if _, has := found["entries"]; has {
		t.Fatalf("列表载荷不得内联 entries: %v", found)
	}
	if found["entry_count"] != float64(2) {
		t.Fatalf("entry_count=%v, want 2", found["entry_count"])
	}
}

func TestGetIPList_returnsEntries(t *testing.T) {
	newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('detail-list', '数据中心', '[{"value":"192.0.2.1","remark":"r1"}]')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id", h.GetIPList)

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "192.0.2.1") || !strings.Contains(resp.Body.String(), "r1") {
		t.Fatalf("详情须含条目: %s", resp.Body.String()[:300])
	}
	// 不存在 → 404
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, httptest.NewRequest(http.MethodGet, "/security/ip-lists/99999", nil))
	if resp2.Code != http.StatusNotFound {
		t.Fatalf("缺失 id status=%d, want 404", resp2.Code)
	}
}

// 用户名单不得与内置威胁名单重名（2026-09-24 用户裁定）——内置重名走专属
// 409 提示；同库既有通用重名校验含内置行，本测试钉住专属文案分支。
func TestCreateIPList_rejectsBuiltinName(t *testing.T) {
	newBackupTestHandlers(t) // 迁移已种子三源内置名单（新专业化名）
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/security/ip-lists", h.CreateIPList)

	body := `{"name":"中科大恶意 IP 名单（USTC）","category":"恶意 IP","entries":"[]"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/security/ip-lists", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "内置威胁情报名单保留") {
		t.Fatalf("应提示内置保留名: %s", resp.Body.String())
	}
}

// 内置威胁名单引用门禁（2026-09-24 用户裁定）：system=1 名单仅允许 IP ACL
// 黑名单（deny）引用；信任名单 / ACL 白名单（allow/bypass）/ CRS 排除一律 400。
func TestCreatePolicy_rejectsBuiltinListOutsideACLDeny(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	var sysID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&sysID); err != nil {
		t.Fatalf("内置名单种子缺失: %v", err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}
	refs := fmt.Sprintf(`[%d]`, sysID)

	// 信任名单引用内置名单 → 400
	if resp := post(`{"name":"t1","policy_type":"stage0","ip_whitelist_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("信任名单引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 白名单模式引用内置名单 → 400
	if resp := post(`{"name":"t2","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"allow","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("ACL allow 引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL bypass 引用内置名单 → 400
	if resp := post(`{"name":"t2b","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"bypass","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("ACL bypass 引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 黑名单模式引用内置名单 → 放行（唯一合法用途）
	if resp := post(`{"name":"t3","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusOK {
		t.Fatalf("ACL deny 引用内置名单应放行, got %d: %s", resp.Code, resp.Body.String())
	}
	// 用户名单不受限（信任名单引用自建名单 → 放行）
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('自建名单', '数据中心', '[]')`); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自建名单'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if resp := post(fmt.Sprintf(`{"name":"t4","policy_type":"stage0","ip_whitelist_refs":"[%d]"}`, userID)); resp.Code != http.StatusOK {
		t.Fatalf("信任名单引用自建名单应放行, got %d: %s", resp.Code, resp.Body.String())
	}
}
