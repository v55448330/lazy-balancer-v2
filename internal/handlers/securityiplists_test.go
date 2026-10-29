package handlers

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func newIPListRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)
	router.POST("/security/ip-lists", h.CreateIPList)
	router.GET("/security/ip-lists/:id", h.GetIPList)
	router.PUT("/security/ip-lists/:id", h.UpdateIPList)
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)
	router.POST("/security/ip-lists/:id/ips", h.AddIPToList)
	router.POST("/security/ip-lists/:id/remove-ip", h.RemoveIPFromList)
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	router.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	router.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
	router.GET("/security/policies/:id", h.GetSecurityPolicy)
	router.GET("/security/policies", h.ListSecurityPolicies)
	return router
}

func seedIPListRow(t *testing.T, name, entriesJSON string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, ?)`, name, entriesJSON)
	if err != nil {
		t.Fatalf("seed ip list %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSecurityPolicyRefs_createAndUpdatePersistDedupedJSON(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "refs-dedupe", `[{"value":"203.0.113.1"}]`)
	refs := fmt.Sprintf("[%d,%d,%d]", listID, listID, listID)
	response := postJSON(t, router, "/security/policies", map[string]any{
		"name": "refs-dedupe-policy", "mode": "off", "ip_acl_enabled": true, "ip_acl_mode": "deny", "ip_acl_list_refs": refs,
	})
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var policyID int
	var stored string
	if err := db.DB.QueryRow(`SELECT id, ip_acl_list_refs FROM security_policies WHERE name='refs-dedupe-policy'`).Scan(&policyID, &stored); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[%d]", listID)
	if stored != want {
		t.Fatalf("create stored refs=%s, want %s", stored, want)
	}
	response = putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{"ip_acl_list_refs": refs})
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE id=?`, policyID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != want {
		t.Fatalf("update stored refs=%s, want %s", stored, want)
	}
}

func TestSecurityWriteEndpoints_rejectNoncanonicalNumericIDs(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   map[string]any
		seed   string
		count  string
	}{
		{name: "update block page", method: http.MethodPut, path: "/security/block-pages/", body: map[string]any{"name": "page", "content": "changed"}, seed: `INSERT INTO security_block_pages (id,name,content,is_default,is_builtin) VALUES (5,'page','original',0,0)`, count: `SELECT COUNT(*) FROM security_block_pages WHERE id=5 AND content='original'`},
		{name: "delete block page", method: http.MethodDelete, path: "/security/block-pages/", seed: `INSERT INTO security_block_pages (id,name,content,is_default,is_builtin) VALUES (5,'page','original',0,0)`, count: `SELECT COUNT(*) FROM security_block_pages WHERE id=5`},
		{name: "delete policy", method: http.MethodDelete, path: "/security/policies/", seed: `INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'policy','off',1)`, count: `SELECT COUNT(*) FROM security_policies WHERE id=5`},
		{name: "add IP", method: http.MethodPost, path: "/security/ip-lists/", body: map[string]any{"value": "203.0.113.8"}, seed: `INSERT INTO security_ip_lists (id,name,entries) VALUES (5,'list','[]')`, count: `SELECT COUNT(*) FROM security_ip_lists WHERE id=5 AND entries='[]'`},
		{name: "update IP list", method: http.MethodPut, path: "/security/ip-lists/", body: map[string]any{"description": "changed"}, seed: `INSERT INTO security_ip_lists (id,name,entries,description) VALUES (5,'list','[]','original')`, count: `SELECT COUNT(*) FROM security_ip_lists WHERE id=5 AND description='original'`},
	}
	for _, tc := range cases {
		for _, id := range []string{"5.0", "not-a-number"} {
			t.Run(tc.name+"/"+id, func(t *testing.T) {
				setupSecurityPolicyTestDB(t)
				router := newIPListRouter(t)
				if _, err := db.DB.Exec(tc.seed); err != nil {
					t.Fatal(err)
				}
				path := tc.path + id
				if tc.name == "add IP" {
					path += "/ips"
				}
				var response *httptest.ResponseRecorder
				switch tc.method {
				case http.MethodPut:
					response = putJSON(t, router, path, tc.body)
				case http.MethodPost:
					response = postJSON(t, router, path, tc.body)
				default:
					response = deleteRequest(t, router, path)
				}
				if response.Code != http.StatusBadRequest {
					t.Fatalf("%s %s status=%d body=%s, want 400", tc.method, path, response.Code, response.Body.String())
				}
				var unchanged int
				if err := db.DB.QueryRow(tc.count).Scan(&unchanged); err != nil {
					t.Fatal(err)
				}
				if unchanged != 1 {
					t.Fatal("invalid id must not mutate the addressed row")
				}
			})
		}
	}
}

func TestCreateIPList_validationMatrix(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)

	valid := map[string]any{"name": "办公网", "description": "desc", "category": "内网", "entries": `[{"value":"10.0.0.0/8","remark":"内网段"}]`}
	rec := postJSON(t, router, "/security/ip-lists", valid)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid create status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	cases := []struct {
		name    string
		body    map[string]any
		want    int
		wantMsg string
	}{
		{"empty name", map[string]any{"name": "  ", "entries": "[]"}, 400, "名称不能为空"},
		{"name too long", map[string]any{"name": strings.Repeat("长", 51), "entries": "[]"}, 400, "名称长度"},
		{"description too long", map[string]any{"name": "ok", "description": strings.Repeat("d", 201), "entries": "[]"}, 400, "描述长度"},
		{"category too long", map[string]any{"name": "ok", "category": strings.Repeat("c", 33), "entries": "[]"}, 400, "分类长度"},
		{"remark too long", map[string]any{"name": "ok", "entries": fmt.Sprintf(`[{"value":"1.2.3.4","remark":"%s"}]`, strings.Repeat("r", 101))}, 400, "备注长度"},
		{"invalid entry value", map[string]any{"name": "ok", "entries": `[{"value":"999.1.1.1","remark":""}]`}, 400, "无效的 IP/CIDR"},
		{"entries not json", map[string]any{"name": "ok", "entries": "not-json"}, 400, "JSON 数组"},
		{"too many entries", map[string]any{"name": "ok", "entries": bigEntriesJSON(2001)}, 400, "条目数量"},
		{"dup name case-insensitive", map[string]any{"name": "办公网", "entries": "[]"}, 409, "已存在"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, router, "/security/ip-lists", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status=%d body=%s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if !strings.Contains(rec.Body.String(), tc.wantMsg) {
				t.Fatalf("body=%s, want message containing %q", rec.Body.String(), tc.wantMsg)
			}
		})
	}
}

// 策略引用的 IP 列表数量封顶 64(去重后)——无上限的 refs 会让
// 渲染端逐条展开 ACL 条目,单策略即可撑爆配置体积。
func TestSecurityPolicy_ipListRefsCappedAt64(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	refsJSON := func(n int) string {
		ids := make([]int, n)
		for i := range n {
			ids[i] = i + 1
		}
		raw, _ := json.Marshal(ids)
		return string(raw)
	}
	for i := 1; i <= 65; i++ {
		seedIPListRow(t, fmt.Sprintf("list-%d", i), `[{"value":"10.0.0.1","remark":""}]`)
	}

	rec := postJSON(t, router, "/security/policies", map[string]any{
		"name": "cap-65", "ip_acl_list_refs": refsJSON(65),
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能超过 64") {
		t.Fatalf("65 refs must 400 with cap message, got %d %s", rec.Code, rec.Body.String())
	}

	rec = postJSON(t, router, "/security/policies", map[string]any{
		"name": "cap-64", "ip_acl_list_refs": refsJSON(64),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("64 refs must pass, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateIPList_globalCountLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	for i := 0; i < 200; i++ {
		if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, '[]')`, fmt.Sprintf("列表-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	rec := postJSON(t, router, "/security/ip-lists", map[string]any{"name": "第201个", "entries": "[]"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "上限") {
		t.Fatalf("status=%d body=%s, want 400 上限", rec.Code, rec.Body.String())
	}
}

// 名单额度只计用户创建的名单（与备份导入 validateBackupIPListQuota 同口径）：
// 系统内置名单由 SeedSystemIPLists 自动补齐、不占用户额度——此前新建门按
// 全表行数计，系统名单会挤掉用户可建空间（导入 197 条用户名单后新建被误挡）。
func TestCreateIPList_quotaCountsUserListsOnly(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := tx.Exec(`INSERT INTO security_ip_lists (name, entries, system) VALUES (?, '[]', 1)`, fmt.Sprintf("系统名单-%d", i)); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	for i := 0; i < ipListMaxGlobalCount-1; i++ {
		if _, err := tx.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, '[]')`, fmt.Sprintf("用户名单-%d", i)); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var totalRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists`).Scan(&totalRows); err != nil {
		t.Fatal(err)
	}
	if totalRows <= ipListMaxGlobalCount {
		t.Fatalf("夹具必须让全表行数超过额度（total=%d），否则旧口径不会误挡", totalRows)
	}

	// 第 200 个用户名单：放行（系统名单不占额度）。
	rec := postJSON(t, router, "/security/ip-lists", map[string]any{"name": "额度边界-200", "entries": "[]"})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 200（系统名单不占用户额度）", rec.Code, rec.Body.String())
	}
	// 第 201 个用户名单：拒绝。
	rec = postJSON(t, router, "/security/ip-lists", map[string]any{"name": "额度边界-201", "entries": "[]"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "上限") {
		t.Fatalf("status=%d body=%s, want 400 上限", rec.Code, rec.Body.String())
	}
}

func TestRemoveIPFromList_rejectsNonCanonicalIDs(t *testing.T) {
	for _, id := range []string{"5.0", "%205", "abc", "0", "-1"} {
		t.Run(id, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newIPListRouter(t)
			if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (5,'ids','[{"value":"203.0.113.8","remark":""}]')`); err != nil {
				t.Fatal(err)
			}
			response := postJSON(t, router, "/security/ip-lists/"+id+"/remove-ip", map[string]any{"value": "203.0.113.8"})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("id %q status=%d body=%s, want canonical-id 400", id, response.Code, response.Body.String())
			}
		})
	}

	// 回归：规范十进制 ID 正常移除。
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (5,'ids','[{"value":"203.0.113.8","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	response := postJSON(t, router, "/security/ip-lists/5/remove-ip", map[string]any{"value": "203.0.113.8"})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"removed":true`) {
		t.Fatalf("canonical id status=%d body=%s, want successful removal", response.Code, response.Body.String())
	}
}

func TestIPListHandlers_emptyEntriesAreNormalized(t *testing.T) {
	for _, operation := range []string{"get", "update", "add", "remove"} {
		t.Run(operation, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newIPListRouter(t)
			if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (5,'empty','')`); err != nil {
				t.Fatal(err)
			}
			var response *httptest.ResponseRecorder
			switch operation {
			case "get":
				response = getRequest(t, router, "/security/ip-lists/5")
			case "update":
				response = putJSON(t, router, "/security/ip-lists/5", map[string]any{"description": "changed"})
			case "add":
				response = postJSON(t, router, "/security/ip-lists/5/ips", map[string]any{"value": "203.0.113.8"})
			case "remove":
				response = postJSON(t, router, "/security/ip-lists/5/remove-ip", map[string]any{"value": "203.0.113.8"})
			}
			if response.Code != http.StatusOK {
				t.Fatalf("%s empty entries status=%d body=%s, want normalized 200", operation, response.Code, response.Body.String())
			}
			if operation == "get" && (!strings.Contains(response.Body.String(), `"entries":[]`) || !strings.Contains(response.Body.String(), `"entry_count":0`)) {
				t.Fatalf("get empty entries body=%s, want []/0", response.Body.String())
			}
			if operation == "remove" && !strings.Contains(response.Body.String(), `"removed":false`) {
				t.Fatalf("remove empty entries body=%s, want idempotent removed=false", response.Body.String())
			}
		})
	}
}

func bigEntriesJSON(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"value":"10.1.0.%d","remark":""}`, i%250+1)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestUpdateIPList_fullReplaceAnd404(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	id := seedIPListRow(t, "旧名", `[{"value":"1.2.3.4","remark":""}]`)
	seedIPListRow(t, "占用名", "[]")

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"name": "新名", "entries": `[{"value":"192.0.2.1","remark":"改"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body.String())
	}
	var storedName, storedEntries string
	if err := db.DB.QueryRow("SELECT name, entries FROM security_ip_lists WHERE id=?", id).Scan(&storedName, &storedEntries); err != nil {
		t.Fatal(err)
	}
	if storedName != "新名" || !strings.Contains(storedEntries, "192.0.2.1") || strings.Contains(storedEntries, "1.2.3.4") {
		t.Fatalf("row=(%s,%s), want full replace", storedName, storedEntries)
	}

	rec = putJSON(t, router, "/security/ip-lists/424242", map[string]any{"name": "x"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing list status=%d, want 404", rec.Code)
	}
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"name": "占用名"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("dup name status=%d, want 409", rec.Code)
	}
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"entries": `[{"value":"bad","remark":""}]`})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid entry status=%d, want 400", rec.Code)
	}
}

func TestIPListNames_unicodeCaseInsensitiveUniqueness(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)

	first := postJSON(t, router, "/security/ip-lists", map[string]any{"name": "Ä", "entries": "[]"})
	if first.Code != http.StatusOK {
		t.Fatalf("create first status=%d body=%s", first.Code, first.Body.String())
	}
	duplicate := postJSON(t, router, "/security/ip-lists", map[string]any{"name": "ä", "entries": "[]"})
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("Unicode case variant create status=%d body=%s, want 409", duplicate.Code, duplicate.Body.String())
	}

	secondID := seedIPListRow(t, "另一个名单", "[]")
	rename := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", secondID), map[string]any{"name": "ä"})
	if rename.Code != http.StatusConflict {
		t.Fatalf("Unicode case variant rename status=%d body=%s, want 409", rename.Code, rename.Body.String())
	}
	var firstID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='Ä'`).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	self := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", firstID), map[string]any{"name": "ä"})
	if self.Code != http.StatusOK {
		t.Fatalf("case-only self rename status=%d body=%s, want 200", self.Code, self.Body.String())
	}
}

func TestDeleteIPList_referenceGuard(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	aclList := seedIPListRow(t, "acl-引用", "[]")
	wlList := seedIPListRow(t, "wl-引用", "[]")
	free := seedIPListRow(t, "未引用", "[]")

	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_list_refs, enabled) VALUES ('ACL引用策略', ?, 1)`, fmt.Sprintf("[%d]", aclList)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_whitelist_refs, enabled) VALUES ('WL引用策略', ?, 1)`, fmt.Sprintf("[%d]", wlList)); err != nil {
		t.Fatal(err)
	}

	rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", aclList))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "该 IP 列表正被 1 个启用的安全策略引用，请先解除引用") {
		t.Fatalf("acl-ref delete status=%d body=%s, want 409 guard", rec.Code, rec.Body.String())
	}
	rec = deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", wlList))
	if rec.Code != http.StatusConflict {
		t.Fatalf("wl-ref delete status=%d, want 409", rec.Code)
	}
	rec = deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", free))
	if rec.Code != http.StatusOK {
		t.Fatalf("unreferenced delete status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE id=?", free).Scan(&count); err != nil || count != 0 {
		t.Fatalf("row must be deleted, count=%d err=%v", count, err)
	}
	rec = deleteRequest(t, router, "/security/ip-lists/424242")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing delete status=%d, want 404", rec.Code)
	}
}

func TestAddIPToList_idempotentAndAppend(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	id := seedIPListRow(t, "追加目标", `[{"value":"10.0.0.1","remark":"手工"}]`)

	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "203.0.113.7"})
	if rec.Code != http.StatusOK {
		t.Fatalf("append status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Added bool `json:"added"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Data.Added {
		t.Fatalf("first append must report added=true: %s", rec.Body.String())
	}
	var entries string
	var updatedBy int
	if err := db.DB.QueryRow("SELECT entries, updated_by FROM security_ip_lists WHERE id=?", id).Scan(&entries, &updatedBy); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entries, `"203.0.113.7"`) || !strings.Contains(entries, "事件处置") {
		t.Fatalf("appended entry missing remark 事件处置: %s", entries)
	}

	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "203.0.113.7"})
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Added {
		t.Fatalf("duplicate append must report added=false: %s", rec.Body.String())
	}

	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "999.0.0.1"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid value status=%d, want 400", rec.Code)
	}
	rec = postJSON(t, router, "/security/ip-lists/424242/ips", map[string]any{"value": "1.2.3.4"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing list status=%d, want 404", rec.Code)
	}
}

func TestListIPLists_refCountsAndRefPolicies(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	target := seedIPListRow(t, "被引用列表", `[{"value":"10.0.0.0/8","remark":""},{"value":"192.0.2.0/24","remark":""}]`)
	for i := 0; i < 15; i++ {
		seedIPListRow(t, fmt.Sprintf("未引用-%d", i), "[]")
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_list_refs, enabled) VALUES ('ACL 引用方', ?, 1)`, fmt.Sprintf("[%d]", target)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_whitelist_refs, enabled) VALUES ('WL 引用方', ?, 1)`, fmt.Sprintf("[%d]", target)); err != nil {
		t.Fatal(err)
	}
	// 名称含目标 id 数字但未引用：Go 侧 JSON 解析不得产生 LIKE 式假阳性。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, enabled) VALUES (?, 1)`, fmt.Sprintf("名字带 %d 但不引用", target)); err != nil {
		t.Fatal(err)
	}

	rec := getRequest(t, router, "/security/ip-lists")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			ID          int `json:"id"`
			EntryCount  int `json:"entry_count"`
			RefCount    int `json:"ref_count"`
			RefPolicies []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"ref_policies"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// 夹具行数 + 内置系统名单（数量直接取自种子行，名单族增减不再需要改断言）
	var seedSystem int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1`).Scan(&seedSystem); err != nil {
		t.Fatal(err)
	}
	wantRows := 16 + seedSystem
	if resp.Code != 0 || len(resp.Data) != wantRows {
		t.Fatalf("code=%d rows=%d, want %d rows（16 夹具 + %d 内置名单）", resp.Code, len(resp.Data), wantRows, seedSystem)
	}
	for _, row := range resp.Data {
		if int64(row.ID) == target {
			if row.EntryCount != 2 || row.RefCount != 2 || len(row.RefPolicies) != 2 {
				t.Fatalf("target row=%+v, want entry_count=2 ref_count=2", row)
			}
			names := row.RefPolicies[0].Name + "," + row.RefPolicies[1].Name
			if !strings.Contains(names, "ACL 引用方") || !strings.Contains(names, "WL 引用方") {
				t.Fatalf("ref_policies=%+v, want both referencing policies", row.RefPolicies)
			}
			continue
		}
		if row.RefCount != 0 || len(row.RefPolicies) != 0 {
			t.Fatalf("unreferenced row %d ref_count=%d, want 0（不得交叉误报）", row.ID, row.RefCount)
		}
	}
}

func TestPolicyCreateUpdate_ipListRefs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "策略引用", `[{"value":"10.0.0.0/8","remark":""}]`)

	payload := map[string]any{
		"name": "带引用策略", "mode": "off",
		"ip_acl_list_refs":  fmt.Sprintf("[%d]", listID),
		"ip_whitelist_refs": "[]",
	}
	rec := postJSON(t, router, "/security/policies", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("create policy status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	rec = getRequest(t, router, fmt.Sprintf("/security/policies/%d", created.Data.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("get policy status=%d body=%s", rec.Code, rec.Body.String())
	}
	var detail struct {
		Data struct {
			Policy struct {
				IPACLListRefs   string `json:"ip_acl_list_refs"`
				IPWhitelistRefs string `json:"ip_whitelist_refs"`
			} `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Data.Policy.IPACLListRefs != fmt.Sprintf("[%d]", listID) {
		t.Fatalf("ip_acl_list_refs=%q, want [%d]", detail.Data.Policy.IPACLListRefs, listID)
	}
	if detail.Data.Policy.IPWhitelistRefs != "[]" {
		t.Fatalf("ip_whitelist_refs=%q, want []", detail.Data.Policy.IPWhitelistRefs)
	}

	// 空串归一为 "[]"。
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", created.Data.ID), map[string]any{"ip_acl_list_refs": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("update normalize status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := db.DB.QueryRow("SELECT ip_acl_list_refs FROM security_policies WHERE id=?", created.Data.ID).Scan(&detail.Data.Policy.IPACLListRefs); err != nil {
		t.Fatal(err)
	}
	if detail.Data.Policy.IPACLListRefs != "[]" {
		t.Fatalf("after normalize refs=%q, want []", detail.Data.Policy.IPACLListRefs)
	}

	// 更新持久化 + 未知 id 拒绝。
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", created.Data.ID), map[string]any{"ip_whitelist_refs": fmt.Sprintf("[%d]", listID)})
	if rec.Code != http.StatusOK {
		t.Fatalf("update refs status=%d body=%s", rec.Code, rec.Body.String())
	}
	var wlRefs string
	if err := db.DB.QueryRow("SELECT ip_whitelist_refs FROM security_policies WHERE id=?", created.Data.ID).Scan(&wlRefs); err != nil {
		t.Fatal(err)
	}
	if wlRefs != fmt.Sprintf("[%d]", listID) {
		t.Fatalf("persisted ip_whitelist_refs=%q", wlRefs)
	}

	rec = postJSON(t, router, "/security/policies", map[string]any{"name": "悬空引用", "ip_acl_list_refs": "[999]"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "引用了不存在的 IP 列表 #999") {
		t.Fatalf("unknown ref status=%d body=%s, want 400 #999", rec.Code, rec.Body.String())
	}
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", created.Data.ID), map[string]any{"ip_acl_list_refs": "[888]"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "引用了不存在的 IP 列表 #888") {
		t.Fatalf("update unknown ref status=%d body=%s, want 400 #888", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, router, "/security/policies", map[string]any{"name": "坏形状", "ip_acl_list_refs": `["x"]`})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad shape status=%d, want 400", rec.Code)
	}
}

func TestListSecurityPolicies_summaryCarriesRefs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "摘要引用", "[]")
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_list_refs, enabled) VALUES ('摘要策略', ?, 1)`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
	rec := getRequest(t, router, "/security/policies")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			Name          string `json:"name"`
			HasIPControl  bool   `json:"has_ip_control"`
			IPACLListRefs string `json:"ip_acl_list_refs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 || resp.Data[0].IPACLListRefs != fmt.Sprintf("[%d]", listID) {
		t.Fatalf("summary=%+v, want refs carried", resp.Data)
	}
}

// DeleteIPList 引用门与 DeleteSecurityCustomRule/
// DeleteSecurityBlockPage 同口径——仅 enabled=1 策略的引用阻止删除；禁用策略
// 的悬空引用由重启用门兜底（UpdateSecurityPolicy 重启用时按
// 「显式值 ?? 存量值」有效形态过 validateIPListRefsExistence，见
// handlers/security.go 重启用门段）。
func TestDeleteIPList_referenceGuardEnabledPoliciesOnly(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	aclDisabled := seedIPListRow(t, "acl-禁用引用", "[]")
	wlDisabled := seedIPListRow(t, "wl-禁用引用", "[]")
	crsDisabled := seedIPListRow(t, "crs-禁用引用", "[]")
	enabledRef := seedIPListRow(t, "启用引用", "[]")

	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_list_refs, enabled) VALUES ('禁用ACL策略', ?, 0)`, fmt.Sprintf("[%d]", aclDisabled)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_whitelist_refs, enabled) VALUES ('禁用WL策略', ?, 0)`, fmt.Sprintf("[%d]", wlDisabled)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, crs_excluded_rules, enabled) VALUES ('禁用CRS策略', ?, 0)`, fmt.Sprintf(`[{"target":"942100","scope":"list","listRefs":[%d]}]`, crsDisabled)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_list_refs, enabled) VALUES ('启用ACL策略', ?, 1)`, fmt.Sprintf("[%d]", enabledRef)); err != nil {
		t.Fatal(err)
	}

	// 目标形状：仅被禁用策略引用的列表可删（三引用通道同口径）
	for _, id := range []int64{aclDisabled, wlDisabled, crsDisabled} {
		rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("delete list %d referenced only by disabled policy: status=%d body=%s, want 200", id, rec.Code, rec.Body.String())
		}
		var count int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE id=?", id).Scan(&count); err != nil || count != 0 {
			t.Fatalf("list %d must be deleted, count=%d err=%v", id, count, err)
		}
	}
	// 回归形状：启用策略引用仍 409
	rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", enabledRef))
	if rec.Code != http.StatusConflict {
		t.Fatalf("enabled-ref delete status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
}

// 配套钉住（有意不对称，非遗漏）：UpdateIPList 清空门保持偏严——
// 禁用 allow 策略引用的列表同样禁止清空（不按 enabled 过滤）。重启用门
// 只校验引用存在性、不校验引用列表条目非空，门只数 ref ID
// 个数；若清空门放过禁用策略，重启用后 allow+空生效名单 fail-open 无兜底。
func TestUpdateIPList_clearGateCountsDisabledAllowPolicy(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	id := seedIPListRow(t, "被禁用allow策略引用", `[{"value":"10.0.0.1","remark":""}]`)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, enabled) VALUES ('禁用allow策略', 1, 'allow', ?, 0)`, fmt.Sprintf("[%d]", id)); err != nil {
		t.Fatal(err)
	}
	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"entries": "[]"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("clearing list referenced by disabled allow policy: status=%d body=%s, want 409（重启用路径无空名单兜底，清空门须保持偏严）", rec.Code, rec.Body.String())
	}
}

// 安全域端点级实证：写端点在 bind 前经 guardConfiguredJSONBody——
// 配置 1MB 上限时 ≈2MB body 预检 413（未接 guard 的端点会落入正常校验 400）。
func TestCreateIPList_configuredBodyLimit413(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET request_body_max_size_mb=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	router := newIPListRouter(t)
	big := `{"name":"big","entries":"` + strings.Repeat("a", 2<<20) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/security/ip-lists", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(big))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s, want 413", rec.Code, rec.Body.String())
	}
}

// ---- 策略载荷构造（内联/引用名单变体）----

func policyPayloadAllow(name string, inline string, refIDs ...int64) map[string]any {
	refs := "[]"
	if len(refIDs) > 0 {
		parts := make([]string, len(refIDs))
		for i, id := range refIDs {
			parts[i] = fmt.Sprintf("%d", id)
		}
		refs = "[" + strings.Join(parts, ",") + "]"
	}
	return map[string]any{
		"name": name, "policy_type": "stage1", "mode": "blocking", "ip_acl_enabled": true, "ip_acl_mode": "allow",
		"ip_acl_list": inline, "ip_acl_list_refs": refs,
	}
}

func TestSecurityPolicyAllowMode_effectiveListNonEmpty(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	emptyID := seedIPListRow(t, "空名单", "[]")
	filledID := seedIPListRow(t, "有名单", `[{"value":"10.0.0.0/8","remark":""}]`)

	// 形状 1：引用存在但条目为空 → 生效 allow 集合为空，拒绝（旧实现只看引用个数）。
	rec := postJSON(t, router, "/security/policies", policyPayloadAllow("空引用", "[]", emptyID))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with empty referenced list status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	// 文案方向必须与发射语义一致：allow 空集 = 否定算子恒命中 = 拒绝全部
	// （全站锁死），不是「放行所有请求」。
	if !strings.Contains(rec.Body.String(), "拒绝所有请求") {
		t.Fatalf("empty allow message must explain fail-closed semantics, got %s", rec.Body.String())
	}

	// 形状 2：引用条目非空 → 通过。
	rec = postJSON(t, router, "/security/policies", policyPayloadAllow("非空引用", "[]", filledID))
	if rec.Code != http.StatusOK {
		t.Fatalf("create with non-empty referenced list status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	// 形状 3：纯 inline 非空 → 通过。
	rec = postJSON(t, router, "/security/policies", policyPayloadAllow("纯内联", `["198.51.100.0/24"]`))
	if rec.Code != http.StatusOK {
		t.Fatalf("create with inline entries status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	// 形状 4：更新为「空 inline + 引用空名单」→ 拒绝（合并后生效集合为空）。
	polyID := createTestPolicy(t, router, policyPayloadAllow("更新策略", "[]", filledID))
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", polyID), map[string]any{
		"ip_acl_list": "[]", "ip_acl_list_refs": fmt.Sprintf("[%d]", emptyID),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update to empty effective allow set status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}

	// 形状 5：多引用其一非空 → 通过（不要求每个 ref 非空）。
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", polyID), map[string]any{
		"ip_acl_list": "[]", "ip_acl_list_refs": fmt.Sprintf("[%d,%d]", emptyID, filledID),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update with one non-empty ref status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	// 形状 6：更新为「空 inline 且无引用」→ 拒绝（既有语义回归）。
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", polyID), map[string]any{
		"ip_acl_list": "[]", "ip_acl_list_refs": "[]",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update to no refs status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

func TestSecurityPolicyAllowMode_referenceLookupFailure500(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	if _, err := db.DB.Exec(`DROP TABLE security_ip_lists`); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, router, "/security/policies", policyPayloadAllow("查询失败", "[]", 1))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("reference lookup failure status=%d body=%s, want 500 (guard must not fail open)", rec.Code, rec.Body.String())
	}
}

func ipListEntriesForTest(t *testing.T, id int64) []string {
	t.Helper()
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("parse entries %q: %v", raw, err)
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Value
	}
	return out
}

func TestRemoveIPFromList_removesAllDuplicateValues(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "重复值", `[{"value":"1.2.3.4","remark":""},{"value":"1.2.3.4","remark":""},{"value":"5.6.7.8","remark":""}]`)

	// When：移除重复值
	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", listID), map[string]any{"value": "1.2.3.4"})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove duplicate status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	// Then：所有同值条目删除，异值保留
	got := ipListEntriesForTest(t, listID)
	if len(got) != 1 || got[0] != "5.6.7.8" {
		t.Fatalf("entries after duplicate removal=%v, want [5.6.7.8]", got)
	}
	// 回滚形状：事务失败（触发器）时 DB 保持原状
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_ip_list_update BEFORE UPDATE ON security_ip_lists BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", listID), map[string]any{"value": "5.6.7.8"})
	if rec.Code == http.StatusOK {
		t.Fatalf("injected update failure must not report success: %s", rec.Body.String())
	}
	if got := ipListEntriesForTest(t, listID); len(got) != 1 || got[0] != "5.6.7.8" {
		t.Fatalf("failed removal mutated entries=%v", got)
	}
}

func TestRemoveIPFromList_rejectsEmptyingAllowReferencedList(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "被引用名单", `[{"value":"10.0.0.0/8","remark":""}]`)

	// Given：allow 策略以「空 inline + 本名单引用」为生效集合
	rec := postJSON(t, router, "/security/policies", policyPayloadAllow("引用策略", "[]", listID))
	if rec.Code != http.StatusOK {
		t.Fatalf("seed policy status=%d body=%s", rec.Code, rec.Body.String())
	}

	// When：移除最后一条 → 生效 allow 集合将为空（fail-open），必须 409
	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", listID), map[string]any{"value": "10.0.0.0/8"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("emptying allow-referenced list status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	if got := ipListEntriesForTest(t, listID); len(got) != 1 {
		t.Fatalf("rejected removal mutated entries=%v", got)
	}

	// 多引用其一非空 / 策略 inline 非空 → 允许清空该名单
	otherID := seedIPListRow(t, "其他名单", `[{"value":"192.0.2.0/24","remark":""}]`)
	rec = postJSON(t, router, "/security/policies", policyPayloadAllow("多引用策略", "[]", listID, otherID))
	if rec.Code != http.StatusOK {
		t.Fatalf("seed multi-ref policy status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 删除 listID 仍被策略1（唯一引用）阻塞——先确认偏严语义：所有 allow 策略逐一检查
	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", listID), map[string]any{"value": "10.0.0.0/8"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("single-ref policy still blocks emptying status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
}

// 引用视图纳入受信代理面——列表接口须显式标注
// trusted_proxy_referenced（ref_policies 不伪造策略项，ref_count 合并展示）。
func TestIPListRefView_includesTrustedProxy(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "受信代理名单", `[{"value":"10.0.0.0/8","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
	rec := getRequest(t, router, "/security/ip-lists")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data []ipListRow `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, row := range payload.Data {
		if row.ID != int(listID) {
			continue
		}
		if !row.TrustedProxyReferenced {
			t.Fatal("trusted_proxy_referenced must be true")
		}
		if row.RefCount != 1 || len(row.RefPolicies) != 0 {
			t.Fatalf("ref_count=%d ref_policies=%d, want merged count 1 with no fake policy rows", row.RefCount, len(row.RefPolicies))
		}
		return
	}
	t.Fatalf("list %d missing from response", listID)
}

func TestAllowEffectiveListNonEmpty_ignoresExpiredEntries(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	id := seedIPListRow(t, "expired-allow", `[{"value":"203.0.113.7","expires_at":"2000-01-01 00:00:00"}]`)
	nonEmpty, err := allowEffectiveListNonEmpty(db.DB, "[]", fmt.Sprintf("[%d]", id))
	if err != nil {
		t.Fatal(err)
	}
	if nonEmpty {
		t.Fatal("expired-only referenced list must not count as non-empty allow set")
	}
	id2 := seedIPListRow(t, "future-allow", `[{"value":"203.0.113.8","expires_at":"2999-01-01 00:00:00"}]`)
	nonEmpty, err = allowEffectiveListNonEmpty(db.DB, "[]", fmt.Sprintf("[%d]", id2))
	if err != nil {
		t.Fatal(err)
	}
	if !nonEmpty {
		t.Fatal("future entry must count as non-empty allow set")
	}
}

// 保存一组「全部已到期」的条目等价于生效集合为空——
// allow 引用名单的清空门不得被原始 len>0 绕过（与 remove-ip 的同源
// 判据用 AutobanActiveEntries 过滤后的有效集合，渲染侧同口径）。此前仅
// remove-ip 修了口径，UpdateIPList 仍按原始条目数判定 ⇒ allow 策略 fail-open。
func TestUpdateIPList_expiredOnlyEntriesBlockedByAllowPolicy(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	id := seedIPListRow(t, "allow-引用-到期条目", `[{"value":"10.0.0.1","remark":""}]`)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, enabled) VALUES ('启用allow策略', 1, 'allow', ?, 1)`, fmt.Sprintf("[%d]", id)); err != nil {
		t.Fatal(err)
	}

	// 形状 1：仅已到期条目 → 生效集合为空 → 409（原实现 len(entries)>0 放行）
	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"entries": `[{"value":"10.9.9.9","remark":"","expires_at":"2000-01-01 00:00:00"}]`,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("expired-only save status=%d body=%s, want 409（生效集合为空=放行全部）", rec.Code, rec.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "10.0.0.1") {
		t.Fatalf("rejected save must not mutate entries, got %s", stored)
	}

	// 形状 2（回归）：含一条未到期条目 → 生效集合非空 → 200
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"entries": `[{"value":"10.9.9.9","remark":"","expires_at":"2099-01-01 00:00:00"},{"value":"10.9.9.10","remark":"","expires_at":"2000-01-01 00:00:00"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("active+expired save status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

// 幂等无写分支（追加已生效条目 / 移除不在名单的值）只做 SELECT + 内存比较，
// 事务内没有写语句：不得 Commit，也不得把「不可能发生的提交错误」报成
// 「提交结果不确定」（会诱导调用方重试并占住连接锁）。结构钉按 AST 定位
// 两个 handler，任何新增的 tx.Commit 调用都会转红。
func TestIPListIdempotentBranches_doNotCommit(t *testing.T) {
	source, err := os.ReadFile("securityiplists.go")
	if err != nil {
		t.Fatalf("read securityiplists.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "securityiplists.go", source, 0)
	if err != nil {
		t.Fatalf("parse securityiplists.go: %v", err)
	}
	for _, name := range []string{"AddIPToList", "RemoveIPFromList"} {
		fn := findFuncDecl(file, name)
		if fn == nil {
			t.Fatalf("securityiplists.go 缺少函数 %s", name)
		}
		commits := 0
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && isTxCommitCall(call) {
				commits++
			}
			return true
		})
		if commits != 0 {
			t.Fatalf("%s 含 %d 处 tx.Commit（幂等无写路径必须只回滚；提交统一在共享 applier 内）", name, commits)
		}
	}
}

// 条目实际变化判定按解析后的集合比较：键序/空白/数组重排（前端序列化差异、
// MCP 客户端重排）不得判为变化而触发热路径重写与审计噪音；任一字段真实
// 变化必须检出。
func TestIPListEntriesChanged_semanticComparison(t *testing.T) {
	cases := []struct {
		name    string
		oldJSON string
		newJSON string
		changed bool
	}{
		{"同字节", `[{"value":"10.0.0.1","remark":""}]`, `[{"value":"10.0.0.1","remark":""}]`, false},
		{"键序与空白差异", `[{"value":"10.0.0.1","remark":"a"}]`, `[ { "remark" : "a" , "value" : "10.0.0.1" } ]`, false},
		{"数组重排", `[{"value":"10.0.0.1"},{"value":"10.0.0.2"}]`, `[{"value":"10.0.0.2"},{"value":"10.0.0.1"}]`, false},
		{"备注变化", `[{"value":"10.0.0.1","remark":"a"}]`, `[{"value":"10.0.0.1","remark":"b"}]`, true},
		{"到期时间变化", `[{"value":"10.0.0.1","expires_at":"2099-01-01 00:00:00"}]`, `[{"value":"10.0.0.1"}]`, true},
		{"条目增减", `[{"value":"10.0.0.1"}]`, `[{"value":"10.0.0.1"},{"value":"10.0.0.2"}]`, true},
		{"左值脏行退回字节比较", `not-json`, `[{"value":"10.0.0.1"}]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ipListEntriesChanged(tc.oldJSON, tc.newJSON); got != tc.changed {
				t.Fatalf("changed=%v, want %v", got, tc.changed)
			}
		})
	}
}

// buildIPListEntries 造 n 条合法条目（可选到期时间），供上限/剔除用例复用。
func buildIPListEntries(t *testing.T, n int, expiresAt string) []models.IPListEntry {
	t.Helper()
	entries := make([]models.IPListEntry, 0, n)
	for i := range n {
		entries = append(entries, models.IPListEntry{
			Value:     fmt.Sprintf("10.%d.%d.1", i/256, i%256),
			ExpiresAt: expiresAt,
		})
	}
	return entries
}

func marshalIPListEntries(t *testing.T, entries []models.IPListEntry) string {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// 条目上限按**生效**条目计：自动封禁关闭后到期条目不再被任务
// 清理，按原始长度计上限会让「生效 2000 + 到期残留」的整表保存被 400 挡下，
// 用户只能逐行删除到期行。保存时到期条目被剔除（到期即解封），原始条数与
// 生效条数不再有两个口径。
func TestIPListSave_capCountsActiveEntriesAndPrunesExpired(t *testing.T) {
	const expiredAt = "2000-01-01 00:00:00"
	t.Run("生效 2000 + 到期残留 5 → 放行且剔除到期条目", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newIPListRouter(t)
		listID := seedIPListRow(t, "active-cap-ok", `[]`)
		payload := append(buildIPListEntries(t, ipListMaxEntries, ""), buildIPListEntries(t, 5, expiredAt)...)
		rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
			"entries": marshalIPListEntries(t, payload),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s（生效条目未超上限，到期残留不得挡下保存）", rec.Code, rec.Body.String())
		}
		var payloadResp struct {
			Data struct {
				EntryCount    int `json:"entry_count"`
				PrunedExpired int `json:"pruned_expired"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payloadResp); err != nil {
			t.Fatalf("decode: %v body=%s", err, rec.Body.String())
		}
		if payloadResp.Data.EntryCount != ipListMaxEntries || payloadResp.Data.PrunedExpired != 5 {
			t.Fatalf("响应披露=(entry_count=%d, pruned_expired=%d), want (%d, 5)",
				payloadResp.Data.EntryCount, payloadResp.Data.PrunedExpired, ipListMaxEntries)
		}
		var stored string
		if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, listID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		var parsed []models.IPListEntry
		if err := json.Unmarshal([]byte(stored), &parsed); err != nil {
			t.Fatalf("stored entries: %v", err)
		}
		if len(parsed) != ipListMaxEntries {
			t.Fatalf("落库条目=%d, want %d（到期条目必须剔除）", len(parsed), ipListMaxEntries)
		}
		for _, entry := range parsed {
			if entry.ExpiresAt != "" {
				t.Fatalf("到期条目未被剔除: %+v", entry)
			}
		}
	})

	t.Run("生效 2001 → 400 且文案点明生效口径", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newIPListRouter(t)
		listID := seedIPListRow(t, "active-cap-over", `[]`)
		payload := append(buildIPListEntries(t, ipListMaxEntries+1, ""), buildIPListEntries(t, 5, expiredAt)...)
		rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
			"entries": marshalIPListEntries(t, payload),
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "生效条目数量不能超过") {
			t.Fatalf("错误文案未点明生效口径: %s", body)
		}
	})

	t.Run("仅剩到期条目的保存仍走 allow 空集门", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newIPListRouter(t)
		listID := seedIPListRow(t, "all-expired", `[]`)
		// 引用该名单的 allow 策略：清空（到期剔除后为空集）必须 409。
		if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs) VALUES ('all-expired-policy','off',1,1,'allow',?)`, fmt.Sprintf("[%d]", listID)); err != nil {
			t.Fatal(err)
		}
		rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{
			"entries": marshalIPListEntries(t, buildIPListEntries(t, 3, expiredAt)),
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s, want 409（生效集变空必须拦截）", rec.Code, rec.Body.String())
		}
	})
}

// 名单「引用」展示含禁用策略（展示面全量），删除门只计启用——引用项必须
// 携带启用态，并单独给出阻止删除的引用数：否则页面出现
// 「显示有引用却可删除」，删除后禁用策略留下悬空引用（重启用时才 400）。
func TestIPListRefs_exposeEnabledStateAndBlockingCount(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "refs-enabled", `[{"value":"203.0.113.1"}]`)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs) VALUES ('refs-enabled-on','off',1,1,'deny',?)`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs) VALUES ('refs-enabled-off','off',0,1,'deny',?)`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}

	rec := getRequest(t, router, "/security/ip-lists")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data []struct {
			ID              int               `json:"id"`
			RefCount        int               `json:"ref_count"`
			RefCountEnabled int               `json:"ref_count_enabled"`
			RefPolicies     []ipListRefPolicy `json:"ref_policies"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	rowIdx := -1
	for i := range payload.Data {
		if payload.Data[i].ID == int(listID) {
			rowIdx = i
		}
	}
	if rowIdx < 0 {
		t.Fatalf("名单 #%d 不在列表响应中: %s", listID, rec.Body.String())
	}
	row := payload.Data[rowIdx]
	if row.RefCount != 2 || row.RefCountEnabled != 1 {
		t.Fatalf("ref_count=%d ref_count_enabled=%d, want 2/1", row.RefCount, row.RefCountEnabled)
	}
	states := map[string]bool{}
	for _, ref := range row.RefPolicies {
		states[ref.Name] = ref.Enabled
	}
	if !states["refs-enabled-on"] || states["refs-enabled-off"] {
		t.Fatalf("引用启用态错配: %+v", row.RefPolicies)
	}
	// 删除门只计启用——禁用引用的存在不阻止删除（既有裁定，展示口径不得改变门）。
	if _, err := db.DB.Exec(`UPDATE security_policies SET enabled=0 WHERE name='refs-enabled-on'`); err != nil {
		t.Fatal(err)
	}
	delRec := httptest.NewRecorder()
	router.ServeHTTP(delRec, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/security/ip-lists/%d", listID), nil))
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200（禁用引用不阻止删除）", delRec.Code, delRec.Body.String())
	}
}

// 备注控制字符门：导出件以「值 空格 备注」逐行组文本，备注含换行会造出伪条目
// （导出再导入即误加 IP）；制表/回车/其他控制字符同样破坏行结构与展示。
func TestValidateIPListShape_rejectsControlCharsInRemark(t *testing.T) {
	shape := func(remark string) error {
		entries := fmt.Sprintf(`[{"value":"198.51.100.1","remark":%q}]`, remark)
		_, _, err := validateIPListShape("list", "", "cat", entries)
		return err
	}
	for _, bad := range []string{"a\n1.2.3.4", "a\rb", "a\tb", "a\x00b", "a\x1fb", "a\x7fb"} {
		if err := shape(bad); err == nil {
			t.Errorf("备注 %q 必须被拒（控制字符破坏导出行结构）", bad)
		}
	}
	for _, ok := range []string{"", "正常备注", "ip 归属地：美国", "a b"} {
		if err := shape(ok); err != nil {
			t.Errorf("备注 %q 不应被拒: %v", ok, err)
		}
	}
}

// 元数据-only 更新（entries 缺席）是独立分支：存量条目不是本次输入，不得重跑
// 条目校验——存量含脏值（导入遗留/带外改库）时改名/改描述不应被
// 「条目 N 包含无效的 IP/CIDR」400 挡死（文案与用户动作不匹配、无自助修复入口）。
// 审计条数取库内行数（与导出/删除口径一致），而非到期剔除后的生效条数。
func TestUpdateIPList_metadataOnlyToleratesDirtyStoredEntries(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	const seed = `[{"value":"bad-ip","remark":"x"},{"value":"203.0.113.9","expires_at":"2000-01-01 00:00:00"}]`
	listID := seedIPListRow(t, "脏条目名单", seed)

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{"description": "只改描述"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（元数据-only 不得重校验存量条目）", rec.Code, rec.Body.String())
	}
	// 条目文本原样写回（不丢数据、不静默剔除到期行）
	var entries string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE id=?`, listID).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if entries != seed {
		t.Fatalf("entries=%q, want 原样 %q", entries, seed)
	}
	// 审计条数=库内行数（2），不是到期剔除后的生效条数（1）
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='IP 地址列表' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(detail, "，2 条）") {
		t.Fatalf("audit detail=%q, want 库内行数 2 条（与导出/删除口径一致）", detail)
	}

	// 回归形状：带 entries 的整表保存仍走全量校验（脏值必须 400，不得借
	// 元数据分支放行）
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", listID), map[string]any{"entries": `[{"value":"bad-ip"}]`})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("整表保存脏条目 status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

// 详情端点必须与列表同口径装载引用面：ref_count/ref_count_enabled/
// ref_policies/trusted_proxy_* 此前在详情恒零值且 ref_policies 为 null
// （前端契约声明非可选数组），消费详情的调用方会把被引用名单看成 0 引用。
func TestGetIPList_detailCarriesRefSurface(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	listID := seedIPListRow(t, "详情引用面", `[{"value":"10.0.0.0/8","remark":""}]`)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_list_refs, enabled) VALUES ('详情引用方', ?, 1)`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf("[%d]", listID)); err != nil {
		t.Fatal(err)
	}

	rec := getRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", listID))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"ref_policies":null`) {
		t.Fatalf("ref_policies 必须归一为数组（前端契约非可选）：%s", rec.Body.String())
	}
	var payload struct {
		Data ipListRow `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	row := payload.Data
	if row.RefCount != 2 || row.RefCountEnabled != 2 {
		t.Fatalf("ref_count=%d ref_count_enabled=%d, want 2/2（1 策略引用 + 受信代理）", row.RefCount, row.RefCountEnabled)
	}
	if len(row.RefPolicies) != 1 || row.RefPolicies[0].Name != "详情引用方" {
		t.Fatalf("ref_policies=%+v, want 单个「详情引用方」", row.RefPolicies)
	}
	if !row.TrustedProxyReferenced || row.TrustedProxyScope != "受信代理网段" {
		t.Fatalf("trusted_proxy=(%v,%q), want (true,受信代理网段)", row.TrustedProxyReferenced, row.TrustedProxyScope)
	}

	// 回归形状：无引用名单的详情 ref_policies 为 [] 且计数 0
	plainID := seedIPListRow(t, "无引用详情", `[{"value":"192.0.2.1"}]`)
	rec = getRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", plainID))
	if rec.Code != http.StatusOK {
		t.Fatalf("plain detail status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.RefCount != 0 || payload.Data.RefPolicies == nil || len(payload.Data.RefPolicies) != 0 {
		t.Fatalf("plain row ref=(%d,%v), want (0, 空数组)", payload.Data.RefCount, payload.Data.RefPolicies)
	}
}

func TestIPListHandlers_corruptAutobanEntriesPointToFullReplacement(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, services.AutobanPresetListName).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='{bad' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"/ips", "/remove-ip"} {
		recorder := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d%s", id, suffix), map[string]any{"value": "203.0.113.9"})
		if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "整表覆盖") || strings.Contains(recorder.Body.String(), "删除后重建") {
			t.Fatalf("%s status=%d body=%s, want 500 + 可执行的整表覆盖提示", suffix, recorder.Code, recorder.Body.String())
		}
	}
	recorder := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"name": services.AutobanPresetListName, "entries": "[]"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("整表覆盖应可修复损坏条目: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

// 500 分片样板单源：chunkIDs 声明为「受信代理校验、备份导入、IP 名单、威胁
// 筛查四处消费」的唯一样板，但名单侧两处（allow 生效集合装载、引用存在性
// 校验）此前仍是手写 start+=500 循环——两套样板并行演进（一处改块大小/占位
// 符构造，另一处静默保持旧语义）。按函数体源码扫描把「手写分片」钉成失败。
func TestSecurityIPListSharding_usesChunkIDsSingleSource(t *testing.T) {
	source, err := os.ReadFile("securityiplists.go")
	if err != nil {
		t.Fatalf("read securityiplists.go: %v", err)
	}
	for _, signature := range []string{
		"func loadIPListEntriesForAllow(q ipListQueryer, ids []int64) (map[int64][]string, error) {",
		"func validateIPListRefsExistence(q policyQueryRower, aclIDs, wlIDs []int64) (string, error) {",
	} {
		body, ok := handlerFunctionBody(string(source), signature)
		if !ok {
			t.Fatalf("securityiplists.go 中未找到 %q（函数改名/内联会让本守卫失效）", signature)
		}
		if !strings.Contains(body, "chunkIDs(") {
			t.Errorf("%q 未使用 chunkIDs 单源分片（chunkIDs 是全部 500 分片样板的唯一实现）", signature)
		}
		if strings.Contains(body, "start += ") {
			t.Errorf("%q 仍含手写分片循环（start += ...），必须改为 for _, ch := range chunkIDs(...)", signature)
		}
	}
}

// 分片等价性回归：引用 id 超过单块上限（500）时两处分片消费端必须跨块取全
// （单块 IN 查询会被 SQLite 变量上限截断/报错，或被实现遗漏成只查首块）。
func TestLoadIPListEntriesForAllow_spansMultipleChunks(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	const total = 501
	ids := make([]int64, 0, total)
	for i := 0; i < total; i++ {
		ids = append(ids, seedIPListRow(t, fmt.Sprintf("分片名单 %d", i+1), fmt.Sprintf(`[{"value":"10.%d.%d.1"}]`, i/250, i%250+1)))
	}
	out, err := loadIPListEntriesForAllow(db.DB, ids)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out) != total {
		t.Fatalf("装载 %d 个名单，want %d（跨块必须全取）", len(out), total)
	}
	for _, id := range []int64{ids[0], ids[499], ids[500]} { // 首块 / 首块末 / 次块首
		if values, ok := out[id]; !ok || len(values) != 1 {
			t.Fatalf("名单 #%d 条目=%v ok=%v, want 单条（跨块边界不得遗漏）", id, values, ok)
		}
	}
	// 去重形状：同一 id 重复引用不放大绑定变量，也不产生重复 key
	dup := append(append([]int64{}, ids...), ids[0], ids[500])
	out, err = loadIPListEntriesForAllow(db.DB, dup)
	if err != nil {
		t.Fatalf("load dup: %v", err)
	}
	if len(out) != total {
		t.Fatalf("重复引用后装载 %d，want %d", len(out), total)
	}
}

// 引用存在性校验同样跨块：501 个引用全部存在时不得漏报缺失；缺失项优先按
// acl 组报告（组序口径不因分片数变化）。
func TestValidateIPListRefsExistence_spansMultipleChunks(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	const total = 501
	ids := make([]int64, 0, total)
	for i := 0; i < total; i++ {
		ids = append(ids, seedIPListRow(t, fmt.Sprintf("存在性名单 %d", i+1), `[]`))
	}
	if msg, err := validateIPListRefsExistence(db.DB, ids, nil); err != nil || msg != "" {
		t.Fatalf("全部存在不得报缺失: msg=%q err=%v", msg, err)
	}
	// 缺失项落在次块：必须仍被检出
	missing := append(append([]int64{}, ids...), 999999)
	if msg, err := validateIPListRefsExistence(db.DB, missing, nil); err != nil || !strings.Contains(msg, "#999999") {
		t.Fatalf("次块缺失项 msg=%q err=%v, want 报告 #999999", msg, err)
	}
}
