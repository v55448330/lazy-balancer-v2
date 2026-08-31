package handlers

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
	router.PUT("/security/ip-lists/:id", h.UpdateIPList)
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)
	router.POST("/security/ip-lists/:id/ips", h.AddIPToList)
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
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
		{"too many entries", map[string]any{"name": "ok", "entries": bigEntriesJSON(501)}, 400, "条目数量"},
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
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "该 IP 列表正被 1 个安全策略引用，请先解除引用") {
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
	if resp.Code != 0 || len(resp.Data) != 16 {
		t.Fatalf("code=%d rows=%d, want 16 rows", resp.Code, len(resp.Data))
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
