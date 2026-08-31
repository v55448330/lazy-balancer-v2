package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func postBackupImport(t *testing.T, h *Handlers, backup string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// W2：策略 refs 引用备份内不存在的 IP 列表 → 整包 400 点名策略与悬挂 id，
// 零写入（与 R49 C-#2 绑定悬挂引用同口径——refs 落库后引用展开静默跳过，
// UI 宣称的引用控制静默失效）。
func TestImportConfigBackup_rejectsPolicyReferencingMissingIPList(t *testing.T) {
	// Given：策略引用列表 99，备份仅有列表 1
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_policies": {{"id": 7, "name": "refs-policy", "mode": "off", "ip_acl_list_refs": "[99]", "ip_whitelist_refs": "[1]"}},
		"security_ip_lists": {{"id": 1, "name": "list-1", "entries": "[]"}},
	})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	for _, want := range []string{"refs-policy", "引用了不存在的 IP 列表 99"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("rejection must name %q: %s", want, response.Body.String())
		}
	}
	for _, table := range []string{"security_policies", "security_ip_lists"} {
		var count int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("rejected backup must not persist %s, got %d rows", table, count)
		}
	}
}

// W2 对照组：引用完整的 refs + 列表（含空串 entries 视同 '[]'）导入成功并落库。
func TestImportConfigBackup_acceptsValidIPListReferences(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_policies": {{"id": 7, "name": "refs-policy", "mode": "off", "ip_acl_list_refs": "[1,2]", "ip_whitelist_refs": "[2]"}},
		"security_ip_lists": {
			{"id": 1, "name": "acl-list", "entries": `[{"value":"10.0.0.1","remark":"r"}]`},
			{"id": 2, "name": "wl-list", "entries": ""},
		},
	})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var aclRefs, wlRefs string
	if err := db.DB.QueryRow("SELECT ip_acl_list_refs,ip_whitelist_refs FROM security_policies WHERE id=7").Scan(&aclRefs, &wlRefs); err != nil {
		t.Fatalf("read imported policy refs: %v", err)
	}
	if aclRefs != "[1,2]" || wlRefs != "[2]" {
		t.Fatalf("imported refs mismatch: acl=%q whitelist=%q", aclRefs, wlRefs)
	}
	var listCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists").Scan(&listCount); err != nil {
		t.Fatalf("count imported ip lists: %v", err)
	}
	if listCount != 2 {
		t.Fatalf("imported ip lists=%d, want 2", listCount)
	}
}

// W2：refs 形状门——必须是整数数组的 JSON 文本（字符串列），非数组 JSON、
// 非整数元素、非字符串类型均 400 点名字段。
func TestImportConfigBackup_rejectsMalformedIPListRefs(t *testing.T) {
	tests := []struct {
		name  string
		refs  any
		field string
	}{
		{name: "non-array json", refs: `{"x":1}`, field: "ip_acl_list_refs"},
		{name: "non-integer elements", refs: `["a","b"]`, field: "ip_acl_list_refs"},
		{name: "fractional elements", refs: `[1.5]`, field: "ip_whitelist_refs"},
		{name: "non-string inline array", refs: []any{1, 2}, field: "ip_acl_list_refs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			policy := map[string]any{"id": 7, "name": "refs-policy", "mode": "off"}
			policy[tt.field] = tt.refs
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"security_policies": {policy},
				"security_ip_lists": {{"id": 1, "name": "list-1", "entries": "[]"}},
			})

			// When
			response := postBackupImport(t, h, backup)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			for _, want := range []string{tt.field, "需为整数数组的 JSON 文本"} {
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("rejection must name %q: %s", want, response.Body.String())
				}
			}
		})
	}
}

// W2：security_ip_lists.entries 形状门——备份携带该表时 entries 需为 JSON
// 数组文本（空串视同 '[]'）；非 JSON / 非数组 / 非字符串类型均 400 点名行。
func TestImportConfigBackup_rejectsIPListWithInvalidEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries any
	}{
		{name: "not json", entries: "not-json"},
		{name: "json object not array", entries: `{"value":"10.0.0.1"}`},
		{name: "non-string type", entries: 123},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"security_ip_lists": {{"id": 1, "name": "bad-list", "entries": tt.entries}},
			})

			// When
			response := postBackupImport(t, h, backup)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			for _, want := range []string{"安全 IP 列表 #1", "entries 需为 JSON 数组文本"} {
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("rejection must name %q: %s", want, response.Body.String())
				}
			}
		})
	}
}

// W2：导出携带 security_ip_lists 行与策略 refs 列（导出/导入往返不丢引用）。
func TestExportConfigBackup_includesSecurityIPLists(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries) VALUES (3,'exp-list','d','allow','[{"value":"10.0.0.1","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,ip_acl_list_refs) VALUES (4,'p','off','[3]')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var backup configBackup
	if err := json.Unmarshal(response.Body.Bytes(), &backup); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	listRows, ok := backup.Tables["security_ip_lists"]
	if !ok || len(listRows) != 1 {
		t.Fatalf("export must carry security_ip_lists with 1 row, got %+v", backup.Tables["security_ip_lists"])
	}
	if listRows[0]["name"] != "exp-list" || listRows[0]["category"] != "allow" {
		t.Fatalf("exported ip list row mismatch: %+v", listRows[0])
	}
	policyRows := backup.Tables["security_policies"]
	if len(policyRows) != 1 || policyRows[0]["ip_acl_list_refs"] != "[3]" {
		t.Fatalf("exported policy refs missing: %+v", policyRows)
	}
}

// W2：全量替换语义——备份携带空 security_ip_lists 表（主节点已清空）时，
// 导入必须清掉本地列表行（deleteOrder/insertOrder 含新表）。
func TestImportConfigBackup_emptyIPListsTableWipesLocalLists(t *testing.T) {
	// Given：本地存在备份之外的列表行
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (11,'local-only','[]')`); err != nil {
		t.Fatal(err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip_lists": {},
	})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("security_ip_lists rows=%d after empty-table import, want 0", count)
	}
}
