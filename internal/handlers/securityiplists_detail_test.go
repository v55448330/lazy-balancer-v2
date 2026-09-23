package handlers

import (
	"encoding/json"
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
