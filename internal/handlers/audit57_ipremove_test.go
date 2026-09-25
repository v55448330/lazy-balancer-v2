package handlers

// 第 57 轮弹框重构后端（用户裁定）：IP 快捷弹框支持「从地址列表移除 IP」。
// 镜像 AddIPToList：system 只读守卫/事务/幂等语义/审计走 finishTxApply。
// 语义：值在名单中 → 移除并 200 {removed:true}；不在 → 200 {removed:false}
// （幂等，重复移除无害）；system=1 内置名单 → 400（威胁情报库维护，只读）。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func ipRemoveRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/ip-lists/:id/remove-ip", h.RemoveIPFromList)
	return router
}

func postRemove(t *testing.T, router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

type removeResult struct {
	Code int `json:"code"`
	Data struct {
		Removed bool `json:"removed"`
	} `json:"data"`
}

func decodeRemove(t *testing.T, rec *httptest.ResponseRecorder) removeResult {
	t.Helper()
	var r removeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("unmarshal %s: %v", rec.Body.String(), err)
	}
	return r
}

func TestRemoveIPFromList_removesEntry(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := ipRemoveRouter(t)
	id := seedIPListRow(t, "移除目标", `[{"value":"203.0.113.7","remark":"事件处置"},{"value":"10.0.0.1","remark":""}]`)

	rec := postRemove(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", id), map[string]any{"value": "203.0.113.7"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var entriesJSON string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, id).Scan(&entriesJSON); err != nil {
		t.Fatal(err)
	}
	if entriesJSON != `[{"value":"10.0.0.1","remark":""}]` {
		t.Fatalf("entries=%s, want 仅剩 10.0.0.1", entriesJSON)
	}
}

func TestRemoveIPFromList_idempotentWhenAbsent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := ipRemoveRouter(t)
	id := seedIPListRow(t, "移除幂等", `[{"value":"10.0.0.1","remark":""}]`)

	rec := postRemove(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", id), map[string]any{"value": "203.0.113.7"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200（幂等）", rec.Code)
	}
	if got := decodeRemove(t, rec).Data.Removed; got {
		t.Fatalf("removed=%v, want false（重复移除）", got)
	}
	var entriesJSON string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, id).Scan(&entriesJSON); err != nil {
		t.Fatal(err)
	}
	if entriesJSON != `[{"value":"10.0.0.1","remark":""}]` {
		t.Fatalf("entries=%s, want 原样", entriesJSON)
	}
}

func TestRemoveIPFromList_systemListRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := ipRemoveRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries, system) VALUES ('threat-ustc', '[{"value":"1.2.3.4","remark":""}]', 1)`); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='threat-ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	rec := postRemove(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", id), map[string]any{"value": "1.2.3.4"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（内置名单只读）", rec.Code, rec.Body.String())
	}
}
