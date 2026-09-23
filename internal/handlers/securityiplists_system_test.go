package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 内置只读名单（威胁情报库，system=1）写保护（v2.3.2 名单化重构）：
// 更新/删除/追加条目/同名新建一律响亮拒绝——内容由更新任务独占维护。
func TestIPListWritePaths_rejectSystemLists(t *testing.T) {
	h := newBackupTestHandlers(t)
	var sysID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&sysID); err != nil {
		t.Fatalf("system list seed missing: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/ip-lists", h.CreateIPList)
	router.PUT("/security/ip-lists/:id", h.UpdateIPList)
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)
	router.POST("/security/ip-lists/:id/ips", h.AddIPToList)

	var sysName string
	if err := db.DB.QueryRow(`SELECT name FROM security_ip_lists WHERE id=?`, sysID).Scan(&sysName); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		method, path, body string
	}{
		{http.MethodPut, "/security/ip-lists/" + strconv.Itoa(sysID), `{"entries":"[{\"value\":\"1.2.3.4\"}]"}`},
		{http.MethodDelete, "/security/ip-lists/" + strconv.Itoa(sysID), ""},
		{http.MethodPost, "/security/ip-lists/" + strconv.Itoa(sysID) + "/ips", `{"value":"1.2.3.4"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest && resp.Code != http.StatusConflict && resp.Code != http.StatusForbidden {
			t.Fatalf("%s %s → %d, want 响亮拒绝（400/409/403）: %s", tc.method, tc.path, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "内置") {
			t.Fatalf("%s %s body=%s, want 含「内置」", tc.method, tc.path, resp.Body.String())
		}
	}

	// 同名新建（占用内置名单名）
	req := httptest.NewRequest(http.MethodPost, "/security/ip-lists", strings.NewReader(`{"name":"`+sysName+`","entries":"[]"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code == http.StatusOK {
		t.Fatalf("占用内置名单名新建不得成功: %s", resp.Body.String())
	}

	// 回归形状：普通列表照常可写
	var userID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=0 ORDER BY id LIMIT 1`).Scan(&userID); err != nil {
		// 没有普通列表则建一个
		req := httptest.NewRequest(http.MethodPost, "/security/ip-lists", strings.NewReader(`{"name":"用户列表-v232","entries":"[]"}`))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("普通列表创建失败: %s", resp.Body.String())
		}
		if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='用户列表-v232'`).Scan(&userID); err != nil {
			t.Fatal(err)
		}
	}
	req2 := httptest.NewRequest(http.MethodPost, "/security/ip-lists/"+strconv.Itoa(userID)+"/ips", strings.NewReader(`{"value":"192.0.2.1"}`))
	req2.Header.Set("Content-Type", "application/json")
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, req2)
	if resp2.Code != http.StatusOK {
		t.Fatalf("普通列表追加条目被拒: %d %s", resp2.Code, resp2.Body.String())
	}
}
