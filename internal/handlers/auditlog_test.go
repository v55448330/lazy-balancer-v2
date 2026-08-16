package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetAuditLogs_returnsRawUtcForFrontendConversion(t *testing.T) {
	// Given
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := mainDB.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, timezone VARCHAR(50)); INSERT INTO global_config VALUES (1, 'Asia/Shanghai')"); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR(50), action VARCHAR(50), resource VARCHAR(100), detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('admin', '登录成功', '用户认证', '', '127.0.0.1', '2026-07-19 12:00:00')"); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/audit-logs", h.GetAuditLogs)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/audit-logs?page=1&page_size=10", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			List []struct {
				CreatedAt string `json:"created_at"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Data.List) != 1 {
		t.Fatalf("expected 1 log, got %d", len(body.Data.List))
	}
	// 后端统一返回裸 UTC 字符串（时区转换由前端 formatDate 按 /config 时区执行），
	// 避免历史上"后端转一次 + 前端再转一次"的 +8h 双重转换。
	if body.Data.List[0].CreatedAt != "2026-07-19 12:00:00" {
		t.Fatalf("created_at = %q, want raw UTC \"2026-07-19 12:00:00\" (conversion belongs to the frontend)", body.Data.List[0].CreatedAt)
	}
}

func TestGetAuditLogs_falls_back_to_username_when_user_lookup_fails(t *testing.T) {
	// Given
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		_ = mainDB.Close()
		_ = auditDB.Close()
	})
	if _, err := mainDB.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, timezone VARCHAR(50)); INSERT INTO global_config VALUES (1, 'UTC')"); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, username TEXT, action TEXT, resource TEXT, detail TEXT, ip_address TEXT, created_at DATETIME); INSERT INTO audit_log VALUES (1, 'deleted-user', '更新', '配置', '', '', '2026-07-19 12:00:00')"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/audit-logs", (&Handlers{}).GetAuditLogs)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			List []struct {
				DisplayName string `json:"display_name"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Data.List) != 1 || body.Data.List[0].DisplayName != "deleted-user" {
		t.Fatalf("logs=%+v, want username fallback", body.Data.List)
	}
}

// newAuditLogTestRouter 构建带主/审计双库的 GetAuditLogs 测试环境，返回 router。
func newAuditLogTestRouter(t *testing.T, rows string) *gin.Engine {
	t.Helper()
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := mainDB.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, timezone VARCHAR(50)); INSERT INTO global_config VALUES (1, 'Asia/Shanghai')"); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR(50), action VARCHAR(50), resource VARCHAR(100), detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		t.Fatal(err)
	}
	if rows != "" {
		if _, err := auditDB.Exec(rows); err != nil {
			t.Fatal(err)
		}
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/audit-logs", (&Handlers{}).GetAuditLogs)
	return router
}

func TestGetAuditLogs_filtersByColumnsAndDetail(t *testing.T) {
	// Given
	router := newAuditLogTestRouter(t, `
		INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES
		('admin', '登录成功', '用户认证', '登录成功', '10.0.0.1', '2026-08-01 00:00:00'),
		('ops',    '创建',     '规则',     '创建规则 lb_x', '192.168.1.5', '2026-08-02 00:00:00'),
		('admin',  '删除',     '规则',     '删除规则 lb_y', '10.0.0.1', '2026-08-03 00:00:00')`)

	// When/Then: 按操作人
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/audit-logs?username=adm", nil))
	assertAuditRows(t, resp, 2)

	// 按操作
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/audit-logs?action=登录", nil))
	assertAuditRows(t, resp, 1)

	// 详情关键词
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/audit-logs?keyword=lb_y", nil))
	assertAuditRows(t, resp, 1)

	// 组合筛选
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/audit-logs?username=admin&resource=规则", nil))
	assertAuditRows(t, resp, 1)
}

func TestGetAuditLogs_timeRangeConvertedFromConfiguredTimezone(t *testing.T) {
	// Given：UTC 存储 2026-08-02 04:00:00（配置时区上海 = 12:00）
	router := newAuditLogTestRouter(t,
		"INSERT INTO audit_log (username, action, created_at) VALUES ('admin', '更新', '2026-08-02 04:00:00')")
	get := func(query string) *httptest.ResponseRecorder {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/audit-logs?"+query, nil)
		router.ServeHTTP(resp, req)
		return resp
	}

	// When：按配置时区的本地时间范围过滤（12:00 落在 [11:00, 13:00]）
	assertAuditRows(t, get(url.Values{"start_time": {"2026-08-02 11:00:00"}, "end_time": {"2026-08-02 13:00:00"}}.Encode()), 1)

	// When：范围完全在事件之前 → 不命中
	assertAuditRows(t, get(url.Values{"start_time": {"2026-08-02 13:00:01"}, "end_time": {"2026-08-02 15:00:00"}}.Encode()), 0)

	// When：日期-only 起点（上海 8/2 00:00 = UTC 7/1 16:00，覆盖事件）
	assertAuditRows(t, get(url.Values{"start_time": {"2026-08-02"}, "end_time": {"2026-08-02"}}.Encode()), 1)
}

func assertAuditRows(t *testing.T, resp *httptest.ResponseRecorder, want int) {
	t.Helper()
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Data struct {
			List  []json.RawMessage `json:"list"`
			Total int64             `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Data.List) != want || body.Data.Total != int64(want) {
		t.Fatalf("rows=%d total=%d, want %d", len(body.Data.List), body.Data.Total, want)
	}
}

func TestGetAuditLogOptions_groupsDistinctValues(t *testing.T) {
	// Given
	router := newAuditLogTestRouter(t, `
		INSERT INTO audit_log (username, action, resource, created_at) VALUES
		('admin', '更新', '全局配置', '2026-08-01 00:00:00'),
		('admin', '更新', '全局配置', '2026-08-02 00:00:00'),
		('ops',   '删除', '',        '2026-08-03 00:00:00')`)
	router.GET("/audit-logs/options", (&Handlers{}).GetAuditLogOptions)

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))

	// Then：去重 + 空值排除 + 高频在前
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Data struct {
			Usernames []struct {
				Value string `json:"value"`
				Count int64  `json:"count"`
			} `json:"usernames"`
			Actions []struct {
				Value string `json:"value"`
				Count int64  `json:"count"`
			} `json:"actions"`
			Resources []struct {
				Value string `json:"value"`
				Count int64  `json:"count"`
			} `json:"resources"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Data.Usernames) != 2 || body.Data.Usernames[0].Value != "admin" || body.Data.Usernames[0].Count != 2 {
		t.Fatalf("usernames=%+v", body.Data.Usernames)
	}
	if len(body.Data.Resources) != 1 {
		t.Fatalf("resources should exclude empty, got %+v", body.Data.Resources)
	}
}
