package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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
// total 的 5s 进程缓存按筛选签名分桶且不区分库实例：交换 db.AuditDB 时必须
// 重置，否则「无筛选」请求会读到上一夹具库的计数（跨用例假绿/顺序依赖）。
func newAuditLogTestRouter(t *testing.T, rows string) *gin.Engine {
	t.Helper()
	resetAuditLogCountCacheForTest()
	t.Cleanup(resetAuditLogCountCacheForTest)
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

// 降级形态（审计库未装配）的响应键集必须与健康路径/文档示例一致：同端点
// 在两种状态下键集不同，按示例生成的客户端读取就绪标志会拿到 null，并把
// 未文档化的 partial 当未知字段。
func TestAuditLogResponses_degradedShapeMatchesDocumentedKeys(t *testing.T) {
	oldAuditDB := db.AuditDB
	db.AuditDB = nil
	t.Cleanup(func() { db.AuditDB = oldAuditDB })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	h := &Handlers{}
	router.GET("/audit-logs", h.GetAuditLogs)
	router.GET("/audit-logs/options", h.GetAuditLogOptions)

	decodeData := func(path string) map[string]any {
		t.Helper()
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s parse: %v", path, err)
		}
		return body.Data
	}

	logs := decodeData("/audit-logs")
	if logs["total_stale"] != true {
		t.Errorf("降级列表 total_stale=%v, want true（键与健康路径同集）: %v", logs["total_stale"], logs)
	}
	if logs["partial"] != true {
		t.Errorf("降级列表 partial=%v, want true: %v", logs["partial"], logs)
	}
	assertKeySetsEqual(t, "GET /audit-logs 降级形态", mapKeysOf(docResponseExample(t, "GET /audit-logs")), mapKeysOf(logs))

	options := decodeData("/audit-logs/options")
	for _, key := range []string{"usernames", "actions", "resources"} {
		items, ok := options[key].([]any)
		if !ok || len(items) != 0 {
			t.Errorf("降级下拉 %s=%v, want 空数组", key, options[key])
		}
	}
	if options["partial"] != true {
		t.Errorf("降级下拉 partial=%v, want true: %v", options["partial"], options)
	}
	assertKeySetsEqual(t, "GET /audit-logs/options 降级形态", mapKeysOf(docResponseExample(t, "GET /audit-logs/options")), mapKeysOf(options))
}

// total 的 5s 进程缓存按筛选条件签名分桶，键不区分审计库实例——测试交换
// db.AuditDB 后必须重置，否则无筛选请求会读到上一夹具库的计数。
func TestAuditLogTotalCache_isolatedAcrossRouters(t *testing.T) {
	first := newAuditLogTestRouter(t, "INSERT INTO audit_log (username, action, created_at) VALUES ('admin','更新','2026-08-01 00:00:00')")
	recorder := httptest.NewRecorder()
	first.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"total":1`) {
		t.Fatalf("first router status=%d body=%s, want total=1", recorder.Code, recorder.Body.String())
	}

	second := newAuditLogTestRouter(t, "")
	recorder = httptest.NewRecorder()
	second.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("second router status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"total":1`) {
		t.Fatalf("body=%s, 换了空库仍读到上一夹具的计数（缓存未随夹具重置）", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"total":0`) {
		t.Fatalf("body=%s, want total=0", recorder.Body.String())
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

func TestGetAuditLogs_hugePageDoesNot500(t *testing.T) {
	// Given：审计库有一条记录（复用 raw-UTC 测试的建库方式）
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
	if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, created_at) VALUES ('admin', '登录成功', '2026-07-19 12:00:00')"); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/audit-logs", (&Handlers{}).GetAuditLogs)

	// When：page 为 int64 最大值（(page-1)*pageSize 溢出为负 OFFSET）
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit-logs?page=9223372036854775807", nil))

	// Then：400 而非 500（溢出页被深翻页门显式拒绝并指引筛选）。
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "筛选") {
		t.Fatalf("deep page message must guide filtering: %s", recorder.Body.String())
	}
}

// 审计库缺表（查询失败）时下拉选项接口须留痕并标记 partial——
// 此前恒 200 + 空列表，故障与「真空库」不可区分、运维零信号。
func TestGetAuditLogOptions_queryFailureLogsAndMarksPartial(t *testing.T) {
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db") // 无 audit_log 表
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	resetAuditOptionsCacheForTest()

	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/audit-logs/options", h.GetAuditLogOptions)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Code int `json:"code"`
		Data struct {
			Partial bool                     `json:"partial"`
			Actions []map[string]interface{} `json:"actions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Data.Partial {
		t.Fatalf("partial=false, want true（查询失败轮必须标记部分结果）: %s", rec.Body.String())
	}
	if body.Data.Actions == nil {
		t.Errorf("actions 旧字段缺失（兼容性契约）: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "查询失败") {
		t.Fatalf("日志缺少「查询失败」留痕: %q", logs.String())
	}
}

// 审计库未就绪的降级响应必须回显请求分页参数（此前固定在解析前返回
// page=1/page_size=20，按文档生成的分页器会跳回首页）。
func TestGetAuditLogs_degradedResponseEchoesRequestedPagination(t *testing.T) {
	old := db.AuditDB
	db.AuditDB = nil
	t.Cleanup(func() { db.AuditDB = old })

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/audit-logs?page=3&page_size=50", nil)
	(&Handlers{}).GetAuditLogs(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Page     int  `json:"page"`
			PageSize int  `json:"page_size"`
			Partial  bool `json:"partial"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Page != 3 || resp.Data.PageSize != 50 {
		t.Fatalf("page=%d page_size=%d, want 3/50（降级响应须回显请求分页）", resp.Data.Page, resp.Data.PageSize)
	}
	if !resp.Data.Partial {
		t.Fatal("降级响应必须 partial=true")
	}
}

// 深翻页门必须同样作用于降级路径：审计库未就绪时 ?page=501 若回 200，同一
// 参数在故障窗口内外状态码分叉，按文档生成的分页器会算出越界偏移。
func TestGetAuditLogs_degradedResponseStillRejectsDeepPage(t *testing.T) {
	old := db.AuditDB
	db.AuditDB = nil
	t.Cleanup(func() { db.AuditDB = old })

	for _, tc := range []struct {
		page int
		want int
	}{
		{page: auditLogDeepPageLimit + 1, want: http.StatusBadRequest},
		{page: auditLogDeepPageLimit, want: http.StatusOK},
	} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/audit-logs?page="+strconv.Itoa(tc.page), nil)
		(&Handlers{}).GetAuditLogs(ctx)
		if recorder.Code != tc.want {
			t.Fatalf("page=%d status=%d body=%s, want %d", tc.page, recorder.Code, recorder.Body.String(), tc.want)
		}
		if tc.want != http.StatusOK {
			continue
		}
		var resp struct {
			Data struct {
				Page    int  `json:"page"`
				Partial bool `json:"partial"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Data.Page != tc.page || !resp.Data.Partial {
			t.Fatalf("上限页回显 page=%d partial=%v, want %d/true", resp.Data.Page, resp.Data.Partial, tc.page)
		}
	}
}

// 行为钉：审计库存在不可解析的 created_at（带外改库/旧版本遗留）时，500 只回
// 固定文案——此前两个明细分支把驱动原文（表列名 + "sql: Scan error"）拼进
// 响应，而该端点在 business 组，任意登录用户可见。
func TestGetAuditLogs_500BodyHidesDriverDetails(t *testing.T) {
	router := newAuditLogTestRouter(t, `INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('admin','登录成功','用户认证','','127.0.0.1','not-a-time')`)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, leak := range []string{"created_at", "sql:", "Scan error", "audit_log"} {
		if strings.Contains(body, leak) {
			t.Fatalf("500 body 泄露内部细节 %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "读取操作日志失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}

// COUNT 与明细查询两个早期失败面也必须走统一 5xx 写点：响应保持固定文案，
// 运行日志区分操作名并保留底层原因，避免线上只有前端 500 而无法排障。
func TestGetAuditLogs_queryFailuresLogOperationAndCause(t *testing.T) {
	cases := []struct {
		name      string
		mutation  string
		operation string
	}{
		{name: "count", mutation: "DROP TABLE audit_log", operation: "统计操作日志总数"},
		{name: "rows", mutation: "ALTER TABLE audit_log DROP COLUMN action", operation: "查询操作日志明细"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := newAuditLogTestRouter(t, tc.mutation)
			logs := captureLog(t)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
			}
			if body := response.Body.String(); !strings.Contains(body, "查询操作日志失败") || strings.Contains(body, "no such") {
				t.Fatalf("响应未保持固定脱敏文案: %s", body)
			}
			if got := logs.String(); !strings.Contains(got, tc.operation) || !strings.Contains(got, "no such") {
				t.Fatalf("日志缺少操作名 %q 或底层原因: %q", tc.operation, got)
			}
		})
	}
}
