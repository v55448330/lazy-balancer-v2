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

// 爬虫地址库管理面：列表+开关+独立排程+状态/日志端点（手动更新经任务引擎，同威胁库口径）。
func newCrawlerTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	testHandlers := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/crawler-lib", testHandlers.GetCrawlerLib)
	router.PUT("/security/crawler-lib/:id/flags", testHandlers.UpdateCrawlerLibFlags)
	router.PUT("/security/crawler-lib/auto-update", testHandlers.UpdateCrawlerAutoUpdate)
	router.PUT("/security/crawler-lib/schedule", testHandlers.UpdateCrawlerSchedule)
	router.GET("/security/crawler-lib/update/status", testHandlers.GetCrawlerLibUpdateStatus)
	router.GET("/security/crawler-lib/update/logs", testHandlers.GetCrawlerLibUpdateLogs)
	return router
}

func seedCrawlerSource(t *testing.T, id int, name string, entryCount int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_crawler_sources
		(id, name, display_name, url, format, update_enabled, entry_count, version, update_status, last_checked, next_update)
		VALUES (?, ?, ?, 'https://example.com/ips.json', 'json', 1, ?, '2026.10.16', 'success', '2026-10-16 02:00:00', '2026-10-17 02:00:00')`,
		id, name, "爬虫机器人 "+name, entryCount); err != nil {
		t.Fatal(err)
	}
}

func TestCrawlerLib_getListsSourcesWithTotal(t *testing.T) {
	// Given
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 1, "googlebot", 170)
	seedCrawlerSource(t, 2, "gptbot", 46)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
		VALUES ('Google 官方爬虫 IP（common-crawlers）', 'Google 官方源', '搜索引擎爬虫', '66.249.66.0/24', 1, datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/crawler-lib", nil))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			Sources []struct {
				ID         int    `json:"id"`
				Name       string `json:"name"`
				EntryCount int    `json:"entry_count"`
				Version    string `json:"version"`
				NextUpdate string `json:"next_update"`
				ListID     int    `json:"list_id"`
			} `json:"sources"`
			TotalEntries int `json:"total_entries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, resp.Body.String())
	}
	if len(payload.Data.Sources) != 2 {
		t.Fatalf("sources=%d want 2 body=%s", len(payload.Data.Sources), resp.Body.String())
	}
	if payload.Data.TotalEntries != 216 {
		t.Errorf("total_entries=%d want 216", payload.Data.TotalEntries)
	}
	if payload.Data.Sources[0].Name != "googlebot" || payload.Data.Sources[0].NextUpdate == "" {
		t.Errorf("首源字段缺失: %+v", payload.Data.Sources[0])
	}
	if payload.Data.Sources[0].ListID == 0 {
		t.Errorf("googlebot list_id=0，内置名单关联缺失")
	}
	if payload.Data.Sources[1].ListID != 0 {
		t.Errorf("gptbot 无名单应 list_id=0，实际 %d", payload.Data.Sources[1].ListID)
	}
}

func TestCrawlerLib_listLookupFailureReturns500(t *testing.T) {
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 1, "googlebot", 170)
	if _, err := db.DB.Exec(`DROP TABLE security_ip_lists`); err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/crawler-lib", nil))
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("list lookup failure must not return a partial 200: status=%d body=%s", resp.Code, resp.Body.String())
	}
	// 固定文案 + 服务端留痕：business 组任意登录用户可读，底层 SQL/表名
	// 不得拼进响应（把 err.Error() 拼回是同类重构的常见回退）。
	body := resp.Body.String()
	if !strings.Contains(body, "读取爬虫源失败") {
		t.Fatalf("body=%s, want 固定文案", body)
	}
	if strings.Contains(body, "no such table") || strings.Contains(body, "security_ip_lists") || strings.Contains(body, "sql:") {
		t.Fatalf("响应泄漏内部结构: %s", body)
	}
}

func TestCrawlerLibFlags_updateAndNotFound(t *testing.T) {
	// Given
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 1, "googlebot", 170)
	// 关闭前留下失败状态与排程槽：关闭必须清掉瞬时失败态与过期槽，
	// 否则列表继续显示「更新失败」，重新启用也无法武装首槽。
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='failed', message='下载或解析失败' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When：关闭源开关
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/security/crawler-lib/1/flags",
		strings.NewReader(`{"update_enabled":false}`)))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var enabled int
	var status, message, nextUpdate string
	if err := db.DB.QueryRow(`SELECT update_enabled, update_status, message, COALESCE(next_update,'') FROM security_crawler_sources WHERE id=1`).Scan(&enabled, &status, &message, &nextUpdate); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Errorf("update_enabled=%d want 0", enabled)
	}
	if status != "idle" {
		t.Errorf("关闭后 update_status=%q want idle（残留失败态会继续计入库健康）", status)
	}
	if message != "已关闭自动更新" {
		t.Errorf("关闭后 message=%q want 已关闭自动更新", message)
	}
	if nextUpdate != "" {
		t.Errorf("关闭后 next_update=%q want 空（重新启用才能武装首槽）", nextUpdate)
	}

	// When：不存在的源
	resp404 := httptest.NewRecorder()
	router.ServeHTTP(resp404, httptest.NewRequest(http.MethodPut, "/security/crawler-lib/999/flags",
		strings.NewReader(`{"update_enabled":true}`)))
	// Then
	if resp404.Code != http.StatusNotFound {
		t.Errorf("未知源 status=%d want 404 body=%s", resp404.Code, resp404.Body.String())
	}

	// When：空字段
	resp400 := httptest.NewRecorder()
	router.ServeHTTP(resp400, httptest.NewRequest(http.MethodPut, "/security/crawler-lib/1/flags",
		strings.NewReader(`{}`)))
	// Then
	if resp400.Code != http.StatusBadRequest {
		t.Errorf("空字段 status=%d want 400 body=%s", resp400.Code, resp400.Body.String())
	}
}

func TestCrawlerLib_scheduleAndAutoUpdateIndependent(t *testing.T) {
	// Given
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 1, "googlebot", 170)

	// When：分别保存爬虫总闸与排程
	autoResp := httptest.NewRecorder()
	router.ServeHTTP(autoResp, httptest.NewRequest(http.MethodPut, "/security/crawler-lib/auto-update",
		strings.NewReader(`{"auto_update":false}`)))
	scheduleResp := httptest.NewRecorder()
	router.ServeHTTP(scheduleResp, httptest.NewRequest(http.MethodPut, "/security/crawler-lib/schedule",
		strings.NewReader(`{"days":[2,4],"time":"05:30"}`)))
	if autoResp.Code != http.StatusOK || scheduleResp.Code != http.StatusOK {
		t.Fatalf("auto=%d schedule=%d bodies=%s / %s", autoResp.Code, scheduleResp.Code, autoResp.Body.String(), scheduleResp.Body.String())
	}
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, httptest.NewRequest(http.MethodGet, "/security/crawler-lib", nil))

	// Then：GET 回读爬虫自己的配置，威胁排程仍保持默认
	var payload struct {
		Data struct {
			AutoUpdate   bool   `json:"auto_update"`
			ScheduleDays []int  `json:"schedule_days"`
			ScheduleTime string `json:"schedule_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.AutoUpdate || len(payload.Data.ScheduleDays) != 2 || payload.Data.ScheduleDays[0] != 2 || payload.Data.ScheduleDays[1] != 4 || payload.Data.ScheduleTime != "05:30" {
		t.Fatalf("爬虫配置回读错误: %+v", payload.Data)
	}
	var threatAuto int
	var threatDays, threatTime string
	if err := db.DB.QueryRow(`SELECT threat_auto_update,threat_schedule_days,threat_schedule_time FROM global_config WHERE id=1`).Scan(&threatAuto, &threatDays, &threatTime); err != nil {
		t.Fatal(err)
	}
	if threatAuto != 1 || threatDays != "1,2,3,4,5,6,7" || threatTime != "04:00" {
		t.Errorf("威胁配置被爬虫写操作污染: auto=%d days=%s time=%s", threatAuto, threatDays, threatTime)
	}
}

func TestCrawlerLibUpdateStatus_readsOwnTaskHistory(t *testing.T) {
	// Given：爬虫任务自己的一条成功历史
	router := newCrawlerTestRouter(t)
	initTaskEngineForTest(t)
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id,family,trigger,operator,status,started_at,finished_at,duration_ms)
		VALUES (?,'security','manual','alice','success','2026-10-17 01:00:00','2026-10-17 01:00:05',5000)`, services.CrawlerTaskID); err != nil {
		t.Fatal(err)
	}

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/crawler-lib/update/status", nil))

	// Then：状态与威胁任务无关，直接来自 crawlerbot-update 历史
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Data struct {
			Running    bool   `json:"running"`
			Trigger    string `json:"trigger"`
			StartedAt  string `json:"started_at"`
			FinishedAt string `json:"finished_at"`
			Outcome    string `json:"outcome"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Running || payload.Data.Trigger != "manual" || payload.Data.StartedAt != "2026-10-17 01:00:00" || payload.Data.FinishedAt != "2026-10-17 01:00:05" || payload.Data.Outcome != "success" {
		t.Fatalf("爬虫任务状态错误: %+v", payload.Data)
	}
}

func TestLoadSystemListIDs_readsBuiltinNameMapping(t *testing.T) {
	newBackupTestHandlers(t)
	var wantID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&wantID); err != nil {
		t.Fatal(err)
	}
	var wantName string
	if err := db.DB.QueryRow(`SELECT name FROM security_ip_lists WHERE id=?`, wantID).Scan(&wantName); err != nil {
		t.Fatal(err)
	}

	got, err := loadSystemListIDs()
	if err != nil {
		t.Fatalf("load system list ids: %v", err)
	}
	if got[wantName] != wantID {
		t.Fatalf("list id for %q=%d, want %d (full map=%v)", wantName, got[wantName], wantID, got)
	}
}

// 爬虫源开关状态机与威胁库同口径：已启用且 failed 重复提交 enable 保留
// 失败态/文案/计数（不得只清文案留下 failed+空失败文案）；关闭清
// consecutive_failures；关闭→启用归一为 idle/”/0。
func TestUpdateCrawlerLibFlags_enableStateMachineNormalized(t *testing.T) {
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 7, "statebot", 10)
	put := func(enabled bool) {
		body := `{"update_enabled":false}`
		if enabled {
			body = `{"update_enabled":true}`
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/security/crawler-lib/7/flags", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("enabled=%t status=%d body=%s", enabled, rec.Code, rec.Body.String())
		}
	}
	state := func() (string, string, int) {
		var status, message string
		var failures int
		if err := db.DB.QueryRow(`SELECT COALESCE(update_status,''), COALESCE(message,''), COALESCE(consecutive_failures,0) FROM security_crawler_sources WHERE id=7`).Scan(&status, &message, &failures); err != nil {
			t.Fatal(err)
		}
		return status, message, failures
	}

	// 已启用 + failed：重复提交 enable 保留失败态/文案/计数（同威胁库口径）
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1, update_status='failed', message='boom', consecutive_failures=3 WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	put(true)
	if status, message, failures := state(); status != "failed" || message != "boom" || failures != 3 {
		t.Fatalf("already-enabled state=(%s,%q,%d), want (failed,boom,3)（不得只清文案留 failed）", status, message, failures)
	}

	// 关闭：清失败计数（与威胁库同口径）
	put(false)
	if status, message, failures := state(); status != "idle" || message != "已关闭自动更新" || failures != 0 {
		t.Fatalf("disabled state=(%s,%q,%d), want (idle,已关闭自动更新,0)", status, message, failures)
	}

	// 关闭 → 启用：归一 idle/''/0
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='failed', message='old', consecutive_failures=2 WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	put(true)
	if status, message, failures := state(); status != "idle" || message != "" || failures != 0 {
		t.Fatalf("re-enabled state=(%s,%q,%d), want (idle,\"\",0)", status, message, failures)
	}
}

// 开关类审计必须记录目标状态：旧文案「X 更新开关」事后无法判断这次操作是
// 开还是关（同族另有 CRS/IP2Region/爬虫三处内联副本，统一走
// enabledStateLabel）。夹具口径：本用例曾寄居 cluster_mode_test.go 并额外调用
// db.InitializeAuditDB 覆盖包级 db.AuditDB——fixture 的 db.Initialize 已装配
// audit 库，二次直换句柄不 Close 会让前一句柄连同连接/fd 泄漏至进程退出，
// 违反「直换包级句柄必须 Close / SetDB」（本用例主题也属爬虫地址库，与集群
// 模式无关）。现只依赖 newBackupTestHandlers 的单一夹具，并断言句柄未被直换。
func TestSwitchAudit_recordsTargetState(t *testing.T) {
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 41, "测试爬虫源", 0)
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0 WHERE id=41`); err != nil {
		t.Fatalf("seed crawler source state: %v", err)
	}
	auditHandle := db.AuditDB

	put := func(enabled bool) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, "/security/crawler-lib/41/flags", strings.NewReader(fmt.Sprintf(`{"update_enabled":%t}`, enabled)))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("enabled=%t status=%d body=%s", enabled, recorder.Code, recorder.Body.String())
		}
	}
	latest := func() string {
		var detail string
		if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE resource='爬虫地址库' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
			t.Fatalf("query audit: %v", err)
		}
		return detail
	}

	put(true)
	if detail := latest(); !strings.Contains(detail, "开启") {
		t.Fatalf("开启审计未记录目标状态: %q", detail)
	}
	put(false)
	if detail := latest(); !strings.Contains(detail, "关闭") {
		t.Fatalf("关闭审计未记录目标状态: %q", detail)
	}
	// 句柄身份不变：夹具装配的 audit 库必须贯穿用例（直换=泄漏前一句柄）。
	if db.AuditDB != auditHandle {
		t.Fatal("用例期间 db.AuditDB 被直换（直换包级句柄必须 Close 旧句柄/走 SetDB）")
	}
}
