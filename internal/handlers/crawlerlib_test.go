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

func TestCrawlerLibFlags_updateAndNotFound(t *testing.T) {
	// Given
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 1, "googlebot", 170)

	// When：关闭源开关
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/security/crawler-lib/1/flags",
		strings.NewReader(`{"update_enabled":false}`)))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow(`SELECT update_enabled FROM security_crawler_sources WHERE id=1`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Errorf("update_enabled=%d want 0", enabled)
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
		VALUES ('crawlerbot-update','security','manual','alice','success','2026-10-17 01:00:00','2026-10-17 01:00:05',5000)`); err != nil {
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
