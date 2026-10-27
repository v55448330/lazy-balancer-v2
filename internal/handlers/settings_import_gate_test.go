package handlers

// 导入窗口写门覆盖面：除用户/密钥/证书/CA/集群/节点族外，写入 global_config
// 与版本/源表的设置端点同样在导入全量替换范围内——自动备份设置、OIDC 设置
// （保存/删除）、规则库自动更新、四族库排程、自动封禁配置在窗口内提交都会被
// 导入静默覆盖或撞写锁 500，必须与同族端点一样 409 fast-fail。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestSettingsWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/settings/auto-backup", h.UpdateAutoBackupSettings)
	router.PUT("/settings/oidc", h.OIDCSettingsUpdate)
	router.DELETE("/settings/oidc", h.OIDCSettingsDelete)
	router.PUT("/security/crs/auto-update", h.UpdateCRSAutoUpdate)
	router.PUT("/security/crs/schedule", h.UpdateCRSSchedule)
	router.PUT("/security/ip2region/schedule", h.UpdateIP2RegionSchedule)
	router.PUT("/security/threat/schedule", h.UpdateThreatSchedule)
	router.PUT("/security/crawler/schedule", h.UpdateCrawlerSchedule)
	router.PUT("/security/crawler-lib/auto-update", h.UpdateCrawlerAutoUpdate)
	router.PUT("/security/crawler-lib/:id/flags", h.UpdateCrawlerLibFlags)
	router.PUT("/security/autoban", h.UpdateAutobanConfig)
	router.POST("/system/restart", h.RestartService)

	// 落库侧快照：409 必须是「未落库」而不是「落库后报错」。
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crawler_sources
		(id, name, display_name, url, format, update_enabled, update_status)
		VALUES (1, 'googlebot', 'Google', 'https://example.test/crawlers.txt', 'txt', 0, 'idle')`); err != nil {
		t.Fatalf("seed crawler source: %v", err)
	}
	var autoBefore int
	if err := db.DB.QueryRow(`SELECT COALESCE(crawler_auto_update,0) FROM global_config WHERE id=1`).Scan(&autoBefore); err != nil {
		t.Fatalf("read crawler auto update: %v", err)
	}
	var enabledBefore, statusBefore string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_enabled,0), COALESCE(update_status,'') FROM security_crawler_sources WHERE id=1`).
		Scan(&enabledBefore, &statusBefore); err != nil {
		t.Fatalf("read crawler source: %v", err)
	}

	// 模拟导入会话进行中（configImportBusy 的事实源：窗口计数）。
	beginImportWindowForTest(t)

	calls := []struct{ method, path, body string }{
		{"PUT", "/settings/auto-backup", `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":7,"sections":["rules"]}`},
		{"PUT", "/settings/oidc", `{"enabled":true,"issuer":"https://idp.example","client_id":"cid"}`},
		{"DELETE", "/settings/oidc", ""},
		{"PUT", "/security/crs/auto-update", `{"auto_update":true}`},
		{"PUT", "/security/crs/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/ip2region/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/threat/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/crawler/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/crawler-lib/auto-update", `{"auto_update":true}`},
		{"PUT", "/security/crawler-lib/1/flags", `{"update_enabled":true}`},
		{"PUT", "/security/autoban", `{"enabled":true}`},
		{"POST", "/system/restart", ""},
	}
	for _, call := range calls {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内设置写端点必须 fast-fail）",
				call.method, call.path, recorder.Code, recorder.Body.String())
		}
		// 文案收紧为单次前缀 + 动作词：action 只传短动作词，拼接后不得重复
		// 「配置导入进行中」（重启端点曾传「执行服务重启（配置导入进行中）」）。
		if got := strings.Count(recorder.Body.String(), "配置导入进行中"); got != 1 {
			t.Fatalf("%s %s body=%s, want 恰好一次「配置导入进行中」（got %d）",
				call.method, call.path, recorder.Body.String(), got)
		}
	}
	// 重启端点的完整文案与同族一致：前缀 + 纯动作词。
	for _, call := range calls {
		if call.path != "/system/restart" {
			continue
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(call.method, call.path, nil)
		router.ServeHTTP(recorder, request)
		if !strings.Contains(recorder.Body.String(), "暂不能执行服务重启") || strings.Contains(recorder.Body.String(), "（") {
			t.Fatalf("POST /system/restart body=%s, want「配置导入进行中，暂不能执行服务重启」（无重复短语）", recorder.Body.String())
		}
	}

	var autoAfter int
	if err := db.DB.QueryRow(`SELECT COALESCE(crawler_auto_update,0) FROM global_config WHERE id=1`).Scan(&autoAfter); err != nil {
		t.Fatalf("read crawler auto update after: %v", err)
	}
	if autoAfter != autoBefore {
		t.Fatalf("窗口内 crawler_auto_update %d→%d，409 前不得落库", autoBefore, autoAfter)
	}
	var enabledAfter, statusAfter string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_enabled,0), COALESCE(update_status,'') FROM security_crawler_sources WHERE id=1`).
		Scan(&enabledAfter, &statusAfter); err != nil {
		t.Fatalf("read crawler source after: %v", err)
	}
	if enabledAfter != enabledBefore || statusAfter != statusBefore {
		t.Fatalf("窗口内爬虫源 %s/%s→%s/%s，409 前不得落库", enabledBefore, statusBefore, enabledAfter, statusAfter)
	}
}

// 对照：窗口外同一端点不被 409 门恒拒（门只按导入会话持锁判定）。
func TestSettingsWritesAllowedOutsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/security/autoban", h.UpdateAutobanConfig)
	router.PUT("/security/crawler-lib/auto-update", h.UpdateCrawlerAutoUpdate)
	router.PUT("/security/crawler-lib/:id/flags", h.UpdateCrawlerLibFlags)

	calls := []struct{ path, body string }{
		{"/security/autoban", `{not-json`},
		{"/security/crawler-lib/auto-update", `{not-json`},
		{"/security/crawler-lib/1/flags", `{not-json`},
	}
	for _, call := range calls {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, call.path, strings.NewReader(call.body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusConflict {
			t.Fatalf("%s 窗口外请求被 409 门恒拒: body=%s", call.path, recorder.Body.String())
		}
	}
}
