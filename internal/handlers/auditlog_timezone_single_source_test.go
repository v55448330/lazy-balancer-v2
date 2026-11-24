package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 审计列表的时间筛选窗口必须使用进程内时区单源 services.CurrentLocation()
// （init/刷新 daemon/设置保存三路维护），不得逐请求重读 global_config：
// 两套事实源在 DB 瞬断或值非法时会让审计时间窗口按 UTC 而页面其余时间字段
// 仍按配置时区（同一页时间口径分裂），且每请求多一次点查 + LoadLocation。
func TestGetAuditLogs_timeWindowUsesServicesCurrentLocation(t *testing.T) {
	withIsolatedGlobal(t)
	router, _ := newAuditLogRouter(t)
	resetAuditLogCountCacheForTest()
	t.Cleanup(resetAuditLogCountCacheForTest)

	// 时区单源显式落东京（UTC+9）；用例结束恢复到与进程默认 CST(+8) 等价的
	// IANA 名（Asia/Shanghai），不改变后续用例的时区语义。
	if _, err := services.ConfigureLocation("Asia/Tokyo"); err != nil {
		t.Fatalf("configure location: %v", err)
	}
	t.Cleanup(func() {
		if _, err := services.ConfigureLocation("Asia/Shanghai"); err != nil {
			t.Logf("恢复默认时区失败: %v", err)
		}
	})

	// 带外写入非法时区：旧实现逐请求重读 → 降级 UTC（窗口错位 + 留痕）。
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='Mars/Phobos' WHERE id=1`); err != nil {
		t.Fatalf("seed invalid timezone: %v", err)
	}
	// UTC 20:00 = 东京次日 05:00，按东京「2026-01-02」整天应命中。
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at)
		VALUES ('tz-user','登录','用户认证','','1.1.1.1','2026-01-01 20:00:00')`); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit-logs?start_time=2026-01-02&end_time=2026-01-02", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Total int64 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Data.Total != 1 {
		t.Fatalf("东京整天的筛选 total=%d, want 1（窗口未用 CurrentLocation=Asia/Tokyo，按 UTC 解析漏行）: %s",
			payload.Data.Total, recorder.Body.String())
	}
	if strings.Contains(logs.String(), "audit-log-timezone") {
		t.Fatalf("审计列表仍逐请求重读/降级时区（单源应只由 services 刷新 daemon 留痕）: %q", logs.String())
	}
}
