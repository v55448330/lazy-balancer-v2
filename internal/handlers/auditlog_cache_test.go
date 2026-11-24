package handlers

// 审计日志读路径的三条成本/可观测契约：
//   - 下拉选项并发 miss 只跑一趟聚合（single-flight），不再 3N 次全表 GROUP BY；
//   - 列表 total 走短 TTL 缓存并以 total_stale 披露（百万行库的每请求全表
//     COUNT(*) 是首屏固定成本）；
//   - 时区单源：时间窗口按 services.CurrentLocation()，不逐请求重读
//     global_config（配置时区降级留痕归 services 的刷新状态机）。

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestGetAuditLogOptions_concurrentMissRunsSingleAggregation(t *testing.T) {
	withIsolatedGlobal(t)
	resetAuditOptionsCacheForTest()
	oldFetch := auditOptionsFetch
	var calls atomic.Int32
	auditOptionsFetch = func(context.Context) (map[string]interface{}, error) {
		calls.Add(1)
		time.Sleep(60 * time.Millisecond) // 拉长窗口：并发请求必须等待同一趟
		return map[string]interface{}{
			"usernames": []interface{}{},
			"actions":   []interface{}{},
			"resources": []interface{}{},
		}, nil
	}
	t.Cleanup(func() {
		auditOptionsFetch = oldFetch
		resetAuditOptionsCacheForTest()
	})

	router, _ := newAuditLogRouter(t)
	const concurrency = 8
	var wg sync.WaitGroup
	codes := make([]int, concurrency)
	wg.Add(concurrency)
	for i := range concurrency {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))
			codes[i] = rec.Code
		}()
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("并发请求 %d 状态码=%d, want 200", i, code)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("并发 8 请求聚合 %d 趟, want 1（single-flight 未生效，60s 边界会 3N 次全表 GROUP BY）", got)
	}
}

type auditLogsPayload struct {
	Data struct {
		Total      int64 `json:"total"`
		TotalStale bool  `json:"total_stale"`
	} `json:"data"`
}

func getAuditLogsTotal(t *testing.T, router http.Handler) auditLogsPayload {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit-logs status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload auditLogsPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode audit-logs: %v", err)
	}
	return payload
}

func TestGetAuditLogs_totalServedFromShortCacheWithDisclosure(t *testing.T) {
	withIsolatedGlobal(t)
	router, _ := newAuditLogRouter(t)
	resetAuditLogCountCacheForTest()
	oldTTL := auditLogCountCacheTTL
	auditLogCountCacheTTL = 60 * time.Millisecond
	t.Cleanup(func() {
		auditLogCountCacheTTL = oldTTL
		resetAuditLogCountCacheForTest()
	})
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('cache-user','登录','用户认证','','1.1.1.1')`); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	// When/Then 首轮：真实计数且未标记陈旧。
	first := getAuditLogsTotal(t, router)
	if first.Data.Total != 1 || first.Data.TotalStale {
		t.Fatalf("首轮 total=%d stale=%v, want 1/false", first.Data.Total, first.Data.TotalStale)
	}

	// When：TTL 内新增一行。
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('cache-user','登录','用户认证','','1.1.1.1')`); err != nil {
		t.Fatalf("seed second audit row: %v", err)
	}
	cached := getAuditLogsTotal(t, router)
	// Then：命中缓存（不再全表计数）且显式披露陈旧，不冒充实时。
	if cached.Data.Total != 1 || !cached.Data.TotalStale {
		t.Fatalf("TTL 内 total=%d stale=%v, want 1/true（缓存命中须披露）", cached.Data.Total, cached.Data.TotalStale)
	}

	// When：TTL 过期。
	time.Sleep(80 * time.Millisecond)
	refreshed := getAuditLogsTotal(t, router)
	// Then：重新计数并清除陈旧标记。
	if refreshed.Data.Total != 2 || refreshed.Data.TotalStale {
		t.Fatalf("过期后 total=%d stale=%v, want 2/false", refreshed.Data.Total, refreshed.Data.TotalStale)
	}
}

// 时区单源回归：审计列表不再逐请求重读 global_config.timezone / LoadLocation
// ——带外非法值既不影响列表（恒 200，窗口按 services.CurrentLocation()，与
// 页面其余时间字段同源），也不由本端点留痕（降级归 services 的
// timezone-refresh 状态机：首报 warn、恢复 info）。
func TestGetAuditLogs_timezoneDegradationOwnedByServices(t *testing.T) {
	router := newAuditLogTestRouter(t, "")
	// Given：带外写入非法时区值，此后开始捕获日志。
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='Mars/Phobos' WHERE id=1`); err != nil {
		t.Fatalf("seed invalid timezone: %v", err)
	}
	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When：审计页轮询两次。
	for range 2 {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200（列表不消费 global_config.timezone）", rec.Code, rec.Body.String())
		}
	}

	// Then：本端点零时区留痕（逐请求重读的残留信号 = 旧实现回归）。
	if strings.Contains(logs.String(), "audit-log-timezone") {
		t.Fatalf("审计列表仍逐请求留痕时区降级（单源应归 services 刷新状态机）: %q", logs.String())
	}
}
