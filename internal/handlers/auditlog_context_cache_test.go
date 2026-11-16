package handlers

// 审计列表读路径契约：
//   - 计数/明细/用户名富化查询消费请求 context：客户端断开后百万行
//     COUNT(*)/OFFSET 扫描必须中止，不得继续占用 SQLite 连接；
//   - 计数缓存桶满时逐出 at 最旧的桶（而非清空全表——清空会让紧随其后的
//     请求全部退化回全表 COUNT）。

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestGetAuditLogs_canceledRequestContextAbortsQueries(t *testing.T) {
	router := newAuditLogTestRouter(t, `
		INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES
		('admin','登录','用户认证','','10.0.0.1')`)
	resetAuditLogCountCacheForTest()
	t.Cleanup(resetAuditLogCountCacheForTest)

	// 对照组：正常请求返回 200。
	healthy := httptest.NewRecorder()
	router.ServeHTTP(healthy, httptest.NewRequest(http.MethodGet, "/audit-logs", nil))
	if healthy.Code != http.StatusOK {
		t.Fatalf("control status=%d body=%s", healthy.Code, healthy.Body.String())
	}

	// When：请求 context 已取消。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/audit-logs", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：查询被中止（不得跑完全表扫描后返回 200 完整列表）。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("canceled status=%d body=%s, want 500（查询须消费请求 context）", response.Code, response.Body.String())
	}
}

func TestGetAuditLogs_countCacheEvictsOldestBucketInsteadOfResetting(t *testing.T) {
	newAuditLogTestRouter(t, "")
	resetAuditLogCountCacheForTest()
	t.Cleanup(resetAuditLogCountCacheForTest)

	keys := make([]string, 0, auditLogCountCacheMaxEntries+1)
	for i := 0; i <= auditLogCountCacheMaxEntries; i++ {
		where := fmt.Sprintf(" WHERE action = 'unique-%d'", i)
		keys = append(keys, auditLogCountCacheKey(where, nil))
		if _, _, err := cachedAuditLogTotal(context.Background(), db.AuditDB, where, nil); err != nil {
			t.Fatalf("count %d: %v", i, err)
		}
	}

	auditLogCounts.Lock()
	size := len(auditLogCounts.entries)
	_, oldestStillCached := auditLogCounts.entries[keys[0]]
	_, secondStillCached := auditLogCounts.entries[keys[1]]
	_, newestCached := auditLogCounts.entries[keys[len(keys)-1]]
	auditLogCounts.Unlock()

	if size != auditLogCountCacheMaxEntries {
		t.Fatalf("缓存桶数=%d, want %d", size, auditLogCountCacheMaxEntries)
	}
	if oldestStillCached {
		t.Fatal("最旧桶未被逐出（应只删 at 最旧的一个）")
	}
	if !secondStillCached {
		t.Fatal("次旧桶被误清——越界不得整表重置")
	}
	if !newestCached {
		t.Fatal("新桶未写入")
	}
}

// 缓存键与筛选条件一一对应：值含字面 US 分隔符（\x1f）时不得与另一组
// 筛选碰撞（裸拼接形态 username="a\x1fb"&action="c" 与
// username="a"&action="b\x1fc" 曾生成同一键，TTL 内跨筛选串用 total）。
func TestAuditLogCountCacheKey_separatorInValueDoesNotCollide(t *testing.T) {
	where := "username LIKE ? AND action LIKE ?"
	keyA := auditLogCountCacheKey(where, []interface{}{"a\x1fb", "c"})
	keyB := auditLogCountCacheKey(where, []interface{}{"a", "b\x1fc"})
	if keyA == keyB {
		t.Fatalf("含分隔符的两组筛选生成同一缓存键（跨筛选串用 total）: %q", keyA)
	}
	// 回归形状：同值同键（缓存命中语义不变）。
	if auditLogCountCacheKey(where, []interface{}{"a\x1fb", "c"}) != keyA {
		t.Fatal("同筛选条件键不稳定——缓存命中语义被破坏")
	}
	// 常规值不受转义影响语义（键形态变化但一一对应保持）。
	k1 := auditLogCountCacheKey(where, []interface{}{"admin", "登录"})
	k2 := auditLogCountCacheKey(where, []interface{}{"admin", "登"})
	if k1 == k2 {
		t.Fatal("不同常规值碰撞")
	}
}
