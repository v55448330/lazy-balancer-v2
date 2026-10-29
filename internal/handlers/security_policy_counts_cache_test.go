package handlers

// 策略列表「24h 拦截/触发」列出聚合缓存：同一窗口锚点内复用近 24h 聚合
// （不重复扫描 metrics 库），过期后重查；失败不缓存。

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func listPolicies24hCounts(t *testing.T, h *Handlers) (blocked, trigger map[int]int, raw string) {
	t.Helper()
	router := gin.New()
	router.GET("/policies", h.ListSecurityPolicies)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			ID         int `json:"id"`
			Blocked24h int `json:"blocked_24h"`
			Trigger24h int `json:"trigger_24h"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	blocked, trigger = map[int]int{}, map[int]int{}
	for _, p := range resp.Data {
		blocked[p.ID] = p.Blocked24h
		trigger[p.ID] = p.Trigger24h
	}
	return blocked, trigger, rec.Body.String()
}

func TestListSecurityPolicies_24hCountsCachedWithinWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	resetSecurityPolicy24hCountsCacheForTest()
	oldTTL := securityPolicy24hCountsCacheTTL
	securityPolicy24hCountsCacheTTL = time.Minute
	t.Cleanup(func() { securityPolicy24hCountsCacheTTL = oldTTL; resetSecurityPolicy24hCountsCacheForTest() })

	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode) VALUES (7, '缓存策略', 'blocking')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (policy_id, action) VALUES (7,'blocked'),(7,'logged')`); err != nil {
		t.Fatal(err)
	}

	// 缓存键含分钟锚点：显式传同一个 now 直调 loader，跨分钟边界不再随机
	// 假红（端点只作接线断言）。
	now := time.Now()
	readCounts := func() (int, int) {
		t.Helper()
		counts, err := loadSecurityPolicy24hCounts(db.MetricsDB, now)
		if err != nil {
			t.Fatalf("load 24h counts: %v", err)
		}
		return counts.blocked[7], counts.trigger[7]
	}

	// Given 首次调用（缓存未命中）→ 真实计数。
	if blocked, trigger := readCounts(); blocked != 1 || trigger != 2 {
		t.Fatalf("首次 blocked=%d trigger=%d, want 1/2", blocked, trigger)
	}

	// When 事件表新增 5 条拦截行后立刻再取。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (policy_id, action)
		VALUES (7,'blocked'),(7,'blocked'),(7,'blocked'),(7,'blocked'),(7,'blocked')`); err != nil {
		t.Fatal(err)
	}
	// Then TTL 内命中缓存，不得重查（仍返回旧计数）。
	if blocked, trigger := readCounts(); blocked != 1 || trigger != 2 {
		t.Fatalf("TTL 内 blocked=%d trigger=%d, want 1/2（缓存命中时不得重查）", blocked, trigger)
	}

	// When 缓存禁用（等价 TTL 过期）后请求。
	securityPolicy24hCountsCacheTTL = 0
	// Then 必须重查并拿到新计数。
	if blocked, trigger := readCounts(); blocked != 6 || trigger != 7 {
		t.Fatalf("失效后 blocked=%d trigger=%d, want 6/7（过期必须重查）", blocked, trigger)
	}

	// 端点接线：列表返回的列与 loader 同源。
	blocked, trigger, _ := listPolicies24hCounts(t, h)
	if blocked[7] != 6 || trigger[7] != 7 {
		t.Fatalf("列表端点 blocked=%d trigger=%d, want 6/7（与 loader 同源）", blocked[7], trigger[7])
	}
}

// 退避形状（失败不缓存）：缓存仍应保持空表——错误不落缓存，下一请求重试。
func TestLoadSecurityPolicy24hCounts_failureNotCached(t *testing.T) {
	newBackupTestHandlers(t)
	resetSecurityPolicy24hCountsCacheForTest()
	t.Cleanup(resetSecurityPolicy24hCountsCacheForTest)
	oldTTL := securityPolicy24hCountsCacheTTL
	securityPolicy24hCountsCacheTTL = time.Minute
	t.Cleanup(func() { securityPolicy24hCountsCacheTTL = oldTTL })

	// Given 指标库被关闭（查询必失败）。
	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecurityPolicy24hCounts(closed, time.Now()); err == nil {
		t.Fatal("关闭的指标库必须显式报错（不得静默空计数）")
	}
	securityPolicy24hCountsMu.Lock()
	cached := len(securityPolicy24hCountsCache)
	securityPolicy24hCountsMu.Unlock()
	if cached != 0 {
		t.Fatalf("失败结果被缓存（%d 条），下一请求不会重试", cached)
	}
}

// 命中路径必须返回缓存条目的副本：调用方改写返回 map 不得穿透缓存——
// 共享底层 map 时，任一调用方的写都会改写后续所有命中方的视图。
func TestLoadSecurityPolicy24hCounts_hitReturnsClone(t *testing.T) {
	h := newBackupTestHandlers(t)
	_ = h
	resetSecurityPolicy24hCountsCacheForTest()
	oldTTL := securityPolicy24hCountsCacheTTL
	securityPolicy24hCountsCacheTTL = time.Minute
	t.Cleanup(func() { securityPolicy24hCountsCacheTTL = oldTTL; resetSecurityPolicy24hCountsCacheForTest() })

	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode) VALUES (8, '克隆策略', 'blocking')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (policy_id, action) VALUES (8,'blocked'),(8,'logged')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first, err := loadSecurityPolicy24hCounts(db.MetricsDB, now)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	// When 调用方改写返回值（真实 handler 只读，但契约上返回面必须自持）。
	first.blocked[8] = 999
	first.trigger[8] = 999

	// Then 再次命中仍为库内原值。
	second, err := loadSecurityPolicy24hCounts(db.MetricsDB, now)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if second.blocked[8] != 1 || second.trigger[8] != 2 {
		t.Fatalf("second blocked=%d trigger=%d, want 1/2（命中必须返回副本，调用方改写不得穿透缓存）",
			second.blocked[8], second.trigger[8])
	}
}

// 并发 miss 必须合并为一趟聚合查询（singleflight）：策略列表多页签/多客户端
// 秒级轮询，miss 瞬间的并发不得放大为 N 趟近 24h 全窗口扫描。
func TestLoadSecurityPolicy24hCounts_concurrentMissRunsSingleQuery(t *testing.T) {
	newBackupTestHandlers(t)
	resetSecurityPolicy24hCountsCacheForTest()
	t.Cleanup(resetSecurityPolicy24hCountsCacheForTest)
	oldTTL := securityPolicy24hCountsCacheTTL
	securityPolicy24hCountsCacheTTL = 0 // 全部请求走 miss 路径
	t.Cleanup(func() { securityPolicy24hCountsCacheTTL = oldTTL })

	realQuery := querySecurityPolicy24hCounts
	var queries atomic.Int64
	release := make(chan struct{})
	querySecurityPolicy24hCounts = func(metricsDB *sql.DB, since string) (securityPolicy24hCounts, error) {
		queries.Add(1)
		// 首个航班停在闸口：singleflight 下其余调用方全部阻塞在 Do 内
		//（可由协程栈观测）；无合并时每个调用方各自执行到闸口（计数 >1）。
		<-release
		return realQuery(metricsDB, since)
	}
	t.Cleanup(func() { querySecurityPolicy24hCounts = realQuery })

	const callers = 10
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := loadSecurityPolicy24hCounts(db.MetricsDB, time.Now()); err != nil {
				t.Errorf("load: %v", err)
			}
		}()
	}
	// 确定性等待：直到 callers-1 个协程栈出现在 singleflight.Do 内（其余调用方
	// 已被首趟航班合流且无法自行完成），再放行航班。等不到则放行并由计数断言
	// 如实失败。
	deadline := time.Now().Add(5 * time.Second)
	merged := false
	for time.Now().Before(deadline) {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		if strings.Count(string(buf[:n]), "singleflight.(*Group).Do") >= callers-1 {
			merged = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	wg.Wait()

	if !merged {
		t.Fatal("5s 内未观测到并发调用方合流进 singleflight.Do（实现已偏离合并契约）")
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("并发 miss 聚合查询=%d, want 1（singleflight 必须合并为一趟扫描）", got)
	}
}
