package handlers

// 大屏实时流量端点（Plan B）：代理 Caddy admin 自定义端点 /lb/traffic-stats
// （caddygeoip per-country 原子计数器），国名翻译中文（geoipnames 单源）+
// Reserved/空/0 键过滤；admin 不可达时空数据降级（200，非 500——大屏轮询容忍
// 瞬时不可达，可用性位 available 披露）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func newTrafficProxyRouter(t *testing.T, adminURL string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: adminURL}}
	router := gin.New()
	router.GET("/security/overview/threat-screen/traffic", h.GetThreatScreenTraffic)
	return router
}

func TestGetThreatScreenTraffic_proxiesAndTranslates(t *testing.T) {
	// Given: admin 端点返回 per-country 快照（xdb 原始英文名/「中国」）
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lb/traffic-stats" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"countries":{"United States":{"attack":12,"normal":345},"中国":{"attack":0,"normal":88},"Reserved":{"attack":1,"normal":0},"0":{"attack":2,"normal":3}},"sample_n":1,"collecting":false}`))
	}))
	t.Cleanup(admin.Close)
	router := newTrafficProxyRouter(t, admin.URL)

	// When
	rec := getRequest(t, router, "/security/overview/threat-screen/traffic")

	// Then: 国名翻译中文（United States→美国 与质心表对齐）、Reserved/0 过滤、
	// available=true、2s 超时保护
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"美国"`) || !strings.Contains(body, `"中国"`) {
		t.Fatalf("国名未翻译: %s", body)
	}
	if strings.Contains(body, "Reserved") || strings.Contains(body, "United States") {
		t.Fatalf("原始国名/保留键泄漏: %s", body)
	}
	if !strings.Contains(body, `"available":true`) {
		t.Fatalf("缺 available=true: %s", body)
	}
	var payload struct {
		Data struct {
			Countries map[string]struct {
				Attack uint64 `json:"attack"`
				Normal uint64 `json:"normal"`
			} `json:"countries"`
			Available  bool `json:"available"`
			Collecting bool `json:"collecting"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Countries["美国"].Attack != 12 || payload.Data.Countries["美国"].Normal != 345 {
		t.Fatalf("美国=%+v", payload.Data.Countries["美国"])
	}
	if _, exists := payload.Data.Countries["0"]; exists {
		t.Fatalf("xdb 无效国家键 0 必须过滤: %+v", payload.Data.Countries)
	}
	if got := len(payload.Data.Countries); got != 2 {
		t.Fatalf("countries=%+v, want only 美国 and 中国", payload.Data.Countries)
	}
	// 采集租约状态原样透传：无租约时累计冻结，前端不得把冻结值当实时流量
	if payload.Data.Collecting {
		t.Fatalf("collecting 必须透传 admin 快照的 false: %+v", payload.Data)
	}
}

func TestGetThreatScreenTraffic_adminUnavailableDegrades(t *testing.T) {
	// Given: admin 不可达（connection refused）
	router := newTrafficProxyRouter(t, "http://127.0.0.1:1")

	// When
	rec := getRequest(t, router, "/security/overview/threat-screen/traffic")

	// Then: 200 空数据降级（available=false）——大屏轮询容忍瞬时不可达，
	// 不 500（每 1-2s 一次的轮询若 500 会在前端日志刷屏）
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 降级", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("body=%s, want available=false", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"countries":{}`) {
		t.Fatalf("body=%s, want 空 countries", rec.Body.String())
	}
	// 降级响应同样披露 collecting=false（冻结/不可达都不得当作实时流量）
	if !strings.Contains(rec.Body.String(), `"collecting":false`) {
		t.Fatalf("body=%s, want collecting=false", rec.Body.String())
	}
}

func TestGetThreatScreenTraffic_timeoutGuard(t *testing.T) {
	// Given: admin 挂起（超时保护 2s 生效，不阻塞大屏轮询协程）
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	t.Cleanup(slow.Close)
	router := newTrafficProxyRouter(t, slow.URL)
	start := time.Now()

	// When
	rec := getRequest(t, router, "/security/overview/threat-screen/traffic")
	elapsed := time.Since(start)

	// Then: 约 2s 返回降级（<3s 挂起时长）；降级必须是显式 available=false，
	// 且确实等到了超时（删除抓取逻辑后用例会立即返回，一眼转红）。
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("body=%s, want available=false（超时降级）", rec.Body.String())
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("elapsed=%v, want ≥1.5s（必须真实等待 2s 超时，而非早退空降级）", elapsed)
	}
	if elapsed >= 3*time.Second {
		t.Fatalf("elapsed=%v, want <3s（2s 超时保护）", elapsed)
	}
}

func TestGetThreatScreenTraffic_shortTTLCacheHit(t *testing.T) {
	// Given: admin 端点计数器 + 1s TTL 进程内缓存（计数仅统计 traffic-stats
	// 主路径——l4-conn-stats 是同轮伴生抓取，缺失时静默跳过，不参与主体
	// 抓取次数断言）
	var hits int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lb/l4-conn-stats" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"countries":{"中国":{"attack":1,"normal":2}},"sample_n":1}`))
	}))
	t.Cleanup(admin.Close)
	router := newTrafficProxyRouter(t, admin.URL)

	// When: 连续两次请求（TTL 内）
	rec1 := getRequest(t, router, "/security/overview/threat-screen/traffic")
	rec2 := getRequest(t, router, "/security/overview/threat-screen/traffic")

	// Then: 第二次命中缓存——上游仅抓取一次，两次响应一致
	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		t.Fatalf("status=%d/%d", rec1.Code, rec2.Code)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("upstream hits=%d, want 1（1s TTL 缓存命中）", got)
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Fatalf("cached response mismatch:\n%s\n%s", rec1.Body.String(), rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"available":true`) {
		t.Fatalf("cached body=%s, want available=true", rec2.Body.String())
	}
}

func TestGetThreatScreenTraffic_cacheExpires(t *testing.T) {
	withIsolatedGlobal(t)
	// Given: 缓存 TTL 缩短至 50ms（测试缝）
	old := threatTrafficCacheTTL
	threatTrafficCacheTTL = 50 * time.Millisecond
	t.Cleanup(func() { threatTrafficCacheTTL = old })
	var hits int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lb/l4-conn-stats" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"countries":{"中国":{"attack":1,"normal":2}},"sample_n":1}`))
	}))
	t.Cleanup(admin.Close)
	router := newTrafficProxyRouter(t, admin.URL)

	// When: 首次请求 → 过期后再请求
	_ = getRequest(t, router, "/security/overview/threat-screen/traffic")
	time.Sleep(80 * time.Millisecond)
	_ = getRequest(t, router, "/security/overview/threat-screen/traffic")

	// Then: TTL 过期后重新抓取
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("upstream hits=%d, want 2（TTL 过期后重新抓取）", got)
	}
}

func TestGetThreatScreenTraffic_failureNotCached(t *testing.T) {
	// Given: traffic-stats 首次请求返回 502，第二次恢复（l4 伴生端点恒 404，
	// 不参与失败序列）
	var hits int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lb/l4-conn-stats" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"countries":{"中国":{"attack":1,"normal":2}},"sample_n":1}`))
	}))
	t.Cleanup(admin.Close)
	router := newTrafficProxyRouter(t, admin.URL)

	// When
	rec1 := getRequest(t, router, "/security/overview/threat-screen/traffic")
	rec2 := getRequest(t, router, "/security/overview/threat-screen/traffic")

	// Then: 失败不缓存——第一次降级 available=false，第二次真实抓取成功
	if !strings.Contains(rec1.Body.String(), `"available":false`) {
		t.Fatalf("first body=%s, want available=false 降级", rec1.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"available":true`) || !strings.Contains(rec2.Body.String(), `"中国"`) {
		t.Fatalf("second body=%s, want 恢复后真实数据", rec2.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("upstream hits=%d, want 2（失败结果不缓存）", got)
	}
}
