package handlers

// 大屏实时流量端点（Plan B）：代理 Caddy admin 自定义端点 /lb/traffic-stats
// （caddygeoip per-country 原子计数器），国名翻译中文（geoipnames 单源）+
// Reserved/空键过滤；admin 不可达时空数据降级（200，非 500——大屏轮询容忍
// 瞬时不可达，可用性位 available 披露）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		_, _ = w.Write([]byte(`{"countries":{"United States":{"attack":12,"normal":345},"中国":{"attack":0,"normal":88},"Reserved":{"attack":1,"normal":0}},"sample_n":1}`))
	}))
	t.Cleanup(admin.Close)
	router := newTrafficProxyRouter(t, admin.URL)

	// When
	rec := getRequest(t, router, "/security/overview/threat-screen/traffic")

	// Then: 国名翻译中文（United States→美国 与质心表对齐）、Reserved 过滤、
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
			Available bool `json:"available"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Countries["美国"].Attack != 12 || payload.Data.Countries["美国"].Normal != 345 {
		t.Fatalf("美国=%+v", payload.Data.Countries["美国"])
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

	// Then: 约 2s 返回降级（<3s 挂起时长）
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if elapsed >= 3*time.Second {
		t.Fatalf("elapsed=%v, want <3s（2s 超时保护）", elapsed)
	}
}
