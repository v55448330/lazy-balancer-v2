package handlers

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

// D5-S3（N+11 轮）：GetCaddyConfig 与 ApplyConfigOnStartup 的就绪探针硬编码
// http://localhost:2019/config/，忽略 cfg.CaddyAdminURL（GetCaddyStatus 已正确
// 使用配置值）——自定义 admin 地址的部署下两者探测的是错误端点。两测试以
// httptest 假 admin 端点断言「确实拨号了配置的 URL」。
// 判别依据：就绪探针发 GET /config/，而配置应用路径（GenerateAndApplyConfigForce）
// 只发 POST /load——假端点上出现 GET /config/ 即证明探针走了配置地址。

func TestGetCaddyConfig_dialsConfiguredAdminURL(t *testing.T) {
	// Given 配置指向假 admin 端点（非默认 localhost:2019）
	hit := false
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			hit = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apps":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(fake.Close)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: fake.URL}}
	router := gin.New()
	router.GET("/config", h.GetCaddyConfig)

	// When
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config", nil))

	// Then 200 且请求确实落在配置的 admin URL 上（修复前拨号 localhost:2019）
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !hit {
		t.Fatalf("GetCaddyConfig 未拨号 cfg.CaddyAdminURL（%s）下的 GET /config/", fake.URL)
	}
}

func TestApplyConfigOnStartup_readinessProbeDialsConfiguredAdminURL(t *testing.T) {
	// Given 假 admin 端点按序记录请求（/config/ GET 与 /load POST 均放行）
	var mu sync.Mutex
	var order []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fake.Close)
	h := newBackupTestHandlers(t)
	h.cfg = &config.Config{CaddyAdminURL: fake.URL}
	h.caddyService = services.NewCaddyService(fake.URL)

	// When 启动应用（空规则库）
	if err := h.ApplyConfigOnStartup(); err != nil {
		t.Fatalf("ApplyConfigOnStartup: %v", err)
	}

	// Then 就绪探针（GET /config/）命中配置地址，且先于配置应用（POST /load）
	mu.Lock()
	defer mu.Unlock()
	firstReady, firstLoad := -1, -1
	for i, req := range order {
		if req == "GET /config/" && firstReady < 0 {
			firstReady = i
		}
		if req == "POST /load" && firstLoad < 0 {
			firstLoad = i
		}
	}
	if firstReady < 0 {
		t.Fatalf("就绪探针未拨号 cfg.CaddyAdminURL（%s）下的 GET /config/，实际请求=%v", fake.URL, order)
	}
	if firstLoad >= 0 && firstReady > firstLoad {
		t.Fatalf("就绪探针应先于配置应用：ready=#%d load=#%d order=%v", firstReady, firstLoad, order)
	}
}
