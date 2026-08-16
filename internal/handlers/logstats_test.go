package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func TestLogPaths_fixedDirIndependentOfLogFile(t *testing.T) {
	// 自定义 LOG_FILE 目录不得影响五个写死 /app/logs 的日志族的路径根；
	// 只有 runtime 日志跟随 LogFile。
	gotDir, gotRuntime := logPaths(&config.Config{LogFile: "/tmp/x/y.log"})
	if gotDir != "/app/logs" {
		t.Fatalf("fixedDir=%q, want /app/logs (caddy/crs/ip2region/certjob/rules writers hardcode /app/logs)", gotDir)
	}
	if gotRuntime != "/tmp/x/y.log" {
		t.Fatalf("runtimePath=%q, want /tmp/x/y.log", gotRuntime)
	}
}

func TestLogPaths_defaults(t *testing.T) {
	gotDir, gotRuntime := logPaths(nil)
	if gotDir != "/app/logs" || gotRuntime != "/app/logs/lazy-balancer.log" {
		t.Fatalf("defaults: dir=%q runtime=%q", gotDir, gotRuntime)
	}
}

func newLogStatsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	return router
}

func TestGetLogStats_rejectsTraversalCaddyID(t *testing.T) {
	// Given a fresh DB and a path-traversal caddy_id
	setupSecurityPolicyTestDB(t)
	router := newLogStatsRouter()

	// When /logs/stats is requested with a traversal value
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logs/stats?caddy_id=../../etc/passwd", nil)
	router.ServeHTTP(recorder, req)

	// Then the request is rejected with 400 instead of escaping the log directory
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

func TestGetLogStats_acceptsValidCaddyID(t *testing.T) {
	// Given a fresh DB and a well-formed caddy_id
	setupSecurityPolicyTestDB(t)
	router := newLogStatsRouter()

	// When /logs/stats is requested with a valid id
	recorder := getRequest(t, router, "/logs/stats?caddy_id=lb_abc123")

	// Then it succeeds normally
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}
