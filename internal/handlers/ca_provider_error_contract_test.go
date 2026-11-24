package handlers

import (
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 证书/DNS 族「5xx 统一写点」：管理员打开 CA 提供商列表/详情遇 DB 读故障时
// 响应只回固定文案可以，但底层原因必须进运行日志（此前两处裸 500 零留痕，
// 面板只显示通用错误、日志无线索）。文案保持键化（message_key 不降级）。
func TestCAProviderReadFailuresLogUnderlyingCause(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	if _, err := db.DB.Exec(`DROP TABLE ca_providers`); err != nil {
		t.Fatalf("drop ca_providers: %v", err)
	}

	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ca-providers", h.ListCAProviders)
	router.GET("/ca-providers/:id", h.GetCAProvider)

	for _, path := range []string{"/ca-providers", "/ca-providers/7"} {
		logs.Reset()
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("%s status=%d body=%s, want 500", path, recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(logs.String(), "ca_providers") {
			t.Fatalf("%s 500 未留痕底层原因（运行日志无可归因线索）: %q", path, logs.String())
		}
		if !strings.Contains(recorder.Body.String(), `"message_key"`) {
			t.Fatalf("%s 500 响应缺 message_key（键化契约降级）: %s", path, recorder.Body.String())
		}
	}
}
