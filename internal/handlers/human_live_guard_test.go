package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 与同族的 /security/human/stats 对齐：
//  1. 未装配 cfg 的嵌入/测试形态返回零值 200，不得裸解引用 panic；
//  2. Caddy admin 不可达/旧插件缺端点时视图静默降级（保留空运行态），
//     但必须按状态转换留痕——首报一次，恢复一次，不逐轮刷日志。
func TestGetHumanLiveChallenges_nilConfigZeroPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/security/human/live", (&Handlers{}).GetHumanLiveChallenges)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/human/live?scope=active", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("nil-cfg status=%d body=%q, want 200（零值运行态）", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data humanLiveChallengePayload `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Data.ActiveCount != 0 || len(payload.Data.Sessions) != 0 {
		t.Fatalf("nil-cfg 返回非零运行态: %+v", payload.Data)
	}
}

func TestGetHumanLiveChallenges_logsAdminFailureOnce(t *testing.T) {
	withIsolatedGlobal(t)
	services.ResetLogStateTransitionForTest("human-live-challenges")
	t.Cleanup(func() { services.ResetLogStateTransitionForTest("human-live-challenges") })

	h := newBackupTestHandlers(t)
	h.cfg.CaddyAdminURL = "http://127.0.0.1:1" // 连接必败：等价 admin 未配置

	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/human/live", h.GetHumanLiveChallenges)
	for range 2 {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/human/live?scope=active", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("admin 不可达时 status=%d body=%s, want 200（降级空运行态）", recorder.Code, recorder.Body.String())
		}
	}

	const failureLine = "读取配置失败（human-live-challenges）"
	if got := strings.Count(logs.String(), failureLine); got != 1 {
		t.Fatalf("admin 拉取失败留痕 %d 条, want 1（首报去重；0=完全静默、>1=逐轮刷日志）: %q", got, logs.String())
	}
}
