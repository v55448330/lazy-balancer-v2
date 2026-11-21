package handlers

// HDL154-P3-01：退化提交分支（DB 已提交、运行配置未生效）必须与成功分支
// 同口径发布通知事件——热路径/默认策略此前只在成功分支发，通知面漏报。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

func TestSecurityWrite_transportFailureStillPublishesNotify(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	withIsolatedGlobal(t)
	var mu sync.Mutex
	var events []notify.Event
	oldPublish := notifyPublish
	notifyPublish = func(evt notify.Event) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}
	t.Cleanup(func() { notifyPublish = oldPublish })

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := closed.URL
	closed.Close()
	h := &Handlers{caddyService: services.NewCaddyService(url)}
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)

	rec := httptest.NewRecorder()
	body := `{"name":"退化提交也要通知","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5,"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "但 Caddy 配置应用失败") {
		t.Fatalf("status=%d body=%s，want 200 退化提交", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || events[0].Type != notify.EvtCustomRuleChanged {
		t.Fatalf("退化提交事件=%+v，want 单条 EvtCustomRuleChanged", events)
	}
}

func TestApplyDefaultPolicies_degradedApplyStillPublishesEvents(t *testing.T) {
	env := newDefaultPoliciesTestEnv(t)
	// 管理接口不可达 → DB 默认策略已提交、运行配置未生效（退化分支）。
	env.h.caddyService = services.NewCaddyService("http://127.0.0.1:1")

	rec := env.post("")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s，want 200（退化提交不阻断保存）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "已保存，但重载 Caddy 配置失败") {
		t.Fatalf("body=%s，want 退化提示文案", rec.Body.String())
	}
	if events := env.capturedEvents(); len(events) == 0 {
		t.Fatal("退化提交未发布默认策略/名单事件（通知面漏报）")
	}
}
