package services

// CC 触发动作渲染链钉测：投影下发 cc_trigger_action/cc_queue_wait_sec；
// 页回退链三态（queue→9007 / reject→9001 / challenge→9005/9006）。

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestBuildHumanHandler_projectsCCTriggerAction(t *testing.T) {
	setupGeoipConfigTestDB(t)
	humanSecretMu.Lock()
	humanSecretCache = ""
	humanSecretMu.Unlock()
	policies := []*models.SecurityPolicy{{
		HumanVerifyMode: "auto", HumanVerifyType: "js", HumanVerifyTTL: 30,
		CCDetectEnabled: true, CCRPSLimit: 40, CCRPSWindow: 10, CC4xxRatio: 70,
		CCTriggerAction: "queue", CCQueueWaitSec: 25,
	}}
	cfg := buildHumanHandler("lb_test", policies)
	if cfg == nil {
		t.Fatal("handler 不得为 nil")
	}
	if cfg["cc_trigger_action"] != "queue" {
		t.Fatalf("cc_trigger_action=%v, want queue", cfg["cc_trigger_action"])
	}
	if cfg["cc_queue_wait_sec"] != 25 {
		t.Fatalf("cc_queue_wait_sec=%v, want 25", cfg["cc_queue_wait_sec"])
	}
}

func TestCCChallengeFallbackQueueUses9007(t *testing.T) {
	ctx := &securityPolicyContext{
		blockPageByID:     map[int]string{builtinQueueWaitPageID: "<html>{{queue_widget}}</html>"},
		blockPageTypeByID: map[int]string{builtinQueueWaitPageID: "text/html"},
	}
	policies := []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "auto", CCTriggerAction: "queue"}}
	html, _ := humanChallengeFallbackPage(ctx, policies)
	if html != "<html>{{queue_widget}}</html>" {
		t.Fatalf("queue 动作必须回退 9007 等待页: %q", html)
	}
}

func TestCCChallengeFallbackRejectUses9001(t *testing.T) {
	ctx := &securityPolicyContext{
		blockPageByID:     map[int]string{builtinRateLimitPageID: "<html>429</html>"},
		blockPageTypeByID: map[int]string{builtinRateLimitPageID: "text/html"},
	}
	policies := []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "auto", CCTriggerAction: "reject"}}
	html, _ := humanChallengeFallbackPage(ctx, policies)
	if html != "<html>429</html>" {
		t.Fatalf("reject 动作必须回退 9001 拒绝页: %q", html)
	}
}

// Given auto 模式 + CC 触发动作 challenge（默认态），验证方式 js / slider。
// When 选挑战页回退。
// Then 按验证方式回退 9006 / 9005——三态链的 challenge 支必须实钉
// （头注释宣称三态，此前只钉 queue/reject 两态）。
func TestCCChallengeFallbackAutoChallengeByVerifyType(t *testing.T) {
	cases := []struct {
		name   string
		typ    string
		pageID int
		html   string
	}{
		{"js→9006", "js", builtinHumanJSVerifyPageID, "<html>js-challenge</html>"},
		{"slider→9005", "slider", builtinHumanVerifyPageID, "<html>slider-challenge</html>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := &securityPolicyContext{
				blockPageByID:     map[int]string{c.pageID: c.html},
				blockPageTypeByID: map[int]string{c.pageID: "text/html"},
			}
			policies := []*models.SecurityPolicy{{
				CCDetectEnabled: true, HumanVerifyMode: "auto", HumanVerifyType: c.typ,
				CCTriggerAction: "challenge",
			}}
			html, _ := humanChallengeFallbackPage(ctx, policies)
			if html != c.html {
				t.Fatalf("auto+challenge(%s) 必须回退 %d 挑战页: %q", c.typ, c.pageID, html)
			}
		})
	}
}
