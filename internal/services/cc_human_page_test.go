package services

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestCCChallengeFallbackUsesBuiltinHumanPage(t *testing.T) {
	ctx := &securityPolicyContext{
		blockPageByID:     map[int]string{builtinHumanVerifyPageID: "<html>{{human_verify_widget}}</html>"},
		blockPageTypeByID: map[int]string{builtinHumanVerifyPageID: "text/html; charset=utf-8"},
	}
	for name, policies := range map[string][]*models.SecurityPolicy{
		"cc-verify": {{CCDetectEnabled: true, HumanVerifyMode: "force"}},
		"force":     {{HumanVerifyMode: "force"}},
	} {
		html, ctype := humanChallengeFallbackPage(ctx, policies)
		if html != "<html>{{human_verify_widget}}</html>" || ctype != "text/html; charset=utf-8" {
			t.Fatalf("%s 未回退内置人机验证页: html=%q ctype=%q", name, html, ctype)
		}
	}
}

func TestCCChallengeFallbackSkipsNonChallenge(t *testing.T) {
	ctx := &securityPolicyContext{
		blockPageByID:     map[int]string{builtinHumanVerifyPageID: "<html>page</html>"},
		blockPageTypeByID: map[int]string{builtinHumanVerifyPageID: "text/html"},
	}
	for name, policies := range map[string][]*models.SecurityPolicy{
		"noHuman": {{CCDetectEnabled: true}},
		"nonCC":   {{CCDetectEnabled: false}},
		"empty":   nil,
	} {
		if html, ctype := humanChallengeFallbackPage(ctx, policies); html != "" || ctype != "" {
			t.Fatalf("%s 不应回退内置人机验证页: html=%q ctype=%q", name, html, ctype)
		}
	}
	if html, _ := humanChallengeFallbackPage(nil, []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "force"}}); html != "" {
		t.Fatalf("nil ctx 不应回退: %q", html)
	}
}

// Given force 合并模式（任一 force 策略即 force）+ CC 动作 queue/reject，
// 页表同时备齐验证页与 CC 动作页。
// When 内置挑战页回退选页。
// Then force 恒按验证方式选 9005/9006（CC 动作不参与——强制验证的请求必须
// 拿到可完成验证的挑战页，排队/拒绝页会让 force 验证死路）；auto 模式现行
// 按 CC 动作选页行为不变。
func TestCCChallengeFallbackForceIgnoresCCAction(t *testing.T) {
	ctx := &securityPolicyContext{
		blockPageByID: map[int]string{
			builtinHumanVerifyPageID:   "<html>slider</html>",
			builtinHumanJSVerifyPageID: "<html>js</html>",
			builtinQueueWaitPageID:     "<html>queue</html>",
			builtinRateLimitPageID:     "<html>429</html>",
		},
		blockPageTypeByID: map[int]string{
			builtinHumanVerifyPageID:   "text/html",
			builtinHumanJSVerifyPageID: "text/html",
			builtinQueueWaitPageID:     "text/html",
			builtinRateLimitPageID:     "text/html",
		},
	}
	cases := []struct {
		name string
		pols []*models.SecurityPolicy
		want string
	}{
		{"force-slider-queue", []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "force", CCTriggerAction: "queue"}}, "<html>slider</html>"},
		{"force-slider-reject", []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "force", CCTriggerAction: "reject"}}, "<html>slider</html>"},
		{"force-js-queue", []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "force", HumanVerifyType: "js", CCTriggerAction: "queue"}}, "<html>js</html>"},
		{"force-js-reject", []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "force", HumanVerifyType: "js", CCTriggerAction: "reject"}}, "<html>js</html>"},
		{"force-mixed-top-wins", []*models.SecurityPolicy{
			{CCDetectEnabled: true, HumanVerifyMode: "auto", CCTriggerAction: "queue"},
			{HumanVerifyMode: "force"},
		}, "<html>slider</html>"},
		{"auto-queue-unchanged", []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "auto", CCTriggerAction: "queue"}}, "<html>queue</html>"},
		{"auto-reject-unchanged", []*models.SecurityPolicy{{CCDetectEnabled: true, HumanVerifyMode: "auto", CCTriggerAction: "reject"}}, "<html>429</html>"},
	}
	for _, c := range cases {
		html, ctype := humanChallengeFallbackPage(ctx, c.pols)
		if html != c.want || ctype != "text/html" {
			t.Fatalf("%s 选页错位: html=%q ctype=%q, want %q", c.name, html, ctype, c.want)
		}
	}
}
