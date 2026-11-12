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
