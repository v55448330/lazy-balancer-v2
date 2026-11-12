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
	policies := []*models.SecurityPolicy{{CCDetectEnabled: true, CCResponse: "verify"}}
	html, ctype := ccChallengeFallbackPage(ctx, policies)
	if html != "<html>{{human_verify_widget}}</html>" || ctype != "text/html; charset=utf-8" {
		t.Fatalf("CC verify 未回退内置人机验证页: html=%q ctype=%q", html, ctype)
	}
}

func TestCCChallengeFallbackSkipsBanAndNonCC(t *testing.T) {
	ctx := &securityPolicyContext{
		blockPageByID:     map[int]string{builtinHumanVerifyPageID: "<html>page</html>"},
		blockPageTypeByID: map[int]string{builtinHumanVerifyPageID: "text/html"},
	}
	for name, policies := range map[string][]*models.SecurityPolicy{
		"ban":   {{CCDetectEnabled: true, CCResponse: "ban"}},
		"nonCC": {{CCDetectEnabled: false, CCResponse: "verify"}},
		"empty": nil,
	} {
		if html, ctype := ccChallengeFallbackPage(ctx, policies); html != "" || ctype != "" {
			t.Fatalf("%s 不应回退内置人机验证页: html=%q ctype=%q", name, html, ctype)
		}
	}
	if html, _ := ccChallengeFallbackPage(nil, []*models.SecurityPolicy{{CCDetectEnabled: true, CCResponse: "verify"}}); html != "" {
		t.Fatalf("nil ctx 不应回退: %q", html)
	}
}
