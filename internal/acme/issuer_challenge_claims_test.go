package acme

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

// CA 复用同账号同标识的 pending 授权时，同域名两条签发会得到同一 token →
// 同一 keyAuth。按值清理无法从记录本身区分两条在途签发——先结束的一方必须
// 让出清理权，由最后结束的一方统一回收。
func TestIssuer_Cleanup_sharedValueReclaimedOnlyByLastIssuance(t *testing.T) {
	dnsprovider.ResetChallengeClaimsForTest()
	t.Cleanup(dnsprovider.ResetChallengeClaimsForTest)

	const (
		domain = "example.com"
		fqdn   = "_acme-challenge.example.com."
		value  = "shared-key-auth"
	)
	zone := zoneFromDomain(domain)
	provider := &valueAwareProvider{records: map[string]string{value: "record-" + value}}
	claimFirst, first := dnsprovider.ClaimChallengeValue(zone, fqdn, value)
	if !first {
		t.Fatal("首笔登记必须允许预清理")
	}
	claimSecond, first := dnsprovider.ClaimChallengeValue(zone, fqdn, value)
	if first {
		t.Fatal("同值第二笔登记必须识别出对方仍在途")
	}

	challenge := func(claim *dnsprovider.ChallengeClaim) ChallengeInfo {
		return ChallengeInfo{Domain: domain, TokenFQDN: fqdn, Value: value, claim: claim}
	}
	issuer := &Issuer{Provider: provider}

	issuer.cleanup(context.Background(), []ChallengeInfo{challenge(claimFirst)})
	if len(provider.cleanedValues) != 0 {
		t.Fatalf("先结束的签发不得清理仍在途的同值 TXT，cleaned=%v", provider.cleanedValues)
	}
	if _, exists := provider.records[value]; !exists {
		t.Fatal("同值 TXT 必须保留给仍在途的签发")
	}

	issuer.cleanup(context.Background(), []ChallengeInfo{challenge(claimSecond)})
	if len(provider.cleanedValues) != 1 {
		t.Fatalf("最后结束的签发必须回收同值 TXT，cleaned=%v", provider.cleanedValues)
	}
	if _, exists := provider.records[value]; exists {
		t.Fatal("同值 TXT 未被回收")
	}
}

// 未登记在途句柄的 ChallengeInfo（测试/外部构造）保持既有清理语义：
// 不得因缺少登记而跳过清理。
func TestIssuer_Cleanup_unclaimedChallengeStillCleans(t *testing.T) {
	dnsprovider.ResetChallengeClaimsForTest()
	t.Cleanup(dnsprovider.ResetChallengeClaimsForTest)

	const value = "unclaimed-key-auth"
	provider := &valueAwareProvider{records: map[string]string{value: "record-" + value}}
	issuer := &Issuer{Provider: provider}
	issuer.cleanup(context.Background(), []ChallengeInfo{{
		Domain: "example.com", TokenFQDN: "_acme-challenge.example.com.", Value: value,
	}})
	if len(provider.cleanedValues) != 1 {
		t.Fatalf("无在途登记的挑战必须照旧清理，cleaned=%v", provider.cleanedValues)
	}
}
