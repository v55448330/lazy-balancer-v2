package dnsproviders

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

type stubRound42Provider struct {
	presentErr error
	cleanupErr error
}

func (s *stubRound42Provider) Present(context.Context, string, string, string, int) error {
	return s.presentErr
}

func (s *stubRound42Provider) CleanUp(context.Context, string, string) error {
	return s.cleanupErr
}

// CERT42-6（第 42 轮审计）：Validate 的 CleanUp 失败时测试 TXT 记录可能已残留——
// 错误文案必须点名手动清理路径（含记录名 _acme-challenge.lb-test），避免运维
// 误判为纯连通性问题；返回错误语义不变（验证仍判失败）。
func TestDNSPod_Validate_cleanupFailureAdvisesManualCleanup(t *testing.T) {
	// Given a provider whose present succeeds but cleanup fails
	old := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) {
		return &stubRound42Provider{cleanupErr: errors.New("Record.Remove failed: timeout")}, nil
	}
	t.Cleanup(func() { newDNSProviderFromCredentials = old })
	provider := &DNSPod{}
	creds := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}

	// When validation runs
	err := provider.Validate(creds, "example.com")

	// Then it still fails, and the message names the manual cleanup path
	if err == nil {
		t.Fatal("want error（验证仍判失败）, got nil")
	}
	if !strings.Contains(err.Error(), "手动清理") {
		t.Fatalf("error=%q, want 手动清理提示", err.Error())
	}
	if !strings.Contains(err.Error(), "_acme-challenge.lb-test") {
		t.Fatalf("error=%q, want 残留记录名 _acme-challenge.lb-test", err.Error())
	}
}

// CERT42-6 回归形状：Present 失败不属于清理残留场景，文案不得出现手动清理提示。
func TestDNSPod_Validate_presentFailureKeepsOriginalMessage(t *testing.T) {
	// Given a provider whose present fails
	old := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) {
		return &stubRound42Provider{presentErr: errors.New("Domain.List failed: no auth")}, nil
	}
	t.Cleanup(func() { newDNSProviderFromCredentials = old })
	provider := &DNSPod{}
	creds := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}

	// When validation runs
	err := provider.Validate(creds, "example.com")

	// Then the write-test error is returned unchanged
	if err == nil || !strings.Contains(err.Error(), "DNS 写入测试失败") {
		t.Fatalf("error=%v, want DNS 写入测试失败", err)
	}
	if strings.Contains(err.Error(), "手动清理") {
		t.Fatalf("error=%q, must not mention 手动清理 for present failure", err.Error())
	}
}
