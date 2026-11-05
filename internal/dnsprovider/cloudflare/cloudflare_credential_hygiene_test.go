package cloudflare

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/internal/retry"
)

// 凭据卫生门禁：API Token 不得经任何日志/错误文案/序列化路径落明文——错误
// 体脱敏（明文定向替换 + Bearer 形态正则兜底 + 变体回声 fail-closed 整段
// 丢弃）、String() 只暴露账户摘要、ownership 账本只落摘要。
const hygieneToken = "cf-tok-abcdef123456XYZ"

func TestProvider_errorTextNeverEchoesToken(t *testing.T) {
	t.Run("plaintext echo", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.overrides["GET /zones"] = cfResponse{status: 403, body: `{"success":false,"errors":[{"code":10000,"message":"request rejected: ` + hygieneToken + ` is bad"}],"result":null}`}
		p := newCloudflareTestProvider(t, hygieneToken, s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil {
			t.Fatal("必须失败")
		}
		if strings.Contains(err.Error(), hygieneToken) {
			t.Fatalf("错误文案泄漏 Token 明文: %v", err)
		}
		if !strings.Contains(err.Error(), "***") {
			t.Fatalf("错误文案未脱敏: %v", err)
		}
	})

	t.Run("bearer header echo", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		s.overrides["GET /zones"] = cfResponse{status: 400, body: `{"success":false,"errors":[{"code":6003,"message":"Invalid request headers: Authorization: Bearer ` + hygieneToken + ` not accepted"}],"result":null}`}
		p := newCloudflareTestProvider(t, hygieneToken, s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil {
			t.Fatal("必须失败")
		}
		if strings.Contains(err.Error(), hygieneToken) {
			t.Fatalf("Bearer 回声未脱敏: %v", err)
		}
	})

	t.Run("transformed echo withheld", func(t *testing.T) {
		s := newCloudflareTestServer(t)
		// 大小写变换的变体回声：定向替换不命中，fail-closed 整段丢弃。
		s.overrides["GET /zones"] = cfResponse{status: 403, body: `{"success":false,"errors":[{"code":0,"message":"token ` + strings.ToUpper(hygieneToken) + ` invalid"}],"result":null}`}
		p := newCloudflareTestProvider(t, hygieneToken, s)
		err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600)
		if err == nil {
			t.Fatal("必须失败")
		}
		if !strings.Contains(err.Error(), "withheld") {
			t.Fatalf("变体回声未整段丢弃: %v", err)
		}
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(hygieneToken)) {
			t.Fatalf("变体回声泄漏: %v", err)
		}
	})

	t.Run("String redacts", func(t *testing.T) {
		p := New(hygieneToken)
		if strings.Contains(p.String(), hygieneToken) {
			t.Fatalf("String() 泄漏 Token: %s", p.String())
		}
		if !strings.Contains(p.String(), "cloudflare.Provider{account:") {
			t.Fatalf("String()=%q, want 账户摘要形态", p.String())
		}
	})
}

// ownership 账本是明文 JSON：Token 只能以账户摘要形态落盘。
func TestProvider_ownershipLedgerNeverStoresToken(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.zones["example.com"] = "z1"
	dataDir := t.TempDir()
	p, err := NewPersistent(hygieneToken, dataDir)
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	p.endpoint = s.srv.URL + "/client/v4"
	p.client.Transport = &retry.Transport{Base: http.DefaultTransport, InitialBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
	resetCloudflareCaches(t)

	if err := p.Present(t.Context(), "example.com", "_acme-challenge.example.com", "v", 600); err != nil {
		t.Fatalf("Present: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "acme_dns_ownership.json"))
	if err != nil {
		t.Fatalf("read ownership: %v", err)
	}
	if strings.Contains(string(data), hygieneToken) {
		t.Fatalf("ownership 账本泄漏 Token 明文: %s", data)
	}
	if !strings.Contains(string(data), p.account) {
		t.Fatalf("ownership 账本缺账户摘要: %s", data)
	}
}
