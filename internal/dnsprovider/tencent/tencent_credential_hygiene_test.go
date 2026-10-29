package tencent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// String/%+v 任何形态都不得回显凭据（与 dnspod.Provider 同口径——导出字段
// 时代任何一次日志/序列化即泄密）。
func TestProvider_StringRedactsCredential(t *testing.T) {
	provider, err := New("test-secret-id", "test-secret-key")
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	for _, form := range []string{fmt.Sprintf("%s", provider), fmt.Sprintf("%+v", provider), provider.String()} {
		if strings.Contains(form, "test-secret-id") || strings.Contains(form, "test-secret-key") {
			t.Fatalf("字符串形态泄露凭据: %q", form)
		}
	}
	if !strings.Contains(provider.String(), provider.account) {
		t.Fatalf("脱敏形态应保留账户摘要以便排障: %q", provider.String())
	}
}

// sdkEchoTransport 让指定 action 返回回声凭据明文的 SDK 错误体（模拟中间
// 网关/WAF 拦截页把请求参数拼进 Message 的低概率形态）。
type sdkEchoTransport struct {
	action string
	body   string
}

func (transport *sdkEchoTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_, _ = io.ReadAll(request.Body)
	_ = request.Body.Close()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(transport.body)),
		Request:    request,
	}, transport.actionAssert(request.Header.Get("X-TC-Action"))
}

func (transport *sdkEchoTransport) actionAssert(actual string) error {
	if actual != transport.action {
		return fmt.Errorf("unexpected action %q (want %q)", actual, transport.action)
	}
	return nil
}

// tencent 侧错误文案脱敏钉：SDK 错误 Message 回声凭据明文时，三个错误出口
// （createRecord/deleteRecord/cleanUp 的 DeleteRecord failed 包装）拼进错误
// 链的文案都不得含明文。与 dnspod 侧 TestProvider_apiCall_redactsEchoedLoginToken
// 同口径——正常 SDK 错误只含 Code/Message/RequestId，泄露面是网关回声。
func TestProvider_SDKErrorRedactsEchoedSecret(t *testing.T) {
	echoBody := `{"Response":{"Error":{"Code":"InvalidParameterValue","Message":"invalid param rejected: SecretId=test-secret-id SecretKey=test-secret-key","RequestId":"req-1"},"RequestId":"req-1"}}`

	t.Run("createRecord", func(t *testing.T) {
		provider, err := New("test-secret-id", "test-secret-key")
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		provider.client.WithHttpTransport(&sdkEchoTransport{action: "CreateRecord", body: echoBody})
		_, err = provider.createRecord(context.Background(), "example.com", "_acme-challenge", "value", 60)
		if err == nil {
			t.Fatal("回声错误体必须导致失败")
		}
		if strings.Contains(err.Error(), "test-secret-id") || strings.Contains(err.Error(), "test-secret-key") {
			t.Fatalf("错误文案泄露凭据: %v", err)
		}
		if !strings.Contains(err.Error(), "CreateRecord failed") {
			t.Fatalf("动作名必须保留（排障自明）: %v", err)
		}
	})

	t.Run("deleteRecord", func(t *testing.T) {
		provider, err := New("test-secret-id", "test-secret-key")
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		provider.client.WithHttpTransport(&sdkEchoTransport{action: "DeleteRecord", body: echoBody})
		err = provider.deleteRecord(context.Background(), "example.com", 42)
		if err == nil {
			t.Fatal("回声错误体必须导致失败")
		}
		if strings.Contains(err.Error(), "test-secret-id") || strings.Contains(err.Error(), "test-secret-key") {
			t.Fatalf("错误文案泄露凭据: %v", err)
		}
		// 非资源不存在错误不得被误判为幂等成功（脱敏不得吞掉分类信号）。
		if isRecordNotFound(err) {
			t.Fatal("InvalidParameterValue 不得判为记录不存在")
		}
	})

	t.Run("cleanUp wraps sanitized", func(t *testing.T) {
		provider, err := New("test-secret-id", "test-secret-key")
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		provider.client.WithHttpTransport(&sdkEchoTransport{action: "DeleteRecord", body: echoBody})
		// ownership==nil 走内存兜底表：预置一条 owned 记录让 cleanUp 真正发起
		// 删除（空表清理不发 API、不产生错误，断言会空转）。
		provider.mu.Lock()
		provider.owned["example.com|_acme-challenge"] = []ownedRecord{{recordID: 42, value: "value"}}
		provider.mu.Unlock()
		err = provider.cleanUp(context.Background(), "example.com", "_acme-challenge.example.com", "value", true)
		if err == nil {
			t.Fatal("回声错误体必须导致清理失败")
		}
		if strings.Contains(err.Error(), "test-secret-id") || strings.Contains(err.Error(), "test-secret-key") {
			t.Fatalf("cleanUp 错误文案泄露凭据: %v", err)
		}
		if !strings.Contains(err.Error(), "DeleteRecord failed") {
			t.Fatalf("包装前缀必须保留: %v", err)
		}
	})

	t.Run("variant case echo withheld", func(t *testing.T) {
		// 大小写变换的回声不参与定向替换，但同样是泄露——命中即整段丢弃。
		variantBody := `{"Response":{"Error":{"Code":"InternalError","Message":"rejected: SECRET-ID=TEST-SECRET-ID malformed","RequestId":"req-2"},"RequestId":"req-2"}}`
		provider, err := New("test-secret-id", "test-secret-key")
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		provider.client.WithHttpTransport(&sdkEchoTransport{action: "CreateRecord", body: variantBody})
		_, err = provider.createRecord(context.Background(), "example.com", "_acme-challenge", "value", 60)
		if err == nil {
			t.Fatal("回声错误体必须导致失败")
		}
		if strings.Contains(strings.ToLower(err.Error()), "test-secret-id") {
			t.Fatalf("变体回声必须整段丢弃: %v", err)
		}
		if !strings.Contains(err.Error(), "withheld") {
			t.Fatalf("变体回声应整段丢弃并保留长度指纹: %v", err)
		}
	})

	t.Run("clean error passes through unchanged", func(t *testing.T) {
		// 正常 SDK 错误（无凭据痕迹）必须原样上抛——不因脱敏丢失诊断文案。
		cleanBody := `{"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"record not found","RequestId":"req-3"},"RequestId":"req-3"}}`
		provider, err := New("test-secret-id", "test-secret-key")
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		provider.client.WithHttpTransport(&sdkEchoTransport{action: "DeleteRecord", body: cleanBody})
		err = provider.deleteRecord(context.Background(), "example.com", 42)
		if err != nil {
			t.Fatalf("记录不存在必须按幂等成功处理: %v", err)
		}
	})
}
