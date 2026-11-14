package tencent

// isRecordNotFound 的记录级精确匹配钉测。
//
// 历史口径把整个 ResourceNotFound 前缀判为「记录不存在」——域名级错误
// （ResourceNotFound.DomainNotFound，域名移出账户/删除后厂商返回）也被当成
// 删除成功：清理误判成功 → 账本条目被移除，而 TXT 可能仍残留（或域名级
// 故障被掩盖）。只有记录级码（ResourceNotFound.NoDataOfRecord 与记录 ID
// 失效类）才允许幂等成功；域名级/其他 ResourceNotFound 子码必须上抛。

import (
	"errors"
	"testing"

	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// 记录级码必须判为「记录不存在」（幂等清理）；域名级与其他 ResourceNotFound
// 子码、非资源错误一律不得误判。
func TestIsRecordNotFound_recordLevelCodesOnly(t *testing.T) {
	for _, tc := range []struct {
		code string
		want bool
	}{
		{"ResourceNotFound.NoDataOfRecord", true},
		{"InvalidParameter.RecordIdInvalid", true},
		{"InvalidRecord.Id", true},
		{"ResourceNotFound.DomainNotFound", false},
		{"ResourceNotFound.Domain", false},
		{"ResourceNotFound", false},
		{"InvalidParameter.DomainNotFound", false},
		{"InvalidParameterValue", false},
		{"AuthFailure.SecretIdNotFound", false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			err := &tcerr.TencentCloudSDKError{Code: tc.code, Message: "test", RequestId: "req"}
			if got := isRecordNotFound(err); got != tc.want {
				t.Fatalf("isRecordNotFound(%s)=%v, want %v", tc.code, got, tc.want)
			}
		})
	}
	// 非 SDK 错误不得误判。
	if isRecordNotFound(errors.New("network timeout")) {
		t.Fatal("非 SDK 错误不得判为记录不存在")
	}
}

// 端到端：域名移出账户后 DeleteRecord 返回域名级 ResourceNotFound——清理
// 必须报错且保留账本条目（不得误判删除成功而移除追踪）。
func TestProvider_CleanUp_domainLevelNotFoundKeepsOwnership(t *testing.T) {
	dataDir := t.TempDir()
	transport := &codedDeleteErrorTransport{code: "ResourceNotFound.DomainNotFound"}
	transport.records = map[uint64]string{}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")
	if err == nil {
		t.Fatal("域名级 ResourceNotFound 不得误判为删除成功")
	}

	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("tencent", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("ownership left=%d, want 1（删除失败必须保留账本条目）", len(left))
	}
}

// 回归形状：记录级 NoDataOfRecord 仍按删除成功处理（幂等清理），账本条目
// 正常移除——收窄不得误伤记录级幂等语义。
func TestProvider_CleanUp_recordLevelNotFoundRemovesOwnership(t *testing.T) {
	dataDir := t.TempDir()
	transport := &codedDeleteErrorTransport{code: "ResourceNotFound.NoDataOfRecord"}
	transport.records = map[uint64]string{}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up with NoDataOfRecord: %v（记录级不存在必须按删除成功处理）", err)
	}

	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	left, err := store.Matching("tencent", "example.com", "_acme-challenge.example.com.")
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%d, want 0（记录级幂等删除后条目必须移除）", len(left))
	}
}
