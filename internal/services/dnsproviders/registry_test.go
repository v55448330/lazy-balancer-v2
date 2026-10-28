package dnsproviders

import (
	"strings"
	"testing"
)

// fakeProvider 只实现注册期需要的 Code/Name/ModuleName；其余能力本用例不触达。
type fakeProvider struct {
	BaseProvider
	code string
}

func (p *fakeProvider) Code() string                        { return p.code }
func (p *fakeProvider) Name() string                        { return p.code }
func (p *fakeProvider) ModuleName() string                  { return "module." + p.code }
func (p *fakeProvider) CredentialFields() []CredentialField { return nil }
func (p *fakeProvider) BuildCredentialsJSON(map[string]string) (map[string]interface{}, error) {
	return nil, nil
}

var _ Provider = (*fakeProvider)(nil)

// 重复 Code 是 init 期复制粘贴漏改的典型形态：此前静默覆盖（List 少一项、
// 字段表与 Validate 来自不同实现）。注册期必须 panic 快速失败。
func TestRegister_duplicateCodePanics(t *testing.T) {
	const code = "test-dup-provider-97"
	Register(&fakeProvider{code: code})
	// 注册表是包级全局：用例结束必须清出替身，否则 -count/-shuffle 下
	// 第二次注册即 panic，且替身会把「真实提供商集合」类断言撑绿。
	t.Cleanup(func() { delete(registry, code) })
	got, ok := Get(code)
	if !ok || got.Code() != code {
		t.Fatalf("首次注册未生效: %v %v", got, ok)
	}

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("重复 Code 注册必须 panic（启动期快速失败）")
		}
		if message, _ := recovered.(string); !strings.Contains(message, "duplicate provider code") || !strings.Contains(message, code) {
			t.Fatalf("panic 文案=%v，必须点名 duplicate provider code 与冲突 Code", recovered)
		}
	}()
	Register(&fakeProvider{code: code})
}
