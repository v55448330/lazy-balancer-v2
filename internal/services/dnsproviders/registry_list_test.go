package dnsproviders

import (
	"sort"
	"testing"
)

type stubListProvider struct {
	BaseProvider
	code string
}

func (s stubListProvider) Code() string                        { return s.code }
func (s stubListProvider) Name() string                        { return s.code }
func (s stubListProvider) ModuleName() string                  { return "stub." + s.code }
func (s stubListProvider) CredentialFields() []CredentialField { return nil }
func (s stubListProvider) BuildCredentialsJSON(map[string]string) (map[string]interface{}, error) {
	return nil, nil
}

// B431-3(第 43 轮):List 原实现直出注册表 map 遍历序,/dns-providers 响应
// 顺序随进程随机——改为按 Code 排序的稳定切片。
func TestList_returnsProvidersSortedByCode(t *testing.T) {
	// Given:乱序注册一批 stub provider(测试结束清出,恢复真实注册表)
	codes := []string{"stub-m", "stub-a", "stub-z", "stub-b", "stub-y", "stub-c", "stub-x", "stub-d"}
	for _, code := range codes {
		Register(&stubListProvider{code: code})
	}
	t.Cleanup(func() {
		for _, code := range codes {
			delete(registry, code)
		}
	})

	// When
	first := List()
	second := List()

	// Then:两次调用逐一相同且按 Code 升序
	if len(first) != len(second) {
		t.Fatalf("List() len %d vs %d", len(first), len(second))
	}
	got := make([]string, 0, len(first))
	for i, p := range first {
		if p != second[i] {
			t.Fatalf("List() 序不稳定:第 %d 位 %q vs %q", i, p.Code(), second[i].Code())
		}
		got = append(got, p.Code())
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("List() codes=%v, want 按 Code 升序", got)
	}
}
