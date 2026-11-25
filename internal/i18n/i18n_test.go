package i18n

import (
	"os"
	"strings"
	"testing"
)

// 目录查词——命中返回中文母本；未登记的键原样返回（fail-visible，便于定位漏登记）。
// 后端没有语言参数：响应文案恒为中文母本，前端按 message_key 用自己的词条渲染。
func TestCatalogLookup(t *testing.T) {
	const key = "t.hello"
	Register(key, "你好")
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		delete(catalog, key)
	})
	if got := T(key); got != "你好" {
		t.Errorf("T(%q)=%q, want 中文母本", key, got)
	}
	if got := T("t.missing"); got != "t.missing" {
		t.Errorf("未登记的键应回落 key 本身, got %q", got)
	}
}

// 重复 Register(同键)为 map 覆盖语义，单边编辑副本会静默分叉——守卫必须对
// Register 调用计数（生成文件里重复的 Register 行），而不是遍历 map 键
// （map 键天然唯一，恒真）。
func TestCatalogKeysUnique(t *testing.T) {
	source, err := os.ReadFile("catalog_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	dups := 0
	for _, line := range strings.Split(string(source), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Register(") {
			continue
		}
		key := strings.TrimPrefix(line, "Register(")
		if i := strings.IndexByte(key, ','); i >= 0 {
			key = key[:i]
		}
		key = strings.Trim(key, `"`)
		if seen[key] {
			dups++
			continue
		}
		seen[key] = true
	}
	if len(seen) == 0 {
		t.Fatal("catalog_gen.go 未扫到任何 Register 调用——守卫对象漂移")
	}
	if dups != 0 {
		t.Fatalf("catalog_gen.go 存在 %d 处重复 Register 键——单边编辑副本将静默分叉", dups)
	}
}

// 生成管线的转义回归:含双引号的词条在用户侧必须是裸引号,
// 不得出现反斜杠(双重转义会让用户看到 {\"all\": true})。
func TestCatalogQuotedEntriesRenderWithoutBackslashes(t *testing.T) {
	for _, key := range []string{"cert.batchIssuanceExplicitConfirmRequired", "cert.acmeEmailNotConfigured"} {
		got := T(key)
		if got == key {
			t.Errorf("%s 未登记", key)
		}
		if strings.Contains(got, `\`) {
			t.Errorf("T(%q)=%q 含反斜杠——词条被双重转义", key, got)
		}
	}
	if got := T("cert.batchIssuanceExplicitConfirmRequired"); !strings.Contains(got, `{"all": true}`) {
		t.Errorf("zh 词条应含裸引号 JSON 示例, got %q", got)
	}
}
