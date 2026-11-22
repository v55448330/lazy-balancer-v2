package handlers

// EvtLibSettingsChanged 的参数位 Fields["3"] 是通知正文模板
// 「用户 %s 变更了%s（%s）」的第三参——必须是面向用户的中文短语，不得回落
// 到处理函数英文名（如「UpdateCRSAutoUpdate」），英文标识符对用户无意义。
// 源码级钉：覆盖 security.go + crawlerlib.go 的全部 7 个发布点（命中计数
// 门防发布点搬移/新增后本门假绿）。

import (
	"os"
	"regexp"
	"testing"
)

var (
	libSettingsNotifyPattern = regexp.MustCompile(`EvtLibSettingsChanged[^\n]*"3":\s*(?:fmt\.Sprintf\("%s",\s*)?"([^"]*)"`)
	hanPattern               = regexp.MustCompile(`\p{Han}`)
)

func TestLibSettingsChangedNotifyParamIsChinesePhrase(t *testing.T) {
	total := 0
	for _, file := range []string{"security.go", "crawlerlib.go"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, m := range libSettingsNotifyPattern.FindAllStringSubmatch(string(raw), -1) {
			total++
			if value := m[1]; !hanPattern.MatchString(value) {
				t.Errorf("%s: EvtLibSettingsChanged 参数 %q 不是中文短语（用户可见正文不得用英文函数名）", file, value)
			}
		}
	}
	if total != 7 {
		t.Fatalf("扫描命中 %d 处 EvtLibSettingsChanged 参数位，want 7（发布点新增/搬移须同步本门）", total)
	}
}
