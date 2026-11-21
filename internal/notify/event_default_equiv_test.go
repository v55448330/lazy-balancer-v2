package notify

// 跨栈共享夹具：web/tests/fixtures/event-default-templates.json 同时被前端
// web/tests/notificationDefaultTemplates.spec.ts 读取。前端「恢复默认模板」
// 写入编辑器/保存的文本必须与后端实际投递的缺省模板逐字一致——两侧各写一份
// 字符串时，后端 QQ 模板调整而前端预置未跟（或微信预置残留重复的事件/节点
// 行）都不会触发任何测试。
//
// 中文模板是双向契约（后端缺省渲染为中文，前端 zh 预置必须逐字相同）；
// 英文预置是前端本地化形态，结构等价由前端 spec 钉（不在本夹具内）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultEventTemplateMatchesFrontendFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "event-default-templates.json"))
	if err != nil {
		t.Fatalf("读取跨栈夹具: %v", err)
	}
	var fixture map[string]string
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("解析跨栈夹具: %v", err)
	}
	if len(fixture) == 0 {
		t.Fatal("跨栈夹具为空")
	}
	for typ, want := range fixture {
		if want == "" {
			t.Fatalf("夹具 %s 模板为空", typ)
		}
		if got := defaultEventTemplate(typ); got != want {
			t.Errorf("defaultEventTemplate(%q) 与前端预置夹具不一致\n got: %q\nwant: %q", typ, got, want)
		}
	}
	// 无缺省模板的通道必须返回空串（空模板=回退 formatBotText 标题+正文+署名）。
	for _, typ := range []string{"webhook", "email", "qqbot_unknown"} {
		if got := defaultEventTemplate(typ); got != "" {
			t.Errorf("defaultEventTemplate(%q)=%q, want 空串（无缺省模板通道）", typ, got)
		}
	}
}
