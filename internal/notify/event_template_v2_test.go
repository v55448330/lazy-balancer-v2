package notify

// 事件模板 v2（2026-11-22 用户裁定第五轮）：
//  1. 节点信息去重——正文不再追加「（节点 X）」后缀（结构化详情区已呈现，
//     双份重复且邮件 pre-wrap 下标签换行产生怪异双括号）；
//  2. QQ 默认模板重设计——去头重脚轻（# 大标题+分节标题），紧凑单层：
//     加粗标题+级别徽记 → 正文 → 分隔线 → 详情行（事件/节点/时间）→ 署名。
import (
	"strings"
	"testing"
	"time"
)

func TestRenderBody_noNodeSuffix(t *testing.T) {
	entry, ok := catalogByID(EvtLoginSuccess)
	if !ok {
		t.Fatal("目录缺登录成功事件")
	}
	got := renderBody(entry, Event{Node: "主节点(1.2.3.4:8000)",
		Fields: map[string]string{"1": "alice", "2": "2026-01-02 03:04:05", "3": "10.1.1.1"}})
	if strings.Contains(got, "（节点") || strings.Contains(got, "节点 主节点") {
		t.Fatalf("正文不得再带节点后缀（详情区已呈现，双份重复）: %q", got)
	}
	if !strings.Contains(got, "alice") {
		t.Fatalf("正文主体丢失: %q", got)
	}
}

func TestDefaultEventTemplateQQ_compactLayout(t *testing.T) {
	tpl := defaultEventTemplate("qq")
	if strings.Contains(tpl, "事件详情") {
		t.Fatalf("QQ 模板不得再含「事件详情」分节标题: %q", tpl)
	}
	if strings.Contains(tpl, "\n# ") || strings.HasPrefix(tpl, "# ") {
		t.Fatalf("QQ 模板不得再用单 # 大标题（头重脚轻；## 次级允许）: %q", tpl)
	}
	if !strings.Contains(tpl, "## ") {
		t.Fatalf("QQ 模板须保留 ## markdown 标题（富文本不被收敛成纯文本）: %q", tpl)
	}
	if !strings.Contains(tpl, "> {{body}}") {
		t.Fatalf("QQ 模板正文须用 > 引用分组（markdown 元素）: %q", tpl)
	}
	for _, ph := range []string{"{{title}}", "{{level}}", "{{body}}", "{{event_title}}", "{{node}}", "{{time}}", "{{brand}}"} {
		if !strings.Contains(tpl, ph) {
			t.Fatalf("QQ 模板缺占位符 %s: %q", ph, tpl)
		}
	}
	// 级别渲染中文（levelLabelZh 已在渲染层）
	msg := Message{EventType: "apikey.expiry_warning", Level: "warn", Title: "T", Body: "B", Node: "主节点(x:1)"}
	got := formatBotTextWithTemplate(tpl, msg, time.Unix(0, 0))
	if !strings.Contains(got, "警告") {
		t.Fatalf("QQ 模板级别未渲染中文: %q", got)
	}
}

func TestDefaultEventTemplateWX_carriesNode(t *testing.T) {
	// 正文后缀移除后，微信默认模板必须自带节点行（否则丢节点信息）
	tpl := defaultEventTemplate("wx_clawbot")
	if !strings.Contains(tpl, "{{node}}") {
		t.Fatalf("微信默认模板缺 {{node}}（正文后缀已移除）: %q", tpl)
	}
}
