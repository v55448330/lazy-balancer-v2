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
	// 2026-11-22 定稿样稿逐字：## 标题 → --- → 加粗正文 → --- → 加粗标签列表
	// （级别去 ⚠️、冒号后留一空格）→ --- → 品牌引用页脚，全程无空行。
	want := "## 🔔 {{title}}\n---\n**{{body}}**\n---\n* **级别**： {{level}}\n* **事件名称**：{{event_title}}\n* **所属节点**：{{node}}\n* **发生时间**：{{time}}\n---\n> {{brand}} 通知中心"
	if tpl != want {
		t.Fatalf("QQ 默认模板偏离定稿样稿:\n got %q\nwant %q", tpl, want)
	}
	if strings.Contains(tpl, "### ") || strings.Contains(tpl, "\n# ") || strings.HasPrefix(tpl, "# ") {
		t.Fatalf("QQ 模板标题层级须为 ##（定稿）: %q", tpl)
	}
	if strings.Contains(tpl, "⚠️") {
		t.Fatalf("定稿模板级别行不带 ⚠️ 前缀: %q", tpl)
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

// TemplateApplied 旁路（2026-11-22 第六轮：用户实测事件模板+通道模板双渲染，
// 标题/正文各两份、外层 ** 字面量泄漏）：事件级模板渲染完成的 Body 是最终
// 消息全量——通道样式模板（content/body/payload_template）不得再套一层。
func TestTemplateApplied_bypassesChannelStyleTemplates(t *testing.T) {
	rendered := "## 🔔 标题\n---\n**正文**\n---\n* **级别**： 警告\n* **事件名称**：证书即将过期\n---\n> 品牌通知中心"
	msg := Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "标题", Body: rendered, TemplateApplied: true}
	// 机器人：通道 content_template 存在也必须旁路，原样发送
	if got := renderBotMessage("## 外层 {{title}}\n> **{{body}}**", msg, time.Unix(0, 0), "qq"); got != rendered {
		t.Fatalf("TemplateApplied 后机器人不得再套通道模板:\n got %q\nwant %q", got, rendered)
	}
	// 邮件 body_template 旁路：正文即最终消息
	if got := renderStyleTemplate("<h1>{{title}}</h1><p>{{body}}</p>", msg, time.Unix(0, 0)); got != rendered {
		t.Fatalf("TemplateApplied 后邮件不得再套通道模板:\n got %q\nwant %q", got, rendered)
	}
	// 未标注（默认链）行为不变：模板仍正常渲染
	msg2 := Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "标题", Body: "正文"}
	if got := renderStyleTemplate("X {{title}} Y", msg2, time.Unix(0, 0)); got != "X 标题 Y" {
		t.Fatalf("默认链模板渲染回归: %q", got)
	}
}
