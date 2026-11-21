package notify

// 日报「渲染模式」显式开关钉测（2026-11-22 用户裁定：模块拼装与自定义模板
// 二选一须显式可见可切，不靠「有没有存模板」隐式推断）。
//   - daily_mode="modules"：模块拼装——忽略该通道已存正文模板，走 items
//     分节渲染（dailyTemplatesSuppressed=true，机器人/邮件/webhook 模板
//     应用点全部旁路，回到与「从未存过模板」完全相同的默认链）。
//   - daily_mode="template"：自定义模板独占（既有行为，钉测见
//     daily_template_mode_test.go）。
//   - daily_mode 缺省：存量回填推断——有任一正文模板键即模板模式（与加
//     开关前的隐式行为一致，存量用户无感）。
import (
	"strings"
	"testing"
	"time"
)

func TestDailyModuleModeEffective(t *testing.T) {
	cases := []struct {
		name  string
		style ChannelStyle
		want  bool // true=模块拼装（抑制通道模板）
	}{
		{"无任何配置=模块拼装", ChannelStyle{}, true},
		{"存量机器人模板（缺省回填）=模板模式", ChannelStyle{ContentTemplate: "tpl"}, false},
		{"存量邮件模板（缺省回填）=模板模式", ChannelStyle{BodyTemplate: "tpl"}, false},
		{"存量webhook模板（缺省回填）=模板模式", ChannelStyle{PayloadTemplate: "{}"}, false},
		{"显式template=模板模式（即使无模板，编辑器侧另有保底）", ChannelStyle{DailyMode: "template"}, false},
		{"显式modules=模块拼装（已存模板保留但不生效）", ChannelStyle{DailyMode: "modules", ContentTemplate: "tpl", PayloadTemplate: "{}"}, true},
		{"未知值按存量推断（向前兼容）", ChannelStyle{DailyMode: "weird", ContentTemplate: "tpl"}, false},
	}
	for _, c := range cases {
		if got := c.style.DailyModuleModeEffective(); got != c.want {
			t.Fatalf("%s: DailyModuleModeEffective=%v want %v", c.name, got, c.want)
		}
	}
}

func TestDailyTemplatesSuppressed(t *testing.T) {
	daily := Message{EventType: EvtDailyReport, DailyModuleMode: true}
	if !daily.dailyTemplatesSuppressed() {
		t.Fatal("日报+模块拼装必须抑制通道模板")
	}
	if (Message{EventType: EvtDailyReport, DailyModuleMode: false}).dailyTemplatesSuppressed() {
		t.Fatal("日报模板模式不得抑制（模板独占）")
	}
	if (Message{EventType: "cfg.apply_failed", DailyModuleMode: true}).dailyTemplatesSuppressed() {
		t.Fatal("事件消息不受日报渲染模式影响")
	}
}

// 机器人：模块拼装模式下 content_template 不生效，回到与无模板一致的
// formatBotText（标题+分节正文；分节成品已含署名，不再附加）。
func TestDailyModuleMode_botsIgnoreStoredTemplate(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Title: "每日日报", DailyModuleMode: true,
		Body: "📊 全局概览\n| 指标 | 值 |\n请求 1200"}
	got := renderBotMessage("【模板痕迹】{{requests}} {{title}}", msg, time.Unix(0, 0), "qq")
	if strings.Contains(got, "模板痕迹") || strings.Contains(got, "{{") {
		t.Fatalf("模块拼装模式不得残留通道模板内容: %s", got)
	}
	if !strings.HasPrefix(got, "每日日报\n") || !strings.Contains(got, "请求 1200") {
		t.Fatalf("模块拼装须回到默认链（标题+分节正文）: %s", got)
	}
	if strings.Contains(got, "—— ") {
		t.Fatalf("日报分节成品已含署名，默认链不得重复附加: %s", got)
	}
	// 模板模式（开关关闭）回归：模板照常渲染
	msg2 := Message{EventType: EvtDailyReport, Title: "每日日报",
		Fields: map[string]string{"requests": "1200"}}
	got2 := renderBotMessage("请求 {{requests}}", msg2, time.Unix(0, 0), "qq")
	if !strings.Contains(got2, "请求 1200") {
		t.Fatalf("模板模式回归失败: %s", got2)
	}
}
