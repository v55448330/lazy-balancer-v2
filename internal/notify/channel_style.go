package notify

// 通道消息样式（style_config）：每通道可定制的消息呈现形态——
//   webhook: payload_template（JSON 模板，占位符 {{title}}/{{body}}/{{level}}/
//            {{event}}/{{time}}/{{node}}；保存时已校验占位符替换后可解析）
//   email:   subject_template（标题模板，同占位符）
//   qq:      msg_type（text=默认文本 / markdown=官方富文本消息 msg_type=2，
//            需机器人具备 markdown 权限，失败留痕可见）
//   wx:      iLink 协议仅文本，无样式项
//   通用:    daily_format（日报渲染格式覆盖，介于日报页配置与自动映射之间）
// 存储：notification_channels.style_config（JSON）；投递读侧合并进
// targetJSON（sender 以 target 内可选键消费，向后兼容旧通道）。

import (
	"encoding/json"
	"strings"
	"time"
)

// ChannelStyle 通道样式（解析后的结构形态）。
type ChannelStyle struct {
	PayloadTemplate string `json:"payload_template"`
	SubjectTemplate string `json:"subject_template"`
	MsgType         string `json:"msg_type"`
	DailyFormat     string `json:"daily_format"`
}

// ParseChannelStyle 容错解析（坏 JSON/空串=零值默认；派发路径不可因样式
// 配置损坏而中断投递）。
func ParseChannelStyle(raw string) ChannelStyle {
	var s ChannelStyle
	if strings.TrimSpace(raw) == "" {
		return s
	}
	_ = json.Unmarshal([]byte(raw), &s)
	return s
}

// MergeStyleIntoTarget 把样式键合并进 target JSON（读侧合并——sender 按着
// target 内可选键消费；target 原有键优先，避免重绑/编辑覆盖目标本体）。
func MergeStyleIntoTarget(targetJSON, styleJSON string) string {
	var target map[string]any
	if err := json.Unmarshal([]byte(targetJSON), &target); err != nil || target == nil {
		return targetJSON
	}
	var style map[string]any
	if err := json.Unmarshal([]byte(styleJSON), &style); err != nil || style == nil {
		return targetJSON
	}
	for _, k := range []string{"payload_template", "subject_template", "body_template", "body_format", "content_template", "msg_type", "daily_format", "method", "headers"} {
		if v, ok := style[k]; ok {
			if _, exists := target[k]; !exists {
				target[k] = v
			}
		}
	}
	merged, err := json.Marshal(target)
	if err != nil {
		return targetJSON
	}
	return string(merged)
}

// renderStyleTemplate 占位符替换（{{title}}/{{body}}/{{level}}/{{event}}/
// {{time}}/{{node}}；未知占位符原样保留——用户可见可自查）。
func renderStyleTemplate(tpl string, msg Message, ts time.Time) string {
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	event := msg.EventType
	if event == "" {
		event = "notification"
	}
	r := strings.NewReplacer(
		"{{title}}", msg.Title,
		"{{body}}", msg.Body,
		"{{level}}", msg.Level,
		"{{event}}", event,
		"{{time}}", ts.Format("2006-01-02 15:04"),
		"{{node}}", msg.Node,
		"{{brand}}", BrandName(),
		"{{date}}", templateDate(msg, ts),
		"{{event_title}}", eventDisplayTitle(msg.EventType),
	)
	return r.Replace(tpl)
}

// renderStyleTemplateJSON webhook payload_template 专用：占位符值经 JSON
// 编码（加引号+转义）后嵌入，与保存校验「占位符替换为 "probe" 仍合法 JSON」
// 同口径——模板写 `"title": {{title}}`，运行时产出合法 JSON 字符串值。
func renderStyleTemplateJSON(tpl string, msg Message, ts time.Time) string {
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	event := msg.EventType
	if event == "" {
		event = "notification"
	}
	enc := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	r := strings.NewReplacer(
		"{{title}}", enc(msg.Title),
		"{{body}}", enc(msg.Body),
		"{{level}}", enc(msg.Level),
		"{{event}}", enc(event),
		"{{time}}", enc(ts.Format(time.RFC3339)),
		"{{node}}", enc(msg.Node),
		"{{brand}}", enc(BrandName()),
		"{{date}}", enc(templateDate(msg, ts)),
		"{{event_title}}", enc(eventDisplayTitle(msg.EventType)),
	)
	return r.Replace(tpl)
}

// templateDate 日报日期变量：优先载荷 Fields["date"]（昨日），缺省=消息时间日期。
func templateDate(msg Message, ts time.Time) string {
	if d := msg.Fields["date"]; d != "" {
		return d
	}
	return ts.Format("2006-01-02")
}

// defaultEventTemplate 事件消息缺省精美模板（通道未自定义 content_template 时
// 的回退形态，与前端 defaultTplFor 同构）：QQ=markdown 富文本、微信=纯文本分隔线。
// 日报不走此回退（渲染底座已含分节+署名）。
func defaultEventTemplate(typ string) string {
	switch typ {
	case "qq":
		return "# 🔔 {{title}}\n\n> {{body}}\n\n## 📋 事件详情\n\n| 项目 | 内容 |\n| --- | --- |\n| 级别 | {{level}} |\n| 事件 | {{event_title}} |\n| 节点 | {{node}} |\n| 时间 | {{time}} |\n\n> {{brand}} · {{time}}"
	case "wx_clawbot":
		return "【{{title}}】\n────────────\n{{body}}\n────────────\n级别：{{level}}\n事件：{{event_title}}\n时间：{{time}}\n—— {{brand}} · {{time}}"
	}
	return ""
}

// renderBotMessage 机器人消息渲染：自定义模板优先；缺省且非日报=通道默认精美
// 模板；日报/无模板回退 formatBotText（标题+正文+署名）。
func renderBotMessage(tpl string, msg Message, ts time.Time, typ string) string {
	if strings.TrimSpace(tpl) == "" && msg.EventType != EvtDailyReport {
		tpl = defaultEventTemplate(typ)
	}
	return formatBotTextWithTemplate(tpl, msg, ts)
}
