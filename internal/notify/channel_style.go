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
	for _, k := range []string{"payload_template", "subject_template", "body_template", "msg_type", "daily_format"} {
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
		"{{time}}", ts.Format(time.RFC3339),
		"{{node}}", msg.Node,
	)
	return r.Replace(tpl)
}
