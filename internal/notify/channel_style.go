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
	"sort"
	"strings"
	"time"
)

// ChannelStyle 通道样式（解析后的结构形态）。
type ChannelStyle struct {
	PayloadTemplate string `json:"payload_template"`
	SubjectTemplate string `json:"subject_template"`
	ContentTemplate string `json:"content_template"`
	BodyTemplate    string `json:"body_template"`
	MsgType         string `json:"msg_type"`
	DailyFormat     string `json:"daily_format"`
	// DailyMode 日报渲染模式显式开关（2026-11-22 用户裁定）："modules"=模块
	// 拼装（忽略已存正文模板，走 items 分节渲染）；"template"=自定义模板独占；
	// 缺省=存量回填推断（见 DailyModuleModeEffective）。
	DailyMode string `json:"daily_mode"`
}

// DailyModuleModeEffective 日报是否走模块拼装（抑制该通道正文模板）。
// 显式值优先；缺省按存量推断——有任一正文模板键（机器人 content_template/
// 邮件 body_template/webhook payload_template）即模板模式，与加开关前的
// 隐式行为一致（存量用户无感迁移）。未知值同样按存量推断（向前兼容）。
func (s ChannelStyle) DailyModuleModeEffective() bool {
	if s.DailyMode == "modules" {
		return true
	}
	if s.DailyMode == "template" {
		return false
	}
	return s.ContentTemplate == "" && s.BodyTemplate == "" && s.PayloadTemplate == ""
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
	// TemplateApplied：Body 即最终消息，任何样式模板（邮件 body_template 等
	// 经此入口的调用方）不得再包裹。
	if msg.TemplateApplied {
		return msg.Body
	}
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	event := msg.EventType
	if event == "" {
		event = "notification"
	}
	pairs := []string{
		"{{title}}", msg.Title,
		"{{body}}", msg.Body,
		"{{level}}", levelLabelZh(msg.Level),
		"{{event}}", event,
		"{{time}}", ts.Format("2006-01-02 15:04"),
		"{{node}}", msg.Node,
		"{{brand}}", BrandName(),
		"{{date}}", templateDate(msg, ts),
		"{{event_title}}", eventDisplayTitle(msg.EventType),
	}
	// 日报变量（2026-11-22 二选一裁定）：模板模式下全部日常变量可放置。
	// 事件消息 Fields 为编号键（"1"/"2"），不参与替换。
	if msg.EventType == EvtDailyReport {
		for _, k := range dailyFieldKeys(msg.Fields, styleReservedPlaceholders) {
			pairs = append(pairs, "{{"+k+"}}", msg.Fields[k])
		}
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// renderSubjectTemplate 邮件主题窄渲染器：只替换元信息占位符
// （title/level/event/time/node/brand/date/event_title），**不替换 {{body}}**。
// TemplateApplied 时 Body 是整篇最终正文，主题模板若沿用通用渲染器会把多行
// markdown 全文顶进主题（NOTIF154-P2-01）；保留 {{body}} 字面量供用户自查。
func renderSubjectTemplate(tpl string, msg Message, ts time.Time) string {
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	event := msg.EventType
	if event == "" {
		event = "notification"
	}
	pairs := []string{
		"{{title}}", msg.Title,
		"{{level}}", levelLabelZh(msg.Level),
		"{{event}}", event,
		"{{time}}", ts.Format("2006-01-02 15:04"),
		"{{node}}", msg.Node,
		"{{brand}}", BrandName(),
		"{{date}}", templateDate(msg, ts),
		"{{event_title}}", eventDisplayTitle(msg.EventType),
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
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
	pairs := []string{
		"{{title}}", enc(msg.Title),
		"{{body}}", enc(msg.Body),
		"{{level}}", enc(msg.Level),
		"{{event}}", enc(event),
		"{{time}}", enc(ts.Format(time.RFC3339)),
		"{{node}}", enc(msg.Node),
		"{{brand}}", enc(BrandName()),
		"{{date}}", enc(templateDate(msg, ts)),
		"{{event_title}}", enc(eventDisplayTitle(msg.EventType)),
	}
	// 日报变量同文本变体：值经 JSON 编码嵌入（保存校验同口径）。
	if msg.EventType == EvtDailyReport {
		for _, k := range dailyFieldKeys(msg.Fields, styleReservedPlaceholders) {
			pairs = append(pairs, "{{"+k+"}}", enc(msg.Fields[k]))
		}
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// 各渲染器已内置的占位符键集（Fields 扩展须排除，防 NewReplacer 重复键 panic）。
var styleReservedPlaceholders = map[string]bool{"date": true, "title": true, "body": true,
	"level": true, "event": true, "time": true, "node": true, "brand": true, "event_title": true}

// botReservedPlaceholders 由 style 集派生（唯一差异=date：机器人模板不收日期
// 变量）——此前两份字面量各自维护，增键必漏一侧。
var botReservedPlaceholders = func() map[string]bool {
	m := make(map[string]bool, len(styleReservedPlaceholders))
	for k := range styleReservedPlaceholders {
		if k == "date" {
			continue
		}
		m[k] = true
	}
	return m
}()

// dailyFieldKeys 日报载荷 Fields 中可作文本变量的键（排除渲染器已内置键；
// 确定性排序便于测试与排查）。
func dailyFieldKeys(fields map[string]string, reserved map[string]bool) []string {
	if len(fields) == 0 {
		return nil
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		if reserved[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
		// markdown 版式（2026-11-22 定稿样稿逐字）：## 标题 → --- → 加粗正文
		// → --- → 加粗标签列表（级别去 ⚠️、冒号后留一空格）→ --- → 品牌
		// 引用页脚，全程无空行。
		return "## 🔔 {{title}}\n---\n**{{body}}**\n---\n* **级别**： {{level}}\n* **事件名称**：{{event_title}}\n* **所属节点**：{{node}}\n* **发生时间**：{{time}}\n---\n> {{brand}} 通知中心"
	case "wx_clawbot":
		return "【{{title}}】\n────────────\n{{body}}\n────────────\n级别：⚠️ {{level}}\n事件名称：{{event_title}}\n所属节点：{{node}}\n发生时间：{{time}}\n\n—— {{brand}} 通知中心"
	}
	return ""
}

// renderBotMessage 机器人消息渲染：自定义模板优先；缺省且非日报=通道默认精美
// 模板；日报/无模板回退 formatBotText（标题+正文+署名）。
func renderBotMessage(tpl string, msg Message, ts time.Time, typ string) string {
	// 事件模板已全量渲染（用户模板含标题/列表/页脚）——通道模板（含默认
	// 预置）再套一层会产生双标题/双正文；原样发送。
	if msg.TemplateApplied {
		return msg.Body
	}
	// 日报模块拼装模式：通道模板不生效，回到与无模板一致的默认链
	// （标题+分节正文；分节成品已含署名）。
	if msg.dailyTemplatesSuppressed() {
		tpl = ""
	}
	// QQ 日报自定义模板：多值变量（TOP IP/路径/临期证书/节点摘要）展开为
	// 语义表格（模板提供上下文标签，变量只出表格本体）——与内置模板同族
	// 设计；微信（纯文本）与其他通道保持原始多行值，不注入 markdown 标记。
	if msg.EventType == EvtDailyReport && typ == "qq" && msg.Fields != nil {
		fields := make(map[string]string, len(msg.Fields))
		for k, v := range msg.Fields {
			fields[k] = v
		}
		for _, k := range []string{"top_ips", "top_paths", "cert_expiring", "nodes_summary"} {
			if v, ok := fields[k]; ok {
				if md, ok2 := mdMultiValueTable(k, v); ok2 {
					// 前后各留一空行：模板里标签行紧跟变量时，表格与标签/
					// 相邻块粘连会被解析器互相吞并（表头变数据行）。
					fields[k] = "\n" + strings.TrimRight(md, "\n") + "\n"
				}
			}
		}
		msg.Fields = fields
	}
	if strings.TrimSpace(tpl) == "" && msg.EventType != EvtDailyReport {
		tpl = defaultEventTemplate(typ)
	}
	return formatBotTextWithTemplate(tpl, msg, ts)
}
