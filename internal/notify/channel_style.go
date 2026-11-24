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
	"html"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ChannelStyle 通道样式（解析后的结构形态）。
//
// 正文模板分两套作用域（2026-11-24 对齐裁定）：
//   - 事件正文模板：payload_template / body_template / content_template——
//     事件消息（含规则级模板回退）与 API 写入的既有语义；界面已无编辑入口。
//   - 日报正文模板：daily_payload_template / daily_body_template /
//     daily_content_template——「每日摘要卡 → 编辑模板」唯一写入口，只作用于
//     日报。存量行（日报卡曾把模板写进事件键）由同一判据归一：派发路径
//     normalizeLegacyDaily、读面 CanonicalChannelStyleJSON、写面 CanonicalTemplateScope。
type ChannelStyle struct {
	PayloadTemplate string `json:"payload_template"`
	SubjectTemplate string `json:"subject_template"`
	ContentTemplate string `json:"content_template"`
	BodyTemplate    string `json:"body_template"`
	// 日报专用正文模板（与事件正文模板分离，见上）。
	DailyPayloadTemplate string `json:"daily_payload_template"`
	DailyBodyTemplate    string `json:"daily_body_template"`
	DailyContentTemplate string `json:"daily_content_template"`
	MsgType              string `json:"msg_type"`
	DailyFormat          string `json:"daily_format"`
	BodyFormat           string `json:"body_format"`
	// DailyMode 日报渲染模式显式开关（2026-11-22 用户裁定）："modules"=模块
	// 拼装（忽略已存日报模板，走 items 分节渲染）；"template"=自定义模板独占；
	// 缺省=存量回填推断（见 DailyModuleModeEffective）。
	DailyMode string `json:"daily_mode"`
}

// dailyValueKeys 日报载荷 values 键集（存量归一判据：模板引用这些变量即视为
// 日报卡产物）。与 dailyValues 的单源一致——新增日报变量须同步两处。
var dailyValueKeys = map[string]bool{
	"requests": true, "allowed": true, "logged": true, "distinct_ips": true,
	"bandwidth": true, "peak_qps": true, "blocked": true, "attack_top": true,
	"top_ips": true, "top_paths": true, "cc_triggered": true, "autoban": true,
	"cert_status": true, "cert_expiring": true, "cluster_status": true,
	"nodes_summary": true, "uptime": true, "threat_db": true, "app_version": true,
	"api_calls": true, "mcp_calls": true, "task_status": true, "backup_status": true,
	"login_status": true,
}

// templateReferencesDailyVariable 模板是否引用任一日报变量（{{name}}）。
func templateReferencesDailyVariable(tpl string) bool {
	for {
		start := strings.Index(tpl, "{{")
		if start < 0 {
			return false
		}
		tpl = tpl[start+2:]
		end := strings.Index(tpl, "}}")
		if end < 0 {
			return false
		}
		if dailyValueKeys[strings.TrimSpace(tpl[:end])] {
			return true
		}
		tpl = tpl[end+2:]
	}
}

// ruleTemplateHTMLTag 规则级邮件模板的发送格式判据：模板含 HTML 标签即按
// text/html 发送（占位符值转义），否则按纯文本原文发送。后端没有规则级格式
// 字段，格式只能由内容决定；与前端规则弹框的格式行同口径
// （notificationDrafts.ruleTemplateIsHtml），两侧一致预览才是实发形态。
var ruleTemplateHTMLTag = regexp.MustCompile(`<\/?[a-zA-Z!][^<>]*>`)

func ruleTemplateIsHTML(tpl string) bool { return ruleTemplateHTMLTag.MatchString(tpl) }

// templateScopePairs 事件正文模板键 → 对应的日报正文模板键。
var templateScopePairs = [3][2]string{
	{"payload_template", "daily_payload_template"},
	{"body_template", "daily_body_template"},
	{"content_template", "daily_content_template"},
}

// legacyDailyTemplate 读时归一判据：事件键上的这份模板是否来自日报卡——行带
// 显式 daily_mode（只有日报卡保存会写），或模板引用日报变量（事件消息没有
// 日报变量）。
func legacyDailyTemplate(dailyMode, tpl string) bool {
	return dailyMode != "" || templateReferencesDailyVariable(tpl)
}

// legacyDailyTemplateAt 行 m 上这一对键是否属于「未按新布局写过的存量行」：
// 事件键非空、对应 daily_* 键未出现、且 legacyDailyTemplate 成立。daily_* 键
// 只要出现（含空串）就是作用域声明——事件键是事件模板，不再归一。
func legacyDailyTemplateAt(m map[string]any, eventKey, dailyKey string) (string, bool) {
	tpl, _ := m[eventKey].(string)
	if tpl == "" {
		return "", false
	}
	if _, explicit := m[dailyKey]; explicit {
		return "", false
	}
	mode, _ := m["daily_mode"].(string)
	if !legacyDailyTemplate(mode, tpl) {
		return "", false
	}
	return tpl, true
}

// normalizeLegacyDaily 存量读时归一（派发路径，内存态不写库）：日报卡曾把
// 模板写进事件键，这类行迁入 daily_*；其余保留为事件模板（API 写入语义）。
// raw 只用来取 daily_* 键是否出现，仅事件键非空的行才解析（常见行零开销）。
func (s *ChannelStyle) normalizeLegacyDaily(raw string) {
	var keys map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &keys) != nil {
		return
	}
	fields := [3][2]*string{
		{&s.PayloadTemplate, &s.DailyPayloadTemplate},
		{&s.BodyTemplate, &s.DailyBodyTemplate},
		{&s.ContentTemplate, &s.DailyContentTemplate},
	}
	for i, p := range templateScopePairs {
		src, dst := fields[i][0], fields[i][1]
		if *src == "" {
			continue
		}
		if _, explicit := keys[p[1]]; explicit {
			continue
		}
		if legacyDailyTemplate(s.DailyMode, *src) {
			*dst, *src = *src, ""
		}
	}
}

// CanonicalChannelStyleJSON 读面输出的模板作用域归一（不写库）：列表接口对
// 存量行直接给出新布局，客户端原样回写不会再把旧事件键带回来。无迁移返回原文。
func CanonicalChannelStyleJSON(raw string) string {
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return raw
	}
	moved := false
	for _, p := range templateScopePairs {
		if tpl, ok := legacyDailyTemplateAt(m, p[0], p[1]); ok {
			m[p[1]], moved = tpl, true
			delete(m, p[0])
		}
	}
	if !moved {
		return raw
	}
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return string(b)
}

// CanonicalTemplateScope 写入侧的模板作用域归一（validateChannelStyle 之后）：
// next=本次要落库的规范化 JSON，stored=写前的行（创建时传空）。读时归一只能
// 凭行形态识别存量日报模板，新写的行不得再落进「事件键非空 + 无 daily_* 键
// + 带 daily_mode」这个形态，否则 API 在带 daily_mode 的通道上写的事件模板
// 会被静默归一成日报模板。逐对（事件键非空时，按序判定）：
//
//  1. 与写前的值逐字相同，且写前行属存量（legacyDailyTemplateAt）→ 迁入
//     daily_*：未改动的存量行被原样回写时，把读时归一的结论落库；
//  2. 模板引用日报变量 → 只可能是日报模板（旧版前端仍把日报草稿写进事件
//     键）→ 归入 daily_*；
//  3. 已带 daily_* 键 → 作用域已显式，不动；
//  4. 其余且带 daily_mode → 事件模板，补显式空 daily_* 键声明作用域。
func CanonicalTemplateScope(next, stored string) string {
	var n map[string]any
	if json.Unmarshal([]byte(next), &n) != nil || n == nil {
		return next
	}
	var st map[string]any
	if json.Unmarshal([]byte(stored), &st) != nil {
		st = nil
	}
	mode, _ := n["daily_mode"].(string)
	changed := false
	for _, p := range templateScopePairs {
		tpl, _ := n[p[0]].(string)
		if tpl == "" {
			continue
		}
		prev, legacy := "", false
		if st != nil {
			prev, legacy = legacyDailyTemplateAt(st, p[0], p[1])
		}
		_, hasDaily := n[p[1]]
		switch {
		case legacy && prev == tpl:
			delete(n, p[0])
			if !hasDaily {
				n[p[1]] = tpl
			}
			changed = true
		case templateReferencesDailyVariable(tpl):
			delete(n, p[0])
			n[p[1]] = tpl
			changed = true
		case hasDaily:
		case mode != "":
			n[p[1]] = ""
			changed = true
		}
	}
	if !changed {
		return next
	}
	b, err := json.Marshal(n)
	if err != nil {
		return next
	}
	return string(b)
}

// DailyModuleModeEffective 日报是否走模块拼装（抑制该通道日报正文模板）。
// 显式值优先；缺省按存量推断——有任一**日报**正文模板键即模板模式。事件正文
// 模板不参与日报模式推断（两套作用域分离）。
func (s ChannelStyle) DailyModuleModeEffective() bool {
	if s.DailyMode == "modules" {
		return true
	}
	if s.DailyMode == "template" {
		return false
	}
	return s.DailyContentTemplate == "" && s.DailyBodyTemplate == "" && s.DailyPayloadTemplate == ""
}

// ParseChannelStyle 容错解析（坏 JSON/空串=零值默认；派发路径不可因样式
// 配置损坏而中断投递）。含存量日报模板归一（见 normalizeLegacyDaily）。
func ParseChannelStyle(raw string) ChannelStyle {
	var s ChannelStyle
	if strings.TrimSpace(raw) == "" {
		return s
	}
	_ = json.Unmarshal([]byte(raw), &s)
	if s.PayloadTemplate != "" || s.BodyTemplate != "" || s.ContentTemplate != "" {
		s.normalizeLegacyDaily(raw)
	}
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
	for _, k := range []string{"payload_template", "subject_template", "body_template", "body_format", "content_template",
		"daily_payload_template", "daily_body_template", "daily_content_template",
		// daily_mode 必须随样式进 target：sender 对合并后的 target 重新解析样式，
		// 缺它则「不含日报变量的存量日报模板」在投递路径上认不出来。
		"daily_mode", "msg_type", "daily_format", "method", "headers"} {
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

// baseTemplatePairs 三个文本型渲染器共用的占位符对（{{placeholder}}, 值）。
// 顺序固定；日报扩展变量由调用方追加（避免 NewReplacer 重复键）。
func baseTemplatePairs(msg Message, ts time.Time) []string {
	event := msg.EventType
	if event == "" {
		event = "notification"
	}
	return []string{
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
}

// dailyTemplatePairs 日报扩展变量对（键排除渲染器已内置键；确定性排序）。
func dailyTemplatePairs(msg Message) []string {
	var pairs []string
	for _, k := range dailyFieldKeys(msg.Fields, styleReservedPlaceholders) {
		pairs = append(pairs, "{{"+k+"}}", msg.Fields[k])
	}
	return pairs
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
	pairs := baseTemplatePairs(msg, ts)
	// 日报变量（2026-11-22 二选一裁定）：模板模式下全部日常变量可放置。
	// 事件消息 Fields 为编号键（"1"/"2"），不参与替换。
	if msg.EventType == EvtDailyReport {
		pairs = append(pairs, dailyTemplatePairs(msg)...)
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// renderStyleTemplateHTML HTML 上下文占位符替换（body_format=html 的通道
// 正文模板）：模板本身是 HTML，占位符**值**必须 HTML 转义——事件正文/字段
// 含 <img onerror> 等外部输入（IP/UA/规则名），原样拼接即注入面。日报变量
// 同口径转义。模板字面量保持原样（那是用户声明的 HTML）。
func renderStyleTemplateHTML(tpl string, msg Message, ts time.Time) string {
	if msg.TemplateApplied {
		return msg.Body
	}
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	pairs := baseTemplatePairs(msg, ts)
	if msg.EventType == EvtDailyReport {
		pairs = append(pairs, dailyTemplatePairs(msg)...)
	}
	for i := 1; i < len(pairs); i += 2 {
		pairs[i] = html.EscapeString(pairs[i])
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// renderSubjectTemplate 邮件主题窄渲染器：只替换元信息占位符
// （title/level/event/time/node/brand/date/event_title），**不替换 {{body}}**。
// TemplateApplied 时 Body 是整篇最终正文，主题模板若沿用通用渲染器会把多行
// markdown 全文顶进主题；保留 {{body}} 字面量供用户自查。
func renderSubjectTemplate(tpl string, msg Message, ts time.Time) string {
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	base := baseTemplatePairs(msg, ts)
	pairs := make([]string, 0, len(base))
	for i := 0; i+1 < len(base); i += 2 {
		if base[i] == "{{body}}" {
			continue
		}
		pairs = append(pairs, base[i], base[i+1])
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// renderStyleTemplateJSON webhook 载荷模板专用：占位符值经 JSON 编码（加引号
// +转义）后嵌入，与保存校验「占位符替换为 "probe" 仍合法 JSON」同口径——
// 模板写 `"title": {{title}}`，运行时产出合法 JSON 字符串值。
//
// 两种占位符约定都接受：裸占位符（保存侧 probe 口径）与裹引号占位符
// `"{{title}}"`（规则弹框旧预置的写法）——后者替换时连引号一起替换为编码值，
// 不会产出 `""x""` 非法 JSON。规则级通道模板与 API 载荷模板共用本函数。
func renderStyleTemplateJSON(tpl string, msg Message, ts time.Time) string {
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	enc := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	addPair := func(pairs []string, key, val string) []string {
		return append(pairs, `"`+key+`"`, enc(val), key, enc(val))
	}
	base := baseTemplatePairs(msg, ts)
	pairs := make([]string, 0, (len(base)/2)*4+8)
	for i := 0; i+1 < len(base); i += 2 {
		val := base[i+1]
		// JSON 变体保留机器枚举与 RFC3339 时刻（文本渲染器用中文级别/分钟粒度，
		// 消费端按 JSON 解析时不能被展示词污染）。
		switch base[i] {
		case "{{level}}":
			val = msg.Level
		case "{{time}}":
			val = ts.Format(time.RFC3339)
		}
		pairs = addPair(pairs, base[i], val)
	}
	// 日报变量同文本变体：值经 JSON 编码嵌入（保存校验同口径）。
	if msg.EventType == EvtDailyReport {
		daily := dailyTemplatePairs(msg)
		for i := 0; i+1 < len(daily); i += 2 {
			pairs = addPair(pairs, daily[i], daily[i+1])
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
