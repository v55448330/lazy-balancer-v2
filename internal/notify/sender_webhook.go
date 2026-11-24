package notify

// webhook 通道适配器：POST JSON（或 GET query payload）到用户配置的 URL。
// 载荷固定七键：level/level_label/time/node/title/body/fields（RFC3339 时间；
// fields 为结构化附加字段对象）。事件模板全量渲染（TemplateApplied）分支与
// 默认分支同 schema，time 同样以发送时刻兜底。method/headers 经 style_config
// 配置（保存侧白名单校验）。2xx=成功，其余状态码连同响应体片段返回错误
// （投递 Daemon 留痕）。10s 超时。Send 不 panic——target 解析失败/URL 缺失均
// 错误返回。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type webhookSender struct{}

func (webhookSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	var cfg struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`  // GET/POST（缺省 POST；保存时已校验）
		Headers map[string]string `json:"headers"` // 受限自定义头（白名单校验在保存侧）
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("webhook 通道目标解析失败: %w", err)
	}
	if cfg.URL == "" {
		return fmt.Errorf("webhook 通道目标缺少 url")
	}
	ts := msg.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	fields := msg.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	// 作用域分离：日报用 daily_payload_template，事件用 payload_template。
	// 经 ParseChannelStyle 解析以获得存量日报模板归一（显式 daily_mode 或
	// 模板引用日报变量 → 视为日报卡产物）。
	style := ParseChannelStyle(targetJSON)
	payloadTemplate := style.PayloadTemplate
	if msg.EventType == EvtDailyReport {
		payloadTemplate = style.DailyPayloadTemplate
	}
	var payload []byte
	if msg.TemplateApplied && msg.TemplateFormat == "json" && json.Valid([]byte(msg.Body)) {
		// 规则级通道模板已按 webhook 形态渲染（JSON 编码占位符值）：Body 即
		// 用户声明的载荷本体，直接作为 POST 体（不再套默认信封）。渲染结果
		// 不是合法 JSON（保存门上线前落库的纯文本模板、或占位符落在键位置的
		// 模板）时不得原样发出——落到下方默认信封。
		payload = []byte(msg.Body)
	} else if msg.TemplateApplied {
		// 事件级模板（所有通道共用的文本版式）已全量渲染：Body 即消息正文。
		// 载荷与默认分支同 schema（level/level_label/time/node/title/body/
		// fields），time 用与默认分支同源的零值兜底（此前只带 5 键且直格式化
		// msg.Time，接收端恒拿到 0001-01-01 时间戳、title/fields 静默缺失）。
		var err error
		payload, err = json.Marshal(map[string]any{
			"level": msg.Level, "level_label": levelLabelZh(msg.Level),
			"time": ts.Format(time.RFC3339), "node": msg.Node,
			"title": msg.Title, "body": msg.Body, "fields": fields,
		})
		if err != nil {
			return fmt.Errorf("载荷编码失败: %w", err)
		}
	} else if payloadTemplate != "" && !msg.dailyTemplatesSuppressed() {
		// 用户 JSON 模板（占位符 {{title}}/{{body}}/{{level}}/{{event}}/
		// {{time}}/{{node}}；保存时已校验占位符替换后可解析）
		payload = []byte(renderStyleTemplateJSON(payloadTemplate, msg, ts))
	} else {
		var err error
		payload, err = json.Marshal(map[string]any{
			"level":       msg.Level,
			"level_label": levelLabelZh(msg.Level),
			"time":        ts.Format(time.RFC3339),
			"node":        msg.Node,
			"title":       msg.Title,
			"body":        msg.Body,
			"fields":      fields,
		})
		if err != nil {
			return fmt.Errorf("webhook 载荷编码失败: %w", err)
		}
	}
	method := http.MethodPost
	if cfg.Method == http.MethodGet {
		method = http.MethodGet
	}
	var req *http.Request
	var err error
	if method == http.MethodGet {
		// GET：载荷经 query 参数传递（url 追加 payload=<JSON>；不携带 body）
		sep := "?"
		if strings.Contains(cfg.URL, "?") {
			sep = "&"
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL+sep+"payload="+url.QueryEscape(string(payload)), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	}
	if err != nil {
		return fmt.Errorf("webhook 请求构造失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// 自定义头覆盖默认（保存侧已白名单校验；Content-Type 允许覆盖以适配
	// form 类接收端）。
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: webhookTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook 返回非 2xx status=%d body=%s", resp.StatusCode, string(body))
	}
	// 消费响应体以便连接复用。
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (s webhookSender) Test(ctx context.Context, targetJSON string) error {
	return s.Send(ctx, targetJSON, testNotificationMessageFor("Webhook"))
}

const webhookTimeout = 10 * time.Second

func init() { RegisterSender("webhook", webhookSender{}) }
