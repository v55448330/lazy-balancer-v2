package notify

// webhook 通道适配器：POST JSON 到用户配置的 URL。
// 载荷固定六键：level/time/node/title/body/fields（RFC3339 时间；fields 为
// 结构化附加字段对象）。2xx=成功，其余状态码连同响应体片段返回错误（投递
// Daemon 留痕）。10s 超时。Send 不 panic——target 解析失败/URL 缺失均错误返回。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type webhookSender struct{}

func (webhookSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	var cfg struct {
		URL             string `json:"url"`
		PayloadTemplate string `json:"payload_template"`
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
	var payload []byte
	if cfg.PayloadTemplate != "" {
		// 用户 JSON 模板（占位符 {{title}}/{{body}}/{{level}}/{{event}}/
		// {{time}}/{{node}}；保存时已校验占位符替换后可解析）
		payload = []byte(renderStyleTemplate(cfg.PayloadTemplate, msg, ts))
	} else {
		var err error
		payload, err = json.Marshal(map[string]any{
			"level":  msg.Level,
			"time":   ts.Format(time.RFC3339),
			"node":   msg.Node,
			"title":  msg.Title,
			"body":   msg.Body,
			"fields": fields,
		})
		if err != nil {
			return fmt.Errorf("webhook 载荷编码失败: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook 请求构造失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
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
	return s.Send(ctx, targetJSON, testNotificationMessage())
}

const webhookTimeout = 10 * time.Second

func init() { RegisterSender("webhook", webhookSender{}) }
