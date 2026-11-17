package notify

// webhook 通道适配器测试：httptest 真 server 抓包断言载荷形态（六键契约）、
// 2xx 成功/非 2xx 报错、目标校验与注册表接线（sendToChannel 端到端）。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookSenderPayloadShape(t *testing.T) {
	var got struct {
		Level  string            `json:"level"`
		Time   string            `json:"time"`
		Node   string            `json:"node"`
		Title  string            `json:"title"`
		Body   string            `json:"body"`
		Fields map[string]string `json:"fields"`
	}
	var method, contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("载荷非合法 JSON: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	msg := Message{
		Level: "warn",
		Time:  time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC),
		Node:  "node-a",
		Title: "证书续签失败",
		Body:  "example.com 续签失败，请检查 DNS",
		Fields: map[string]string{
			"domain": "example.com",
			"error":  "dns",
		},
	}
	// 经注册表接线调用（投递 Daemon 同路径）。
	if err := sendToChannel(context.Background(), "webhook", `{"url":"`+srv.URL+`"}`, msg); err != nil {
		t.Fatalf("sendToChannel 返回错误: %v", err)
	}
	if method != http.MethodPost {
		t.Errorf("请求方法 = %s, want POST", method)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", contentType)
	}
	if got.Level != "warn" || got.Node != "node-a" || got.Title != msg.Title || got.Body != msg.Body {
		t.Errorf("载荷字段不匹配: %+v", got)
	}
	ts, err := time.Parse(time.RFC3339, got.Time)
	if err != nil {
		t.Fatalf("time 非合法 RFC3339: %v", err)
	}
	if !ts.Equal(msg.Time) {
		t.Errorf("time = %s, want %s", got.Time, msg.Time.Format(time.RFC3339))
	}
	if len(got.Fields) != 2 || got.Fields["domain"] != "example.com" || got.Fields["error"] != "dns" {
		t.Errorf("fields 不匹配: %+v", got.Fields)
	}
}

func TestWebhookSenderZeroTimeAndNilFields(t *testing.T) {
	var got struct {
		Time   string            `json:"time"`
		Node   string            `json:"node"`
		Fields map[string]string `json:"fields"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
	}))
	defer srv.Close()
	before := time.Now()
	if err := (webhookSender{}).Send(context.Background(), `{"url":"`+srv.URL+`"}`,
		Message{Level: "info", Title: "t"}); err != nil {
		t.Fatalf("Send 返回错误: %v", err)
	}
	ts, err := time.Parse(time.RFC3339, got.Time)
	if err != nil {
		t.Fatalf("Time 零值未以发送时刻兜底: %v", err)
	}
	if ts.Before(before.Add(-time.Second)) || ts.After(time.Now().Add(time.Second)) {
		t.Errorf("兜底时间偏离发送时刻: %s", got.Time)
	}
	if got.Node != "" {
		t.Errorf("node = %q, want 空", got.Node)
	}
	if got.Fields == nil || len(got.Fields) != 0 {
		t.Errorf("fields = %+v, want 空对象（非 null）", got.Fields)
	}
}

func TestWebhookSenderNon2xxFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := (webhookSender{}).Send(context.Background(), `{"url":"`+srv.URL+`"}`, Message{Level: "info", Title: "t"})
	if err == nil {
		t.Fatal("非 2xx 未返回错误")
	}
	if !strings.Contains(err.Error(), "status=500") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("错误信息未含状态码与响应体: %v", err)
	}
}

func TestWebhookSenderTargetValidation(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"缺 url", `{}`},
		{"非 JSON", `not-json`},
	}
	for _, tc := range cases {
		if err := (webhookSender{}).Send(context.Background(), tc.target, Message{Title: "t"}); err == nil {
			t.Errorf("%s: 未返回错误", tc.name)
		}
	}
}

func TestWebhookSenderTestMessage(t *testing.T) {
	var title string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Title string `json:"title"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &payload)
		title = payload.Title
	}))
	defer srv.Close()
	if err := testChannel(context.Background(), "webhook", `{"url":"`+srv.URL+`"}`); err != nil {
		t.Fatalf("testChannel 返回错误: %v", err)
	}
	if title != "通知中心测试消息" {
		t.Errorf("测试消息标题 = %q", title)
	}
}
