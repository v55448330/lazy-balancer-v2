package notify

// webhook GET/自定义头 + 每通道结果落库 + 订阅通道选择钉测（2026-11-19 第二轮重构）。
// httptest 真 server 抓包断言 method/headers/query payload；真实 SQLite 断言
// notification_delivery_channels 落行与 channel_ids 过滤。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestWebhookSenderGetAndHeaders(t *testing.T) {
	var gotMethod, gotAuth, gotXKey, gotPayload string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotXKey = r.Header.Get("X-Custom-Token")
		gotPayload = r.URL.Query().Get("payload")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	msg := Message{Level: "warn", Title: "测试", Body: "正文", Time: time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)}
	target := `{"url":"` + srv.URL + `","method":"GET","headers":{"Authorization":"Bearer tok123","X-Custom-Token":"abc"}}`
	if err := sendToChannel(context.Background(), "webhook", target, msg); err != nil {
		t.Fatalf("GET 发送失败: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method=%s, want GET", gotMethod)
	}
	if gotAuth != "Bearer tok123" || gotXKey != "abc" {
		t.Fatalf("自定义头未生效: auth=%q x=%q", gotAuth, gotXKey)
	}
	if len(gotBody) != 0 {
		t.Fatalf("GET 不应携带 body, got %d bytes", len(gotBody))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(gotPayload), &payload); err != nil {
		t.Fatalf("query payload 非合法 JSON: %v (%s)", err, gotPayload)
	}
	if payload["title"] != "测试" {
		t.Fatalf("payload.title=%v, want 测试", payload["title"])
	}

	// POST 缺省（无 method 键）回归：body 携带载荷
	targetPost := `{"url":"` + srv.URL + `"}`
	if err := sendToChannel(context.Background(), "webhook", targetPost, msg); err != nil {
		t.Fatalf("POST 发送失败: %v", err)
	}
	if gotMethod != http.MethodPost || len(gotBody) == 0 {
		t.Fatalf("POST 缺省形态破坏: method=%s body=%d", gotMethod, len(gotBody))
	}
}

func TestDeliverOneChannelSelectionAndResults(t *testing.T) {
	newNotifyTestDB(t)

	// 两个 webhook 通道：一成功一失败（失败端点恒 500）
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer okSrv.Close()
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer failSrv.Close()

	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES
		(101, 7, 'webhook', 'ok', ?, 1), (102, 7, 'webhook', 'fail', ?, 1)`,
		`{"url":"`+okSrv.URL+`"}`, `{"url":"`+failSrv.URL+`"}`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	// 订阅只选通道 101（channel_ids=[101]）+ 每通道模板
	if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, channel_ids, channel_templates)
		VALUES (7, 'cert.failed', 'info', '', '[101]', '{"101":"自定义 {{title}}"}')`); err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (7, 'cert.failed', 'critical', '证书失败', '正文', 'pending', 0, datetime('now'))`)
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	id, _ := res.LastInsertId()

	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败", Body: "正文"})

	// 主表 sent（选定通道成功）
	var status string
	_ = db.DB.QueryRow(`SELECT status FROM notification_deliveries WHERE id=?`, id).Scan(&status)
	if status != "sent" {
		t.Fatalf("主表 status=%s, want sent", status)
	}
	// 每通道结果：仅 101 一行 sent（102 未被选择，不得发送/落行）
	var n int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_delivery_channels WHERE delivery_id=?`, id).Scan(&n)
	if n != 1 {
		t.Fatalf("通道结果行数=%d, want 1（仅选定通道）", n)
	}
	var chID int64
	var chStatus string
	_ = db.DB.QueryRow(`SELECT channel_id, status FROM notification_delivery_channels WHERE delivery_id=?`, id).Scan(&chID, &chStatus)
	if chID != 101 || chStatus != "sent" {
		t.Fatalf("结果行 channel=%d status=%s, want 101/sent", chID, chStatus)
	}

	// 无选择订阅（channel_ids 空）=全部通道：102 失败落行，主表 partial（有成功有失败）
	if _, err := db.DB.Exec(`UPDATE notification_subscriptions SET channel_ids='' WHERE user_id=7`); err != nil {
		t.Fatalf("clear selection: %v", err)
	}
	res2, _ := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (7, 'cert.failed', 'critical', '证书失败2', '正文', 'pending', 0, datetime('now'))`)
	id2, _ := res2.LastInsertId()
	deliverOne(context.Background(), id2, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败2", Body: "正文"})
	_ = db.DB.QueryRow(`SELECT status FROM notification_deliveries WHERE id=?`, id2).Scan(&status)
	if status != "partial" {
		t.Fatalf("全通道投递 status=%s, want partial（部分失败）", status)
	}
	var sentRows, failedRows int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_delivery_channels WHERE delivery_id=? AND status='sent'`, id2).Scan(&sentRows)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_delivery_channels WHERE delivery_id=? AND status='failed'`, id2).Scan(&failedRows)
	if sentRows != 1 || failedRows != 1 {
		t.Fatalf("全通道结果 sent=%d failed=%d, want 1/1", sentRows, failedRows)
	}
}
