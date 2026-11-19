package notify

// 投递语义回归（2026-11-19 通知重构）：
//   - partial 状态机：有成功有失败=partial（error 携部分失败原因），全失败=failed，全成功=sent
//   - is_test 测试发送标记：规则测试/单用户日报测试=1，定时全员日报=0
//   - failed_only 重发：partial 行只重发失败通道（retry_channel_ids JSON 过滤），
//     派发消费后清空；全量重发清过滤。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// seedTwoChannelDelivery 建 ok/fail 双 webhook 通道 + 一行 pending 投递。
// failSrv 的状态码由 *failCode 控制（测试内同步翻转，无并发）。
func seedTwoChannelDelivery(t *testing.T, failCode *int) (okSrv, failSrv *httptest.Server, deliveryID int64) {
	t.Helper()
	okSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(okSrv.Close)
	failSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(*failCode) }))
	t.Cleanup(failSrv.Close)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES
		(101, 7, 'webhook', 'ok', ?, 1), (102, 7, 'webhook', 'fail', ?, 1)`,
		`{"url":"`+okSrv.URL+`"}`, `{"url":"`+failSrv.URL+`"}`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (7, 'cert.failed', 'critical', '证书失败', '正文', 'pending', 0, datetime('now'))`)
	if err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	id, _ := res.LastInsertId()
	return okSrv, failSrv, id
}

func deliveryStatus(t *testing.T, id int64) (status, errMsg string) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM notification_deliveries WHERE id=?`, id).Scan(&status, &errMsg); err != nil {
		t.Fatalf("read delivery %d: %v", id, err)
	}
	return status, errMsg
}

func TestDeliverOnePartialFailureMarksPartial(t *testing.T) {
	newNotifyTestDB(t)
	failCode := 500
	_, _, id := seedTwoChannelDelivery(t, &failCode)

	// Given 双通道一成功一失败；When 派发；Then partial（非 sent）+原因留痕
	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败", Body: "正文"})
	status, errMsg := deliveryStatus(t, id)
	if status != "partial" {
		t.Fatalf("部分失败 status=%s, want partial", status)
	}
	if errMsg == "" {
		t.Fatalf("partial 行必须携带部分失败原因")
	}
	var sentRows, failedRows int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_delivery_channels WHERE delivery_id=? AND status='sent'`, id).Scan(&sentRows)
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_delivery_channels WHERE delivery_id=? AND status='failed'`, id).Scan(&failedRows)
	if sentRows != 1 || failedRows != 1 {
		t.Fatalf("通道结果 sent=%d failed=%d, want 1/1", sentRows, failedRows)
	}

	// 全失败（订阅只选失败通道）→ failed
	if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, channel_ids) VALUES (7, 'cert.failed', 'info', '[102]')`); err != nil {
		t.Fatal(err)
	}
	res, _ := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (7, 'cert.failed', 'critical', '全失败', '正文', 'pending', 0, datetime('now'))`)
	idFail, _ := res.LastInsertId()
	deliverOne(context.Background(), idFail, 7, Message{EventType: "cert.failed", Level: "critical", Title: "全失败", Body: "正文"})
	if status, _ = deliveryStatus(t, idFail); status != "failed" {
		t.Fatalf("全失败 status=%s, want failed", status)
	}

	// 全成功（订阅只选成功通道）→ sent
	if _, err := db.DB.Exec(`UPDATE notification_subscriptions SET channel_ids='[101]' WHERE user_id=7`); err != nil {
		t.Fatal(err)
	}
	res2, _ := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (7, 'cert.failed', 'critical', '全成功', '正文', 'pending', 0, datetime('now'))`)
	idOK, _ := res2.LastInsertId()
	deliverOne(context.Background(), idOK, 7, Message{EventType: "cert.failed", Level: "critical", Title: "全成功", Body: "正文"})
	if status, errMsg = deliveryStatus(t, idOK); status != "sent" || errMsg != "" {
		t.Fatalf("全成功 status=%s error=%q, want sent/空", status, errMsg)
	}
}

func TestResendDeliveryFailedOnlyFiltersAndConsumes(t *testing.T) {
	newNotifyTestDB(t)
	failCode := 500
	okSrv, _, id := seedTwoChannelDelivery(t, &failCode)
	var okHits int
	// 包一层计数：ok 端点命中数（重发失败通道时不得再发 ok 通道）
	okSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { okHits++; w.WriteHeader(200) })

	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败", Body: "正文"})
	if status, _ := deliveryStatus(t, id); status != "partial" {
		t.Fatalf("前置 status=%s, want partial", status)
	}
	okHits = 0

	// When failed_only 重发 partial 行；Then retry_channel_ids=[102]
	found, reset, err := ResendDelivery(id, true)
	if err != nil || !found || !reset {
		t.Fatalf("ResendDelivery found=%v reset=%v err=%v", found, reset, err)
	}
	var retryIDs string
	if err := db.DB.QueryRow(`SELECT retry_channel_ids FROM notification_deliveries WHERE id=?`, id).Scan(&retryIDs); err != nil {
		t.Fatal(err)
	}
	if retryIDs != "[102]" {
		t.Fatalf("retry_channel_ids=%q, want [102]（仅失败通道）", retryIDs)
	}

	// 失败端点修复后派发：只发 102，ok 通道不重发；消费后过滤清空
	failCode = 200
	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败", Body: "正文"})
	if okHits != 0 {
		t.Fatalf("failed_only 重发误发成功通道 %d 次", okHits)
	}
	if status, _ := deliveryStatus(t, id); status != "sent" {
		t.Fatalf("重发后 status=%s, want sent", status)
	}
	if err := db.DB.QueryRow(`SELECT retry_channel_ids FROM notification_deliveries WHERE id=?`, id).Scan(&retryIDs); err != nil {
		t.Fatal(err)
	}
	if retryIDs != "" {
		t.Fatalf("retry_channel_ids 消费后未清空: %q", retryIDs)
	}
	// 102 通道结果两行：先 failed 后 sent（历史留痕不覆盖）
	var n int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_delivery_channels WHERE delivery_id=? AND channel_id=102`, id).Scan(&n)
	if n != 2 {
		t.Fatalf("102 结果行数=%d, want 2（failed+sent）", n)
	}
}

func TestResendDeliveryFullResendClearsRetryFilter(t *testing.T) {
	newNotifyTestDB(t)
	failCode := 500
	_, _, id := seedTwoChannelDelivery(t, &failCode)
	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败", Body: "正文"})

	// failed_only 对非 partial 行（failed）=全量重发，不建过滤
	if _, err := db.DB.Exec(`UPDATE notification_deliveries SET status='failed' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResendDelivery(id, true); err != nil {
		t.Fatal(err)
	}
	var retryIDs string
	_ = db.DB.QueryRow(`SELECT retry_channel_ids FROM notification_deliveries WHERE id=?`, id).Scan(&retryIDs)
	if retryIDs != "" {
		t.Fatalf("非 partial 行 failed_only 不应建过滤: %q", retryIDs)
	}

	// 全量重发清除残留过滤（模拟上一轮 failed_only 遗留）
	if _, err := db.DB.Exec(`UPDATE notification_deliveries SET status='partial', retry_channel_ids='[102]' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResendDelivery(id, false); err != nil {
		t.Fatal(err)
	}
	_ = db.DB.QueryRow(`SELECT retry_channel_ids FROM notification_deliveries WHERE id=?`, id).Scan(&retryIDs)
	if retryIDs != "" {
		t.Fatalf("全量重发后 retry_channel_ids=%q, want 空", retryIDs)
	}
}

func TestResendDeliveryFailedOnlyTakesLatestChannelResult(t *testing.T) {
	newNotifyTestDB(t)
	failCode := 500
	_, _, id := seedTwoChannelDelivery(t, &failCode)
	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "证书失败", Body: "正文"})
	// 追加一轮结果：102 最新已成功、101 最新失败（重发追加行形态）
	if _, err := db.DB.Exec(`INSERT INTO notification_delivery_channels (delivery_id, user_id, channel_id, channel_name, channel_type, event_type, status, created_at)
		VALUES (?,7,102,'fail','webhook','cert.failed','sent',datetime('now')), (?,7,101,'ok','webhook','cert.failed','failed',datetime('now'))`, id, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResendDelivery(id, true); err != nil {
		t.Fatal(err)
	}
	var retryIDs string
	_ = db.DB.QueryRow(`SELECT retry_channel_ids FROM notification_deliveries WHERE id=?`, id).Scan(&retryIDs)
	if retryIDs != "[101]" {
		t.Fatalf("retry_channel_ids=%q, want [101]（每通道最新结果行判定）", retryIDs)
	}
}

func TestTestDeliveriesMarkIsTest(t *testing.T) {
	database := newNotifyTestDB(t)
	// 日报采集读 MetricsDB（security_events 等）：测试库同句柄即可（缺表错误被采集侧忽略）
	oldMetrics := db.MetricsDB
	db.MetricsDB = database
	t.Cleanup(func() { db.MetricsDB = oldMetrics })
	if _, err := database.Exec(`CREATE TABLE notification_daily (user_id INTEGER PRIMARY KEY, config TEXT NOT NULL DEFAULT '', updated_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES (101, 7, 'webhook', 'ok', '{"url":"http://127.0.0.1:1"}', 1)`); err != nil {
		t.Fatal(err)
	}

	// 规则测试发送 → is_test=1
	if err := EnqueueTestDelivery(7, "cert.failed"); err != nil {
		t.Fatalf("EnqueueTestDelivery: %v", err)
	}
	var isTest int
	if err := database.QueryRow(`SELECT is_test FROM notification_deliveries WHERE event_type='cert.failed'`).Scan(&isTest); err != nil {
		t.Fatal(err)
	}
	if isTest != 1 {
		t.Fatalf("规则测试 is_test=%d, want 1", isTest)
	}

	// 单用户日报测试 → is_test=1
	if err := DeliverDailyForUser(7, time.Now()); err != nil {
		t.Fatalf("DeliverDailyForUser: %v", err)
	}
	if err := database.QueryRow(`SELECT is_test FROM notification_deliveries WHERE event_type=? AND user_id=7`, EvtDailyReport).Scan(&isTest); err != nil {
		t.Fatal(err)
	}
	if isTest != 1 {
		t.Fatalf("日报测试 is_test=%d, want 1", isTest)
	}

	// 定时全员日报 → is_test=0
	if _, err := database.Exec(`INSERT INTO notification_daily (user_id, config) VALUES (8, '{"enabled":true}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES (102, 8, 'webhook', 'u8', '{"url":"http://127.0.0.1:1"}', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := DeliverDailyForAll(context.Background(), time.Now()); err != nil {
		t.Fatalf("DeliverDailyForAll: %v", err)
	}
	if err := database.QueryRow(`SELECT is_test FROM notification_deliveries WHERE event_type=? AND user_id=8`, EvtDailyReport).Scan(&isTest); err != nil {
		t.Fatal(err)
	}
	if isTest != 0 {
		t.Fatalf("定时日报 is_test=%d, want 0", isTest)
	}
}
