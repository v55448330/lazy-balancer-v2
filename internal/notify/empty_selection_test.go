package notify

// 显式空选 '[]' = 不投递（用户裁定）；缺省空串 = 全部启用通道（默认订阅语义）。
// 三态语义钉测：真实 SQLite + httptest webhook 端点计数。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestDeliverOneExplicitEmptySelectionSkipsDelivery(t *testing.T) {
	newNotifyTestDB(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
	defer srv.Close()
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled) VALUES (201, 7, 'webhook', 'ok', '{"url":"` + srv.URL + `"}', 1)`); err != nil {
		t.Fatal(err)
	}
	// 显式空选 '[]'
	if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, channel_ids) VALUES (7, 'cert.failed', 'info', '[]')`); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at) VALUES (7, 'cert.failed', 'critical', 't', 'b', 'pending', 0, datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	deliverOne(context.Background(), id, 7, Message{EventType: "cert.failed", Level: "critical", Title: "t", Body: "b"})
	if hits != 0 {
		t.Fatalf("显式空选仍发送了 %d 次, want 0", hits)
	}
	var status, errMsg string
	if err := db.DB.QueryRow(`SELECT status, error FROM notification_deliveries WHERE id=?`, id).Scan(&status, &errMsg); err != nil {
		t.Fatal(err)
	}
	if status != "dead" {
		t.Fatalf("status=%s, want dead（不投递留痕）", status)
	}
	// 缺省空串（无 channel_ids）=全部通道：应发送
	if _, err := db.DB.Exec(`UPDATE notification_subscriptions SET channel_ids='' WHERE user_id=7`); err != nil {
		t.Fatal(err)
	}
	res2, _ := db.DB.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, attempts, created_at) VALUES (7, 'cert.failed', 'critical', 't2', 'b', 'pending', 0, datetime('now'))`)
	id2, _ := res2.LastInsertId()
	deliverOne(context.Background(), id2, 7, Message{EventType: "cert.failed", Level: "critical", Title: "t2", Body: "b"})
	if hits != 1 {
		t.Fatalf("缺省空串应发全部通道, hits=%d want 1", hits)
	}
}
