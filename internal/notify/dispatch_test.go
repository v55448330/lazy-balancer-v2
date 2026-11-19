package notify

// dispatch 集成钉测：发布 → pending 落库 → 订阅过滤（显式行 vs 默认集）→
// 级别过滤（真 DB；单消费者循环真实运转，测试只等终态行）。
// 订阅合并语义钉死（缺陷回归位）：显式订阅行是唯一意志表达——显式行
// min_level 高于事件级别时不得被默认集二次纳入；默认集仅补「无显式行」
// 且有启用通道的用户。

import (
	"database/sql"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func resetNotifyBusForTest(t *testing.T) {
	t.Helper()
	// 每次给 Stop 一个未关闭通道（close 已关闭通道会 panic）；Once 同步换新。
	// Stop 后等分发循环真实退出（loopDone）再换全局——在途 dispatch 仍会读
	// 全局，立刻换会构成数据竞争（-race 门）。
	stopCh = make(chan struct{})
	Stop()
	awaitLoopExit(t)
	started.Store(false)
	stopOnce = sync.Once{}
	queue = nil
	droppedCount.Store(0)
	t.Cleanup(func() {
		Stop()
		awaitLoopExit(t)
		started.Store(false)
		stopOnce = sync.Once{}
		queue = nil
	})
}

// awaitLoopExit 等当前分发循环退出（上一轮 Start 的 loopDone；nil=从未启动）。
func awaitLoopExit(t *testing.T) {
	t.Helper()
	if loopDone == nil {
		return
	}
	done := loopDone
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Logf("分发循环 3s 内未退出（继续，随进程回收）")
	}
}

func newNotifyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	old := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/notify.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	t.Cleanup(func() {
		db.DB = old
		database.Close()
	})
	_, err = database.Exec(`
CREATE TABLE notification_channels (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	type TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL DEFAULT '',
	style_config TEXT NOT NULL DEFAULT '{}',
	enabled INTEGER NOT NULL DEFAULT 1,
	UNIQUE(user_id, type, target)
);
CREATE TABLE notification_subscriptions (
	user_id INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	min_level TEXT NOT NULL DEFAULT 'info',
	body_template TEXT NOT NULL DEFAULT '',
	channel_ids TEXT NOT NULL DEFAULT '',
	channel_templates TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (user_id, event_type)
);
CREATE TABLE notification_deliveries (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	level TEXT NOT NULL DEFAULT 'info',
	title TEXT NOT NULL,
	body TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'pending',
	attempts INTEGER NOT NULL DEFAULT 0,
	error TEXT DEFAULT '',
	created_at TEXT NOT NULL,
	sent_at DATETIME,
	is_test INTEGER NOT NULL DEFAULT 0,
	retry_channel_ids TEXT NOT NULL DEFAULT ''
);
CREATE TABLE notification_delivery_channels (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	delivery_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	channel_id INTEGER NOT NULL,
	channel_name TEXT NOT NULL DEFAULT '',
	channel_type TEXT NOT NULL,
	event_type TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'sent',
	error TEXT DEFAULT '',
	created_at TEXT NOT NULL
);`)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func seedNotifySubscribers(t *testing.T, database *sql.DB) {
	t.Helper()
	// user1：显式订阅（min_level=critical）+ 启用通道；user2：无订阅行+启用通道
	//（默认集候选）；user3：无订阅行、无通道；user4：显式订阅 min_level=info。
	for _, uid := range []int64{1, 2, 4} {
		if _, err := database.Exec(`INSERT INTO notification_channels (user_id, type, target) VALUES (?, 'webhook', 'http://x')`, uid); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		uid   int64
		event string
		level string
	}{{1, EvtLoginFailed, "critical"}, {4, EvtLoginFailed, "info"}}
	for _, r := range rows {
		if _, err := database.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level) VALUES (?,?,?)`, r.uid, r.event, r.level); err != nil {
			t.Fatal(err)
		}
	}
}

func deliveryRows(t *testing.T, database *sql.DB, eventType string, minRows int) map[int64]string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows map[int64]string
	for time.Now().Before(deadline) {
		res, err := database.Query(`SELECT user_id, status FROM notification_deliveries WHERE event_type=?`, eventType)
		if err != nil {
			t.Fatal(err)
		}
		current := map[int64]string{}
		for res.Next() {
			var uid int64
			var status string
			if err := res.Scan(&uid, &status); err != nil {
				res.Close()
				t.Fatal(err)
			}
			current[uid] = status
		}
		res.Close()
		// 等足期望行数再断言：分发循环逐用户落行，提前取到部分行会把
		// 「后一行尚未落库」误判为「不应投递」。
		if len(current) >= minRows {
			rows = current
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return rows
}

func TestDispatchSubscriptionFilterAndDefaultSet(t *testing.T) {
	resetNotifyBusForTest(t)
	database := newNotifyTestDB(t)
	seedNotifySubscribers(t, database)
	Start()

	// warn 事件（登录失败，DefaultSub=true）：
	//   user1 显式 critical（warn 未达标）→ 不投（显式行赢，默认集不补）；
	//   user2 默认集（无显式行+有通道）→ 投；
	//   user3 无通道 → 不投；
	//   user4 显式 info → 投。
	Publish(Event{Type: EvtLoginFailed,
		Fields: map[string]string{"1": "root", "2": "认证失败", "3": "10.0.0.9"}})
	rows := deliveryRows(t, database, EvtLoginFailed, 2)
	if _, ok := rows[1]; ok {
		t.Fatalf("显式订阅 min_level=critical 的用户被 warn 事件误投（显式行必须赢过默认集）: %v", rows)
	}
	if _, ok := rows[2]; !ok {
		t.Fatalf("默认集用户（无显式行+有通道）未收到 pending 行: %v", rows)
	}
	if _, ok := rows[3]; ok {
		t.Fatalf("无通道用户不应落投递行: %v", rows)
	}
	if _, ok := rows[4]; !ok {
		t.Fatalf("显式订阅 min_level=info 用户未收到 pending 行: %v", rows)
	}
	for uid, status := range rows {
		if status != "pending" {
			t.Fatalf("user %d 状态=%s，期望 pending", uid, status)
		}
	}

	// critical 事件：user1（显式 critical 达标）与 user2/user4 默认/显式全部达标。
	Publish(Event{Type: EvtImportFailed, Fields: map[string]string{"1": "测试失败原因"}})
	rows = deliveryRows(t, database, EvtImportFailed, 3)
	for _, uid := range []int64{1, 2, 4} {
		if _, ok := rows[uid]; !ok {
			t.Fatalf("critical 事件未投递给 user %d: %v", uid, rows)
		}
	}
	if _, ok := rows[3]; ok {
		t.Fatalf("critical 事件不应投递给无通道 user3: %v", rows)
	}
}

func TestDispatchTemplateRenderAndUnknownEventDropped(t *testing.T) {
	resetNotifyBusForTest(t)
	database := newNotifyTestDB(t)
	if _, err := database.Exec(`INSERT INTO notification_channels (user_id, type, target) VALUES (1, 'webhook', 'http://x')`); err != nil {
		t.Fatal(err)
	}
	// 登录成功为 info 且默认不订阅——显式订阅行验证模板渲染路径。
	if _, err := database.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level) VALUES (1, ?, 'info')`, EvtLoginSuccess); err != nil {
		t.Fatal(err)
	}
	Start()
	// 目录外事件拒绝（订阅矩阵与模板以目录为唯一事实源）。丢弃路径无行可等：
	// 固定静置窗后断言零行（同包事件在窗内必然已消费完）。
	Publish(Event{Type: "totally.unknown", Fields: map[string]string{"1": "x"}})
	time.Sleep(300 * time.Millisecond)
	rows, qerr := database.Query(`SELECT user_id FROM notification_deliveries WHERE event_type='totally.unknown'`)
	if qerr != nil {
		t.Fatal(qerr)
	}
	if rows.Next() {
		rows.Close()
		t.Fatalf("目录外事件不应落投递行")
	}
	rows.Close()
	// 模板按 Fields "1","2" 参数序渲染（目录 BodyFormat 兜底）。
	Publish(Event{Type: EvtLoginSuccess, Fields: map[string]string{"1": "alice", "2": "2026-01-02 03:04:05", "3": "10.1.1.1"}})
	got := deliveryRows(t, database, EvtLoginSuccess, 1)
	if len(got) != 1 {
		t.Fatalf("登录成功事件应投 1 行: %v", got)
	}
	var body string
	if err := database.QueryRow(`SELECT body FROM notification_deliveries WHERE event_type=?`, EvtLoginSuccess).Scan(&body); err != nil {
		t.Fatal(err)
	}
	want := "用户 alice 于 2026-01-02 03:04:05 登录（10.1.1.1）"
	if body != want {
		t.Fatalf("模板参数序渲染错位:\n got %q\nwant %q", body, want)
	}
}

func TestRequeueStalePendingMarksDead(t *testing.T) {
	database := newNotifyTestDB(t)
	stale := time.Now().UTC().Add(-8 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	fresh := time.Now().UTC().Format("2006-01-02 15:04:05")
	for _, r := range []struct{ created string }{{stale}, {fresh}} {
		if _, err := database.Exec(`INSERT INTO notification_deliveries (user_id, event_type, level, title, body, status, created_at)
			VALUES (1, ?, 'warn', 't', 'b', 'pending', ?)`, EvtLoginFailed, r.created); err != nil {
			t.Fatal(err)
		}
	}
	requeueStalePending()
	var dead, pending int
	if err := database.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE status='dead'`).Scan(&dead); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if dead != 1 || pending != 1 {
		t.Fatalf("重投兜底口径错：dead=%d pending=%d（期望 1/1：超龄判 dead、近期留队）", dead, pending)
	}
}
