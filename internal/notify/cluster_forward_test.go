package notify

// 集群事件转发与日报统计上报钉测（2026-11-22 用户裁定：主节点集中汇聚）。
// 覆盖：从节点 Publish 转发不入本地队列 / 主节点本地入队 / 转发失败 spool 落盘
// 且重传成功即删 / 上报载荷节点名与目录门 / 各节点摘要聚合 / 存量日报配置补项。

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// overrideClusterForwardRole 覆写角色探测并在用例结束复原。
func overrideClusterForwardRole(t *testing.T, isMaster bool, masterURL, token string) {
	t.Helper()
	old := clusterForwardRoleDetector
	clusterForwardRoleDetector = func() (bool, string, string, string, error) {
		return isMaster, masterURL, token, "slave-test", nil
	}
	t.Cleanup(func() { clusterForwardRoleDetector = old })
}

// overrideForwardSpoolDir 指定 spool 目录（绕开 db.DataDir 依赖）。
func overrideForwardSpoolDir(t *testing.T, dir string) {
	t.Helper()
	old := clusterFwd.spoolDir
	clusterFwd.spoolDir = dir
	t.Cleanup(func() { clusterFwd.spoolDir = old })
}

// newQueueOnly 提供只带队列的 Publish 环境（不启动分发循环：直接读队列断言）。
func newQueueOnly(t *testing.T) chan Event {
	t.Helper()
	old := queue
	q := make(chan Event, 4)
	queue = q
	t.Cleanup(func() { queue = old })
	return q
}

func TestClusterForward_slaveForwardsInsteadOfQueue(t *testing.T) {
	var gotPath, gotToken string
	var gotBody ClusterEventReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Cluster-Token")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	q := newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "node-x", "2": "detail"}})

	if gotPath != "/api/v1/cluster/events/report" {
		t.Fatalf("上报路径=%q，want /api/v1/cluster/events/report", gotPath)
	}
	if gotToken != "tok-1" {
		t.Fatalf("令牌=%q，want tok-1", gotToken)
	}
	if len(gotBody.Events) != 1 || gotBody.Events[0].Type != EvtCaddyApplyFailed {
		t.Fatalf("上报事件=%+v，want 单条 %s", gotBody.Events, EvtCaddyApplyFailed)
	}
	if len(q) != 0 {
		t.Fatalf("从节点本地队列收到 %d 条（应只转发不入队）", len(q))
	}
}

func TestClusterForward_masterQueuesLocally(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, true, srv.URL, "tok-1")
	q := newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "node-x", "2": "detail"}})

	if called {
		t.Fatal("主节点不应转发上报")
	}
	if len(q) != 1 {
		t.Fatalf("主节点本地队列=%d 条，want 1", len(q))
	}
}

func TestClusterForward_failureSpoolsThenDrainDeletes(t *testing.T) {
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	failing := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	_ = newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "node-x", "2": "detail"}})

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("spool 文件数=%d (err=%v)，want 1", len(entries), err)
	}
	// 原始载荷应保留事件类型（重传内容可解析）
	raw, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if !strings.Contains(string(raw), EvtCaddyApplyFailed) {
		t.Fatalf("spool 载荷缺失事件类型: %s", raw)
	}

	failing = false
	DrainClusterForwardSpool(t.Context())
	entries, _ = os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("重传成功后 spool 残留 %d 个文件", len(entries))
	}
}

func TestClusterForward_unknownEventNotForwarded(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	q := newQueueOnly(t)

	Publish(Event{Type: "not-in-catalog"})

	if called {
		t.Fatal("目录外事件不应上报")
	}
	if len(q) != 0 {
		t.Fatal("目录外事件不应入队")
	}
}

// newNotifySchemaDB 建本批测试所需最小表（投递行 node 列 + 节点统计表）。
func newNotifySchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	old := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/notify-cluster.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	t.Cleanup(func() {
		db.DB = old
		database.Close()
	})
	if _, err := database.Exec(`
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
	retry_channel_ids TEXT NOT NULL DEFAULT '',
	node TEXT NOT NULL DEFAULT ''
);
CREATE TABLE cluster_node_daily_stats (
	date TEXT NOT NULL,
	node TEXT NOT NULL,
	stats_json TEXT NOT NULL DEFAULT '{}',
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (date, node)
);`); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestInsertDeliveryPending_persistsNode(t *testing.T) {
	database := newNotifySchemaDB(t)
	insertDeliveryPending(7, Event{Type: EvtCaddyApplyFailed, Level: LevelWarn,
		Title: "t", Body: "b", Node: "slave-a"})
	var node string
	if err := database.QueryRow(`SELECT node FROM notification_deliveries WHERE user_id=7`).Scan(&node); err != nil {
		t.Fatal(err)
	}
	if node != "slave-a" {
		t.Fatalf("node=%q，want slave-a（集群事件来源节点须落行可见）", node)
	}
	// 投递扫描回读同一列（模板 {{node}} 数据源）
	rows := []struct {
		ID        int64
		UserID    int64
		EventType string
		Level     string
		Title     string
		Body      string
		Node      string
	}{}
	_ = rows
	got, err := pendingDeliveries(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Node != "slave-a" {
		t.Fatalf("pending=%+v，want 单行 node=slave-a", got)
	}
}

func TestCollectNodesSummary_aggregatesPerNode(t *testing.T) {
	database := newNotifySchemaDB(t)
	st1, _ := json.Marshal(ClusterNodeStats{Date: "2026-11-21", Requests: 1200, Blocked: 30, DistinctIPs: 9, TopRule: "SQLi", CCTriggered: 2, Autobans: 1})
	st2, _ := json.Marshal(ClusterNodeStats{Date: "2026-11-21", Requests: 44, Blocked: 0, DistinctIPs: 3, TopRule: "无"})
	if _, err := database.Exec(`INSERT INTO cluster_node_daily_stats (date,node,stats_json) VALUES ('2026-11-21','slave-a',?),('2026-11-21','slave-b',?)`, string(st1), string(st2)); err != nil {
		t.Fatal(err)
	}
	got := collectNodesSummary(t.Context(), "2026-11-21")
	if !strings.Contains(got, "slave-a：请求 1200 · 拦截 30 · 独立IP 9") {
		t.Fatalf("摘要缺失 slave-a 行: %q", got)
	}
	if !strings.Contains(got, "TOP 规则 SQLi") || !strings.Contains(got, "CC 2") || !strings.Contains(got, "自动封禁 1") {
		t.Fatalf("摘要缺失 slave-a 明细: %q", got)
	}
	if !strings.Contains(got, "slave-b：请求 44") || strings.Contains(got, "TOP 规则 无") {
		t.Fatalf("摘要 slave-b 行错误（无 TOP 规则时不应输出「无」）: %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("摘要应为每节点一行（2 行 1 换行）: %q", got)
	}
	// 无数据日期→空串（渲染层省略整项）
	if got := collectNodesSummary(t.Context(), "2026-01-01"); got != "" {
		t.Fatalf("无数据日期摘要=%q，want 空", got)
	}
}

func TestNormalizeDailyItems_legacyClusterConfigGetsNodesSummary(t *testing.T) {
	got := normalizeDailyItems([]string{"requests", "cluster_status", "uptime"})
	if !containsStr(got, "nodes_summary") {
		t.Fatalf("存量集群配置未补 nodes_summary: %v", got)
	}
	// 未启用集群模块的配置不补
	got = normalizeDailyItems([]string{"requests", "uptime"})
	if containsStr(got, "nodes_summary") {
		t.Fatalf("未启用集群模块却被补 nodes_summary: %v", got)
	}
	// 已有则不重复
	got = normalizeDailyItems([]string{"cluster_status", "nodes_summary"})
	if strings.Count(strings.Join(got, ","), "nodes_summary") != 1 {
		t.Fatalf("nodes_summary 重复: %v", got)
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// roundTripFunc 测试用传输（捕获请求后直接应答，不触网）。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// 上报必须走注入传输（生产=services 装配的 TOFU pin 传输——自签主节点下
// 默认传输握手失败会让事件/统计永远 spool 重传不出去）。
func TestClusterForward_usesInjectedTransport(t *testing.T) {
	old := ClusterForwardTransportFactory
	t.Cleanup(func() { ClusterForwardTransportFactory = old })
	var used bool
	ClusterForwardTransportFactory = func(masterURL string) http.RoundTripper {
		if masterURL != "https://master.test:8000" {
			t.Fatalf("工厂收到主节点地址=%q", masterURL)
		}
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			used = true
			if r.URL.Path != "/api/v1/cluster/events/report" {
				t.Fatalf("上报路径=%q", r.URL.Path)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
		})
	}
	if err := postClusterEventReport("https://master.test:8000", "tok", ClusterEventReport{Node: "n",
		Events: []ClusterEventOne{{Type: EvtCaddyApplyFailed}}}); err != nil {
		t.Fatalf("上报失败: %v", err)
	}
	if !used {
		t.Fatal("未使用注入传输（自签主节点下必然握手失败）")
	}
}

// 主节点/单机本地事件必须带节点标识（用户裁定 2026-11-22：主节点事件此前
// Node 恒空，通知里只有从节点事件有节点信息）——非转发路径入队前补「master」。
func TestPublish_masterLocalEventsCarryNodeLabel(t *testing.T) {
	overrideClusterForwardRole(t, true, "http://unused", "") // 主节点：本地入队
	q := newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "m", "2": "d"}})

	if len(q) != 1 {
		t.Fatalf("入队=%d，want 1", len(q))
	}
	if got := (<-q).Node; got != "master" {
		t.Fatalf("本地事件 Node=%q，want master（主节点事件须可辨识来源）", got)
	}
	// 已带 Node 的事件不被覆盖（转发/显式标注语义保留）
	Publish(Event{Type: EvtCaddyApplyFailed, Node: "custom", Fields: map[string]string{"1": "m", "2": "d"}})
	if got := (<-q).Node; got != "custom" {
		t.Fatalf("显式 Node 被覆盖=%q，want custom", got)
	}
}
