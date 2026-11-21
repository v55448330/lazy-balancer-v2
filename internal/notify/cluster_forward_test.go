package notify

// 集群事件转发与日报统计上报钉测（2026-11-22 用户裁定：主节点集中汇聚）。
// 覆盖：从节点 Publish 转发不入本地队列 / 主节点本地入队 / 转发失败 spool 落盘
// 且重传成功即删 / 上报载荷节点名与目录门 / 各节点摘要聚合 / 存量日报配置补项。

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// overrideClusterForwardRole 覆写角色探测并在用例结束复原；同时清空上报
// 客户端缓存（缓存按 masterURL 键，新用例的注入传输不得被上一用例复用）。
func overrideClusterForwardRole(t *testing.T, isMaster bool, masterURL, token string) {
	t.Helper()
	old := clusterForwardRoleDetectorSnapshot()
	setClusterForwardRoleDetectorForTest(func() (bool, string, string, string, error) {
		return isMaster, masterURL, token, "slave-test", nil
	})
	resetClusterForwardClientCache()
	t.Cleanup(func() { setClusterForwardRoleDetectorForTest(old) })
}

// overrideForwardSpoolDir 指定 spool 目录（绕开 db.DataDir 依赖）。
func overrideForwardSpoolDir(t *testing.T, dir string) {
	t.Helper()
	old := clusterForwardSpoolDirSnapshot()
	setClusterForwardSpoolDirForTest(dir)
	t.Cleanup(func() { setClusterForwardSpoolDirForTest(old) })
}

// overrideClusterForwardTransport 装配注入传输（生产=services 的 TOFU pin），
// 用例结束复原为未装配态（客户端缓存随之失效）。
func overrideClusterForwardTransport(t *testing.T, fn func(masterURL string) http.RoundTripper) {
	t.Helper()
	SetClusterForwardTransportFactory(fn)
	t.Cleanup(func() { SetClusterForwardTransportFactory(nil) })
}

// flushClusterForwardQueue 排空转发队列（用例隔离）：入队一个哨兵 job，worker
// 串行处理——哨兵关闭即此前所有事件都已落定（含上一用例遗留）。
func flushClusterForwardQueue(t *testing.T) {
	t.Helper()
	ch := clusterForwardQueue()
	done := make(chan struct{})
	select {
	case ch <- clusterForwardJob{done: done}:
	case <-time.After(15 * time.Second):
		t.Fatal("转发队列无法入队（worker 长期阻塞）")
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("转发队列排空超时（worker 长期阻塞）")
	}
}

// spoolJSONFiles spool 目录内的成品文件（原子写的 .tmp 不算——重传侧同样
// 只看 .json，测试若按任意条目计数会与半成品竞争）。
func spoolJSONFiles(dir string) []os.DirEntry {
	entries, _ := os.ReadDir(dir)
	out := entries[:0]
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, e)
		}
	}
	return out
}

// waitNotifyCond 轮询等待（异步转发/落盘的可观测终态），超时即失败。
func waitNotifyCond(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
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
	flushClusterForwardQueue(t)
	var mu sync.Mutex
	var gotPath, gotToken string
	var gotBody ClusterEventReport
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body ClusterEventReport
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		gotPath, gotToken, gotBody = r.URL.Path, r.Header.Get("X-Cluster-Token"), body
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	q := newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "node-x", "2": "detail"}})

	// Publish 异步转发（不阻塞事件源）：终态由后台单 worker 送达，轮询断言。
	waitNotifyCond(t, "从节点转发上报到达", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return hits == 1
	})
	mu.Lock()
	defer mu.Unlock()
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
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, true, srv.URL, "tok-1")
	q := newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "node-x", "2": "detail"}})

	if called.Load() {
		t.Fatal("主节点不应转发上报")
	}
	if len(q) != 1 {
		t.Fatalf("主节点本地队列=%d 条，want 1", len(q))
	}
}

func TestClusterForward_failureSpoolsThenDrainDeletes(t *testing.T) {
	flushClusterForwardQueue(t)
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	var failing atomic.Bool
	failing.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	_ = newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "node-x", "2": "detail"}})

	// 异步转发失败后由 worker 落 spool：等文件出现再断言内容。
	var entries []os.DirEntry
	waitNotifyCond(t, "失败事件落 spool", func() bool {
		entries = spoolJSONFiles(dir)
		return len(entries) == 1
	})
	// 原始载荷应保留事件类型（重传内容可解析）
	raw, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if !strings.Contains(string(raw), EvtCaddyApplyFailed) {
		t.Fatalf("spool 载荷缺失事件类型: %s", raw)
	}

	failing.Store(false)
	DrainClusterForwardSpool(t.Context())
	entries = spoolJSONFiles(dir)
	if len(entries) != 0 {
		t.Fatalf("重传成功后 spool 残留 %d 个文件", len(entries))
	}
}

func TestClusterForward_unknownEventNotForwarded(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	q := newQueueOnly(t)

	Publish(Event{Type: "not-in-catalog"})

	if called.Load() {
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
);
CREATE TABLE nodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name VARCHAR(100) NOT NULL,
	mode VARCHAR(10) NOT NULL DEFAULT 'slave',
	ip_address VARCHAR(45) NOT NULL,
	port INTEGER DEFAULT 8000,
	is_approved BOOLEAN DEFAULT FALSE,
	status VARCHAR(20) DEFAULT 'offline'
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
	if _, err := database.Exec(`INSERT INTO nodes (name, mode, ip_address, port, is_approved, status) VALUES
		('slave-a','slave','10.0.0.2',8000,1,'online'),
		('slave-b','slave','10.0.0.3',8000,1,'online'),
		('slave-c','slave','10.0.0.4',8000,1,'offline')`); err != nil {
		t.Fatal(err)
	}
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
	// 声明了集群但当日未上报的节点必须可见（否则无法区分单机/从节点挂/上报坏）。
	if !strings.Contains(got, "slave-c：未上报") {
		t.Fatalf("未上报节点被静默: %q", got)
	}
	if strings.Count(got, "\n") != 2 {
		t.Fatalf("摘要应为每节点一行（3 行 2 换行）: %q", got)
	}
	// 声明了集群但该日全部未上报：每个已批准从节点都出「未上报」行。
	wantEmptyDay := "slave-a：未上报\nslave-b：未上报\nslave-c：未上报"
	if got := collectNodesSummary(t.Context(), "2026-01-01"); got != wantEmptyDay {
		t.Fatalf("无数据日期摘要=%q，want %q（未上报可见）", got, wantEmptyDay)
	}
}

// 单机（nodes 表无已批准从节点）即便有孤儿统计行也不得渲染节点摘要。
func TestCollectNodesSummary_singleMachineIgnoresOrphanStats(t *testing.T) {
	database := newNotifySchemaDB(t)
	if _, err := database.Exec(`INSERT INTO cluster_node_daily_stats (date,node,stats_json) VALUES
		('2026-11-21','ghost','{"requests":1}')`); err != nil {
		t.Fatal(err)
	}
	if got := collectNodesSummary(t.Context(), "2026-11-21"); got != "" {
		t.Fatalf("单机摘要=%q，want 空（未声明集群不得渲染孤儿统计）", got)
	}
}

// 查询失败必须可见降级（不能静默当「无从节点」——与单机无法区分）。
func TestCollectNodesSummary_queryFailureVisible(t *testing.T) {
	database := newNotifySchemaDB(t)
	if _, err := database.Exec(`DROP TABLE nodes`); err != nil {
		t.Fatal(err)
	}
	got := collectNodesSummary(t.Context(), "2026-11-21")
	if got == "" || !strings.Contains(got, "节点统计读取失败") {
		t.Fatalf("查询失败摘要=%q，want 可见降级文案", got)
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
	var used atomic.Bool
	overrideClusterForwardTransport(t, func(masterURL string) http.RoundTripper {
		if masterURL != "https://master.test:8000" {
			t.Fatalf("工厂收到主节点地址=%q", masterURL)
		}
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			used.Store(true)
			if r.URL.Path != "/api/v1/cluster/events/report" {
				t.Fatalf("上报路径=%q", r.URL.Path)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
		})
	})
	if err := postClusterEventReport("https://master.test:8000", "tok", ClusterEventReport{Node: "n",
		Events: []ClusterEventOne{{Type: EvtCaddyApplyFailed}}}); err != nil {
		t.Fatalf("上报失败: %v", err)
	}
	if !used.Load() {
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
	if got := (<-q).Node; got != MasterNodeLabel() {
		t.Fatalf("本地事件 Node=%q，want %q（主节点事件须可辨识来源）", got, MasterNodeLabel())
	}
	if !strings.Contains(MasterNodeLabel(), "主节点") {
		t.Fatalf("主节点标签=%q 须含「主节点」类型词", MasterNodeLabel())
	}
	// 已带 Node 的事件不被覆盖（转发/显式标注语义保留）
	Publish(Event{Type: EvtCaddyApplyFailed, Node: "custom", Fields: map[string]string{"1": "m", "2": "d"}})
	if got := (<-q).Node; got != "custom" {
		t.Fatalf("显式 Node 被覆盖=%q，want custom", got)
	}
}

// ── 上报客户端：3xx 判失败 + 同主机 https 升级重放（P2）──

// 3xx 一律判失败：主节点启用管理 HTTPS 后明文端口整体重定向，旧实现把
// 302 当成功并删除 spool（事件静默丢失）。
func TestClusterForward_redirectTreatedAsFailure(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "https://other-host.example/api/v1/cluster/events/report")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	overrideForwardSpoolDir(t, t.TempDir())

	err := postClusterEventReport(srv.URL, "tok", ClusterEventReport{
		BatchID: "redirect-1", Events: []ClusterEventOne{{Type: EvtCaddyApplyFailed, Body: "x"}},
	})
	if err == nil {
		t.Fatalf("302 被判成功（事件静默丢失，hits=%d）", hits.Load())
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("错误未带状态码: %v", err)
	}
}

// 同主机 http→https 升级：按原方法重放一次（路径/令牌/请求体保留）。
func TestClusterForward_replaysSameHostHTTPSUpgrade(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotToken, gotBody string
	hits := 0
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath, gotToken, gotBody = r.URL.Path, r.Header.Get("X-Cluster-Token"), string(raw)
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsSrv.Close)
	tlsURL, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 同主机名（127.0.0.1）升级到 https：端口变化隐含允许。
		w.Header().Set("Location", tlsURL.Scheme+"://"+tlsURL.Host+r.URL.RequestURI())
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(plain.Close)
	overrideClusterForwardRole(t, false, plain.URL, "tok-1")
	overrideForwardSpoolDir(t, t.TempDir())
	overrideClusterForwardTransport(t, func(string) http.RoundTripper {
		return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	})

	err = postClusterEventReport(plain.URL, "tok", ClusterEventReport{
		BatchID: "upgrade-1", Events: []ClusterEventOne{{Type: EvtCaddyApplyFailed, Body: "upgrade-body"}},
	})
	if err != nil {
		t.Fatalf("同主机 https 升级重放失败: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("https 重放命中=%d, want 1", hits)
	}
	if gotPath != "/api/v1/cluster/events/report" {
		t.Fatalf("重放路径=%q（Location 只带主机时须继承原路径）", gotPath)
	}
	if gotToken != "tok" {
		t.Fatalf("重放令牌=%q, want tok", gotToken)
	}
	if !strings.Contains(gotBody, EvtCaddyApplyFailed) || !strings.Contains(gotBody, "upgrade-body") {
		t.Fatalf("重放请求体缺失原载荷: %s", gotBody)
	}
}

// 上报客户端按 masterURL 复用（不再每条事件新建 Transport/每次关闲置连接）。
func TestClusterForwardReport_reusesClientPerMasterURL(t *testing.T) {
	var factoryCalls atomic.Int32
	var roundTrips atomic.Int32
	overrideClusterForwardTransport(t, func(masterURL string) http.RoundTripper {
		factoryCalls.Add(1)
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			roundTrips.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
		})
	})
	for i := 0; i < 3; i++ {
		if err := postClusterEventReport("https://reuse.example:8443", "tok", ClusterEventReport{
			BatchID: "reuse", Events: []ClusterEventOne{{Type: EvtCaddyApplyFailed}}}); err != nil {
			t.Fatalf("第 %d 次上报失败: %v", i+1, err)
		}
	}
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("传输工厂调用 %d 次，want 1（客户端/传输须按 masterURL 复用）", got)
	}
	if got := roundTrips.Load(); got != 3 {
		t.Fatalf("实际请求 %d 次，want 3", got)
	}
}

// ── Publish 异步化（不阻塞事件源，满则 spool）──

// 主节点黑洞（接受连接不应答）时 Publish 必须毫秒级返回——旧实现同步 POST
// 3s 超时并在安全事件摄取/登录路径上周期性卡顿。
func TestPublish_slaveForwardNonBlocking(t *testing.T) {
	flushClusterForwardQueue(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法开监听: %v", err)
	}
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
		_ = l.Close()
	})
	overrideClusterForwardRole(t, false, "http://"+l.Addr().String(), "tok")
	overrideForwardSpoolDir(t, t.TempDir())
	_ = newQueueOnly(t)

	start := time.Now()
	Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "n", "2": "d"}})
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("Publish 耗时 %v（>200ms：转发仍在调用者 goroutine 同步外呼）", d)
	}
}

// 转发队列满时落 spool（有界队列 + 单 worker：worker 被黑洞拖住时溢出事件
// 不得丢失）。
func TestPublish_forwardQueueFullSpools(t *testing.T) {
	flushClusterForwardQueue(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法开监听: %v", err)
	}
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
		_ = l.Close()
	})
	dir := t.TempDir()
	overrideClusterForwardRole(t, false, "http://"+l.Addr().String(), "tok")
	overrideForwardSpoolDir(t, dir)
	_ = newQueueOnly(t)

	for i := 0; i < clusterForwardQueueSize+20; i++ {
		Publish(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "n", "2": "d"}})
	}
	waitNotifyCond(t, "队列满后的溢出事件落 spool", func() bool {
		entries, _ := os.ReadDir(dir)
		return len(entries) > 0
	})
}

// ── 转发投影：原始发生时刻 + Origin/Hop（互指收敛）──

func TestClusterForward_reportCarriesOriginHopAndEventTime(t *testing.T) {
	flushClusterForwardQueue(t)
	got := make(chan ClusterEventReport, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body ClusterEventReport
		_ = json.Unmarshal(raw, &body)
		select {
		case got <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	overrideForwardSpoolDir(t, t.TempDir())
	_ = newQueueOnly(t)

	occurred := time.Date(2026, 11, 21, 1, 2, 3, 0, time.UTC)
	Publish(Event{Type: EvtCaddyApplyFailed, Time: occurred, Fields: map[string]string{"1": "n", "2": "d"}})

	var body ClusterEventReport
	select {
	case body = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("上报未到达")
	}
	if body.Origin != LocalNodeName() {
		t.Fatalf("Origin=%q, want %q（起源节点）", body.Origin, LocalNodeName())
	}
	if body.Hop != 1 {
		t.Fatalf("Hop=%d, want 1（首次转发跳数）", body.Hop)
	}
	if len(body.Events) != 1 {
		t.Fatalf("事件条数=%d", len(body.Events))
	}
	parsed, err := time.Parse(time.RFC3339Nano, body.Events[0].Time)
	if err != nil {
		t.Fatalf("投影时间不是 RFC3339: %q (%v)", body.Events[0].Time, err)
	}
	if !parsed.Equal(occurred) {
		t.Fatalf("投影时间=%s, want 原始发生时刻 %s", parsed, occurred)
	}
}

// 已转发（Hop>=1）或本源事件回到自己时不得再转发：两从节点互指 master_url
// 时事件不得无限回荡。
func TestPublish_dropsForwardedOrOwnOriginEvents(t *testing.T) {
	flushClusterForwardQueue(t)
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	overrideForwardSpoolDir(t, dir)
	_ = newQueueOnly(t)

	Publish(Event{Type: EvtCaddyApplyFailed, Hop: 1, Fields: map[string]string{"1": "n", "2": "d"}})
	Publish(Event{Type: EvtCaddyApplyFailed, Origin: LocalNodeName(), Fields: map[string]string{"1": "n", "2": "d"}})
	time.Sleep(100 * time.Millisecond)
	if got := called.Load(); got != 0 {
		t.Fatalf("已转发/本源事件被再次外呼 %d 次（互指场景会无限回荡）", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("回环事件不应落 spool（残留 %d 个）", len(entries))
	}
}

// ── spool 小项：升主清理 / 写失败留痕 / 目录并发 ──

func TestDiscardClusterForwardSpool_removesAllPending(t *testing.T) {
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	for _, name := range []string{"pending-1.json", "pending-2.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// 非 spool 文件不得被误删
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	DiscardClusterForwardSpool("升主")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "keep.txt" {
		t.Fatalf("清理后残留=%v, want 仅 keep.txt", entries)
	}
	DiscardClusterForwardSpool("升主") // 幂等
}

func TestSpoolClusterEvent_logsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	var buf bytes.Buffer
	var bufMu sync.Mutex
	log.SetOutput(&lockedWriter{mu: &bufMu, w: &buf})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	spoolClusterEvent(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "n", "2": "d"}})
	bufMu.Lock()
	defer bufMu.Unlock()
	if !strings.Contains(buf.String(), "spool 落盘失败") {
		t.Fatalf("WriteAtomic 失败未留痕: %q", buf.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestClusterForwardSpoolDir_concurrentAccess(t *testing.T) {
	dir := t.TempDir()
	old := clusterForwardSpoolDirSnapshot()
	setClusterForwardSpoolDirForTest(dir)
	t.Cleanup(func() { setClusterForwardSpoolDirForTest(old) })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := clusterForwardSpoolDir(); got != dir {
					t.Errorf("spool dir=%q, want %q", got, dir)
					return
				}
			}
		}()
	}
	// 并发读取 + 反复写缓存（-race 下验证读改写受锁保护）。
	for j := 0; j < 20; j++ {
		setClusterForwardSpoolDirForTest(dir)
	}
	wg.Wait()
}

// 统计上报同契约：3xx 判失败（引擎按失败退避重投），不得当成功。
func TestReportNodeStatsToMaster_redirectTreatedAsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://other-host.example/api/v1/cluster/node-stats/report")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")

	err := ReportNodeStatsToMaster(t.Context(), ClusterNodeStats{Date: "2026-11-21", Requests: 1})
	if err == nil {
		t.Fatal("统计上报 302 被判成功（当日块静默丢失）")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("错误未带状态码: %v", err)
	}
}
