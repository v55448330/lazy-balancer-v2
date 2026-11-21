package handlers

// 集群事件/统计上报端点钉测（2026-11-22 用户裁定：主节点集中汇聚）。
// 覆盖：requireMaster 门（降级主节点拒绝）/ 节点身份以认证节点行为准
// （载荷伪造他节点名被覆盖）/ 目录外事件不上报 / spool 批次 BatchID 幂等去重 /
// 统计上报 (date,node(label)) upsert、旧键迁移与日期窗口 / 请求体上限。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// seedClusterNodeForReport 建一个已审批从节点（cluster_node_id 的 nodes 行）。
func seedClusterNodeForReport(t *testing.T, id int, name string) {
	t.Helper()
	seedClusterNodeForReportAt(t, id, name, "10.0.0.9", 8000)
}

func seedClusterNodeForReportAt(t *testing.T, id int, name, ip string, port int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved) VALUES (?,?,?,?,?,1)`,
		id, name, "slave", ip, port); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

func clusterReportRouter(t *testing.T, h *Handlers, nodeID int, path string, handler gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(path, func(c *gin.Context) {
		c.Set("cluster_node_id", nodeID)
		handler(c)
	})
	return router
}

func postClusterJSON(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec
}

// clusterReportDate 由配置时区推出相对今日的日期标签（统计窗口测试用）。
func clusterReportDate(daysFromToday int) string {
	loc := services.CurrentLocation()
	if loc == nil {
		loc = time.Local
	}
	return time.Now().In(loc).AddDate(0, 0, daysFromToday).Format("2006-01-02")
}

func TestHandleClusterEventReport_pinsNodeNameToAuthenticatedNode(t *testing.T) {
	withIsolatedGlobal(t) // 改写 clusterEventPublish seam
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 42, "slave-a")
	var captured []notify.Event
	oldPublish := clusterEventPublish
	clusterEventPublish = func(evt notify.Event) { captured = append(captured, evt) }
	t.Cleanup(func() { clusterEventPublish = oldPublish })

	router := clusterReportRouter(t, h, 42, "/cluster/events/report", h.HandleClusterEventReport)
	body := `{"node":"forged-node","events":[{"type":"cfg.caddy_apply_failed","node":"forged-node","fields":{"1":"x","2":"y"}}]}`
	rec := postClusterJSON(router, "/cluster/events/report", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if len(captured) != 1 {
		t.Fatalf("入总线事件数=%d，want 1", len(captured))
	}
	// 2026-11-22 第三轮裁定：节点标签=「从节点 name(ip:port)」（seed ip 10.0.0.9:8000），
	// 载荷伪造 node=forged 不生效（以认证节点行为准）。
	if captured[0].Node != "从节点 slave-a(10.0.0.9:8000)" {
		t.Fatalf("事件 Node=%q，want 从节点 slave-a(10.0.0.9:8000)（以认证节点行为准，防伪造）", captured[0].Node)
	}
	if !strings.Contains(rec.Body.String(), `"accepted":1`) {
		t.Fatalf("响应=%s，want accepted=1", rec.Body.String())
	}
}

func TestHandleClusterEventReport_dedupsSpoolBatchAndDropsUnknownEvents(t *testing.T) {
	withIsolatedGlobal(t) // 改写 clusterEventPublish seam
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 43, "slave-b")
	var captured []notify.Event
	oldPublish := clusterEventPublish
	clusterEventPublish = func(evt notify.Event) { captured = append(captured, evt) }
	t.Cleanup(func() { clusterEventPublish = oldPublish })

	router := clusterReportRouter(t, h, 43, "/cluster/events/report", h.HandleClusterEventReport)
	// 批次键必须每轮唯一：去重窗口是进程级全局态（-count=2 时固定键会让
	// 第二轮被首轮的登记误判为重复——假红/假绿）。
	batchID := fmt.Sprintf("spool-%d", time.Now().UnixNano())
	body := `{"node":"slave-b","spooled":true,"batch_id":"` + batchID + `","events":[{"type":"cfg.caddy_apply_failed"},{"type":"not-in-catalog"}]}`
	first := postClusterJSON(router, "/cluster/events/report", body)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"accepted":1`) {
		t.Fatalf("首投 status=%d body=%s，want 200 accepted=1（目录外丢弃）", first.Code, first.Body.String())
	}
	second := postClusterJSON(router, "/cluster/events/report", body)
	if !strings.Contains(second.Body.String(), `"deduped":true`) {
		t.Fatalf("重投响应=%s，want deduped=true", second.Body.String())
	}
	if len(captured) != 1 {
		t.Fatalf("重投后入总线数=%d，want 仍 1（批次幂等）", len(captured))
	}
}

func TestHandleClusterEventReport_rejectsNonMaster(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 45, "slave-d")
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	published := 0
	oldPublish := clusterEventPublish
	clusterEventPublish = func(notify.Event) { published++ }
	t.Cleanup(func() { clusterEventPublish = oldPublish })

	router := clusterReportRouter(t, h, 45, "/cluster/events/report", h.HandleClusterEventReport)
	rec := postClusterJSON(router, "/cluster/events/report", `{"events":[{"type":"cfg.caddy_apply_failed"}]}`)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-LB-Error-Code") != masterRequiredErrorCode {
		t.Fatalf("非主节点 status=%d errcode=%q body=%s，want 403 master_required", rec.Code, rec.Header().Get("X-LB-Error-Code"), rec.Body.String())
	}
	if published != 0 {
		t.Fatalf("非主节点仍发布 %d 条事件（降级主节点必须拒绝）", published)
	}
}

func TestHandleClusterNodeStatsReport_upsertsAndValidates(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 44, "slave-c")
	router := clusterReportRouter(t, h, 44, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport)
	date := clusterReportDate(-1)
	label := "从节点 slave-c(10.0.0.9:8000)"

	rec := postClusterJSON(router, "/cluster/node-stats/report", `{"date":"`+date+`","requests":100,"blocked":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"node":"slave-c"`) {
		t.Fatalf("响应=%s，want node=name（文档口径 name，非 label）", rec.Body.String())
	}
	// 同日重报覆盖（槽点重试自愈）而非重复行
	rec = postClusterJSON(router, "/cluster/node-stats/report", `{"date":"`+date+`","requests":200,"blocked":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("重报 status=%d，want 200", rec.Code)
	}
	var count int
	var raw string
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cluster_node_daily_stats WHERE date=? AND node=?`, date, label).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("行数=%d，want 1（(date,node) upsert）", count)
	}
	if err := db.DB.QueryRow(`SELECT stats_json FROM cluster_node_daily_stats WHERE date=? AND node=?`, date, label).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var st notify.ClusterNodeStats
	if err := json.Unmarshal([]byte(raw), &st); err != nil || st.Requests != 200 || st.Blocked != 5 {
		t.Fatalf("stats=%+v (err=%v)，want 重报覆盖后的 200/5", st, err)
	}

	// 日期格式非法→400；节点未登记→403
	if rec := postClusterJSON(router, "/cluster/node-stats/report", `{"date":"11/21/2026"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法日期 status=%d，want 400", rec.Code)
	}
	unknownRouter := clusterReportRouter(t, h, 9999, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport)
	if rec := postClusterJSON(unknownRouter, "/cluster/node-stats/report", `{"date":"`+date+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("未登记节点 status=%d，want 403", rec.Code)
	}
}

func TestHandleClusterNodeStatsReport_keysByNodeLabelSoSameNameNodesDoNotCollide(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 两节点同名（nodes.name 无 UNIQUE），仅 ip:port 不同。
	seedClusterNodeForReportAt(t, 71, "dup", "10.1.0.1", 8000)
	seedClusterNodeForReportAt(t, 72, "dup", "10.1.0.2", 8000)
	date := clusterReportDate(-1)

	first := postClusterJSON(clusterReportRouter(t, h, 71, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport),
		"/cluster/node-stats/report", `{"date":"`+date+`","requests":111}`)
	if first.Code != http.StatusOK {
		t.Fatalf("节点 A 上报 status=%d body=%s", first.Code, first.Body.String())
	}
	second := postClusterJSON(clusterReportRouter(t, h, 72, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport),
		"/cluster/node-stats/report", `{"date":"`+date+`","requests":222}`)
	if second.Code != http.StatusOK {
		t.Fatalf("节点 B 上报 status=%d body=%s", second.Code, second.Body.String())
	}
	rows, err := db.DB.Query(`SELECT node, stats_json FROM cluster_node_daily_stats WHERE date=? ORDER BY node`, date)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int64{}
	for rows.Next() {
		var node, raw string
		if err := rows.Scan(&node, &raw); err != nil {
			t.Fatal(err)
		}
		var st notify.ClusterNodeStats
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			t.Fatal(err)
		}
		got[node] = st.Requests
	}
	if len(got) != 2 {
		t.Fatalf("同名节点统计行数=%d，want 2（键须含 ip:port，不得互相覆盖）: %v", len(got), got)
	}
	if got["从节点 dup(10.1.0.1:8000)"] != 111 || got["从节点 dup(10.1.0.2:8000)"] != 222 {
		t.Fatalf("统计归属错误: %v", got)
	}
}

func TestHandleClusterNodeStatsReport_migratesLegacyBareNameKey(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 73, "legacy")
	date := clusterReportDate(-1)
	if _, err := db.DB.Exec(`INSERT INTO cluster_node_daily_stats (date,node,stats_json) VALUES (?,?,?)`,
		date, "legacy", `{"date":"`+date+`","requests":1}`); err != nil {
		t.Fatal(err)
	}

	rec := postClusterJSON(clusterReportRouter(t, h, 73, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport),
		"/cluster/node-stats/report", `{"date":"`+date+`","requests":9}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var legacyRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cluster_node_daily_stats WHERE date=? AND node='legacy'`, date).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 0 {
		t.Fatalf("旧裸名行残留 %d 行（存量键未迁移，同名节点仍会共享归属）", legacyRows)
	}
	var requests int64
	var raw string
	if err := db.DB.QueryRow(`SELECT stats_json FROM cluster_node_daily_stats WHERE date=? AND node=?`, date, "从节点 legacy(10.0.0.9:8000)").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var st notify.ClusterNodeStats
	_ = json.Unmarshal([]byte(raw), &st)
	requests = st.Requests
	if requests != 9 {
		t.Fatalf("迁移后行数据 requests=%d，want 9", requests)
	}
}

func TestHandleClusterNodeStatsReport_rejectsDateOutsideWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 74, "window")
	router := clusterReportRouter(t, h, 74, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport)

	for _, tc := range []struct {
		offset int
		want   int
	}{
		{0, http.StatusOK},
		{-1, http.StatusOK},
		{-2, http.StatusOK},
		{1, http.StatusBadRequest},
		{-3, http.StatusBadRequest},
	} {
		rec := postClusterJSON(router, "/cluster/node-stats/report",
			`{"date":"`+clusterReportDate(tc.offset)+`"}`)
		if rec.Code != tc.want {
			t.Fatalf("offset=%d date=%s status=%d body=%s, want %d",
				tc.offset, clusterReportDate(tc.offset), rec.Code, rec.Body.String(), tc.want)
		}
	}
}

func TestClusterReportEndpoints_rejectNonMaster(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 46, "slave-e")
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	date := clusterReportDate(-1)
	body := `{"date":"` + date + `","requests":1}`
	rec := postClusterJSON(clusterReportRouter(t, h, 46, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport),
		"/cluster/node-stats/report", body)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-LB-Error-Code") != masterRequiredErrorCode {
		t.Fatalf("非主节点统计上报 status=%d errcode=%q body=%s，want 403 master_required", rec.Code, rec.Header().Get("X-LB-Error-Code"), rec.Body.String())
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cluster_node_daily_stats`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("非主节点仍落库 %d 行统计", rows)
	}
}

func TestClusterReportEndpoints_enforceBodyLimit(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 47, "slave-f")
	huge := strings.Repeat("x", int(clusterReportBodyLimitBytes)+1)
	eventBody := `{"events":[{"type":"cfg.caddy_apply_failed","body":"` + huge + `"}]}`
	if rec := postClusterJSON(clusterReportRouter(t, h, 47, "/cluster/events/report", h.HandleClusterEventReport),
		"/cluster/events/report", eventBody); rec.Code != http.StatusBadRequest {
		t.Fatalf("事件上报超限 status=%d，want 400（请求体上限）", rec.Code)
	}
	statsBody := `{"date":"` + clusterReportDate(-1) + `","top_rule":"` + huge + `"}`
	if rec := postClusterJSON(clusterReportRouter(t, h, 47, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport),
		"/cluster/node-stats/report", statsBody); rec.Code != http.StatusBadRequest {
		t.Fatalf("统计上报超限 status=%d，want 400（请求体上限）", rec.Code)
	}
}

// 上报事件必须携带原始发生时刻（RFC3339，spool 重放不得改写成重放时刻）与
// Origin/Hop 防回荡标记（互指 master_url 的两从节点单跳收敛）。
func TestHandleClusterEventReport_carriesOriginalTimeOriginHop(t *testing.T) {
	withIsolatedGlobal(t) // 改写 clusterEventPublish seam
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 46, "slave-time")
	var captured []notify.Event
	oldPublish := clusterEventPublish
	clusterEventPublish = func(evt notify.Event) { captured = append(captured, evt) }
	t.Cleanup(func() { clusterEventPublish = oldPublish })

	router := clusterReportRouter(t, h, 46, "/cluster/events/report", h.HandleClusterEventReport)
	body := `{"node":"slave-time","origin":"slave-origin","hop":1,"events":[{"type":"cfg.caddy_apply_failed","time":"2026-11-21T01:02:03.000000042Z"}]}`
	rec := postClusterJSON(router, "/cluster/events/report", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if len(captured) != 1 {
		t.Fatalf("入总线事件数=%d，want 1", len(captured))
	}
	want := time.Date(2026, 11, 21, 1, 2, 3, 42, time.UTC)
	if !captured[0].Time.Equal(want) {
		t.Fatalf("事件时间=%s, want 原始发生时刻 %s（spool 重放不得改成重放时刻）", captured[0].Time, want)
	}
	if captured[0].Origin != "slave-origin" {
		t.Fatalf("Origin=%q, want slave-origin", captured[0].Origin)
	}
	if captured[0].Hop != 1 {
		t.Fatalf("Hop=%d, want 1（接收端不再转发）", captured[0].Hop)
	}

	// 缺省形态：无 origin/time → Origin 回退上报者节点名，Time 零值（Publish 补当前）。
	captured = nil
	rec = postClusterJSON(router, "/cluster/events/report", `{"node":"slave-time","events":[{"type":"cfg.caddy_apply_failed"}]}`)
	if rec.Code != http.StatusOK || len(captured) != 1 {
		t.Fatalf("缺省形态 status=%d captured=%d", rec.Code, len(captured))
	}
	if captured[0].Origin != "slave-time" {
		t.Fatalf("缺省 Origin=%q, want 上报者节点名 slave-time", captured[0].Origin)
	}
	if captured[0].Hop != 0 {
		t.Fatalf("缺省 Hop=%d, want 0", captured[0].Hop)
	}
	if !captured[0].Time.IsZero() {
		t.Fatalf("缺省 Time=%s, want 零值（由 Publish 补当前时刻）", captured[0].Time)
	}
}

// 节点行查询失败分型：库读故障（非 sql.ErrNoRows）不是「身份未登记」——403
// 会让从节点把不可自愈的库故障当身份问题处理并停止上报。只破坏 nodes 查询
// （角色门读 global_config 仍可用），确保断言落在「身份读取分型」而非角色门。
func TestHandleClusterNodeStatsReport_dbFailureIs500Not403(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 47, "slave-dbfail")
	router := clusterReportRouter(t, h, 47, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport)

	if _, err := db.DB.Exec(`DROP TABLE nodes`); err != nil {
		t.Fatalf("drop nodes table: %v", err)
	}
	rec := postClusterJSON(router, "/cluster/node-stats/report", `{"date":"`+clusterReportDate(-1)+`","requests":1}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("库故障 status=%d body=%s, want 500（非 403 身份问题）", rec.Code, rec.Body.String())
	}
}
