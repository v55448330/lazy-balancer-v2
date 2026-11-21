package handlers

// 集群事件/统计上报端点钉测（2026-11-22 用户裁定：主节点集中汇聚）。
// 覆盖：节点名以认证节点行为准（载荷伪造他节点名被覆盖）/ 目录外事件不上报 /
// spool 批次 BatchID 幂等去重 / 统计上报 (date,node) upsert 与日期校验。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// seedClusterNodeForReport 建一个已审批从节点（cluster_node_id 的 nodes 行）。
func seedClusterNodeForReport(t *testing.T, id int, name string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved) VALUES (?,?,?,?,?,1)`,
		id, name, "slave", "10.0.0.9", 8000); err != nil {
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
	// 2026-11-22 第三轮裁定：节点标签=「从节点 name(ip:port)」（seed ip 10.9.9.9:8000），
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
	body := `{"node":"slave-b","spooled":true,"batch_id":"spool-1","events":[{"type":"cfg.caddy_apply_failed"},{"type":"not-in-catalog"}]}`
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

func TestHandleClusterNodeStatsReport_upsertsAndValidates(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 44, "slave-c")
	router := clusterReportRouter(t, h, 44, "/cluster/node-stats/report", h.HandleClusterNodeStatsReport)

	rec := postClusterJSON(router, "/cluster/node-stats/report", `{"date":"2026-11-21","requests":100,"blocked":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	// 同日重报覆盖（槽点重试自愈）而非重复行
	rec = postClusterJSON(router, "/cluster/node-stats/report", `{"date":"2026-11-21","requests":200,"blocked":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("重报 status=%d，want 200", rec.Code)
	}
	var count int
	var raw string
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cluster_node_daily_stats WHERE date='2026-11-21' AND node='slave-c'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("行数=%d，want 1（(date,node) upsert）", count)
	}
	if err := db.DB.QueryRow(`SELECT stats_json FROM cluster_node_daily_stats WHERE date='2026-11-21' AND node='slave-c'`).Scan(&raw); err != nil {
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
	if rec := postClusterJSON(unknownRouter, "/cluster/node-stats/report", `{"date":"2026-11-21"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("未登记节点 status=%d，want 403", rec.Code)
	}
}
