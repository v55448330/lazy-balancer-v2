package handlers

// 第 49 轮 F49-11：UpdateRule 的 upstreams 写入必须增量收敛（replaceUpstreamsTx，
// 镜像 replacePathRulesTx 三入口语义）——修复前恒 DELETE 全删 + INSERT：任何
// 规则编辑（含纯改名）都重建全部上游行（id 递增），且恒触发行级同步触发器
// （upstreams 在集群版本矩阵内）→ 每次 UpdateRule 多一轮从端同步。
//
// 断言口径为可观察终态：内容一致的存量行 id 原样保留 + 上游表写操作计数为零
// （tally 触发器与 cluster_version 行级触发器同事件——零写入即零同步 bump）；
// 内容变更按身份键（host+port+protocol）或显式 id 原地 UPDATE 保 id；
// 消失行 DELETE、新增行 INSERT。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

type upstreamChurnRow struct {
	ID       int
	Host     string
	Port     int
	Weight   int
	Protocol string
}

func readUpstreamChurnRows(t *testing.T, ruleID string) []upstreamChurnRow {
	t.Helper()
	rows, err := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(protocol,'http')
		FROM upstreams WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		t.Fatalf("read upstreams: %v", err)
	}
	defer rows.Close()
	var out []upstreamChurnRow
	for rows.Next() {
		var row upstreamChurnRow
		if err := rows.Scan(&row.ID, &row.Host, &row.Port, &row.Weight, &row.Protocol); err != nil {
			t.Fatalf("scan upstreams: %v", err)
		}
		out = append(out, row)
	}
	return out
}

// installUpstreamWriteTally 安装与 cluster_version 行级触发器同事件的写计数
// 触发器并清零——计数即「会引发集群同步 bump 的写操作次数」。
func installUpstreamWriteTally(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`DROP TRIGGER IF EXISTS tally_upstreams_insert;
		DROP TRIGGER IF EXISTS tally_upstreams_update;
		DROP TRIGGER IF EXISTS tally_upstreams_delete;
		CREATE TABLE IF NOT EXISTS upstream_write_tally (n INTEGER);
		DELETE FROM upstream_write_tally;
		CREATE TRIGGER tally_upstreams_insert AFTER INSERT ON upstreams BEGIN INSERT INTO upstream_write_tally VALUES (1); END;
		CREATE TRIGGER tally_upstreams_update AFTER UPDATE ON upstreams BEGIN INSERT INTO upstream_write_tally VALUES (1); END;
		CREATE TRIGGER tally_upstreams_delete AFTER DELETE ON upstreams BEGIN INSERT INTO upstream_write_tally VALUES (1); END`); err != nil {
		t.Fatalf("install tally triggers: %v", err)
	}
}

func upstreamWriteCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM upstream_write_tally`).Scan(&count); err != nil {
		t.Fatalf("read tally: %v", err)
	}
	return count
}

func putRuleBody(t *testing.T, router *gin.Engine, ruleID, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/rules/"+ruleID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT %s status=%d body=%s", ruleID, recorder.Code, recorder.Body.String())
	}
}

func TestUpdateRule_upstreams_incrementalConvergence(t *testing.T) {
	// Given：一条 http 规则 + 两条上游（经真实 PUT 落库，取回真实 id）
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress) VALUES ('lb_upchurn','upchurn','原始描述','http','upchurn.example.test',8080,'weighted_round_robin','',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	putRuleBody(t, router, "lb_upchurn", `{"upstreams":[
		{"host":"127.0.0.1","port":9001,"weight":1,"enabled":true},
		{"host":"127.0.0.1","port":9002,"weight":2,"enabled":true}]}`)
	seeded := readUpstreamChurnRows(t, "lb_upchurn")
	if len(seeded) != 2 {
		t.Fatalf("seed rows=%d, want 2", len(seeded))
	}
	installUpstreamWriteTally(t)

	// When 1：同内容编辑（无 id 回传，MCP/API 客户端形状）
	putRuleBody(t, router, "lb_upchurn", `{"description":"改名后","upstreams":[
		{"host":"127.0.0.1","port":9001,"weight":1,"enabled":true},
		{"host":"127.0.0.1","port":9002,"weight":2,"enabled":true}]}`)
	// Then 1：id 原样保留 + 上游表零写入（修复前 id 递增、tally=4）
	after1 := readUpstreamChurnRows(t, "lb_upchurn")
	if len(after1) != 2 || after1[0].ID != seeded[0].ID || after1[1].ID != seeded[1].ID {
		t.Fatalf("同内容编辑重建了上游行：%+v（want ids %d/%d）", after1, seeded[0].ID, seeded[1].ID)
	}
	if n := upstreamWriteCount(t); n != 0 {
		t.Fatalf("同内容编辑触发 %d 次上游写（应 0 次——零写入零同步 bump）", n)
	}

	// When 2：显式 id 回传同内容（前端编辑形状）
	putRuleBody(t, router, "lb_upchurn", fmt.Sprintf(`{"upstreams":[
		{"id":%d,"host":"127.0.0.1","port":9001,"weight":1,"enabled":true},
		{"id":%d,"host":"127.0.0.1","port":9002,"weight":2,"enabled":true}]}`, seeded[0].ID, seeded[1].ID))
	// Then 2：同样零写入
	after2 := readUpstreamChurnRows(t, "lb_upchurn")
	if after2[0].ID != seeded[0].ID || after2[1].ID != seeded[1].ID {
		t.Fatalf("显式 id 同内容写入仍重建行：%+v", after2)
	}
	if n := upstreamWriteCount(t); n != 0 {
		t.Fatalf("显式 id 同内容编辑触发 %d 次上游写（应 0 次）", n)
	}

	// When 3：改一个上游权重（9002 weight 2→5，无 id——身份键配对）
	putRuleBody(t, router, "lb_upchurn", `{"upstreams":[
		{"host":"127.0.0.1","port":9001,"weight":1,"enabled":true},
		{"host":"127.0.0.1","port":9002,"weight":5,"enabled":true}]}`)
	// Then 3：只 UPDATE 该行（tally=1），id 保留，未变更行零触碰
	after3 := readUpstreamChurnRows(t, "lb_upchurn")
	if len(after3) != 2 || after3[0].ID != seeded[0].ID || after3[1].ID != seeded[1].ID {
		t.Fatalf("权重变更重建了行：%+v（want ids %d/%d）", after3, seeded[0].ID, seeded[1].ID)
	}
	if after3[1].Weight != 5 {
		t.Fatalf("权重变更未落库：%+v", after3[1])
	}
	if n := upstreamWriteCount(t); n != 1 {
		t.Fatalf("单权重变更触发 %d 次上游写（应 1 次=仅该行 UPDATE）", n)
	}

	// When 4：删一行 + 加一行（保留 9001，移除 9002，新增 9003）
	putRuleBody(t, router, "lb_upchurn", `{"upstreams":[
		{"host":"127.0.0.1","port":9001,"weight":1,"enabled":true},
		{"host":"127.0.0.1","port":9003,"weight":3,"enabled":true}]}`)
	// Then 4：保留行 id 不动；消失行删除、新增行插入（tally +2 = DELETE+INSERT）
	after4 := readUpstreamChurnRows(t, "lb_upchurn")
	if len(after4) != 2 {
		t.Fatalf("after add/remove rows=%d, want 2 (%+v)", len(after4), after4)
	}
	if after4[0].ID != seeded[0].ID || after4[0].Port != 9001 {
		t.Fatalf("保留行被重建：%+v（want id=%d）", after4[0], seeded[0].ID)
	}
	if after4[1].Port != 9003 || after4[1].ID == seeded[1].ID {
		t.Fatalf("新增行形态错误：%+v", after4[1])
	}
	if n := upstreamWriteCount(t); n != 3 {
		t.Fatalf("增删形态累计写 %d 次（应 3=1 UPDATE + 1 DELETE + 1 INSERT）", n)
	}
}
