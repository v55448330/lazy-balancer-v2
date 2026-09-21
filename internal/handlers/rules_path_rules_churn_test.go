package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// 第 47 轮 F-47-10：path_rules 写入必须保留未变更行的身份与时间戳。
//
// 修复前 replacePathRulesTx 恒 DELETE 全删 + INSERT：任何规则编辑（含纯改名）
// 都会重置该规则全部路径规则的 id/created_at/updated_at，并恒触发行级触发器
// （path_rules 在同步版本矩阵内）→ 每次 UpdateRule 多一轮从端同步。
//
// 断言口径为可观察终态（DB 行）：内容一致的存量行 id/created_at 原样保留、
// 内容变更的行保 id/created_at 而 updated_at 刷新、消失的行删除、新增行插入。
// 时间戳以显式标记值钉住（DDL 默认 CURRENT_TIMESTAMP 仅秒级，同秒写入无法
// 区分删除重建，故 seed 后改写为可区分的哨兵值）。
const (
	churnCreatedSentinel = "2000-01-01 00:00:00"
	churnUpdatedSentinel = "2001-01-01 00:00:00"
)

type churnRow struct {
	ID            int
	SortOrder     int
	MatchType     string
	Path          string
	UpstreamPath  string
	UpstreamsJSON string
	CreatedAt     string
	UpdatedAt     string
}

func readChurnRows(t *testing.T, ruleID string) []churnRow {
	t.Helper()
	rows, err := db.DB.Query(`SELECT id, sort_order, match_type, path, upstream_path,
		COALESCE(upstreams_json,''), COALESCE(created_at,''), COALESCE(updated_at,'')
		FROM path_rules WHERE rule_id=? ORDER BY sort_order, id`, ruleID)
	if err != nil {
		t.Fatalf("read path_rules: %v", err)
	}
	defer rows.Close()
	var out []churnRow
	for rows.Next() {
		var row churnRow
		if err := rows.Scan(&row.ID, &row.SortOrder, &row.MatchType, &row.Path, &row.UpstreamPath, &row.UpstreamsJSON, &row.CreatedAt, &row.UpdatedAt); err != nil {
			t.Fatalf("scan path_rules: %v", err)
		}
		out = append(out, row)
	}
	return out
}

func stampChurnSentinels(t *testing.T, ruleID string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE path_rules SET created_at=?, updated_at=? WHERE rule_id=?`,
		churnCreatedSentinel, churnUpdatedSentinel, ruleID); err != nil {
		t.Fatalf("stamp sentinels: %v", err)
	}
}

func putRule(t *testing.T, router *gin.Engine, ruleID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/rules/"+ruleID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT %s status=%d body=%s", ruleID, recorder.Code, recorder.Body.String())
	}
	return recorder
}

func TestUpdateRule_pathRules_preserveIdentityAndTimestamps(t *testing.T) {
	// Given：一条含两条路径规则的规则（通过真实 PUT 落库，取回真实 id）
	handler, _ := newRuleFeatureTestHandlersWithCapture(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress) VALUES ('lb_churn','churn','原始描述','http','churn.example.test',8080,'weighted_round_robin','',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_churn','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	putRule(t, router, "lb_churn", `{"description":"原始描述","custom_routes_enabled":true,"path_rules":[
		{"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":[{"protocol":"http","address":"127.0.0.1","port":9100,"weight":1}]},
		{"sort_order":1,"match_type":"exact","path":"/healthz","upstream_path":"","upstreams":null}]}`)
	seeded := readChurnRows(t, "lb_churn")
	if len(seeded) != 2 {
		t.Fatalf("seed rows=%d, want 2", len(seeded))
	}
	stampChurnSentinels(t, "lb_churn")

	// When 1：纯改名编辑（path_rules 原样回传，带真实 id）
	putRule(t, router, "lb_churn", fmt.Sprintf(`{"description":"改名后","path_rules":[
		{"id":%d,"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":[{"protocol":"http","address":"127.0.0.1","port":9100,"weight":1}]},
		{"id":%d,"sort_order":1,"match_type":"exact","path":"/healthz","upstream_path":"","upstreams":null}]}`, seeded[0].ID, seeded[1].ID))
	// Then 1：身份与时间戳全部原样保留（修复前 id 递增、时间戳回落 now）
	after1 := readChurnRows(t, "lb_churn")
	if len(after1) != 2 {
		t.Fatalf("after rename rows=%d, want 2", len(after1))
	}
	for index := range after1 {
		if after1[index].ID != seeded[index].ID {
			t.Fatalf("改名编辑重建了路径规则行：id %d -> %d（应保留原行）", seeded[index].ID, after1[index].ID)
		}
		if after1[index].CreatedAt != churnCreatedSentinel || after1[index].UpdatedAt != churnUpdatedSentinel {
			t.Fatalf("改名编辑改写了时间戳：row %d created=%q updated=%q（应保持 %q/%q）",
				after1[index].ID, after1[index].CreatedAt, after1[index].UpdatedAt, churnCreatedSentinel, churnUpdatedSentinel)
		}
	}

	// When 2：无 id 客户端（MCP/API/导入路径）回传内容一致的存量行
	putRule(t, router, "lb_churn", `{"path_rules":[
		{"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":[{"protocol":"http","address":"127.0.0.1","port":9100,"weight":1}]},
		{"sort_order":1,"match_type":"exact","path":"/healthz","upstream_path":"","upstreams":null}]}`)
	// Then 2：同样零写入（内容一致即复用原行）
	after2 := readChurnRows(t, "lb_churn")
	for index := range after2 {
		if after2[index].ID != seeded[index].ID || after2[index].CreatedAt != churnCreatedSentinel {
			t.Fatalf("无 id 同内容写入仍未复用原行：%+v（want id=%d created=%q）", after2[index], seeded[index].ID, churnCreatedSentinel)
		}
	}

	// When 3：带 id 变更上游（改端口 9100→9200）
	putRule(t, router, "lb_churn", fmt.Sprintf(`{"path_rules":[
		{"id":%d,"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":[{"protocol":"http","address":"127.0.0.1","port":9200,"weight":1}]},
		{"id":%d,"sort_order":1,"match_type":"exact","path":"/healthz","upstream_path":"","upstreams":null}]}`, seeded[0].ID, seeded[1].ID))
	// Then 3：变更行保 id/created_at，updated_at 刷新；未变更行仍零触碰
	after3 := readChurnRows(t, "lb_churn")
	if len(after3) != 2 {
		t.Fatalf("after upstream change rows=%d, want 2", len(after3))
	}
	if after3[0].ID != seeded[0].ID {
		t.Fatalf("变更行被重建：id %d -> %d（应原地 UPDATE 保留 created_at）", seeded[0].ID, after3[0].ID)
	}
	if after3[0].CreatedAt != churnCreatedSentinel {
		t.Fatalf("变更行 created_at 被重置：%q（应保留 %q）", after3[0].CreatedAt, churnCreatedSentinel)
	}
	if after3[0].UpdatedAt == churnUpdatedSentinel {
		t.Fatalf("变更行 updated_at 未刷新：%q", after3[0].UpdatedAt)
	}
	if !strings.Contains(after3[0].UpstreamsJSON, "9200") {
		t.Fatalf("变更也未落库：upstreams_json=%q", after3[0].UpstreamsJSON)
	}
	if after3[1].ID != seeded[1].ID || after3[1].UpdatedAt != churnUpdatedSentinel || after3[1].CreatedAt != churnCreatedSentinel {
		t.Fatalf("未变更行被牵连改动：%+v", after3[1])
	}

	// When 4：无 id 客户端变更同一行的上游（键匹配路径应原地 UPDATE）
	stampChurnSentinels(t, "lb_churn")
	putRule(t, router, "lb_churn", `{"path_rules":[
		{"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":[{"protocol":"http","address":"127.0.0.1","port":9300,"weight":1}]},
		{"sort_order":1,"match_type":"exact","path":"/healthz","upstream_path":"","upstreams":null}]}`)
	// Then 4：id 与 created_at 保留（键为 匹配类型+path+upstream_path），updated_at 刷新
	after4 := readChurnRows(t, "lb_churn")
	if after4[0].ID != seeded[0].ID || after4[0].CreatedAt != churnCreatedSentinel {
		t.Fatalf("无 id 变更行未原地复用：%+v（want id=%d created=%q）", after4[0], seeded[0].ID, churnCreatedSentinel)
	}
	if after4[0].UpdatedAt == churnUpdatedSentinel {
		t.Fatalf("无 id 变更行 updated_at 未刷新：%q", after4[0].UpdatedAt)
	}
	if !strings.Contains(after4[0].UpstreamsJSON, "9300") {
		t.Fatalf("无 id 变更未落库：%q", after4[0].UpstreamsJSON)
	}

	// When 5：删一行 + 加一行（保留 /api 行，移除 /healthz，新增 /metrics）
	stampChurnSentinels(t, "lb_churn")
	putRule(t, router, "lb_churn", fmt.Sprintf(`{"path_rules":[
		{"id":%d,"sort_order":0,"match_type":"prefix","path":"/api","upstream_path":"/v1","upstreams":[{"protocol":"http","address":"127.0.0.1","port":9300,"weight":1}]},
		{"sort_order":2,"match_type":"prefix","path":"/metrics","upstream_path":"","upstreams":null}]}`, seeded[0].ID))
	// Then 5：存活行保身份，消失行删除，新增行插入
	after5 := readChurnRows(t, "lb_churn")
	if len(after5) != 2 {
		t.Fatalf("after add/remove rows=%d, want 2 (%+v)", len(after5), after5)
	}
	var apiRow, metricsRow *churnRow
	for index := range after5 {
		switch after5[index].Path {
		case "/api":
			apiRow = &after5[index]
		case "/metrics":
			metricsRow = &after5[index]
		}
	}
	if apiRow == nil || metricsRow == nil {
		t.Fatalf("行集合错误：%+v", after5)
	}
	if apiRow.ID != seeded[0].ID || apiRow.CreatedAt != churnCreatedSentinel {
		t.Fatalf("存活行被重建：%+v（want id=%d created=%q）", *apiRow, seeded[0].ID, churnCreatedSentinel)
	}
	for _, row := range after5 {
		if row.Path == "/healthz" {
			t.Fatalf("被移除的路径规则仍在：%+v", row)
		}
	}
	if metricsRow.ID == 0 || metricsRow.CreatedAt == churnCreatedSentinel {
		t.Fatalf("新增行未插入或误用哨兵时间戳：%+v", *metricsRow)
	}
}
