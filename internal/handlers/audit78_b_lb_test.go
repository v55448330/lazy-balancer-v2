package handlers

// 第 78 轮 B 域（U04-04 / U04-05 / U04-06）回归：
//   - U04-04：DuplicateRule 复制前把源行投影为共享保存输入，复用
//     validateRulePayloadBeforeSave（host/端口/权重/查重/请求体）；
//     零启用上游/零上游按复制语义放行（不套 Create 表单门）。
//   - U04-05：重试窗口上界——显式越界 400（交 validateRuleFeatures），
//     仅存量越界自愈；interval 越界时同步归零 duration，避免
//     duration>0+interval=0 的渲染必填门矛盾（caddy.go）。
//   - U04-06：BatchRuleBlockPages 入口 trim+去重保序；bound 按
//     RowsAffected>0 计，同值命中计入 unchanged。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// seedDuplicateSourceRule 直改 DB 造存量源行（duplicate 只读存量，不接受载荷）。
func seedDuplicateSourceRule(t *testing.T, id, name, protocol, domain string, port int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress)
		VALUES (?,?,?,?,?,?,'weighted_round_robin',0,1)`, id, name, "", protocol, domain, port); err != nil {
		t.Fatalf("seed rule %s: %v", id, err)
	}
}

// TestDuplicateRule_validatesSourcePayload：直改 DB 制造的坏上游（负权重/
// 空 host/端口 0）在复制路径必须 400 并点名源规则（修复前只跑
// validateRuleFeatures，坏上游原样放大到副本）。
func TestDuplicateRule_validatesSourcePayload(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	type upstreamRow struct {
		host    string
		port    int
		weight  int
		enabled bool
	}
	cases := []struct {
		name       string
		ruleID     string
		ruleName   string
		port       int
		upstreams  []upstreamRow
		wantStatus int
		wantBody   string
	}{
		{
			name: "negative weight", ruleID: "lb_dupneg", ruleName: "dup-neg", port: 18801,
			upstreams:  []upstreamRow{{host: "127.0.0.1", port: 9000, weight: -5, enabled: true}},
			wantStatus: http.StatusBadRequest, wantBody: "权重",
		},
		{
			name: "empty host", ruleID: "lb_dupemptyhost", ruleName: "dup-empty-host", port: 18802,
			upstreams:  []upstreamRow{{host: "", port: 9000, weight: 1, enabled: true}},
			wantStatus: http.StatusBadRequest, wantBody: "主机",
		},
		{
			name: "zero port", ruleID: "lb_dupzeroport", ruleName: "dup-zero-port", port: 18803,
			upstreams:  []upstreamRow{{host: "127.0.0.1", port: 0, weight: 1, enabled: true}},
			wantStatus: http.StatusBadRequest, wantBody: "端口",
		},
		{
			name: "healthy", ruleID: "lb_duphealthy", ruleName: "dup-healthy", port: 18804,
			upstreams:  []upstreamRow{{host: "127.0.0.1", port: 9000, weight: 1, enabled: true}},
			wantStatus: http.StatusCreated,
		},
		{
			// 复制语义：源行零启用上游合法（副本默认禁用，可事后启用/补上游）
			name: "zero enabled upstream", ruleID: "lb_dupzeroenabled", ruleName: "dup-zero-enabled", port: 18805,
			upstreams:  []upstreamRow{{host: "127.0.0.1", port: 9000, weight: 1, enabled: false}},
			wantStatus: http.StatusCreated,
		},
		{
			// 复制语义：零上游存量行合法（rules_update_semantics_test 已钉）
			name: "no upstream", ruleID: "lb_dupnostreams", ruleName: "dup-no-upstream", port: 18806,
			wantStatus: http.StatusCreated,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seedDuplicateSourceRule(t, tc.ruleID, tc.ruleName, "http", tc.ruleName+".test", tc.port)
			for _, u := range tc.upstreams {
				enabled := 0
				if u.enabled {
					enabled = 1
				}
				if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,?,?,?,?,'http')`,
					tc.ruleID, u.host, u.port, u.weight, enabled); err != nil {
					t.Fatalf("seed upstream: %v", err)
				}
			}

			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+tc.ruleID+"/duplicate", nil))

			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			if tc.wantBody != "" {
				body := response.Body.String()
				if !strings.Contains(body, tc.wantBody) || !strings.Contains(body, tc.ruleName) || !strings.Contains(body, tc.ruleID) {
					t.Fatalf("body=%s, want 点名源规则 %s（%s）与字段原因 %q", body, tc.ruleName, tc.ruleID, tc.wantBody)
				}
			}
		})
	}

	// 被判拒的源行不得产生副本
	var copies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name LIKE '%（副本）'`).Scan(&copies); err != nil {
		t.Fatal(err)
	}
	if copies != 3 {
		t.Fatalf("copies=%d, want 3（健康/零启用/零上游三条放行，坏行不得落库）", copies)
	}
}

// TestUpdateRule_tryWindowStoredHealsButExplicitRejected：合并前记录请求是否
// 显式提供重试窗口——显式 >60000 交 validateRuleFeatures 400；仅存量越界
// 自愈，且 interval 越界时 duration 同步归零（否则 duration>0+interval=0
// 命中渲染必填门，保存成功但配置生成必败）。
func TestUpdateRule_tryWindowStoredHealsButExplicitRejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	seed := func(id, name string, port, duration, interval int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,
			tcp_try_duration,tcp_try_interval)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',1,?,?)`, id, name, "", name+".test", port, duration, interval); err != nil {
			t.Fatalf("seed rule %s: %v", id, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,?,9000,1,1,'http')`, id, "127.0.0.1"); err != nil {
			t.Fatalf("seed upstream %s: %v", id, err)
		}
	}
	put := func(id, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+id, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	// 存量越界（duration=5000 + interval=70000）：任意编辑保存成功，
	// 且 duration/interval 不得残留 duration>0+interval=0 的矛盾形态。
	seed("lb_storedtrywin", "stored-try-win", 18810, 5000, 70000)
	if response := put("lb_storedtrywin", `{"name":"stored-try-win-renamed"}`); response.Code != http.StatusOK {
		t.Fatalf("stored out-of-range edit: status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var duration, interval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_storedtrywin'`).
		Scan(&duration, &interval); err != nil {
		t.Fatal(err)
	}
	if duration != 0 || interval != 0 {
		t.Fatalf("存量越界未自愈: duration=%d interval=%d, want 0/0", duration, interval)
	}
	if duration > 0 && interval <= 0 {
		t.Fatalf("自愈后自相矛盾: duration=%d interval=%d（渲染必填门必败）", duration, interval)
	}

	// 显式 interval 越界 → 400（修复前静默归零 200）
	seed("lb_explicittrywin", "explicit-try-win", 18811, 0, 250)
	if response := put("lb_explicittrywin", `{"tcp_try_interval":70000}`); response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "重试间隔") {
		t.Fatalf("explicit interval out-of-range: status=%d body=%s, want 400 重试间隔", response.Code, response.Body.String())
	}
	// 显式 duration 越界 → 400
	if response := put("lb_explicittrywin", `{"tcp_try_duration":70000}`); response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "重试窗口") {
		t.Fatalf("explicit duration out-of-range: status=%d body=%s, want 400 重试窗口", response.Code, response.Body.String())
	}
	// 显式合法值尊重输入
	if response := put("lb_explicittrywin", `{"tcp_try_duration":5000,"tcp_try_interval":250}`); response.Code != http.StatusOK {
		t.Fatalf("explicit valid window: status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_explicittrywin'`).
		Scan(&duration, &interval); err != nil {
		t.Fatal(err)
	}
	if duration != 5000 || interval != 250 {
		t.Fatalf("显式合法窗口未落库: duration=%d interval=%d, want 5000/250", duration, interval)
	}
}

// batchResultAll 解析批量阶段页响应（bound/unchanged/skipped）。
func batchResultAll(t *testing.T, recorder *httptest.ResponseRecorder) (int, int, []map[string]any) {
	t.Helper()
	var payload struct {
		Data struct {
			Bound     int              `json:"bound"`
			Unchanged int              `json:"unchanged"`
			Skipped   []map[string]any `json:"skipped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode batch result: %v (body=%s)", err, recorder.Body.String())
	}
	return payload.Data.Bound, payload.Data.Unchanged, payload.Data.Skipped
}

// TestBatchRuleBlockPages_dedupesAndCountsUnchanged：入口 trim+去重保序；
// bound 按 RowsAffected>0 计，同值命中进 unchanged（bound 不再把零写入
// 的规则算作「成功」）。不存在/TCP 跳过文案与顺序回归。
func TestBatchRuleBlockPages_dedupesAndCountsUnchanged(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	// 重复 id（含空白形态）→ 只处理一次：bound=1
	response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1"," lb_b1 ","lb_b1"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if response.Code != http.StatusOK {
		t.Fatalf("dedupe batch status=%d body=%s", response.Code, response.Body.String())
	}
	bound, unchanged, skipped := batchResultAll(t, response)
	if bound != 1 || unchanged != 0 || len(skipped) != 0 {
		t.Fatalf("dedupe batch bound=%d unchanged=%d skipped=%v, want bound=1 unchanged=0 skipped=0", bound, unchanged, skipped)
	}

	// 同值命中 → unchanged=1、bound=0
	response = postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if response.Code != http.StatusOK {
		t.Fatalf("same-value batch status=%d body=%s", response.Code, response.Body.String())
	}
	bound, unchanged, skipped = batchResultAll(t, response)
	if bound != 0 || unchanged != 1 || len(skipped) != 0 {
		t.Fatalf("same-value batch bound=%d unchanged=%d skipped=%v, want bound=0 unchanged=1", bound, unchanged, skipped)
	}

	// 混合：ghost（不存在）→ tcp → 真实变更；skipped 顺序=提交顺序
	response = postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_ghost","lb_bt","lb_b2"],"block_page_stage1_id":7,"block_page_stage1_status":401,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if response.Code != http.StatusOK {
		t.Fatalf("mixed batch status=%d body=%s", response.Code, response.Body.String())
	}
	bound, unchanged, skipped = batchResultAll(t, response)
	if bound != 1 || unchanged != 0 || len(skipped) != 2 {
		t.Fatalf("mixed batch bound=%d unchanged=%d skipped=%v, want bound=1 unchanged=0 skipped=2", bound, unchanged, skipped)
	}
	if skipped[0]["rule_id"] != "lb_ghost" || skipped[0]["reason"] != "规则不存在" {
		t.Fatalf("skipped[0]=%v, want lb_ghost/规则不存在", skipped[0])
	}
	if skipped[1]["rule_id"] != "lb_bt" || skipped[1]["reason"] != "TCP 规则不经过安全链" {
		t.Fatalf("skipped[1]=%v, want lb_bt/TCP 规则不经过安全链", skipped[1])
	}
}
