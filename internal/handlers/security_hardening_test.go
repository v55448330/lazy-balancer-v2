package handlers

// 写侧/拆分侧守卫与批量口径（审计发现修复的钉测试族）：
// ACL 启用门按合并后终态特征判定、拆分迁移拒绝悬空引用传播、
// 威胁情报库开关接导入门、batch-bind 幂等 unchanged 计数、
// 策略摘要暴露 CRS 陈旧选择。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// ACL 启用门判据必须是「合并后终态是否仍含自身阶段特征」而非存量行：
// 存量 stage2（CC 开启）策略在同一请求内关停 CC 并启用 ACL——合并终态只有
// G1 特征、重推断为 stage1，不构成 mixed 漂移，不得按存量 G2 误拒。
func TestUpdateSecurityPolicy_aclGateUsesMergedTerminalFeatures(t *testing.T) {
	t.Run("stage2 同请求关停限流并启用 ACL 放行", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "rl-to-acl-nil", "policy_type": "stage2", "human_verify_mode": "force", "human_verify_type": "slider"})

		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
			"ip_acl_enabled": true, "ip_acl_mode": "deny", "ip_acl_list": `["203.0.113.0/24"]`,
			"human_verify_mode": "off",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200（合并终态仅 G1，重推断 stage1）", rec.Code, rec.Body.String())
		}
		var ptype string
		var aclEnabled int
		if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,''), COALESCE(ip_acl_enabled,0) FROM security_policies WHERE id=?`, id).Scan(&ptype, &aclEnabled); err != nil {
			t.Fatal(err)
		}
		if ptype != "stage1" || aclEnabled != 1 {
			t.Fatalf("final=(%s,acl=%d), want (stage1,1)", ptype, aclEnabled)
		}
	})

	t.Run("stage3 同请求关闭 WAF 并启用 ACL 放行", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "waf-to-acl", "policy_type": "stage3", "mode": "blocking"})

		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
			"ip_acl_enabled": true, "ip_acl_mode": "deny", "ip_acl_list": `["203.0.113.0/24"]`,
			"mode": "off",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200（mode=off 后 G3 消失，重推断 stage1）", rec.Code, rec.Body.String())
		}
		var ptype string
		if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,'') FROM security_policies WHERE id=?`, id).Scan(&ptype); err != nil {
			t.Fatal(err)
		}
		if ptype != "stage1" {
			t.Fatalf("final policy_type=%q, want stage1", ptype)
		}
	})

	t.Run("自身阶段特征仍存时维持拒绝", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "rl-keep", "policy_type": "stage2", "human_verify_mode": "force", "human_verify_type": "slider"})

		// 只启用 ACL 不动限流——合并终态 G1∪G2 → mixed 漂移，必须 400
		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
			"ip_acl_enabled": true, "ip_acl_mode": "deny", "ip_acl_list": `["203.0.113.0/24"]`,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	})
}

// 拆分迁移是「新建策略」路径，与 Create 同门：原策略的悬空拦截页/自定义
// 规则引用（禁用态策略不拦删除门，引用可悬空）不得复制给子策略——直接
// 拒绝拆分，先修原策略。
func TestSplitSecurityPolicy_rejectsDanglingReferences(t *testing.T) {
	t.Run("悬空拦截页", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := splitRouter(t)
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,block_page_id,block_status_code,policy_type,enabled)
			VALUES ('mix-dangling-page','blocking',1,'deny','["203.0.113.0/24"]',4242,403,'mixed',0)`)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		response := postSplit(t, router, int(id))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "拦截页面不存在") {
			t.Fatalf("dangling block page must 400, got %d body=%s", response.Code, response.Body.String())
		}
		// 原策略保持原样（不产生半截子策略）
		var childCount int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name LIKE 'mix-dangling-page（%'`).Scan(&childCount); err != nil {
			t.Fatal(err)
		}
		if childCount != 0 {
			t.Fatalf("split must not create children on dangling refs, got %d", childCount)
		}
	})

	t.Run("悬空自定义规则", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := splitRouter(t)
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,custom_rules,policy_type,enabled)
			VALUES ('mix-dangling-cr','blocking','[424242]','mixed',0)`)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		response := postSplit(t, router, int(id))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "自定义规则") {
			t.Fatalf("dangling custom rules must 400, got %d body=%s", response.Code, response.Body.String())
		}
	})
}

// 威胁情报库开关两端点（auto_update 总闸 / 逐源 update_enabled）与
// 同族 CRS/IP2Region 端点同口径：导入窗口 409 fast-fail（
// security_threat_sources 在导入全量替换清单内，窗口内写入会被静默覆盖）。
func TestThreatEndpoints_rejectWriteDuringImport(t *testing.T) {
	beginImportWindowForTest(t)

	gin.SetMode(gin.TestMode)
	h := &Handlers{}

	// 导入门先于 body 解析——空 body 也必须 409 而非 400。
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/security/threat/auto-update", nil)
	h.UpdateThreatAutoUpdate(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("UpdateThreatAutoUpdate during import = %d body=%s, want 409", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/security/threat/sources/1", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	h.UpdateThreatSourceFlags(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("UpdateThreatSourceFlags during import = %d body=%s, want 409", recorder.Code, recorder.Body.String())
	}

	// 爬虫源开关同族：门同样先于 body 解析（空 body 也得 409 而非 400）。
	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/security/crawler-lib/1/flags", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	h.UpdateCrawlerLibFlags(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("UpdateCrawlerLibFlags during import = %d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
}

// batch-bind 幂等 merge（目标集与现绑定完全一致）不得计为「成功」——
// 与同族 batch-block-pages 的 bound/unchanged 双计数口径一致，取证时可
// 区分真实变更与零写入。
func TestBatchBindSecurityPolicies_unchangedMergeCountedSeparately(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := stageBatchRouter(handler)

	body := `{"policy_ids":[1],"rule_ids":["lb_b1"],"mode":"merge"}`
	first := postStageJSON(t, router, "/security/policies/batch-bind", body)
	if first.Code != http.StatusOK {
		t.Fatalf("first bind status=%d body=%s", first.Code, first.Body.String())
	}
	bound1, unchanged1 := batchBindCounts(t, first)
	if bound1 != 1 || unchanged1 != 0 {
		t.Fatalf("first bind bound=%d unchanged=%d, want 1/0", bound1, unchanged1)
	}

	// 幂等重放：零写入 → bound=0 unchanged=1
	second := postStageJSON(t, router, "/security/policies/batch-bind", body)
	if second.Code != http.StatusOK {
		t.Fatalf("second bind status=%d body=%s", second.Code, second.Body.String())
	}
	bound2, unchanged2 := batchBindCounts(t, second)
	if bound2 != 0 || unchanged2 != 1 {
		t.Fatalf("idempotent merge bound=%d unchanged=%d, want 0/1（零写入不得计为成功）", bound2, unchanged2)
	}
}

func batchBindCounts(t *testing.T, recorder *httptest.ResponseRecorder) (bound, unchanged int) {
	t.Helper()
	var payload struct {
		Data struct {
			Bound     int `json:"bound"`
			Unchanged int `json:"unchanged"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode batch-bind result: %v (body=%s)", err, recorder.Body.String())
	}
	return payload.Data.Bound, payload.Data.Unchanged
}

// 策略摘要暴露 CRS 陈旧选择：CRS 更替后存量策略的组/ID 选择静默失效
// （渲染 skip+WARN），列表必须给出可观测标记而不是只在日志里。
func TestListSecurityPolicies_exposesStaleCRSSelections(t *testing.T) {
	useCRSRuleIndexFixture(t)
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	// 直插绕过写侧存在性门（模拟 CRS 更替前的存量选择）
	for _, p := range []struct {
		name   string
		groups string
	}{
		{"stale-group", `["99"]`},
		{"stale-id", `["999999"]`},
		{"fresh", `["42"]`},
		{"empty", `[]`},
	} {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, crs_rule_groups, enabled) VALUES (?, 'blocking', ?, 1)`, p.name, p.groups); err != nil {
			t.Fatal(err)
		}
	}

	recorder := getRequest(t, router, "/security/policies")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data []struct {
			Name     string `json:"name"`
			CRSStale bool   `json:"crs_stale_selections"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list: %v (body=%s)", err, recorder.Body.String())
	}
	got := map[string]bool{}
	for _, p := range payload.Data {
		got[p.Name] = p.CRSStale
	}
	want := map[string]bool{"stale-group": true, "stale-id": true, "fresh": false, "empty": false}
	if len(payload.Data) != len(want) {
		t.Fatalf("列表行数=%d, want %d（行被丢弃时仅查 map 会把缺失当成 false 蒙混通过）", len(payload.Data), len(want))
	}
	for name, w := range want {
		v, present := got[name]
		if !present {
			t.Fatalf("策略 %s 未出现在列表（行被丢弃）", name)
		}
		if v != w {
			t.Fatalf("policy %s crs_stale_selections=%v, want %v", name, v, w)
		}
	}
}

// 阶段统计（流程抽屉计数 chip）30s 缓存：TTL 内重复请求复用结果，
// 窗口锚点内新增事件不反映；缓存清空后立即反映——与策略 24h 计数
// （security_policy_counts_cache.go）同范式。
func TestGetRuleStageStats_cachedWithinTTL(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled) VALUES ('lb_cache','cache','http','',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	seedBlocked := func(triggered string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,rule_caddy_id,client_ip,rule_triggered,action) VALUES (datetime('now','-1 hour'),'lb_cache','203.0.113.9',?,'blocked')`, triggered); err != nil {
			t.Fatal(err)
		}
	}
	seedBlocked("942100")
	router := stageBatchRouter(handler)

	get := func() int {
		t.Helper()
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/rules/lb_cache/stage-stats", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var payload struct {
			Data struct {
				Stage3 int `json:"stage3_blocked_24h"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return payload.Data.Stage3
	}

	if got := get(); got != 1 {
		t.Fatalf("first read stage3=%d, want 1", got)
	}
	seedBlocked("942100")
	if got := get(); got != 1 {
		t.Fatalf("cached read stage3=%d, want 1（TTL 内复用）", got)
	}
	resetRuleStageStatsCacheForTest()
	if got := get(); got != 2 {
		t.Fatalf("post-reset read stage3=%d, want 2", got)
	}
}

// 写侧去重：crs_rule_groups 重复条目归一时按首见保序去重落库——重复组号
// 会渲染重复 Include 触发 coraza duplicated rule id 编译拒绝。
func TestValidateAndNormalizeCRSField_dedupesRuleGroups(t *testing.T) {
	useCRSRuleIndexFixture(t)
	val := `["42","20","42"]`
	if err := validateAndNormalizeCRSField("crs_rule_groups", &val, true); err != nil {
		t.Fatalf("dedupe: %v", err)
	}
	if val != `["42","20"]` {
		t.Fatalf("normalized = %s, want [\"42\",\"20\"]", val)
	}
}

// crs_rule_groups 条数上限（与 crs_excluded_rules 50 条同族限量）：
// 超大数组放大配置体积与生成时间。夹具使用 201 个**互不相同**的 6 位合法形态
// ID——全同条目会被去重压到上限以内，上限实现若先归一后计数就会蒙混通过。
func TestValidateAndNormalizeCRSField_ruleGroupsCapped(t *testing.T) {
	useCRSRuleIndexFixture(t)
	entries := make([]string, 0, services.CRSRuleGroupsMaxEntries+1)
	for i := 0; i <= services.CRSRuleGroupsMaxEntries; i++ {
		entries = append(entries, fmt.Sprintf(`"%d"`, 942100+i))
	}
	val := "[" + strings.Join(entries, ",") + "]"
	err := validateAndNormalizeCRSField("crs_rule_groups", &val, true)
	if err == nil || !strings.Contains(err.Error(), "不能超过") {
		t.Fatalf("over-cap payload must be rejected, err=%v", err)
	}
}
