package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 策略实体单职化写侧（policy_type）：显式提交 stage1/stage2/stage3 时阶段外
// 字段归一为零值（类型与内容不漂移）；缺省提交按内容推断落 type；显式 mixed
// 与非法值 400；更新侧缺省（nil）按合并后内容重推断。列表/详情响应携带
// policy_type 供策略页按类型分组。

func TestCreateSecurityPolicy_explicitTypeNormalizesOutOfStageFields(t *testing.T) {
	// Given：显式 stage1 但携带 WAF/限流内容
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	body := `{"name":"typed-acl","policy_type":"stage1","mode":"blocking","crs_rule_groups":"[\"42\"]",
		"custom_rules":"[1]","rate_limit_enabled":true,"rate_limit_rps":100,
		"ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list":"[\"203.0.113.0/24\"]"}`
	request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：201；mode='off'、CRS/自定义/限流归零、阶段 1 字段保留、type=stage1
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 2xx", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var mode, policyType, crsGroups, customRules string
	var rlEnabled bool
	var aclList string
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,''), COALESCE(policy_type,''), COALESCE(crs_rule_groups,'[]'), COALESCE(custom_rules,'[]'), COALESCE(rate_limit_enabled,0), COALESCE(ip_acl_list,'[]') FROM security_policies WHERE id=?`, payload.Data.ID).
		Scan(&mode, &policyType, &crsGroups, &customRules, &rlEnabled, &aclList); err != nil {
		t.Fatal(err)
	}
	if policyType != "stage1" || mode != "off" || crsGroups != "[]" || customRules != "[]" || rlEnabled || aclList != `["203.0.113.0/24"]` {
		t.Fatalf("stored=(type %s, mode %s, crs %s, custom %s, rl %v, acl %s), want stage1 with out-of-stage fields zeroed",
			policyType, mode, crsGroups, customRules, rlEnabled, aclList)
	}
}

func TestCreateSecurityPolicy_typeInferredAndMixedRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// 缺省提交按内容推断
	request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(`{"name":"infer-waf","mode":"blocking"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 2xx", response.Code, response.Body.String())
	}
	var policyType string
	if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,'') FROM security_policies WHERE name='infer-waf'`).Scan(&policyType); err != nil {
		t.Fatal(err)
	}
	if policyType != "stage3" {
		t.Fatalf("inferred type=%q, want stage3", policyType)
	}

	// 显式 mixed / 非法值 → 400
	for _, body := range []string{
		`{"name":"bad-mixed","policy_type":"mixed","mode":"blocking"}`,
		`{"name":"bad-type","policy_type":"stage9","mode":"blocking"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %s status=%d, want 400", body, response.Code)
		}
	}
}

func TestUpdateSecurityPolicy_nilTypeReinfersAfterContentChange(t *testing.T) {
	// Given：存量混合策略（blocking+ACL）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,policy_type,enabled) VALUES ('mixed-p','blocking',1,'deny','["10.0.0.0/8"]','mixed',1)`); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='mixed-p'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// When：仅更新内容（关闭 ACL 并清空名单），不提供 policy_type → 按合并内容重推断为 stage3
	request := httptest.NewRequest(http.MethodPut, "/security/policies/"+strconv.Itoa(id), strings.NewReader(`{"ip_acl_enabled":false,"ip_acl_list":"[]"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var policyType string
	if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,'') FROM security_policies WHERE id=?`, id).Scan(&policyType); err != nil {
		t.Fatal(err)
	}
	if policyType != "stage3" {
		t.Fatalf("re-inferred type=%q, want stage3", policyType)
	}
}

func TestUpdateSecurityPolicy_explicitTypeSwitchNormalizes(t *testing.T) {
	// Given：存量混合策略（blocking+限流）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,rate_limit_enabled,rate_limit_rps,rate_limit_burst,policy_type,enabled) VALUES ('switch-p','blocking',1,100,50,'mixed',1)`); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='switch-p'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// When：显式切换为 stage2
	request := httptest.NewRequest(http.MethodPut, "/security/policies/"+strconv.Itoa(id), strings.NewReader(`{"policy_type":"stage2"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：mode 归 off、type=stage2、限流字段保留
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var mode, policyType string
	var rps int
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,''), COALESCE(policy_type,''), COALESCE(rate_limit_rps,0) FROM security_policies WHERE id=?`, id).Scan(&mode, &policyType, &rps); err != nil {
		t.Fatal(err)
	}
	if policyType != "stage2" || mode != "off" || rps != 100 {
		t.Fatalf("stored=(type %s, mode %s, rps %d), want (stage2, off, 100)", policyType, mode, rps)
	}
}

func TestListAndGetSecurityPolicy_carryPolicyType(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES ('typed-list','blocking','stage3',1)`); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='typed-list'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// 列表
	recorder := getRequest(t, router, "/security/policies")
	var listPayload struct {
		Data []struct {
			Name       string `json:"name"`
			PolicyType string `json:"policy_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, p := range listPayload.Data {
		if p.Name == "typed-list" {
			found = true
			if p.PolicyType != "stage3" {
				t.Fatalf("list policy_type=%q, want stage3", p.PolicyType)
			}
		}
	}
	if !found {
		t.Fatal("typed-list missing from list response")
	}

	// 详情
	recorder = getRequest(t, router, "/security/policies/"+strconv.Itoa(id))
	var detailPayload struct {
		Data struct {
			Policy struct {
				PolicyType string `json:"policy_type"`
			} `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &detailPayload); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detailPayload.Data.Policy.PolicyType != "stage3" {
		t.Fatalf("detail policy_type=%q, want stage3", detailPayload.Data.Policy.PolicyType)
	}
}

// 混合策略仅可更新迁移（2026-09-20 用户裁定）：三个绑定写入口
// （BindRuleToPolicy / SetRuleSecurityPolicies / BatchBindSecurityPolicies）
// 一律 400 拒绝 mixed 策略 id——存量混合绑定保持有效（迁移前不清除），
// 但不得新增。前端绑定编辑器同步过滤 mixed 可选项。
func TestBindWritePaths_rejectMixedPolicies(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
	router.POST("/security/policies/batch-bind", h.BatchBindSecurityPolicies)

	// Given：mixed 策略 + 单职策略 + http 规则
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES
		(1,'mixed-p','blocking','mixed',1),(2,'typed-p','blocking','stage3',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_mb','mb','http','mb.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_mb','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}

	// BindRuleToPolicy：mixed → 400；typed → 2xx
	recorder := postJSON(t, router, "/security/policies/1/bind", map[string]any{"rule_caddy_id": "lb_mb"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bind mixed status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	recorder = postJSON(t, router, "/security/policies/2/bind", map[string]any{"rule_caddy_id": "lb_mb"})
	if recorder.Code != http.StatusOK && recorder.Code != http.StatusCreated {
		t.Fatalf("bind typed status=%d body=%s, want 2xx", recorder.Code, recorder.Body.String())
	}

	// SetRuleSecurityPolicies：集合含 mixed → 400
	request := httptest.NewRequest(http.MethodPut, "/security/rules/lb_mb/policies", strings.NewReader(`{"policy_ids":[2,1]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("set policies with mixed status=%d body=%s, want 400", response.Code, response.Body.String())
	}

	// BatchBindSecurityPolicies：集合含 mixed → 400
	response = postStageJSON(t, router, "/security/policies/batch-bind", `{"rule_ids":["lb_mb"],"policy_ids":[1],"mode":"merge"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("batch-bind with mixed status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

// 阶段 0 信任名单策略（2026-09-20 用户裁定）：显式 stage0 创建保留信任名单
// +trust_detection（默认直通）；显式 stage1 创建/更新一律清除信任字段
// （信任已归属阶段 0，类型与内容不漂移）。
func TestCreateSecurityPolicy_stage0KeepsTrustAndDetection(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	body := `{"name":"trust-vip","policy_type":"stage0","ip_whitelist_enabled":true,"ip_whitelist":"[\"10.0.0.9\"]","trust_detection":true,"mode":"blocking","rate_limit_enabled":true,"rate_limit_rps":100}`
	request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("create stage0 status=%d body=%s, want 2xx", response.Code, response.Body.String())
	}
	var policyType, mode, whitelist string
	var trustDetection, rlEnabled bool
	if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,''), COALESCE(mode,''), COALESCE(ip_whitelist,'[]'), COALESCE(trust_detection,0), COALESCE(rate_limit_enabled,0) FROM security_policies WHERE name='trust-vip'`).
		Scan(&policyType, &mode, &whitelist, &trustDetection, &rlEnabled); err != nil {
		t.Fatal(err)
	}
	if policyType != "stage0" || mode != "off" || whitelist != `["10.0.0.9"]` || !trustDetection || rlEnabled {
		t.Fatalf("stage0 stored=(type %s, mode %s, wl %s, detection %v, rl %v), want stage0 with trust+detection kept, rest zeroed",
			policyType, mode, whitelist, trustDetection, rlEnabled)
	}
}

func TestCreateSecurityPolicy_stage1ClearsTrustFields(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	body := `{"name":"acl-notrust","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list":"[\"203.0.113.0/24\"]","ip_whitelist_enabled":true,"ip_whitelist":"[\"10.0.0.1\"]"}`
	request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("create stage1 status=%d body=%s, want 2xx", response.Code, response.Body.String())
	}
	var whitelist, wlRefs string
	var wlEnabled bool
	if err := db.DB.QueryRow(`SELECT COALESCE(ip_whitelist,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(ip_whitelist_enabled,1) FROM security_policies WHERE name='acl-notrust'`).
		Scan(&whitelist, &wlRefs, &wlEnabled); err != nil {
		t.Fatal(err)
	}
	if whitelist != "[]" || wlRefs != "[]" {
		t.Fatalf("stage1 trust fields=(wl %s, refs %s), want cleared (trust belongs to stage 0)", whitelist, wlRefs)
	}
	_ = wlEnabled
}

func TestSplitSecurityPolicy_trustBecomesStage0ChildWithDetection(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	// mixed：blocking + 信任名单（g0+g3）
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,ip_whitelist,ip_whitelist_enabled,policy_type,enabled) VALUES ('mix-trust','blocking','["10.0.0.9"]',1,'mixed',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_st','st','http','st.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_st',?)`, id); err != nil {
		t.Fatal(err)
	}

	response := postSplit(t, router, int(id))
	if response.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload splitPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var stage0ID int
	for _, child := range payload.Data.Created {
		if child.PolicyType == "stage0" {
			stage0ID = child.ID
		}
	}
	if stage0ID == 0 {
		t.Fatalf("split must create a stage0 child for the trust feature group: %+v", payload.Data.Created)
	}
	// 阶段 0 子策略：信任保留 + trust_detection=1（保留检测=迁移前语义保持）
	var whitelist string
	var trustDetection bool
	if err := db.DB.QueryRow(`SELECT COALESCE(ip_whitelist,'[]'), COALESCE(trust_detection,0) FROM security_policies WHERE id=?`, stage0ID).Scan(&whitelist, &trustDetection); err != nil {
		t.Fatal(err)
	}
	if whitelist != `["10.0.0.9"]` || !trustDetection {
		t.Fatalf("stage0 child=(wl %s, detection %v), want trust kept + detection=1", whitelist, trustDetection)
	}
}

// 策略列表「内容摘要」列数据源：SecurityPolicySummary.blocked_24h = 近 24h
// 该策略 blocked 安全事件数（security_events.policy_id，24h 窗口；policy_id=0
// 的未归因事件不计入）。
func TestListSecurityPolicies_carriesBlocked24h(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES (1,'b24','blocking','stage3',1),(2,'b24b','off','stage1',1)`); err != nil {
		t.Fatal(err)
	}
	seedEvt := func(policyID int, action, timeExpr string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,rule_caddy_id,policy_id,client_ip,method,uri,event_type,rule_triggered,rule_msg,action,anomaly_score,rule_name,policy_name,transaction_id)
			VALUES (`+timeExpr+`,'lb_x',?,'203.0.113.9','GET','/x','waf','942100','msg',?,0,'x','b24',?)`, policyID, action, fmt.Sprintf("tx-%d-%s-%s", policyID, action, timeExpr)); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	seedEvt(1, "blocked", "datetime('now','-1 hour')")
	seedEvt(1, "blocked", "datetime('now','-2 hours')")
	seedEvt(1, "blocked", "datetime('now','-25 hours')") // 超窗不计
	seedEvt(1, "logged", "datetime('now','-1 hour')")    // 非 blocked 不计
	seedEvt(2, "blocked", "datetime('now','-1 hour')")
	seedEvt(0, "blocked", "datetime('now','-1 hour')") // 未归因不计

	recorder := getRequest(t, router, "/security/policies")
	var payload struct {
		Data []struct {
			Name       string `json:"name"`
			Blocked24h int    `json:"blocked_24h"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]int{}
	for _, p := range payload.Data {
		got[p.Name] = p.Blocked24h
	}
	if got["b24"] != 2 || got["b24b"] != 1 {
		t.Fatalf("blocked_24h=%v, want {b24:2, b24b:1}", got)
	}
}
