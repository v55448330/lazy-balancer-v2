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
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 策略实体单职化写侧（policy_type）：显式提交 stage1/stage2/stage3 时阶段外
// 字段归一为零值（类型与内容不漂移）；缺省提交按内容推断落 type；显式 mixed
// 与非法值 400；更新侧缺省（nil）按合并后内容重推断。列表/详情响应携带
// policy_type 供策略页按类型分组。

func TestCreateSecurityPolicy_explicitTypeNormalizesOutOfStageFields(t *testing.T) {
	// Given：显式 stage1 但携带 WAF/限流内容
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)
	body := `{"name":"typed-acl","policy_type":"stage1","mode":"blocking","crs_rule_groups":"[\"42\"]",
		"custom_rules":"[1]","rate_limit_enabled":true,"rate_limit_rps":100,
		"ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list":"[\"203.0.113.0/24\"]"}`
	request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：200；mode='off'、CRS/自定义/限流归零、阶段 1 字段保留、type=stage1
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 200", response.Code, response.Body.String())
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
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 200", response.Code, response.Body.String())
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
		`{"name":"inferred-mixed","mode":"blocking","ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list":"[\"10.0.0.0/8\"]"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %s status=%d, want 400", body, response.Code)
		}
	}
	var inferredMixedCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='inferred-mixed'`).Scan(&inferredMixedCount); err != nil {
		t.Fatal(err)
	}
	if inferredMixedCount != 0 {
		t.Fatal("缺省 policy_type 推断为 mixed 的策略不得落库")
	}
}

func TestCreateSecurityPolicy_explicitTypeNormalizesCrawlerExemption(t *testing.T) {
	for _, policyType := range []string{models.PolicyTypeStage0, models.PolicyTypeStage2, models.PolicyTypeStage3} {
		t.Run(policyType, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)
			body := fmt.Sprintf(`{"name":"typed-crawler-%s","policy_type":%q,"geoip_crawler_exempt":true,"geoip_crawler_engines":"[\"googlebot\"]"}`, policyType, policyType)
			request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("create status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var exempt bool
			var engines string
			if err := db.DB.QueryRow(`SELECT geoip_crawler_exempt, geoip_crawler_engines FROM security_policies WHERE name=?`, "typed-crawler-"+policyType).Scan(&exempt, &engines); err != nil {
				t.Fatal(err)
			}
			if exempt || engines != "[]" {
				t.Fatalf("stored crawler fields=(%v,%s), want false/[]", exempt, engines)
			}
		})
	}
}

func TestUpdateSecurityPolicy_crawlerFieldsNormalizedAndValidated(t *testing.T) {
	t.Run("geoip off clears stored exemption", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,geoip_mode,geoip_crawler_exempt,geoip_crawler_engines) VALUES ('crawler-off','stage1','deny',1,'["googlebot"]')`)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		response := putJSON(t, router, "/security/policies/"+strconv.FormatInt(id, 10), map[string]any{"geoip_mode": "off"})
		if response.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
		}
		var exempt bool
		if err := db.DB.QueryRow(`SELECT geoip_crawler_exempt FROM security_policies WHERE id=?`, id).Scan(&exempt); err != nil {
			t.Fatal(err)
		}
		if exempt {
			t.Fatal("geoip_mode=off 后不得残留生效豁免位")
		}
	})

	for _, tc := range []struct {
		name    string
		engines string
	}{
		{name: "unknown engine", engines: `["not-a-crawler"]`},
		{name: "malformed engines", engines: `not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)
			res, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,geoip_mode,geoip_crawler_exempt,geoip_crawler_engines) VALUES ('crawler-validate','stage1','deny',1,'["googlebot"]')`)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := res.LastInsertId()
			response := putJSON(t, router, "/security/policies/"+strconv.FormatInt(id, 10), map[string]any{"geoip_crawler_engines": tc.engines})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("engines-only update status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}

	t.Run("empty engines use create defaults", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,geoip_mode,geoip_crawler_exempt,geoip_crawler_engines) VALUES ('crawler-default','stage1','deny',1,'["googlebot"]')`)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		response := putJSON(t, router, "/security/policies/"+strconv.FormatInt(id, 10), map[string]any{"geoip_crawler_engines": ""})
		if response.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
		}
		var raw string
		if err := db.DB.QueryRow(`SELECT geoip_crawler_engines FROM security_policies WHERE id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if engines := decodeStringArray(t, raw); len(engines) == 0 {
			t.Fatal("空 engines 必须按 Create 口径归一为默认引擎集")
		}
	})
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

// 混合策略仅可更新迁移（2026-09-20 用户裁定）：四个绑定写入口
// （BindRuleToPolicy / SetRuleSecurityPolicies / BatchBindSecurityPolicies /
// BulkUpdatePolicyBindings）一律 400 拒绝 mixed 策略 id——存量混合绑定保持
// 有效（迁移前不清除），但不得新增。前端绑定编辑器同步过滤 mixed 可选项。
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
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)

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

	// 非规范数字 ID（SQLite 亲和会命中行 1）不得绕过 mixed 门。
	recorder = postJSON(t, router, "/security/policies/1.0/bind", map[string]any{"rule_caddy_id": "lb_mb"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bind noncanonical mixed status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
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

	// BulkUpdatePolicyBindings：mixed 策略 id → 400
	response = postJSON(t, router, "/security/policies/1/bindings/bulk", map[string]any{"bind": []string{"lb_mb"}, "unbind": []string{}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("bulk with mixed status=%d body=%s, want 400", response.Code, response.Body.String())
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
	if response.Code != http.StatusOK {
		t.Fatalf("create stage0 status=%d body=%s, want 200", response.Code, response.Body.String())
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
	if response.Code != http.StatusOK {
		t.Fatalf("create stage1 status=%d body=%s, want 200", response.Code, response.Body.String())
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
	// 显式 stage1/2/3 的 ip_whitelist_enabled 归 0
	// 落库（与 Update 路径 &falseVal 同形），不再走 policyWhitelistDefault(nil)=1。
	if wlEnabled {
		t.Fatal("stage1 ip_whitelist_enabled=true, want 0（阶段外信任开关归零）")
	}
}

// 显式 stage2/stage3 创建同样把 ip_whitelist_enabled
// 归 0 落库——此前 applyStageZerosToCreate 置 nil 使 INSERT 落默认 1，
// 与 Update 路径（&falseVal → 0）形状漂移。
func TestCreateSecurityPolicy_stage23ZeroWhitelistEnabled(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	for _, tc := range []struct{ label, policyType, body, policyName string }{
		{"stage2", "stage2", `{"name":"rl-noTrust","policy_type":"stage2","rate_limit_enabled":true,"rate_limit_rps":100,"ip_whitelist_enabled":true}`, "rl-noTrust"},
		{"stage3", "stage3", `{"name":"waf-noTrust","policy_type":"stage3","mode":"blocking","ip_whitelist_enabled":true}`, "waf-noTrust"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("create %s status=%d body=%s, want 200", tc.policyType, response.Code, response.Body.String())
			}
			var wlEnabled bool
			var policyType string
			if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,''), COALESCE(ip_whitelist_enabled,1) FROM security_policies WHERE name=?`, tc.policyName).
				Scan(&policyType, &wlEnabled); err != nil {
				t.Fatal(err)
			}
			if policyType != tc.policyType {
				t.Fatalf("policy_type=%q, want %q（测试夹具失效）", policyType, tc.policyType)
			}
			if wlEnabled {
				t.Fatalf("%s ip_whitelist_enabled=true, want 0（阶段外信任开关归零）", tc.policyType)
			}
		})
	}
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
	seedPolicyAttributionEvent(t, 1, "blocked", "datetime('now','-1 hour')", "b24")
	seedPolicyAttributionEvent(t, 1, "blocked", "datetime('now','-2 hours')", "b24")
	seedPolicyAttributionEvent(t, 1, "blocked", "datetime('now','-25 hours')", "b24") // 超窗不计
	seedPolicyAttributionEvent(t, 1, "logged", "datetime('now','-1 hour')", "b24")    // 非 blocked 不计
	seedPolicyAttributionEvent(t, 2, "blocked", "datetime('now','-1 hour')", "b24")
	seedPolicyAttributionEvent(t, 0, "blocked", "datetime('now','-1 hour')", "b24") // 未归因不计

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

// 策略列表「24h 触发」列数据源：SecurityPolicySummary.trigger_24h = 近 24h
// 归因该策略的 blocked+logged 事件数（security_events.policy_id，24h 窗口；
// policy_id=0 的未归因事件不计入）。blocked_24h 口径不变（仅 blocked）。
func TestListSecurityPolicies_carriesTrigger24h(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES (1,'trg','blocking','stage3',1),(2,'trgb','off','stage1',1)`); err != nil {
		t.Fatal(err)
	}
	seedPolicyAttributionEvent(t, 1, "blocked", "datetime('now','-1 hour')", "trg")
	seedPolicyAttributionEvent(t, 1, "logged", "datetime('now','-2 hours')", "trg")
	seedPolicyAttributionEvent(t, 1, "logged", "datetime('now','-1 hour')", "trg")
	seedPolicyAttributionEvent(t, 1, "logged", "datetime('now','-25 hours')", "trg") // 超窗不计
	seedPolicyAttributionEvent(t, 2, "logged", "datetime('now','-1 hour')", "trg")
	seedPolicyAttributionEvent(t, 0, "logged", "datetime('now','-1 hour')", "trg") // 未归因不计
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES (3,'trgz','blocking','stage3',1)`); err != nil {
		t.Fatal(err)
	} // trgz：零事件策略

	recorder := getRequest(t, router, "/security/policies")
	var payload struct {
		Data []struct {
			Name       string `json:"name"`
			Trigger24h *int   `json:"trigger_24h"`
			Blocked24h int    `json:"blocked_24h"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	trigger := map[string]int{}
	blocked := map[string]int{}
	for _, p := range payload.Data {
		// 指针判缺：「24h 触发」列每条策略恒显示（含 0）——字段必须显式携带，
		// 缺省（omitempty/漏赋值）时前端 ?? 0 兜底会掩盖漏算缺陷。
		if p.Trigger24h == nil {
			t.Fatalf("trigger_24h 缺失于策略 %s（零事件策略也须显式携带）", p.Name)
		}
		trigger[p.Name] = *p.Trigger24h
		blocked[p.Name] = p.Blocked24h
	}
	if trigger["trg"] != 3 || trigger["trgb"] != 1 || trigger["trgz"] != 0 {
		t.Fatalf("trigger_24h=%v, want {trg:3, trgb:1, trgz:0}", trigger)
	}
	if blocked["trg"] != 1 || blocked["trgb"] != 0 || blocked["trgz"] != 0 {
		t.Fatalf("blocked_24h=%v, want {trg:1, trgb:0, trgz:0}（口径不变）", blocked)
	}
}

// 限流策略唯一绑定（2026-09-20 用户裁定）：一条规则最多绑定一条 stage2
// 限流策略——BindRuleToPolicy 拒绝第二条限流、SetRuleSecurityPolicies 的
// 提交集含 ≥2 条 stage2 即 400、batch-bind 提交集含 ≥2 条 stage2 即 400、
// batch-bind merge 后单规则含 ≥2 条 stage2 进 skipped。存量多限流绑定保持
// 可运行（重新保存时收敛到一条）。
func TestBindWritePaths_rateLimitUniqueness(t *testing.T) {
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
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,rate_limit_enabled,rate_limit_rps,enabled) VALUES
		(1,'rl-a','off','stage2',1,100,1),(2,'rl-b','off','stage2',1,50,1),(3,'waf-a','blocking','stage3',0,0,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rl','rl','http','rl.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_rl','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}

	// 绑第一条限流 → 2xx
	recorder := postJSON(t, router, "/security/policies/1/bind", map[string]any{"rule_caddy_id": "lb_rl"})
	if recorder.Code != http.StatusOK && recorder.Code != http.StatusCreated {
		t.Fatalf("bind first rate-limit status=%d body=%s, want 2xx", recorder.Code, recorder.Body.String())
	}
	// 再绑第二条限流 → 400
	recorder = postJSON(t, router, "/security/policies/2/bind", map[string]any{"rule_caddy_id": "lb_rl"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bind second rate-limit status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	// 幂等重绑同一条限流 → 仍 2xx
	recorder = postJSON(t, router, "/security/policies/1/bind", map[string]any{"rule_caddy_id": "lb_rl"})
	if recorder.Code != http.StatusOK && recorder.Code != http.StatusCreated {
		t.Fatalf("re-bind same rate-limit status=%d body=%s, want 2xx", recorder.Code, recorder.Body.String())
	}
	// SetRuleSecurityPolicies：提交集含 2 条 stage2 → 400
	request := httptest.NewRequest(http.MethodPut, "/security/rules/lb_rl/policies", strings.NewReader(`{"policy_ids":[1,2]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("set policies with two stage2 status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	// SetRuleSecurityPolicies：收敛为 1 条 stage2 + WAF → 200
	request = httptest.NewRequest(http.MethodPut, "/security/rules/lb_rl/policies", strings.NewReader(`{"policy_ids":[1,3]}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("set policies with one stage2 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	// batch-bind：提交集含 2 条 stage2 → 400
	response = postStageJSON(t, router, "/security/policies/batch-bind", `{"rule_ids":["lb_rl"],"policy_ids":[1,2],"mode":"replace"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("batch-bind with two stage2 status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	// batch-bind：merge 后单规则含 2 条 stage2 → skipped
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rl2','rl2','http','rl2.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_rl2','127.0.0.1',9000,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rl2',1)`); err != nil {
		t.Fatal(err)
	}
	response = postStageJSON(t, router, "/security/policies/batch-bind", `{"rule_ids":["lb_rl2"],"policy_ids":[2],"mode":"merge"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("batch-bind merge second stage2 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	bound, skipped := batchResult(t, response)
	if bound != 0 || len(skipped) != 1 || skipped[0]["rule_id"] != "lb_rl2" {
		t.Fatalf("batch-bind merge bound=%d skipped=%v, want bound=0 skipped=[lb_rl2]", bound, skipped)
	}
}

// trust_detection 仅 stage0（信任名单）策略消费——创建
// stage1/2/3 策略时该开关恒写 0，请求携带 true 不得落库（models.SecurityPolicy
// 契约「仅 stage0 消费；其他类型恒 0」的写侧强制）。
func TestCreateSecurityPolicy_zeroesTrustDetectionForNonStage0(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	for _, policyType := range []string{"stage1", "stage2", "stage3"} {
		name := "信任漂移-" + policyType
		recorder := postJSON(t, router, "/security/policies", map[string]any{
			"name": name, "policy_type": policyType, "trust_detection": true,
		})
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s create status=%d body=%s, want 200", policyType, recorder.Code, recorder.Body.String())
		}
		var stored int
		if err := db.DB.QueryRow(`SELECT COALESCE(trust_detection,0) FROM security_policies WHERE name=?`, name).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != 0 {
			t.Errorf("%s policy trust_detection=%d, want 0 (non-stage0 must not carry the trust flag)", policyType, stored)
		}
	}
}

// 回归形状：stage0 创建保留 trust_detection=true（保留检测语义）。
func TestCreateSecurityPolicy_keepsTrustDetectionForStage0(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	recorder := postJSON(t, router, "/security/policies", map[string]any{
		"name": "信任保留", "policy_type": "stage0", "ip_whitelist": `["192.0.2.9"]`, "trust_detection": true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("stage0 create status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(trust_detection,0) FROM security_policies WHERE name='信任保留'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("stage0 policy trust_detection=%d, want 1 (detection-retained is a stage0 semantic)", stored)
	}
}

// 显式 stage1 类型更新携带 trust_detection=true：更新路径不再静默归零，
// 而是 400 显式拒绝（阶段外字段显式生效 = 矛盾载荷；静默丢弃会让 API/MCP 无法
// 从 200 区分「已生效」与「被忽略」）。类型切换的调用方需显式清除该字段。
func TestUpdateSecurityPolicy_rejectsTrustDetectionForExplicitStage1(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "更新信任漂移"})
	var before int
	if err := db.DB.QueryRow(`SELECT COALESCE(trust_detection,0) FROM security_policies WHERE id=?`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}

	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"policy_type": "stage1", "trust_detection": true,
	})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "阶段 0") {
		t.Fatalf("update status=%d body=%s, want 400 指引阶段 0", recorder.Code, recorder.Body.String())
	}
	var after int
	if err := db.DB.QueryRow(`SELECT COALESCE(trust_detection,0) FROM security_policies WHERE id=?`, id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("被拒绝的更新不得落库: before=%d after=%d", before, after)
	}
}

// 存量 stage1 策略缺省类型提交（nil policy_type）显式携带
// trust_detection=true 同样归零。
func TestUpdateSecurityPolicy_zeroesTrustDetectionForStoredStage1(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection) VALUES ('存量stage1', 'off', 1, 'stage1', 0)`); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='存量stage1'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"trust_detection": true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(trust_detection,0) FROM security_policies WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("stored stage1 policy trust_detection=%d after update, want 0", stored)
	}
}

// 回归形状：stage0 更新保留 trust_detection=true（直通/保留检测二选一仍可改）。
func TestUpdateSecurityPolicy_keepsTrustDetectionForStage0(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, trust_detection, ip_whitelist, ip_whitelist_enabled) VALUES ('存量stage0', 'off', 1, 'stage0', 0, '["192.0.2.9"]', 1)`); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='存量stage0'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"policy_type": "stage0", "trust_detection": true,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(trust_detection,0) FROM security_policies WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("stage0 policy trust_detection=%d after update, want 1", stored)
	}
}

// seedPolicyAttributionEvent 写入一条归因到指定策略的指标事件（策略列表
// 24h 计数用例共用）：timeExpr 为 SQLite 时间表达式（窗口边界由调用方选）。
func seedPolicyAttributionEvent(t *testing.T, policyID int, action, timeExpr, policyName string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,rule_caddy_id,policy_id,client_ip,method,uri,event_type,rule_triggered,rule_msg,action,anomaly_score,rule_name,policy_name,transaction_id)
		VALUES (`+timeExpr+`,'lb_x',?,'203.0.113.9','GET','/x','waf','942100','msg',?,0,'x',?,?)`, policyID, action, policyName, fmt.Sprintf("tx-%d-%s-%s", policyID, action, timeExpr)); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

// 机器客户端 GET→PUT 往返：详情对 ” 存量行（导入/旧快照遗留）回传
// policy_type:""，PUT 必须按「未提供」处理（合并后内容重推断落库），
// 不得 400「无效的策略类型」。此前 PUT 的 switch 无 case ""，回写即 400。
func TestUpdateSecurityPolicy_emptyPolicyTypeTreatedAsOmitted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, policy_type, enabled) VALUES ('legacy-empty-type','blocking','',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// 详情回传空串（存量态，机器客户端据此构造回写载荷）
	rec := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var detail struct {
		Data struct {
			PolicyType string `json:"policy_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Data.PolicyType != "" {
		t.Fatalf("detail policy_type=%q, want \"\"（夹具失效）", detail.Data.PolicyType)
	}

	// When：原样回写
	rec = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"policy_type": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT policy_type=\"\" status=%d body=%s, want 200（空串等价省略）", rec.Code, rec.Body.String())
	}
	// Then：按合并后内容重推断落库（mode=blocking → stage3）
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,'') FROM security_policies WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != models.PolicyTypeStage3 {
		t.Fatalf("stored policy_type=%q, want %q（按合并内容重推断）", stored, models.PolicyTypeStage3)
	}
}

// 反例回归：非法枚举值仍 400（空串特判不得放行任意值）
func TestUpdateSecurityPolicy_invalidPolicyTypeStillRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, policy_type, enabled) VALUES ('bad-explicit-type','blocking','stage3',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"policy_type": "stage9"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT policy_type=stage9 status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}
