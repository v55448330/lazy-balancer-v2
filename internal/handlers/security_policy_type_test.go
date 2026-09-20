package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
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
