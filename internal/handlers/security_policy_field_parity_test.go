package handlers

// 策略字段清单的编译期断言（反射比对）：models.SecurityPolicy 的每个对外列都必须
// 出现在详情 DTO 与列表摘要的对应位置——历史上两次「新增列漏改投影/摘要」事故
// 都是编译通过但运行期静默丢字段（爬虫豁免列表回写被关、详情 DTO 缺席）。
// 本文件把「新增列必须同步」变成测试红。

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// securityPolicyModelJSONFields 返回 SecurityPolicy 的对外 JSON 字段集合
// （json:"-" 的内部计算字段不计）。
func securityPolicyModelJSONFields() map[string]struct{} {
	fields := map[string]struct{}{}
	t := reflect.TypeOf(models.SecurityPolicy{})
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = struct{}{}
	}
	return fields
}

func jsonFieldSet(v any) map[string]struct{} {
	fields := map[string]struct{}{}
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = struct{}{}
	}
	return fields
}

// 详情 DTO 必须覆盖模型全部对外列，唯一例外是 updated_by（列表摘要承载，
// 详情编辑不需要）——新增列若漏改则会命中本测试。
func TestSecurityPolicyDetailCoversEveryModelColumn(t *testing.T) {
	model := securityPolicyModelJSONFields()
	detail := jsonFieldSet(securityPolicyDetail{})
	const documentedDetailGap = "updated_by"

	var missing []string
	for name := range model {
		if name == documentedDetailGap {
			continue
		}
		if _, ok := detail[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("详情 DTO 缺失列 %v——新增列必须同步 securityPolicyDetail/newSecurityPolicyDetail", missing)
	}
	for name := range detail {
		if _, ok := model[name]; !ok {
			t.Fatalf("详情 DTO 出现模型外字段 %q（列集漂移）", name)
		}
	}
}

// 列表摘要必须携带「编辑回写会静默改变行为」的字段族（历史两次事故：
// 爬虫豁免缺席 → 回写即关闭；refs 缺席 → 回写即解绑）。这些字段逐一钉死。
func TestSecurityPolicySummaryCarriesEditorRoundTripFields(t *testing.T) {
	summary := jsonFieldSet(models.SecurityPolicySummary{})
	required := []string{
		"ip_acl_list", "ip_acl_list_refs", "ip_whitelist", "ip_whitelist_refs",
		"ip_whitelist_enabled", "ip_acl_enabled", "ip_acl_mode", "ip_blacklist",
		"geoip_countries", "geoip_mode", "geoip_crawler_exempt", "geoip_crawler_engines",
		"crs_rule_groups", "crs_excluded_count", "custom_rules_count",
		"rate_limit_rps", "rate_limit_burst",
		"waf_check_response", "log_request_body", "policy_type", "trust_detection",
	}
	var missing []string
	for _, name := range required {
		if _, ok := summary[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		t.Fatalf("摘要缺失编辑回写必需字段 %v——前端按摘要回写会静默改变策略行为", missing)
	}
}

// 全非零哨兵回读：每个对外列都写入互不相同的值并逐一比对详情 DTO——
// 编译期字段清单只能证明「字段在」，证明不了「值被正确投影」（曾出现
// 字段存在但取自错误行/默认值的形态）。哨兵全非零使零值兜底无法蒙混。
func TestSecurityPolicyDetailProjectionCarriesSentinels(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (
		name, description, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled,
		ip_whitelist, ip_whitelist_enabled, ip_blacklist,
		rate_limit_enabled, rate_limit_rps, rate_limit_burst,
		crs_rule_groups, crs_excluded_rules, custom_rules, block_page_id, block_status_code, enabled,
		created_at, updated_at, geoip_countries, geoip_mode, geoip_crawler_exempt, geoip_crawler_engines,
		waf_check_response, log_request_body, ip_acl_list_refs, ip_whitelist_refs, updated_by, policy_type, trust_detection,
		human_verify_mode, human_verify_type, human_verify_ttl, human_exempt_paths,
		cc_detect_enabled, cc_rps_limit, cc_rps_window, cc_4xx_ratio, cc_session_anomaly, cc_session_ua_threshold)
		VALUES ('哨兵策略', '哨兵描述', 'custom_only', 15, 'deny', '["203.0.113.0/24"]', 1,
		        '["198.51.100.7"]', 1, '["192.0.2.9"]',
		        1, 321, 77,
		        '["942"]', '["942100"]', '[]', 0, 503, 1,
		        '2026-10-01 01:02:03', '2026-10-02 04:05:06', '["CN"]', 'deny', 1, '["googlebot"]',
		        1, 1, '[3]', '[4]', 7, 'mixed', 1,
		        'auto', 'js', 45, '["/health/"]',
		        1, 55, 15, 65, 1, 7)`)
	if err != nil {
		t.Fatalf("insert sentinel policy: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}

	recorder := getRequest(t, router, "/security/policies/"+strconv.FormatInt(id, 10))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Policy securityPolicyDetail `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	want := securityPolicyDetail{
		ID: int(id), Name: "哨兵策略", Description: "哨兵描述", Mode: "custom_only",
		AnomalyThreshold: 15, IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`, IPACLEnabled: true,
		IPWhitelistEnabled: true, IPWhitelist: `["198.51.100.7"]`, IPBlacklist: `["192.0.2.9"]`,
		RateLimitEnabled: true, RateLimitRPS: 321, RateLimitBurst: 77,
		CRSRuleGroups: `["942"]`, CRSExcludedRules: `["942100"]`, CustomRules: `[]`,
		BlockPageID: 0, BlockStatusCode: 503, Enabled: true,
		CreatedAt: "2026-10-01 01:02:03", UpdatedAt: "2026-10-02 04:05:06",
		GeoIPCountries: `["CN"]`, GeoIPMode: "deny", GeoIPCrawlerExempt: true, GeoIPCrawlerEngines: `["googlebot"]`,
		WAFCheckResponse: true, LogRequestBody: true,
		IPACLListRefs: `[3]`, IPWhitelistRefs: `[4]`, PolicyType: "mixed", TrustDetection: true,
		// 阶段 3 人机验证/CC（2026-11-12）：哨兵全非零，证明详情 DTO 逐列投影
		HumanVerifyMode: "auto", HumanVerifyType: "js", HumanVerifyTTL: 45,
		HumanExemptPaths: `["/health/"]`,
		CCDetectEnabled:  true, CCRPSLimit: 55, CCRPSWindow: 15, CC4xxRatio: 65, CCSessionAnomaly: true, CCSessionUAThreshold: 7,
	}
	if !reflect.DeepEqual(payload.Data.Policy, want) {
		t.Fatalf("详情投影与落库哨兵不一致:\n got=%+v\nwant=%+v", payload.Data.Policy, want)
	}
}
