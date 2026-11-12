package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func setupSecurityPolicyTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 直换包级句柄必须同步复位
		// currentDB——否则 GetDB()/后台循环继续持有已关闭的测试库句柄。
		db.SetDB(oldDB)
	})
}

func newSecurityRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.GET("/security/policies", h.ListSecurityPolicies)
	router.GET("/security/policies/:id", h.GetSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	return router
}

func postJSON(t *testing.T, router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

func putJSON(t *testing.T, router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

func getRequest(t *testing.T, router *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(recorder, req)
	return recorder
}

func createTestPolicy(t *testing.T, router *gin.Engine, payload map[string]any) int {
	t.Helper()
	recorder := postJSON(t, router, "/security/policies", payload)
	if recorder.Code != http.StatusOK {
		t.Fatalf("create policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse create response: %v", err)
	}
	if resp.Data.ID == 0 {
		t.Fatalf("create response missing id: %s", recorder.Body.String())
	}
	return resp.Data.ID
}

func TestBindRuleToPolicy_rejectsMissingPolicy(t *testing.T) {
	// Given a fresh database without any policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When a rule is bound to a nonexistent policy id
	recorder := postJSON(t, router, "/security/policies/999/bind", map[string]any{"rule_caddy_id": "lb_test001"})

	// Then the request is rejected and no binding row is written
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("bind status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE policy_id=999").Scan(&count); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if count != 0 {
		t.Fatalf("orphan binding written for missing policy")
	}
}

func TestListSecurityPolicies_returnsCreatedRows(t *testing.T) {
	// Given a created policy (regression: list used to 500 on RawMessage scan)
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "可列出", "mode": "blocking", "enabled": true}); recorder.Code != http.StatusOK {
		t.Fatalf("create policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	// When the list is requested
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/policies", nil)
	router.ServeHTTP(recorder, req)

	// Then it succeeds and contains the created policy
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if resp.Code != 0 || len(resp.Data) != 1 || resp.Data[0].Name != "可列出" {
		t.Fatalf("list response = %s", recorder.Body.String())
	}
}

func TestListSecurityPolicies_summaryCarriesUpdatedByAndUpdatedAt(t *testing.T) {
	// Given a policy seeded with explicit updated_by and updated_at values
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, enabled, updated_by, updated_at) VALUES ('元数据策略', 1, 42, '2026-08-12 10:00:00')`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	router := newSecurityRouter(t)

	// When the list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then the summary carries updated_by and updated_at
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			UpdatedBy int    `json:"updated_by"`
			UpdatedAt string `json:"updated_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if resp.Code != 0 || len(resp.Data) != 1 {
		t.Fatalf("list response = %s", recorder.Body.String())
	}
	if resp.Data[0].UpdatedBy != 42 {
		t.Fatalf("summary.updated_by = %d, want 42 in %s", resp.Data[0].UpdatedBy, recorder.Body.String())
	}
	if resp.Data[0].UpdatedAt == "" || !strings.HasPrefix(resp.Data[0].UpdatedAt, "2026-08-12") {
		t.Fatalf("summary.updated_at = %q, want the seeded 2026-08-12 timestamp in %s", resp.Data[0].UpdatedAt, recorder.Body.String())
	}
}

func TestGetSecurityPolicy_returnsRawJSONFieldsAsStrings(t *testing.T) {
	// Given a legacy mixed policy seeded directly (mixed cannot be created via API).
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies
		(name, crs_rule_groups, crs_excluded_rules, custom_rules, ip_whitelist, ip_blacklist, enabled, policy_type)
		VALUES ('详情策略','["42"]','["942100","942110"]','[{"id":1,"name":"r1","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]','["192.0.2.0/24"]','["198.51.100.7"]',1,'mixed')`)
	if err != nil {
		t.Fatal(err)
	}
	id64, _ := res.LastInsertId()
	id := int(id64)

	// When the policy detail is requested
	recorder := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))

	// Then the five raw columns arrive as JSON strings, not arrays, and bindings stay an array
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Policy   map[string]json.RawMessage `json:"policy"`
			Bindings []string                   `json:"bindings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse detail response: %v", err)
	}
	want := map[string]string{
		"ip_whitelist":       `["192.0.2.0/24"]`,
		"ip_blacklist":       `["198.51.100.7"]`,
		"crs_rule_groups":    `["42"]`,
		"crs_excluded_rules": `["942100","942110"]`,
		"custom_rules":       `[{"id":1,"name":"r1","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`,
	}
	for field, expected := range want {
		raw, ok := resp.Data.Policy[field]
		if !ok {
			t.Fatalf("policy.%s missing in %s", field, recorder.Body.String())
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("policy.%s = %s, want JSON string: %v", field, raw, err)
		}
		if got != expected {
			t.Fatalf("policy.%s = %q, want %q", field, got, expected)
		}
	}
	if resp.Data.Bindings == nil {
		t.Fatalf("bindings = null, want [] in %s", recorder.Body.String())
	}

	// And a policy with defaults still returns the five fields as "[]" strings
	defaultID := createTestPolicy(t, router, map[string]any{"name": "默认策略"})
	recorder = getRequest(t, router, fmt.Sprintf("/security/policies/%d", defaultID))
	if recorder.Code != http.StatusOK {
		t.Fatalf("default detail status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse default detail response: %v", err)
	}
	for _, field := range []string{"ip_whitelist", "ip_blacklist", "crs_rule_groups", "crs_excluded_rules", "custom_rules"} {
		var got string
		if err := json.Unmarshal(resp.Data.Policy[field], &got); err != nil {
			t.Fatalf("default policy.%s = %s, want JSON string: %v", field, resp.Data.Policy[field], err)
		}
		if got != "[]" {
			t.Fatalf("default policy.%s = %q, want []", field, got)
		}
	}
}

func TestUpdateSecurityPolicy_persistsIPACLModeAndEnabled(t *testing.T) {
	// Given an existing policy with IP ACL disabled in allow mode
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":           "ACL开关策略",
		"ip_acl_enabled": false,
		"ip_acl_mode":    "allow",
	})

	// When the toggle and mode are updated
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"ip_acl_enabled": true,
		"ip_acl_mode":    "deny",
	})

	// Then both columns persist
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var (
		mode    string
		enabled bool
	)
	if err := db.DB.QueryRow("SELECT ip_acl_mode, ip_acl_enabled FROM security_policies WHERE id=?", id).Scan(&mode, &enabled); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if mode != "deny" || !enabled {
		t.Fatalf("ip_acl columns = (%q,%v), want (deny,true)", mode, enabled)
	}
}

func TestUpdateSecurityPolicy_rejectsBlankEnumString(t *testing.T) {
	// Given a policy in blocking mode
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "空串策略", "mode": "blocking"})

	// When the update sends an explicit empty-string mode
	// Then it must be rejected：空串会把 mode 列清空，汇总口径（mode!="off" 即计入
	// WAF）与发射口径（仅 blocking/detection 生效）随即漂移
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"mode": ""})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("blank mode must be rejected with 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, "mode 不能为空串") {
		t.Fatalf("blank mode rejection must name the field, got %s", body)
	}

	// And an explicit empty-string geoip_mode is rejected too（创建时已归一为 allow/deny，空串属于域外值）
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"geoip_mode": ""})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("blank geoip_mode must be rejected with 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	// And the stored mode is untouched by the rejected requests
	var mode string
	if err := db.DB.QueryRow("SELECT mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back mode: %v", err)
	}
	if mode != "blocking" {
		t.Fatalf("rejected updates must not touch mode, got %q", mode)
	}
}

func TestUpdateSecurityPolicy_rejectsBlankName(t *testing.T) {
	// Given a named policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "原名策略"})

	// When the update sends an explicit empty-string name
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"name": ""})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("blank name must be rejected with 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, "策略名称不能为空") {
		t.Fatalf("blank name rejection message mismatch, got %s", body)
	}

	// And a whitespace-only name is rejected too
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"name": "   "})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("whitespace name must be rejected with 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	// And the stored name is untouched by the rejected requests
	var name string
	if err := db.DB.QueryRow("SELECT name FROM security_policies WHERE id=?", id).Scan(&name); err != nil {
		t.Fatalf("read back name: %v", err)
	}
	if name != "原名策略" {
		t.Fatalf("rejected updates must not touch name, got %q", name)
	}
}

func TestUpdateSecurityPolicy_omittedModeLeavesFieldUnchanged(t *testing.T) {
	// Given a policy in blocking mode
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "省略字段策略", "mode": "blocking"})

	// When the update omits mode entirely（指针为 nil → 列不参与 UPDATE）
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"description": "只改描述"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	// Then mode stays blocking
	var mode string
	if err := db.DB.QueryRow("SELECT mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back mode: %v", err)
	}
	if mode != "blocking" {
		t.Fatalf("omitted mode must stay unchanged, got %q", mode)
	}
}

func TestSecurityPolicyWhitelistBlacklist_createAndUpdateRoundTrip(t *testing.T) {
	// Given a legacy mixed policy seeded directly (mixed cannot be created via API).
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_whitelist, ip_blacklist, enabled, policy_type)
		VALUES ('名单策略','["192.0.2.0/24","2001:db8::1"]','["198.51.100.7"]',1,'mixed')`)
	if err != nil {
		t.Fatal(err)
	}
	id64, _ := res.LastInsertId()
	id := int(id64)
	assertListColumns := func(wantWhite, wantBlack string) {
		t.Helper()
		var white, black string
		if err := db.DB.QueryRow("SELECT ip_whitelist, ip_blacklist FROM security_policies WHERE id=?", id).Scan(&white, &black); err != nil {
			t.Fatalf("read back policy: %v", err)
		}
		if white != wantWhite || black != wantBlack {
			t.Fatalf("whitelist/blacklist = (%q,%q), want (%q,%q)", white, black, wantWhite, wantBlack)
		}
	}

	// Then both columns persist from create
	assertListColumns(`["192.0.2.0/24","2001:db8::1"]`, `["198.51.100.7"]`)

	// When both lists are replaced via update
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"ip_whitelist": `["203.0.113.9"]`,
		"ip_blacklist": `["203.0.113.0/24"]`,
	})

	// Then the new values persist and the detail endpoint returns them as strings
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertListColumns(`["203.0.113.9"]`, `["203.0.113.0/24"]`)

	detail := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))
	var resp struct {
		Data struct {
			Policy map[string]json.RawMessage `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse detail response: %v", err)
	}
	var white string
	if err := json.Unmarshal(resp.Data.Policy["ip_whitelist"], &white); err != nil || white != `["203.0.113.9"]` {
		t.Fatalf("detail ip_whitelist = %s (decoded %q), want string %q", resp.Data.Policy["ip_whitelist"], white, `["203.0.113.9"]`)
	}
}

func TestSecurityPolicyList_summaryCarriesExtendedFields(t *testing.T) {
	// Given a legacy mixed policy seeded directly (mixed cannot be created via API).
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies
		(name, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled,
		 ip_whitelist, ip_blacklist,
		 crs_excluded_rules, custom_rules, enabled, policy_type)
		VALUES ('汇总策略','blocking',5,'deny','["203.0.113.0/24","2001:db8::/32"]',1,
		 '["192.0.2.1"]','["198.51.100.0/24","203.0.113.5"]',
		 '["942100","942110"]','[{"id":1,"name":"r1","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]',1,'mixed')`); err != nil {
		t.Fatal(err)
	}

	// When the policy list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then the summary carries the extended fields with parsed counts
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Name             string `json:"name"`
			AnomalyThreshold int    `json:"anomaly_threshold"`
			IPACLMode        string `json:"ip_acl_mode"`
			IPACLList        string `json:"ip_acl_list"`
			IPWhitelist      string `json:"ip_whitelist"`
			IPBlacklist      string `json:"ip_blacklist"`
			CRSExcludedCount int    `json:"crs_excluded_count"`
			CustomRulesCount int    `json:"custom_rules_count"`
			HasIPControl     bool   `json:"has_ip_control"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("list len = %d, want 1: %s", len(resp.Data), recorder.Body.String())
	}
	got := resp.Data[0]
	if got.AnomalyThreshold != 5 || got.IPACLMode != "deny" {
		t.Fatalf("summary scalars = %+v", got)
	}
	if got.IPACLList != `["203.0.113.0/24","2001:db8::/32"]` || got.IPWhitelist != `["192.0.2.1"]` || got.IPBlacklist != `["198.51.100.0/24","203.0.113.5"]` {
		t.Fatalf("summary lists = %+v", got)
	}
	if got.CRSExcludedCount != 2 || got.CustomRulesCount != 1 {
		t.Fatalf("summary counts = (crs %d, custom %d), want (2,1)", got.CRSExcludedCount, got.CustomRulesCount)
	}
	if !got.HasIPControl {
		t.Fatalf("has_ip_control = false, want true")
	}
}

func TestCreateSecurityPolicy_rejectsInvalidIPCIDR(t *testing.T) {
	for _, field := range []string{"ip_acl_list", "ip_whitelist", "ip_blacklist"} {
		t.Run(field, func(t *testing.T) {
			// Given a payload whose IP list contains an entry that is neither IP nor CIDR
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)

			// When the policy is created
			recorder := postJSON(t, router, "/security/policies", map[string]any{
				"name": "bad-" + field,
				field:  `["not-an-ip"]`,
			})

			// Then the request is rejected with a message naming the bad entry
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "not-an-ip") {
				t.Fatalf("error body should name the bad entry: %s", recorder.Body.String())
			}
		})
	}
	t.Run("invalid_json", func(t *testing.T) {
		// Given a payload whose IP list is not a JSON array at all
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)

		// When the policy is created
		recorder := postJSON(t, router, "/security/policies", map[string]any{
			"name":        "bad-json",
			"ip_acl_list": "not-json",
		})

		// Then the request is rejected
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
		}
	})
}

func TestUpdateSecurityPolicy_rejectsInvalidIPCIDR(t *testing.T) {
	for _, field := range []string{"ip_acl_list", "ip_whitelist", "ip_blacklist"} {
		t.Run(field, func(t *testing.T) {
			// Given an existing valid policy
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)
			id := createTestPolicy(t, router, map[string]any{"name": "upd-" + field})

			// When the field is updated to a list containing a bad entry
			recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
				field: `["10.0.0.0/33"]`,
			})

			// Then the request is rejected with a message naming the bad entry
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("update status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "10.0.0.0/33") {
				t.Fatalf("error body should name the bad entry: %s", recorder.Body.String())
			}
		})
	}
	t.Run("invalid_json", func(t *testing.T) {
		// Given an existing valid policy
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "upd-bad-json"})

		// When the field is updated to a non-JSON-array string
		recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
			"ip_whitelist": "not-json",
		})

		// Then the request is rejected
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("update status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
		}
	})
}

func TestGetSecurityPolicy_detailCarriesWAFCheckResponse(t *testing.T) {
	// Given a policy created with the response-body check enabled
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":               "响应体策略",
		"policy_type":        "stage4",
		"waf_check_response": true,
	})

	// When the policy detail is requested
	recorder := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))

	// Then the detail round-trips waf_check_response so the frontend edit form
	// does not silently reset it to false
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Policy struct {
				WAFCheckResponse bool `json:"waf_check_response"`
			} `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse detail response: %v", err)
	}
	if !resp.Data.Policy.WAFCheckResponse {
		t.Fatalf("waf_check_response = false, want true in %s", recorder.Body.String())
	}
}

func TestListSecurityPolicies_summaryCarriesWAFCheckResponse(t *testing.T) {
	// Given a policy created with the response-body check enabled
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	createTestPolicy(t, router, map[string]any{
		"name":               "汇总响应体策略",
		"policy_type":        "stage4",
		"waf_check_response": true,
	})

	// When the policy list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then the summary carries waf_check_response for API consistency
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			WAFCheckResponse bool `json:"waf_check_response"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if resp.Code != 0 || len(resp.Data) != 1 {
		t.Fatalf("list response = %s", recorder.Body.String())
	}
	if !resp.Data[0].WAFCheckResponse {
		t.Fatalf("summary.waf_check_response = false, want true in %s", recorder.Body.String())
	}
}

func TestUpdateSecurityPolicy_crsFieldsNormalizeAndValidate(t *testing.T) {
	// Given a policy created with populated CRS fields
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":               "CRS字段策略",
		"crs_rule_groups":    `["42"]`,
		"crs_excluded_rules": `["942100"]`,
	})

	// When explicit empty strings arrive，Then they normalize to "[]"（镜像 Create 的 ""→"[]" 归一，
	// 避免空串直写列后在发射端解析失败）
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"crs_rule_groups":    "",
		"crs_excluded_rules": "  ",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty-string update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var groups, excluded string
	if err := db.DB.QueryRow("SELECT crs_rule_groups, crs_excluded_rules FROM security_policies WHERE id=?", id).Scan(&groups, &excluded); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if groups != "[]" || excluded != "[]" {
		t.Fatalf("normalized columns = (%q,%q), want ([],[])", groups, excluded)
	}

	// And a non-JSON-array payload is rejected with 400
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": "not-json"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid crs_rule_groups must 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "需为 JSON 数组字符串") {
		t.Fatalf("rejection must explain the JSON-array requirement: %s", recorder.Body.String())
	}
	// 数字数组同样不是字符串数组，必须拒绝
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_excluded_rules": `[942100]`})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("numeric-array crs_excluded_rules must 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	// And a valid array persists as-is
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": `["20","42"]`})
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow("SELECT crs_rule_groups FROM security_policies WHERE id=?", id).Scan(&groups); err != nil {
		t.Fatalf("read back groups: %v", err)
	}
	if groups != `["20","42"]` {
		t.Fatalf("crs_rule_groups = %q, want stored as-is", groups)
	}
}

func TestCreateSecurityPolicy_rejectsInvalidCustomRuleTarget(t *testing.T) {
	// Given a payload whose embedded custom rule uses an unknown target
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When the policy is created
	recorder := postJSON(t, router, "/security/policies", map[string]any{
		"name":         "坏目标规则",
		"custom_rules": `[{"id":1,"name":"r","enabled":true,"conditions":[{"target":"cookie","operator":"contains","pattern":"x"}]}]`,
	})

	// Then the request is rejected with a message naming the bad target
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "target 无效") {
		t.Fatalf("error body should flag the invalid target: %s", recorder.Body.String())
	}
}

func TestCreateSecurityPolicy_rejectsControlCharPattern(t *testing.T) {
	// Given a payload whose embedded custom rule pattern embeds a newline
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When the policy is created
	recorder := postJSON(t, router, "/security/policies", map[string]any{
		"name":         "控制字符规则",
		"custom_rules": `[{"id":1,"name":"r","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"foo\nbar"}]}]`,
	})

	// Then the request is rejected
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "控制字符") {
		t.Fatalf("error body should flag the control char: %s", recorder.Body.String())
	}
}

func TestListSecurityPolicies_ipACLDisabledHidesControlCapability(t *testing.T) {
	// Given a policy whose ACL list still holds entries but ip_acl_enabled is off
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_enabled, ip_acl_mode, ip_acl_list, enabled) VALUES ('关闭ACL', 0, 'deny', '["203.0.113.0/24"]', 1)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When the list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then the summary reports the ACL as disabled and no IP-control capability
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			HasIPControl bool `json:"has_ip_control"`
			IPACLEnabled bool `json:"ip_acl_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("list len = %d, want 1: %s", len(resp.Data), recorder.Body.String())
	}
	if resp.Data[0].HasIPControl {
		t.Fatalf("has_ip_control = true, want false when ip_acl_enabled off: %s", recorder.Body.String())
	}
	if resp.Data[0].IPACLEnabled {
		t.Fatalf("ip_acl_enabled = true, want false: %s", recorder.Body.String())
	}
}

func TestListSecurityPolicies_绕过ModeDisabledHidesControlCapability(t *testing.T) {
	// Given a legacy 绕过-mode policy whose ACL list is populated but disabled
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_enabled, ip_acl_mode, ip_acl_list, enabled) VALUES ('关闭绕过', 0, '绕过', '["203.0.113.0/24"]', 1)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When the list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then 绕过 mode must not claim IP control while disabled (mirrors emission)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			HasIPControl bool `json:"has_ip_control"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("list len = %d, want 1: %s", len(resp.Data), recorder.Body.String())
	}
	if resp.Data[0].HasIPControl {
		t.Fatalf("has_ip_control = true, want false for disabled 绕过 mode: %s", recorder.Body.String())
	}
}

func TestListSecurityPolicies_customRulesCountExcludesDisabled(t *testing.T) {
	// Given two referenced custom rules, one enabled (emittable) and one disabled。
	// 计数与发射侧同判据（customRuleEmittable）：空 conditions 的规则发射端
	// 会跳过，因此启用规则必须带可发射条件，本用例才验证「禁用不计」。
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	emittable := `[{"target":"uri","operator":"regex","pattern":"^/count$"}]`
	res1, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('启用规则', ?, 'block', 5, 1)`, emittable)
	if err != nil {
		t.Fatalf("seed enabled rule: %v", err)
	}
	id1, _ := res1.LastInsertId()
	res2, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('禁用规则', ?, 'block', 5, 0)`, emittable)
	if err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}
	id2, _ := res2.LastInsertId()
	customJSON := fmt.Sprintf("[%d,%d]", id1, id2)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules, enabled) VALUES ('规则计数', 'blocking', ?, 1)`, customJSON); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When the list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then custom_rules_count counts only the enabled rule (emission skips disabled)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			CustomRulesCount int `json:"custom_rules_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("list len = %d, want 1: %s", len(resp.Data), recorder.Body.String())
	}
	if got := resp.Data[0].CustomRulesCount; got != 1 {
		t.Fatalf("custom_rules_count = %d, want 1 (disabled rule excluded): %s", got, recorder.Body.String())
	}
}

// 阶段 4 判定口径：摘要必须同时给出「引用条目数」（含禁用）——前端 chips 与
// 后端 PolicyTypeFeatures.G3 逐字对齐的唯一依据。只给启用计数时，
// 「mode=off 且引用规则全部禁用」的边界策略在预演里少一条子策略。
func TestListSecurityPolicies_customRulesRefCountIncludesDisabled(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	emittable := `[{"target":"uri","operator":"regex","pattern":"^/ref$"}]`
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('禁用规则', ?, 'block', 5, 0)`, emittable)
	if err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}
	id, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, custom_rules, enabled) VALUES ('仅引用禁用规则', 'off', ?, 1)`,
		fmt.Sprintf("[%d]", id)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	recorder := getRequest(t, router, "/security/policies")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Mode                string `json:"mode"`
			CustomRulesCount    int    `json:"custom_rules_count"`
			CustomRulesRefCount int    `json:"custom_rules_ref_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("list len = %d, want 1: %s", len(resp.Data), recorder.Body.String())
	}
	row := resp.Data[0]
	if row.CustomRulesCount != 0 {
		t.Fatalf("custom_rules_count = %d, want 0（禁用规则不计入生效口径）: %s", row.CustomRulesCount, recorder.Body.String())
	}
	if row.CustomRulesRefCount != 1 {
		t.Fatalf("custom_rules_ref_count = %d, want 1（引用非空必须披露，含禁用条目）: %s", row.CustomRulesRefCount, recorder.Body.String())
	}
	// 与后端 G3 同一门：mode=off + 引用非空 → 阶段 4 成立。
	policy := &models.SecurityPolicy{Mode: row.Mode, CustomRules: []byte(fmt.Sprintf("[%d]", id))}
	if !models.PolicyTypeFeatures(policy).G3 {
		t.Fatalf("G3 必须为真（引用非空），摘要 ref_count=%d", row.CustomRulesRefCount)
	}
}

func TestUpdateSecurityPolicy_anomalyThresholdZeroNormalizesToFive(t *testing.T) {
	// Given 创建侧以默认阈值 5 落库的策略（创建请求不带 anomaly_threshold 时
	// CreateSecurityPolicy 的 max1(..., 5) 归一为 5）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "阈值归一策略", "mode": "blocking"})

	// When 更新请求显式传 anomaly_threshold=0（0 非合法枚举值，直接
	// 落库会让发射端 services/security.go:157 的 `AnomalyThreshold > 0` 判断
	// 跳过 SecAction id:900，CRS 回落默认阈值 5，UI 显示 0 与实际行为不符）
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"anomaly_threshold": 0,
	})

	// Then 按创建侧 max1(..., 5) 同口径归一为 5 落库，请求成功
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var threshold int
	if err := db.DB.QueryRow("SELECT anomaly_threshold FROM security_policies WHERE id=?", id).Scan(&threshold); err != nil {
		t.Fatalf("read back anomaly_threshold: %v", err)
	}
	if threshold != 5 {
		t.Fatalf("anomaly_threshold=%d, want 5 (0 归一为创建侧默认)", threshold)
	}
}

func TestUpdateSecurityPolicy_rejectsBlankIPACLMode(t *testing.T) {
	// Given a policy with IP ACL enabled in deny mode
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":           "ACL空串策略",
		"ip_acl_enabled": true,
		"ip_acl_mode":    "deny",
		"ip_acl_list":    `["203.0.113.0/24"]`,
	})

	// When 更新请求显式传空串 ip_acl_mode（空串落库后发射端
	// services/security.go 仅 allow/deny 分支产出规则，零 ACL 规则生效；而
	// SecurityPolicyHasIPControl 只看 enabled && list 非空，UI 仍宣称已启用）
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"ip_acl_mode": ""})

	// Then 与 mode/geoip_mode 同口径拒绝 400，且存量列不被触碰
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("blank ip_acl_mode must be rejected with 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, "ip_acl_mode 不能为空串") {
		t.Fatalf("blank ip_acl_mode rejection must name the field, got %s", body)
	}
	var mode string
	if err := db.DB.QueryRow("SELECT ip_acl_mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back ip_acl_mode: %v", err)
	}
	if mode != "deny" {
		t.Fatalf("rejected update must not touch ip_acl_mode, got %q", mode)
	}
}

func TestCreateSecurityPolicy_defaultsIPACLMode(t *testing.T) {
	// Given 创建请求启用 IP ACL 但省略 ip_acl_mode
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When the policy is created
	id := createTestPolicy(t, router, map[string]any{
		"name":           "ACL默认策略",
		"ip_acl_enabled": true,
		"ip_acl_list":    `["203.0.113.0/24"]`,
	})

	// Then ip_acl_mode 按 geoip_mode 同口径归一为 "deny"：启用态 ACL 绝不携带
	// 空模式落库（空模式在发射端产出零规则）
	var mode string
	if err := db.DB.QueryRow("SELECT ip_acl_mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back ip_acl_mode: %v", err)
	}
	if mode != "deny" {
		t.Fatalf("ip_acl_mode=%q, want default deny", mode)
	}
}

// seedNullColumnPolicy 写入一条多个可空列显式为 NULL 的策略（模拟带外编辑/
// 备份恢复/集群继承产生的 NULL 行），返回策略 ID。测试共用。
func seedNullColumnPolicy(t *testing.T, name string) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO security_policies
		(name, mode, description, ip_whitelist, anomaly_threshold, block_page_id, created_at, updated_by, enabled)
		VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)`, name)
	if err != nil {
		t.Fatalf("seed null-column policy: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read null-column policy id: %v", err)
	}
	return id
}

// 硬化（ListSecurityPolicies）：策略行可空列修复前原样扫入非指针字段——
// 单行 NULL 即 Scan 报错，整个策略列表对 REST/MCP 消费方 500，而生成路径
// （services/security.go scanSecurityPolicyByID）对同样 NULL 已按 COALESCE 口径
// 容忍。修复后列表 SELECT 与生成投影逐列同默认值，NULL 行照常返回。
func TestListSecurityPolicies_toleratesNullNullableColumns(t *testing.T) {
	// Given 一条 mode/description/ip_whitelist/anomaly_threshold/block_page_id/
	// created_at/updated_by/enabled 均为 NULL 的策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	seedNullColumnPolicy(t, "null-list-policy")

	// When GET /security/policies
	recorder := getRequest(t, router, "/security/policies")

	// Then 200，NULL 列按生成口径归一化（mode 'off'/阈值 5/白名单 '[]'/
	// updated_by 0）；enabled 按 schema 默认 1 呈现启用态（List 无 enabled 过滤）
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s, want 200（单行 NULL 不得拖垮整个列表）", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                            `json:"code"`
		Data []models.SecurityPolicySummary `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response %s: %v", recorder.Body.String(), err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("policies=%+v, want 1 entry", resp.Data)
	}
	p := resp.Data[0]
	if p.Mode != "off" || p.AnomalyThreshold != 5 || p.IPWhitelist != "[]" || p.UpdatedBy != 0 || !p.Enabled {
		t.Fatalf("summary=%+v, want mode=off anomaly_threshold=5 ip_whitelist=[] updated_by=0 enabled=true", p)
	}
}

// 硬化（GetSecurityPolicy）：详情读路径与列表同口径——单行 NULL 不得把
// 详情接口打成 500，归一化默认值与生成投影一致。
func TestGetSecurityPolicy_toleratesNullNullableColumns(t *testing.T) {
	// Given 一条多个可空列为 NULL 的策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := seedNullColumnPolicy(t, "null-detail-policy")

	// When GET /security/policies/:id
	recorder := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))

	// Then 200，NULL 列归一化：mode 'off'/description ''/阈值 5/白名单 '[]'/
	// block_page_id 0/created_at ''；enabled 按 schema 默认 1 呈现
	if recorder.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s, want 200（NULL 行不得 500）", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Policy securityPolicyDetail `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse detail response %s: %v", recorder.Body.String(), err)
	}
	p := resp.Data.Policy
	if p.Mode != "off" || p.Description != "" || p.AnomalyThreshold != 5 ||
		p.IPWhitelist != "[]" || p.BlockPageID != 0 || p.CreatedAt != "" || !p.Enabled {
		t.Fatalf("detail=%+v, want mode=off description='' anomaly_threshold=5 ip_whitelist=[] block_page_id=0 created_at='' enabled=true", p)
	}
}

// 2026-09-09 裁定:WAF 模式四态化——mode 新增 custom_only(CRS 不生效、仅自定义
// 规则);异常阈值新增 15 档(CRS 严重规则 +5/条,15=3 条严重命中);策略汇总的
// HasWAF 收敛为「CRS 生效」口径(custom_only 无 CRS → false,自定义规则由
// HasCustomRules 单独呈现)。
func TestCreateSecurityPolicy_acceptsCustomOnlyModeAndThreshold15(t *testing.T) {
	// Given
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	payload := map[string]any{
		"name":              "仅自定义策略",
		"mode":              "custom_only",
		"anomaly_threshold": 15,
		"custom_rules":      `[{"id":1,"name":"r1","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`,
	}

	// When
	recorder := postJSON(t, router, "/security/policies", payload)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("create custom_only policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var mode string
	var threshold int
	if err := db.DB.QueryRow(`SELECT mode, COALESCE(anomaly_threshold,0) FROM security_policies WHERE name='仅自定义策略'`).Scan(&mode, &threshold); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if mode != "custom_only" {
		t.Fatalf("mode=%q, want custom_only", mode)
	}
	// 15 档必须真实落库：归一逻辑（0→5）若误伤 15，阈值会静默退回默认。
	if threshold != 15 {
		t.Fatalf("anomaly_threshold=%d, want 15", threshold)
	}
}

func TestSecurityPolicySummary_customOnlyHasWAFFalse(t *testing.T) {
	// Given:custom_only 与 blocking 各一策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	customRules := `[{"id":1,"name":"r1","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`
	postJSON(t, router, "/security/policies", map[string]any{"name": "仅自定义", "mode": "custom_only", "custom_rules": customRules})
	postJSON(t, router, "/security/policies", map[string]any{"name": "拦截", "mode": "blocking"})

	// When
	recorder := getRequest(t, router, "/security/policies")

	// Then
	var resp struct {
		Data []models.SecurityPolicySummary `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	byName := map[string]models.SecurityPolicySummary{}
	for _, p := range resp.Data {
		byName[p.Name] = p
	}
	if p := byName["仅自定义"]; p.HasWAF || !p.HasCustomRules {
		t.Fatalf("custom_only summary: HasWAF=%v HasCustomRules=%v, want false/true (HasWAF=CRS 生效口径)", p.HasWAF, p.HasCustomRules)
	}
	if p := byName["拦截"]; !p.HasWAF {
		t.Fatalf("blocking summary: HasWAF=%v, want true", p.HasWAF)
	}
}

func TestCreateSecurityPolicy_rejectsUnknownMode(t *testing.T) {
	// Given
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "坏模式", "mode": "custom"})

	// Then
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown mode status=%d, want 400", recorder.Code)
	}
}

// (2026-09-10 审计):IP ACL allow 模式+空生效名单——发射端 len>0 门静默跳过
// (「其余一律拒绝」实际全放行 fail-open)。UI 有守卫,API/MCP 直写可绕;按
// 同型先例在写入侧 400(与 UI 文案同口径)。
// 空白名单保存已放开（2026-11 用户裁定）：空 allow 集可保存，运行时渲染层
// 恒拒（fail-closed）语义不变。
func TestCreateSecurityPolicy_acceptsAllowModeWithEmptyACLList(t *testing.T) {
	// Given
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When:启用 ACL + allow 模式 + 空 list(无内联无引用)
	recorder := postJSON(t, router, "/security/policies", map[string]any{
		"name": "空白名单", "policy_type": "stage1", "mode": "blocking", "ip_acl_enabled": true, "ip_acl_mode": "allow", "ip_acl_list": `[]`,
	})

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("allow+空名单 status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

// (2026-09-10 审计):HasCustomRules 需带模式门——off=全关(2026-09-09 四态化)
// 后,off 策略的自定义规则不发射,能力列不得宣称「按规则内动作执行」。
func TestSecurityPolicySummary_offModeHasCustomRulesFalse(t *testing.T) {
	// Given
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	customRules := `[{"id":1,"name":"r1","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`
	postJSON(t, router, "/security/policies", map[string]any{"name": "off带规则", "mode": "off", "custom_rules": customRules})

	// When
	recorder := getRequest(t, router, "/security/policies")

	// Then
	var resp struct {
		Data []models.SecurityPolicySummary `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range resp.Data {
		if p.Name != "off带规则" {
			continue
		}
		found = true
		if p.HasCustomRules {
			t.Fatalf("off 策略 HasCustomRules=true, want false(模式门)")
		}
	}
	// 行缺失时上面的循环恒不命中——必须先证明该行在列表里。
	if !found {
		t.Fatal("列表中缺少 off带规则（断言未被实际校验）")
	}
}

// UpdateSecurityPolicy 限流门用请求裸值而非有效值回落
// ——存量 rps=10 的策略发 {rate_limit_enabled:true}(部分重启用)时,
// derefInt(req.RateLimitRPS)=0 → 400 误报「rps 必须 ≥1」;显式 {rate_limit_rps:0}
// 时门短路 → 落库 enabled=1+rps=0 → UI 宣称限流启用实际零强制。
// 详情/列表 DTO 必须携带爬虫豁免两列。修复前两处均缺席 → 前端
// 编辑策略时读不到（按 false/默认三引擎渲染），保存时恒回写 false，任何
// 「重命名/改描述」都会静默关闭爬虫豁免（安全行为变更）。
func TestSecurityPolicyDTO_crawlerExemptionRoundTrip(t *testing.T) {
	// Given 一条开启爬虫豁免（引擎限 googlebot）的策略
	setupSecurityPolicyTestDB(t)
	// 启用态地域条目需要已装载的 IP 库（ValidateGeoIPCountries 门）
	services.SetIP2RegionLiveProvincesForTest([]string{"海外", "广东省"})
	t.Cleanup(func() { services.SetIP2RegionLiveProvincesForTest(nil) })
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":       "爬虫豁免策略",
		"geoip_mode": "deny",
		// 启用态空名单 400 → 给一条真实地域条目
		"geoip_countries":       `["海外"]`,
		"geoip_crawler_exempt":  true,
		"geoip_crawler_engines": `["googlebot"]`,
	})

	// When GET 详情
	recorder := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var detailResp struct {
		Data struct {
			Policy securityPolicyDetail `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &detailResp); err != nil {
		t.Fatalf("parse detail %s: %v", recorder.Body.String(), err)
	}
	detail := detailResp.Data.Policy
	// Then 详情两列与库值一致（不是零值）
	if !detail.GeoIPCrawlerExempt {
		t.Fatalf("详情 geoip_crawler_exempt=false，want true（缺口径=编辑即静默关闭豁免）")
	}
	if engines := decodeStringArray(t, detail.GeoIPCrawlerEngines); len(engines) != 1 || engines[0] != "googlebot" {
		t.Fatalf("详情 geoip_crawler_engines=%q，want [\"googlebot\"]", detail.GeoIPCrawlerEngines)
	}

	// When GET 列表
	recorder = getRequest(t, router, "/security/policies")
	var listResp struct {
		Data []models.SecurityPolicySummary `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("parse list %s: %v", recorder.Body.String(), err)
	}
	var summary *models.SecurityPolicySummary
	for i := range listResp.Data {
		if listResp.Data[i].ID == id {
			summary = &listResp.Data[i]
		}
	}
	if summary == nil {
		t.Fatalf("list 缺策略 id=%d", id)
	}
	// Then 列表摘要同值（列表编辑入口按摘要渲染回写）
	if !summary.GeoIPCrawlerExempt {
		t.Fatalf("摘要 geoip_crawler_exempt=false，want true")
	}
	if engines := decodeStringArray(t, summary.GeoIPCrawlerEngines); len(engines) != 1 || engines[0] != "googlebot" {
		t.Fatalf("摘要 geoip_crawler_engines=%q，want [\"googlebot\"]", summary.GeoIPCrawlerEngines)
	}

	// When 模拟前端「读详情 → 原值回写」（重命名场景）
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"name":                  "爬虫豁免策略（改名）",
		"geoip_crawler_exempt":  detail.GeoIPCrawlerExempt,
		"geoip_crawler_engines": detail.GeoIPCrawlerEngines,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	// Then 豁免仍在（round-trip 不丢配置）
	var exempt bool
	var enginesRaw string
	if err := db.DB.QueryRow(`SELECT COALESCE(geoip_crawler_exempt,0), COALESCE(geoip_crawler_engines,'') FROM security_policies WHERE id=?`, id).Scan(&exempt, &enginesRaw); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if !exempt {
		t.Fatalf("round-trip 后 geoip_crawler_exempt=0，want 1（重命名不得关闭豁免）")
	}
	if engines := decodeStringArray(t, enginesRaw); len(engines) != 1 || engines[0] != "googlebot" {
		t.Fatalf("round-trip 后 geoip_crawler_engines=%q，want [\"googlebot\"]", enginesRaw)
	}
}

func decodeStringArray(t *testing.T, raw string) []string {
	t.Helper()
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("parse string array %q: %v", raw, err)
	}
	return list
}

// 内置威胁名单禁令的「请求值 ?? 存量值」合并判定：只改 ip_acl_mode 的更新
// 必须看到存量 crs_excluded_rules 里 scope=list 的内置名单引用——否则
// 「先存内置名单、后翻 allow 模式」可绕过禁令（白名单模式下内置黑名单被
// 当成放行集合，语义反转）。
func TestUpdateSecurityPolicy_builtinListInStoredCRSExclusionsRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	var builtinID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&builtinID); err != nil {
		t.Fatalf("read builtin list id: %v", err)
	}
	// 存量行直接落库（创建门会拒绝该组合，历史行是本次判定的对象）。
	excluded := fmt.Sprintf(`[{"target":"942100","scope":"list","listRefs":[%d]}]`, builtinID)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_enabled, ip_acl_mode, crs_excluded_rules) VALUES ('legacy-builtin-crs', 'blocking', 0, 'deny', ?)`, excluded)
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	id, _ := res.LastInsertId()

	router := newSecurityRouter(t)
	rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"ip_acl_mode": "allow"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400（存量 CRS 排除引用内置名单时不得翻 allow）body=%s", rec.Code, rec.Body.String())
	}
	var mode string
	if err := db.DB.QueryRow(`SELECT ip_acl_mode FROM security_policies WHERE id=?`, id).Scan(&mode); err != nil {
		t.Fatalf("read back mode: %v", err)
	}
	if mode != "deny" {
		t.Fatalf("ip_acl_mode=%q, want 未变更的 deny", mode)
	}
}

// 缺省 policy_type 的推断路径（API/MCP 省略类型）与显式类型路径同口径归一
// 拦截状态码：无拦截页的 deny 恒 403，落 404 会让详情/列表宣称一个不生效的值。
func TestCreateSecurityPolicy_inferredTypeNormalizesBlockStatusCode(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// 空内容 → 推断 stage3；无 block_page_id + 显式 404。
	id := createTestPolicy(t, router, map[string]any{
		"name":              "推断类型状态码",
		"block_status_code": 404,
	})
	var code int
	if err := db.DB.QueryRow(`SELECT COALESCE(block_status_code,0) FROM security_policies WHERE id=?`, id).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("block_status_code=%d, want 0（无页策略的 deny 恒 403，写侧必须归一）", code)
	}
}

// 同一载荷在创建/更新两端必须得到相同结果码：归一先于校验是两端的共同契约。
// 旧实现 Create 先校验 CRS 再按类型归零（阶段外字段本应被丢弃却报 400），
// Update 先校验 IP 列表再归一空串（" " 直接 json.Unmarshal 失败 400）。
func TestSecurityPolicy_normalizeBeforeValidateParity(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// 显式 stage1 + 阶段外 CRS 载荷：Create 必须先按类型归零再校验（旧实现
	// 先校验 → 400「规则 ID 不存在」，而该字段本应被丢弃）。
	// Update 侧对「显式类型 + 阶段外字段」走矛盾载荷显式拒绝（400）——两条
	// 写路径的既定分工：Create 归零、Update 拒绝二义，故此处不要求同码。
	id := createTestPolicy(t, router, map[string]any{
		"name":            "阶段一-忽略CRS",
		"policy_type":     "stage1",
		"crs_rule_groups": `["999999"]`,
	})
	var storedGroups string
	if err := db.DB.QueryRow(`SELECT COALESCE(crs_rule_groups,'') FROM security_policies WHERE id=?`, id).Scan(&storedGroups); err != nil {
		t.Fatal(err)
	}
	if storedGroups != "[]" {
		t.Fatalf("crs_rule_groups=%q, want []（阶段外字段必须归零后落库）", storedGroups)
	}

	// 空白 IP 列表串：两端都必须先归一为 "[]" 再校验。
	createBlank := postJSON(t, router, "/security/policies", map[string]any{
		"name":        "空白列表",
		"ip_acl_list": " ",
	})
	if createBlank.Code != http.StatusOK {
		t.Fatalf("create 空白 ip_acl_list status=%d body=%s, want 200", createBlank.Code, createBlank.Body.String())
	}
	updateBlank := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"ip_acl_list": " ",
	})
	if updateBlank.Code != http.StatusOK {
		t.Fatalf("update 空白 ip_acl_list status=%d body=%s, want 200（归一先于校验）", updateBlank.Code, updateBlank.Body.String())
	}
}

// 阶段 2 CC 防护（2026-11-12）：详情 DTO 必须逐列回传 human_*/cc_*——前端编辑
// 依赖该响应回填；缺席会让「保存」把存量配置覆写为默认值（静默丢配置）。
func TestGetSecurityPolicy_returnsHumanVerifyAndCCFields(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)
	create := map[string]any{
		"name": "人机验证策略", "mode": "off", "policy_type": "stage2",
		"human_verify_mode": "auto", "human_verify_type": "js", "human_verify_ttl": 45,
		"human_exempt_paths": `["/health/"]`,
		"cc_detect_enabled":  true, "cc_rps_limit": 55, "cc_rps_window": 15,
		"cc_4xx_ratio": 65, "cc_session_anomaly": true, "cc_session_ua_threshold": 7,
	}
	id := createTestPolicy(t, router, create)

	recorder := getRequest(t, router, fmt.Sprintf("/security/policies/%d", id))
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Policy map[string]json.RawMessage `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse detail: %v", err)
	}
	strWant := map[string]string{
		"human_verify_mode":  "auto",
		"human_verify_type":  "js",
		"human_exempt_paths": `["/health/"]`,
	}
	for field, expected := range strWant {
		var got string
		if err := json.Unmarshal(resp.Data.Policy[field], &got); err != nil {
			t.Fatalf("policy.%s = %s, want string: %v", field, resp.Data.Policy[field], err)
		}
		if got != expected {
			t.Fatalf("policy.%s = %q, want %q", field, got, expected)
		}
	}
	intWant := map[string]int{
		"human_verify_ttl": 45, "cc_rps_limit": 55,
		"cc_rps_window": 15, "cc_4xx_ratio": 65, "cc_session_ua_threshold": 7,
	}
	for field, expected := range intWant {
		var got int
		if err := json.Unmarshal(resp.Data.Policy[field], &got); err != nil {
			t.Fatalf("policy.%s = %s, want int: %v", field, resp.Data.Policy[field], err)
		}
		if got != expected {
			t.Fatalf("policy.%s = %d, want %d", field, got, expected)
		}
	}
	for field, expected := range map[string]bool{"cc_detect_enabled": true, "cc_session_anomaly": true} {
		var got bool
		if err := json.Unmarshal(resp.Data.Policy[field], &got); err != nil {
			t.Fatalf("policy.%s = %s, want bool: %v", field, resp.Data.Policy[field], err)
		}
		if got != expected {
			t.Fatalf("policy.%s = %v, want %v", field, got, expected)
		}
	}
}

// 阶段外能力归零（五阶段矩阵）：非 stage3 类型必须把人机验证/CC 字段清零，
// 否则类型切换后旧配置残留在别的阶段里（列表/预览宣称存在但永不发射）。
func TestUpdateSecurityPolicy_zeroesHumanFieldsOutsideStage3(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name": "人机→WAF", "mode": "off", "policy_type": "stage2",
		"human_verify_mode": "force", "human_exempt_paths": `["/keep/"]`,
	})

	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"name": "人机→WAF", "mode": "blocking", "policy_type": "stage3",
		"human_verify_mode": "force",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var mode, paths string
	var cc bool
	if err := db.DB.QueryRow(`SELECT COALESCE(human_verify_mode,''), COALESCE(human_exempt_paths,''), COALESCE(cc_detect_enabled,0) FROM security_policies WHERE id=?`, id).Scan(&mode, &paths, &cc); err != nil {
		t.Fatal(err)
	}
	if mode != "off" || paths != "[]" || cc {
		t.Fatalf("stage3(WAF) 残留人机字段：mode=%q paths=%q cc=%v（应 off/[]/false）", mode, paths, cc)
	}

	// 双向：从 stage4 切回 stage3 后人机字段可正常写入
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"name": "人机→WAF", "mode": "off", "policy_type": "stage2", "human_verify_mode": "auto",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update back status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(human_verify_mode,'') FROM security_policies WHERE id=?`, id).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "auto" {
		t.Fatalf("切回 stage2(CC) 后人机模式=%q，应 auto", mode)
	}
}

// 策略级拦截响应方式（auto|html|json）：创建落库、非法值归一、更新可改。
// 拦截页恒为双档（HTML+JSON），实际返回由本字段决定——字段静默丢弃会让
// 用户在策略里选的 JSON 永不生效。
func TestSecurityPolicy_blockResponseModeRoundTrip(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	id := createTestPolicy(t, router, map[string]any{
		"name":                "响应方式-json",
		"policy_type":         "stage1",
		"block_page_id":       1,
		"block_response_mode": "json",
	})
	var mode string
	if err := db.DB.QueryRow("SELECT block_response_mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back block_response_mode: %v", err)
	}
	if mode != "json" {
		t.Fatalf("block_response_mode=%q, want json", mode)
	}

	invalidID := createTestPolicy(t, router, map[string]any{
		"name":                "响应方式-非法",
		"policy_type":         "stage1",
		"block_page_id":       1,
		"block_response_mode": "xml",
	})
	if err := db.DB.QueryRow("SELECT block_response_mode FROM security_policies WHERE id=?", invalidID).Scan(&mode); err != nil {
		t.Fatalf("read back invalid mode: %v", err)
	}
	if mode != "auto" {
		t.Fatalf("非法响应方式应归一 auto，got %q", mode)
	}

	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"block_response_mode": "html"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update mode status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow("SELECT block_response_mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back updated mode: %v", err)
	}
	if mode != "html" {
		t.Fatalf("更新后 block_response_mode=%q, want html", mode)
	}
}
