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

func TestCreateSecurityPolicy_persistsAllColumns(t *testing.T) {
	// Given a fresh database and a full policy payload
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	payload := map[string]any{
		"name":               "全列策略",
		"description":        "覆盖全部列",
		"mode":               "blocking",
		"anomaly_threshold":  10,
		"ip_acl_mode":        "deny",
		"ip_acl_list":        `["203.0.113.0/24"]`,
		"ip_acl_enabled":     true,
		"rate_limit_enabled": true,
		"rate_limit_rps":     50,
		"rate_limit_burst":   10,
		"crs_excluded_rules": `["942100"]`,
		"block_page_id":      1,
		"enabled":            true,
	}

	// When the policy is created
	recorder := postJSON(t, router, "/security/policies", payload)

	// Then the request succeeds and every column round-trips
	if recorder.Code != http.StatusOK {
		t.Fatalf("create policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var (
		aclMode, aclList, whitelist, blacklist, excluded string
		aclEnabled                                       bool
		blockPageID                                      int
	)
	if err := db.DB.QueryRow(`SELECT ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_whitelist, ip_blacklist, crs_excluded_rules, block_page_id FROM security_policies WHERE name='全列策略'`).
		Scan(&aclMode, &aclList, &aclEnabled, &whitelist, &blacklist, &excluded, &blockPageID); err != nil {
		t.Fatalf("read back policy: %v", err)
	}
	if aclMode != "deny" || !aclEnabled {
		t.Fatalf("ip acl columns = (%q,%v), want (deny,true)", aclMode, aclEnabled)
	}
	if whitelist != `[]` {
		t.Fatalf("ip_whitelist = %q, want [] default", whitelist)
	}
	if blacklist != `[]` {
		t.Fatalf("ip_blacklist = %q, want [] default", blacklist)
	}
	if excluded != `["942100"]` {
		t.Fatalf("crs_excluded_rules = %q", excluded)
	}
	if blockPageID != 1 {
		t.Fatalf("block_page_id = %d, want 1", blockPageID)
	}
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

var _ = models.APIResponse{}

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
	// Given a policy whose array columns are populated
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":               "详情策略",
		"crs_rule_groups":    `["42"]`,
		"crs_excluded_rules": `["942100","942110"]`,
		"custom_rules":       `[{"id":1,"name":"r1","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`,
		"ip_whitelist":       `["192.0.2.0/24"]`,
		"ip_blacklist":       `["198.51.100.7"]`,
	})

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
	// Given a policy created with whitelist and blacklist entries
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{
		"name":         "名单策略",
		"ip_whitelist": `["192.0.2.0/24","2001:db8::1"]`,
		"ip_blacklist": `["198.51.100.7"]`,
	})
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
	// Given a policy populated across the extended summary columns
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	createTestPolicy(t, router, map[string]any{
		"name":               "汇总策略",
		"mode":               "blocking",
		"anomaly_threshold":  5,
		"ip_acl_mode":        "deny",
		"ip_acl_list":        `["203.0.113.0/24","2001:db8::/32"]`,
		"ip_acl_enabled":     true,
		"ip_whitelist":       `["192.0.2.1"]`,
		"ip_blacklist":       `["198.51.100.0/24","203.0.113.5"]`,
		"rate_limit_enabled": true,
		"rate_limit_rps":     50,
		"rate_limit_burst":   10,
		"crs_excluded_rules": `["942100","942110"]`,
		"custom_rules":       `[{"id":1,"name":"r1","enabled":true,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`,
		"enabled":            true,
	})

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
			RateLimitRPS     int    `json:"rate_limit_rps"`
			RateLimitBurst   int    `json:"rate_limit_burst"`
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
	if got.AnomalyThreshold != 5 || got.IPACLMode != "deny" || got.RateLimitRPS != 50 || got.RateLimitBurst != 10 {
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
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": `["41","33"]`})
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRow("SELECT crs_rule_groups FROM security_policies WHERE id=?", id).Scan(&groups); err != nil {
		t.Fatalf("read back groups: %v", err)
	}
	if groups != `["41","33"]` {
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

func TestListSecurityPolicies_bypassModeDisabledHidesControlCapability(t *testing.T) {
	// Given a legacy bypass-mode policy whose ACL list is populated but disabled
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, ip_acl_enabled, ip_acl_mode, ip_acl_list, enabled) VALUES ('关闭bypass', 0, 'bypass', '["203.0.113.0/24"]', 1)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When the list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then bypass mode must not claim IP control while disabled (mirrors emission)
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
		t.Fatalf("has_ip_control = true, want false for disabled bypass mode: %s", recorder.Body.String())
	}
}

func TestListSecurityPolicies_customRulesCountExcludesDisabled(t *testing.T) {
	// Given two referenced custom rules, one enabled and one disabled
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res1, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('启用规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed enabled rule: %v", err)
	}
	id1, _ := res1.LastInsertId()
	res2, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('禁用规则', '[]', 'block', 5, 0)`)
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

func TestUpdateSecurityPolicy_anomalyThresholdZeroNormalizesToFive(t *testing.T) {
	// Given 创建侧以默认阈值 5 落库的策略（创建请求不带 anomaly_threshold 时
	// CreateSecurityPolicy 的 max1(..., 5) 归一为 5）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "阈值归一策略", "mode": "blocking"})

	// When 更新请求显式传 anomaly_threshold=0（R44 F3：0 非合法枚举值，直接
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

	// When 更新请求显式传空串 ip_acl_mode（R50 B-#1：空串落库后发射端
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
	// 空模式落库（空模式在发射端产出零规则，R50 B-#1）
	var mode string
	if err := db.DB.QueryRow("SELECT ip_acl_mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read back ip_acl_mode: %v", err)
	}
	if mode != "deny" {
		t.Fatalf("ip_acl_mode=%q, want default deny", mode)
	}
}

// seedNullColumnPolicy 写入一条多个可空列显式为 NULL 的策略（模拟带外编辑/
// 备份恢复/集群继承产生的 NULL 行），返回策略 ID。I-2/I-3 测试共用。
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

// I-2 硬化（ListSecurityPolicies）：策略行可空列修复前原样扫入非指针字段——
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

// I-2 硬化（GetSecurityPolicy）：详情读路径与列表同口径——单行 NULL 不得把
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
