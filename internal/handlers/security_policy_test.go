package handlers

import (
	"bytes"
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
		"crs_rule_groups":    `["REQUEST-942"]`,
		"crs_excluded_rules": `["942100","942110"]`,
		"custom_rules":       `[{"name":"r1"}]`,
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
		"crs_rule_groups":    `["REQUEST-942"]`,
		"crs_excluded_rules": `["942100","942110"]`,
		"custom_rules":       `[{"name":"r1"}]`,
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
		"anomaly_threshold":  9,
		"ip_acl_mode":        "deny",
		"ip_acl_list":        `["203.0.113.0/24","2001:db8::/32"]`,
		"ip_acl_enabled":     true,
		"ip_whitelist":       `["192.0.2.1"]`,
		"ip_blacklist":       `["198.51.100.0/24","203.0.113.5"]`,
		"rate_limit_enabled": true,
		"rate_limit_rps":     50,
		"rate_limit_burst":   10,
		"crs_excluded_rules": `["942100","942110"]`,
		"custom_rules":       `[{"name":"r1"}]`,
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
	if got.AnomalyThreshold != 9 || got.IPACLMode != "deny" || got.RateLimitRPS != 50 || got.RateLimitBurst != 10 {
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

func TestSecurityPolicy_rateLimitResponseRoundTrips(t *testing.T) {
	// Given a policy created with the block_page rate-limit response
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "回读验证", "mode": "blocking", "rate_limit_enabled": true, "rate_limit_rps": 10, "rate_limit_burst": 5, "rate_limit_response": "block_page", "enabled": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	// When the detail is fetched
	var created struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("parse create response: %v", err)
	}
	detail := httptest.NewRecorder()
	router.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/security/policies/"+itoa(created.Data.ID), nil))

	// Then rate_limit_response round-trips instead of silently reverting
	var resp struct {
		Data struct {
			Policy struct {
				RateLimitResponse string `json:"rate_limit_response"`
			} `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse detail: %v", err)
	}
	if resp.Data.Policy.RateLimitResponse != "block_page" {
		t.Fatalf("rate_limit_response = %q, want block_page (body: %s)", resp.Data.Policy.RateLimitResponse, detail.Body.String())
	}
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
