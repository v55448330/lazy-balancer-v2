package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// TestCreateSecurityPolicy_geoipColumnsRoundTrip verifies that geoip_countries
// and geoip_mode are persisted on create and returned by GetSecurityPolicy.
func TestCreateSecurityPolicy_geoipColumnsRoundTrip(t *testing.T) {
	// Given a fresh database and a policy payload carrying geoip fields
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	payload := map[string]any{
		"name":            "地理围栏策略",
		"mode":            "off",
		"geoip_countries": `["海外","广东省"]`,
		"geoip_mode":      "deny",
	}
	id := createTestPolicy(t, router, payload)

	// When the policy is read back
	recorder := getRequest(t, router, "/security/policies/"+strconv.Itoa(id))

	// Then the detail carries the geoip fields unchanged
	if recorder.Code != http.StatusOK {
		t.Fatalf("get policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Policy map[string]any `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse get response: %v", err)
	}
	if got := resp.Data.Policy["geoip_countries"]; got != `["海外","广东省"]` {
		t.Fatalf("geoip_countries=%q, want %q", got, `["海外","广东省"]`)
	}
	if got := resp.Data.Policy["geoip_mode"]; got != "deny" {
		t.Fatalf("geoip_mode=%q, want deny", got)
	}
}

// TestCreateSecurityPolicy_geoipDefaults verifies that omitted geoip fields
// default to an empty list and deny mode.
func TestCreateSecurityPolicy_geoipDefaults(t *testing.T) {
	// Given a fresh database and a policy payload without geoip fields
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "无地理策略"})

	// When the policy is read back
	recorder := getRequest(t, router, "/security/policies/"+strconv.Itoa(id))

	// Then defaults are in place
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Policy map[string]any `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse get response: %v", err)
	}
	if got := resp.Data.Policy["geoip_countries"]; got != "[]" {
		t.Fatalf("geoip_countries=%q, want []", got)
	}
	if got := resp.Data.Policy["geoip_mode"]; got != "deny" {
		t.Fatalf("geoip_mode=%q, want deny", got)
	}
}

// TestUpdateSecurityPolicy_geoipMode_validatesEnum verifies that an invalid
// geoip_mode is rejected on update.
func TestUpdateSecurityPolicy_geoipMode_validatesEnum(t *testing.T) {
	// Given a fresh database with one policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "待校验"})

	// When an update carries an invalid geoip_mode
	recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), map[string]any{
		"geoip_mode": "ban_all",
	})

	// Then it is rejected with 400
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("update status=%d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "geoip_mode") {
		t.Fatalf("body=%s, want geoip_mode error", recorder.Body.String())
	}
}

// TestListSecurityPolicies_geoipSummary verifies the summary list exposes the
// geoip fields.
func TestListSecurityPolicies_geoipSummary(t *testing.T) {
	// Given a fresh database with a geoip policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	createTestPolicy(t, router, map[string]any{
		"name":            "摘要地理",
		"geoip_countries": `["海外"]`,
		"geoip_mode":      "allow",
	})

	// When the list is fetched
	recorder := getRequest(t, router, "/security/policies")

	// Then the summary row carries the geoip fields
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int              `json:"code"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) == 0 {
		t.Fatal("list is empty")
	}
	if got := resp.Data[0]["geoip_countries"]; got != `["海外"]` {
		t.Fatalf("summary geoip_countries=%q, want [\"海外\"]", got)
	}
	if got := resp.Data[0]["geoip_mode"]; got != "allow" {
		t.Fatalf("summary geoip_mode=%q, want allow", got)
	}
}
