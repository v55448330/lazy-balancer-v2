package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func readRateLimitResponse(t *testing.T, id int) string {
	t.Helper()
	var response string
	if err := db.DB.QueryRow("SELECT rate_limit_response FROM security_policies WHERE id=?", id).Scan(&response); err != nil {
		t.Fatalf("read rate_limit_response: %v", err)
	}
	return response
}

func TestCreateSecurityPolicy_rateLimitResponse(t *testing.T) {
	// Given a fresh database
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When a policy is created with block_page response, Then it persists
	id := createTestPolicy(t, router, map[string]any{
		"name":                "限流拦截页",
		"rate_limit_enabled":  true,
		"rate_limit_rps":      100,
		"rate_limit_response": "block_page",
	})
	if got := readRateLimitResponse(t, id); got != "block_page" {
		t.Fatalf("rate_limit_response = %q, want block_page", got)
	}

	// When a policy is created without the field, Then the 429 default persists
	defaultID := createTestPolicy(t, router, map[string]any{"name": "限流默认"})
	if got := readRateLimitResponse(t, defaultID); got != "429" {
		t.Fatalf("default rate_limit_response = %q, want 429", got)
	}

	// When the field is invalid, Then the request is rejected
	recorder := postJSON(t, router, "/security/policies", map[string]any{
		"name":                "限流非法",
		"rate_limit_response": "redirect",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateSecurityPolicy_rateLimitResponse(t *testing.T) {
	// Given an existing policy with the default response
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "限流更新"})

	// When the response is updated to block_page, Then it persists
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"rate_limit_response": "block_page",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := readRateLimitResponse(t, id); got != "block_page" {
		t.Fatalf("rate_limit_response = %q, want block_page", got)
	}

	// When the response is invalid, Then the request is rejected and the stored value is untouched
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"rate_limit_response": "teapot",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("update status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if got := readRateLimitResponse(t, id); got != "block_page" {
		t.Fatalf("rate_limit_response = %q after rejected update, want block_page", got)
	}
}

func TestSecurityPolicy_bypassACLMode(t *testing.T) {
	// Given a fresh database
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	// When a policy is created with bypass mode, Then it persists
	id := createTestPolicy(t, router, map[string]any{
		"name":           "绕过策略",
		"ip_acl_mode":    "bypass",
		"ip_acl_list":    `["203.0.113.0/24"]`,
		"ip_acl_enabled": true,
	})
	var mode string
	if err := db.DB.QueryRow("SELECT ip_acl_mode FROM security_policies WHERE id=?", id).Scan(&mode); err != nil {
		t.Fatalf("read ip_acl_mode: %v", err)
	}
	if mode != "bypass" {
		t.Fatalf("ip_acl_mode = %q, want bypass", mode)
	}

	// When the mode is updated to bypass, Then it persists
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"ip_acl_mode": "bypass",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("update bypass status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	// When an invalid mode is sent to create or update, Then both are rejected
	recorder = postJSON(t, router, "/security/policies", map[string]any{
		"name":        "非法模式",
		"ip_acl_mode": "bogus",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create invalid mode status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"ip_acl_mode": "bogus",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("update invalid mode status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}
