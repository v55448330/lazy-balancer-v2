package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestValidateUpdateConfigRequestNormalizesACMEEmail(t *testing.T) {
	email := "  ops@example.com  "
	req := models.UpdateConfigRequest{ACMEEmail: &email}
	if err := validateUpdateConfigRequest(&req); err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
	if got := *req.ACMEEmail; got != "ops@example.com" {
		t.Fatalf("normalized email=%q", got)
	}
}

func TestValidateUpdateConfigRequestRejectsInvalidACMEEmail(t *testing.T) {
	for _, email := range []string{
		"admin@",
		"Admin <admin@example.com>",
		strings.Repeat("a", 250) + "@example.com",
	} {
		req := models.UpdateConfigRequest{ACMEEmail: &email}
		if err := validateUpdateConfigRequest(&req); err == nil {
			t.Errorf("invalid email %q accepted", email)
		}
	}
}

func TestValidateV2BackupRuntimeSettingsValidatesACMEEmail(t *testing.T) {
	valid := map[string]any{"acme_email": "  ops@example.com  "}
	if err := validateV2BackupRuntimeSettings(valid, nil); err != nil {
		t.Fatalf("valid backup email rejected: %v", err)
	}
	if got := valid["acme_email"]; got != "ops@example.com" {
		t.Fatalf("backup normalized email=%v", got)
	}
	for _, email := range []any{"admin@", 42, strings.Repeat("a", 250) + "@example.com"} {
		config := map[string]any{"acme_email": email}
		if err := validateV2BackupRuntimeSettings(config, nil); err == nil {
			t.Errorf("invalid backup email %v accepted", email)
		}
	}
}

func TestValidateUpdateConfigRequestAllowsEmptyACMEEmail(t *testing.T) {
	email := "   "
	req := models.UpdateConfigRequest{ACMEEmail: &email}
	if err := validateUpdateConfigRequest(&req); err != nil {
		t.Fatalf("empty email must remain available for clearing the setting: %v", err)
	}
	if *req.ACMEEmail != "" {
		t.Fatalf("empty email normalized to %q", *req.ACMEEmail)
	}
}
