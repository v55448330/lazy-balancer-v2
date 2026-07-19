package handlers

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestPlanConfigChangesUnchanged(t *testing.T) {
	logLevel := "info"
	req := models.UpdateConfigRequest{LogLevel: &logLevel, Source: "basic"}
	old := configSnapshot{LogLevel: "info"}

	plan := planConfigChanges(req, old)
	if plan.Changed {
		t.Fatalf("plan.Changed = true, want false; changes = %#v", plan.SectionChanges)
	}
	if plan.Section != "基础设置" {
		t.Fatalf("plan.Section = %q, want 基础设置", plan.Section)
	}
}

func TestPlanConfigChangesGroupsChangedFields(t *testing.T) {
	logLevel := "debug"
	req := models.UpdateConfigRequest{
		LogLevel: &logLevel,
		Source:   "basic",
	}
	old := configSnapshot{LogLevel: "info"}

	plan := planConfigChanges(req, old)
	if !plan.Changed {
		t.Fatal("plan.Changed = false, want true")
	}
	if got := len(plan.SectionChanges["基础设置"]); got != 1 {
		t.Fatalf("basic changes = %d, want 1", got)
	}
}

func TestPlanConfigChangesEqualDNSCredentials(t *testing.T) {
	credentials := "id,token"
	req := models.UpdateConfigRequest{DNSCredentials: &credentials, Source: "acme"}
	old := configSnapshot{DNSCredentials: credentials}

	plan := planConfigChanges(req, old)
	if plan.Changed {
		t.Fatalf("equal DNS credentials marked changed: %#v", plan.SectionChanges)
	}
}

func TestPlanConfigChangesIncludesJWTExpire(t *testing.T) {
	minutes := 30
	req := models.UpdateConfigRequest{JWTExpireMinutes: &minutes, Source: "basic"}
	old := configSnapshot{JWTExpireMinutes: 20}
	plan := planConfigChanges(req, old)
	if !plan.Changed || len(plan.SectionChanges["基础设置"]) != 1 {
		t.Fatalf("JWT expiry change not planned: %#v", plan)
	}
}
