package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestBuildCorazaDirectives_allowEmptyEmitsDenyAll(t *testing.T) {
	p := &models.SecurityPolicy{
		Name: "allow-empty", Mode: "blocking", AnomalyThreshold: 5,
		IPACLEnabled: true, IPACLMode: "allow", IPACLList: "[]",
	}
	directives, err := BuildCorazaDirectives(p, nil, "", false, 0, "lb_allow_empty")
	if err != nil {
		t.Fatalf("allow empty must render fail-closed deny-all, got %v", err)
	}
	if !strings.Contains(directives, "!@ipListFast") || !strings.Contains(directives, "id:2,") {
		t.Fatalf("allow empty must emit negated ipListFast deny rule:\n%s", directives)
	}
}

func TestBuildIPPrecheckDirectives_allowEmptyEmitsDenyAll(t *testing.T) {
	p := &models.SecurityPolicy{
		Name: "allow-empty", Mode: "blocking", AnomalyThreshold: 5,
		IPACLEnabled: true, IPACLMode: "allow", IPACLList: "[]",
	}
	directives, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, 0, "lb_allow_empty")
	if err != nil {
		t.Fatalf("precheck allow empty must render fail-closed deny-all, got %v", err)
	}
	if !strings.Contains(directives, "id:7,") || !strings.Contains(directives, "@rx .*") {
		t.Fatalf("precheck allow empty must emit unconditional deny rule:\n%s", directives)
	}
}
