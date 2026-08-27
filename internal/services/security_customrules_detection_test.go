package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestCustomRuleBlockActionSurvivesDetectionMode(t *testing.T) {
	// Given a detection-mode policy with a blocking custom rule
	policy := &models.SecurityPolicy{
		Mode: "detection",
		CustomRules: json.RawMessage(`[{"id":21,"name":"硬拦截","enabled":true,"action":"block","score":5,"conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/hard-block"}]}]`),
	}

	// When directives are built
	directives := BuildCorazaDirectives(policy, nil)

	// Then the custom deny runs before the DetectionOnly switch, so the
	// rule-level 拦截 action still blocks in detection mode
	denyIdx := strings.Index(directives, "deny,log,setvar:tx.inbound_anomaly_score_pl1")
	switchIdx := strings.Index(directives, "ctl:ruleEngine=DetectionOnly")
	if denyIdx < 0 || switchIdx < 0 {
		t.Fatalf("missing deny action or detection switch:\n%s", directives)
	}
	if denyIdx > switchIdx {
		t.Fatalf("custom deny must be emitted before the DetectionOnly switch:\n%s", directives)
	}
}
