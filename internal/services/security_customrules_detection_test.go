package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"

	"lazy-balancer-v2/internal/models"
)

func TestCustomRuleBlockActionSurvivesDetectionMode(t *testing.T) {
	// Given a detection-mode policy with a blocking custom rule
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "detection",
		CustomRules: json.RawMessage(`[{"id":21,"name":"硬拦截","enabled":true,"action":"block","score":5,"conditions":[` +
			`{"target":"uri","operator":"contains","pattern":"/hard-block"}]}]`),
	}

	// When the rendered policy runs in a real Coraza transaction. CRS Includes
	// and audit sinks are environment concerns; the shared behavior fixture strips
	// the latter while preserving the custom rule and DetectionOnly switch.
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Include ") || strings.HasPrefix(trimmed, "SecRuleUpdateActionById ") {
			continue
		}
		kept = append(kept, line)
	}
	waf := newPrecheckBehaviorWAF(t, strings.Join(kept, "\n"))
	run := func(uri string) *types.Interruption {
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection("203.0.113.7", 5555, "127.0.0.1", 80)
		tx.ProcessURI(uri, "GET", "HTTP/1.1")
		return tx.ProcessRequestHeaders()
	}

	// Then the rule-level deny interrupts before DetectionOnly can downgrade CRS;
	// an adjacent non-matching URI remains a no-interruption control.
	it := run("/hard-block")
	if it == nil {
		t.Fatalf("detection mode must still interrupt a matching custom deny:\n%s", strings.Join(kept, "\n"))
	}
	// 自定义规则经合成 ID 10000+id 发射；无 CRS Include 的夹具中，
	// 该中断只能来自本条自定义 deny。
	if it.RuleID != 10021 {
		t.Fatalf("interruption rule=%d, want synthetic custom deny rule 10021", it.RuleID)
	}
	if other := run("/allowed"); other != nil {
		t.Fatalf("non-matching URI must not interrupt, got rule=%d status=%d", other.RuleID, other.Status)
	}
}
