package handlers

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func automationPolicyFixture(marker string, subjects ...string) map[string]interface{} {
	subjectList := make([]interface{}, 0, len(subjects))
	for _, subject := range subjects {
		subjectList = append(subjectList, subject)
	}
	return map[string]interface{}{
		"subjects": subjectList,
		"issuer":   map[string]interface{}{"module": marker},
	}
}

func automationGlobalPolicyFixture(marker string) map[string]interface{} {
	return map[string]interface{}{
		"issuer": map[string]interface{}{"module": marker},
	}
}

func automationConfigWithPolicies(policies ...interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"tls": map[string]interface{}{
				"automation": map[string]interface{}{
					"policies": policies,
				},
			},
		},
	}
}

func automationPolicyModules(t *testing.T, result map[string]interface{}) []string {
	t.Helper()
	raw, ok := result["automation_policies"].([]interface{})
	if !ok {
		t.Fatalf("automation_policies type = %T, want []interface{}", result["automation_policies"])
	}
	if raw == nil {
		t.Fatal("automation_policies is nil, want initialized empty slice")
	}
	modules := make([]string, 0, len(raw))
	for _, policyVal := range raw {
		policy, _ := policyVal.(map[string]interface{})
		issuer, _ := policy["issuer"].(map[string]interface{})
		module, _ := issuer["module"].(string)
		modules = append(modules, module)
	}
	return modules
}

func TestBuildRuleCaddyContext_AutomationPoliciesScopedToRuleDomains(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		policies    []interface{}
		wantModules []string
	}{
		{
			name:   "policy with subjects matching rule domains is kept",
			domain: "example.com",
			policies: []interface{}{
				automationPolicyFixture("acme", "example.com"),
			},
			wantModules: []string{"acme"},
		},
		{
			name:   "policy matching any of several canonicalized rule domains is kept",
			domain: "Example.com, www.example.com",
			policies: []interface{}{
				automationPolicyFixture("acme", "www.example.com"),
			},
			wantModules: []string{"acme"},
		},
		{
			name:   "policy with non-matching subjects is dropped",
			domain: "example.com",
			policies: []interface{}{
				automationPolicyFixture("acme", "other.com"),
			},
			wantModules: []string{},
		},
		{
			name:   "policy without subjects field is dropped",
			domain: "example.com",
			policies: []interface{}{
				automationGlobalPolicyFixture("internal"),
			},
			wantModules: []string{},
		},
		{
			name:   "empty rule domain yields empty non-nil policies",
			domain: "",
			policies: []interface{}{
				automationPolicyFixture("acme", "example.com"),
			},
			wantModules: []string{},
		},
		{
			name:   "mixed policies keep only domain matches",
			domain: "example.com",
			policies: []interface{}{
				automationPolicyFixture("acme", "example.com"),
				automationPolicyFixture("zerossl", "other.com"),
				automationGlobalPolicyFixture("internal"),
				automationPolicyFixture("empty"),
			},
			wantModules: []string{"acme"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given: a full Caddy config whose TLS app holds the case's automation policies
			fullConfig := automationConfigWithPolicies(tt.policies...)

			// When
			result := buildRuleCaddyContext(fullConfig, "lb_testrule", 443, tt.domain)

			// Then
			gotModules := automationPolicyModules(t, result)
			if !reflect.DeepEqual(gotModules, tt.wantModules) {
				t.Fatalf("automation policy modules = %v, want %v", gotModules, tt.wantModules)
			}
		})
	}
}

func tlsConnPolicyFixture(anyTag []string, sni ...string) map[string]interface{} {
	policy := map[string]interface{}{}
	if anyTag != nil {
		tags := make([]interface{}, 0, len(anyTag))
		for _, tag := range anyTag {
			tags = append(tags, tag)
		}
		policy["certificate_selection"] = map[string]interface{}{"any_tag": tags}
	}
	if sni != nil {
		sniList := make([]interface{}, 0, len(sni))
		for _, name := range sni {
			sniList = append(sniList, name)
		}
		policy["match"] = map[string]interface{}{"sni": sniList}
	}
	return policy
}

func tlsConnPoliciesConfigFixture(caddyID string, policies []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []interface{}{":443"},
						"routes": []interface{}{
							map[string]interface{}{"@id": caddyID},
						},
						"tls_connection_policies": policies,
					},
				},
			},
		},
	}
}

func tlsConnPolicyFingerprints(t *testing.T, raw interface{}) []string {
	t.Helper()
	policies, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("tls_connection_policies type = %T, want []interface{}", raw)
	}
	if policies == nil {
		t.Fatal("tls_connection_policies is nil, want initialized empty slice")
	}
	fingerprints := make([]string, 0, len(policies))
	for _, policyVal := range policies {
		policy, _ := policyVal.(map[string]interface{})
		parts := make([]string, 0)
		if selection, ok := policy["certificate_selection"].(map[string]interface{}); ok {
			if tags, ok := selection["any_tag"].([]interface{}); ok {
				for _, tag := range tags {
					parts = append(parts, fmt.Sprintf("tag=%v", tag))
				}
			}
		}
		if match, ok := policy["match"].(map[string]interface{}); ok {
			if sni, ok := match["sni"].([]interface{}); ok {
				for _, name := range sni {
					parts = append(parts, fmt.Sprintf("sni=%v", name))
				}
			}
		}
		fingerprints = append(fingerprints, strings.Join(parts, ","))
	}
	return fingerprints
}

func TestBuildRuleCaddyContext_TLSConnectionPoliciesScopedToRule(t *testing.T) {
	tests := []struct {
		name             string
		caddyID          string
		domain           string
		policies         []interface{}
		wantFingerprints []string
	}{
		{
			name:    "entry whose any_tag contains the rule caddy id is kept",
			caddyID: "lb_rule1",
			domain:  "other-rule-domain.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_rule1"}, "go029.com"),
			},
			wantFingerprints: []string{"tag=lb_rule1,sni=go029.com"},
		},
		{
			name:    "entry tagged with a different rule id is dropped",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_otherrule"}),
			},
			wantFingerprints: []string{},
		},
		{
			name:    "entry without any_tag but sni intersecting rule domains is kept",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture(nil, "www.go029.com", "go029.com"),
			},
			wantFingerprints: []string{"sni=www.go029.com,sni=go029.com"},
		},
		{
			name:    "entry with neither any_tag nor sni match is dropped",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_otherrule"}, "unrelated.com"),
			},
			wantFingerprints: []string{},
		},
		{
			name:    "server context and top level carry the same filtered set",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_rule1"}, "go029.com"),
				tlsConnPolicyFixture([]string{"lb_otherrule"}, "ry029.com"),
			},
			wantFingerprints: []string{"tag=lb_rule1,sni=go029.com"},
		},
		{
			name:    "rule with no matching entries gets empty non-nil policies",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_otherrule"}, "ry029.com"),
				tlsConnPolicyFixture(nil, "quanyi.go029.com"),
			},
			wantFingerprints: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given: an http server hosting the rule's route plus policies from sibling rules
			fullConfig := tlsConnPoliciesConfigFixture(tt.caddyID, tt.policies)

			// When
			result := buildRuleCaddyContext(fullConfig, tt.caddyID, 443, tt.domain)

			// Then: both the top-level array and the server context carry the rule-scoped set
			gotTop := tlsConnPolicyFingerprints(t, result["tls_connection_policies"])
			if !reflect.DeepEqual(gotTop, tt.wantFingerprints) {
				t.Fatalf("tls_connection_policies = %v, want %v", gotTop, tt.wantFingerprints)
			}

			server, ok := result["server"].(map[string]interface{})
			if !ok || server == nil {
				t.Fatalf("server context = %v, want matching http server", result["server"])
			}
			gotServer := tlsConnPolicyFingerprints(t, server["tls_connection_policies"])
			if !reflect.DeepEqual(gotServer, tt.wantFingerprints) {
				t.Fatalf("server tls_connection_policies = %v, want %v", gotServer, tt.wantFingerprints)
			}
		})
	}
}
