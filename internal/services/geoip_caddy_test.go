package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func setupGeoipConfigTestDB(t *testing.T) {
	t.Helper()
	oldDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = oldDB
	})
}

func seedGeoipPolicy(t *testing.T, ruleCaddyID, countries, mode string) {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, geoip_countries, geoip_mode)
		VALUES ('geoip-test', 'off', 1, ?, ?)`, countries, mode)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := db.DB.Exec("INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)", ruleCaddyID, policyID); err != nil {
		t.Fatal(err)
	}
}

func findRouteByMatcherExpression(t *testing.T, routes []map[string]interface{}, wantExpr string) map[string]interface{} {
	t.Helper()
	for _, route := range routes {
		matchers, ok := route["match"].([]interface{})
		if !ok {
			continue
		}
		for _, matcherValue := range matchers {
			matcher := mustMap(t, matcherValue, "matcher")
			if expr, ok := matcher["expression"].(string); ok && expr == wantExpr {
				return route
			}
		}
	}
	t.Fatalf("no route matched expression %q in %#v", wantExpr, routes)
	return nil
}

func handlerNames(t *testing.T, routeValue interface{}) []string {
	t.Helper()
	route := mustMap(t, routeValue, "route")
	handlers, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("handle has type %T", route["handle"])
	}
	names := make([]string, 0, len(handlers))
	for _, handlerValue := range handlers {
		handler := mustMap(t, handlerValue, "handler")
		name, _ := handler["handler"].(string)
		names = append(names, name)
	}
	return names
}

// TestGenerateHTTPRouteObjects_geoipOverseas_emitsHandlerAndBlockRoute verifies
// that a deny-mode policy listing "海外" yields a geoip pass route, a block route
// matching country_name != 中国, and a main route whose chain starts with geoip.
func TestGenerateHTTPRouteObjects_geoipOverseas_emitsHandlerAndBlockRoute(t *testing.T) {
	// Given a deny-mode geoip policy bound to a rule
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `["海外"]`, "deny")

	// When the route objects are generated
	routes, mainRoute, err := generateHTTPRouteObjects(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}

	// Then the block route carries the 海外 expression and triggers a 403 error
	block := findRouteByMatcherExpression(t, routes, `{http.vars.geoip.country_name} != "中国"`)
	names := handlerNames(t, block)
	if len(names) != 1 || names[0] != "error" {
		t.Fatalf("block route handlers=%v, want [error]", names)
	}
	errorHandler := mustMap(t, block["handle"].([]interface{})[0], "error handler")
	status := errorHandler["status_code"]
	if status != "403" && status != 403 {
		t.Fatalf("block status_code=%#v, want \"403\" or 403", status)
	}
	if block["terminal"] != true {
		t.Fatal("block route must be terminal")
	}

	// And the main route's chain no longer duplicates the geoip handler
	// (it's already executed in the pass route above)
	mainNames := handlerNames(t, mainRoute)
	for _, n := range mainNames {
		if n == "geoip2region" {
			t.Fatalf("main route should not contain geoip2region (handled by pass route), handlers=%v", mainNames)
		}
	}

	// And a pass route populates the geoip vars before the block matcher runs
	first := mustMap(t, routes[0], "first route")
	if got := handlerNames(t, routes[0]); len(got) != 1 || got[0] != "geoip2region" {
		t.Fatalf("routes[0] handlers=%v, want pass-through geoip2region", got)
	}
	if first["terminal"] == true {
		t.Fatal("geoip pass route must not be terminal")
	}
}

// TestGenerateHTTPRouteObjects_geoipProvinces_joinsProvinceMatches verifies
// province entries produce a disjunctive province match.
func TestGenerateHTTPRouteObjects_geoipProvinces_joinsProvinceMatches(t *testing.T) {
	// Given a policy restricting to two provinces
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `["广东省","北京市"]`, "deny")

	// When the route objects are generated
	routes, _, err := generateHTTPRouteObjects(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}

	// Then the block route joins the provinces with OR
	want := `{http.vars.geoip.province} == "广东省" || {http.vars.geoip.province} == "北京市"`
	block := findRouteByMatcherExpression(t, routes, want)
	_ = block
}

// TestGenerateHTTPRouteObjects_geoipAllow_negatesBlockExpression verifies
// allow mode blocks everything outside the matched regions.
func TestGenerateHTTPRouteObjects_geoipAllow_negatesBlockExpression(t *testing.T) {
	// Given an allow-mode policy with one province
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `["广东省"]`, "allow")

	// When the route objects are generated
	routes, _, err := generateHTTPRouteObjects(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}

	// Then the block route negates the matched-region union
	want := `!({http.vars.geoip.province} == "广东省")`
	block := findRouteByMatcherExpression(t, routes, want)
	status := mustMap(t, block["handle"].([]interface{})[0], "block handler")["status_code"]
	if status != 403 {
		t.Fatalf("block status_code=%#v, want 403", status)
	}
}

// TestGenerateHTTPRouteObjects_geoipDisabled_noBlockRoute verifies a policy
// without geoip countries produces no geoip routes.
func TestGenerateHTTPRouteObjects_geoipDisabled_noBlockRoute(t *testing.T) {
	// Given a policy without geoip countries
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `[]`, "deny")

	// When the route objects are generated
	routes, mainRoute, err := generateHTTPRouteObjects(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}

	// Then no geoip routes exist and the main chain has no geoip handler
	for _, routeValue := range routes {
		if strings.Contains(handlerNamesAsString(t, routeValue), "geoip2region") {
			t.Fatalf("unexpected geoip handler in %#v", routeValue)
		}
	}
	if strings.Contains(handlerNamesAsString(t, mainRoute), "geoip2region") {
		t.Fatal("main chain must not contain geoip handler when geoip disabled")
	}
}

// TestGenerateSingleRuleCaddyConfig_geoip_previewIncludesBlockRoute verifies
// the preview path also emits the geoip handler and block route.
func TestGenerateSingleRuleCaddyConfig_geoip_previewIncludesBlockRoute(t *testing.T) {
	// Given a deny-mode overseas geoip policy
	setupGeoipConfigTestDB(t)
	seedGeoipPolicy(t, "rule-http", `["海外"]`, "deny")

	// When the preview config is generated
	config := GenerateSingleRuleCaddyConfig(baseHTTPRule())
	routes := renderedHTTPRoutes(t, config)

	// Then the block route is present with the overseas expression
	routeMap := make([]map[string]interface{}, 0, len(routes))
	for _, routeValue := range routes {
		routeMap = append(routeMap, mustMap(t, routeValue, "route"))
	}
	findRouteByMatcherExpression(t, routeMap, `{http.vars.geoip.country_name} != "中国"`)
}

func handlerNamesAsString(t *testing.T, routeValue interface{}) string {
	t.Helper()
	return strings.Join(handlerNames(t, routeValue), ",")
}
