package services

import (
	"errors"
	"testing"
)

// Round 30 F-3: 渲染层跳转遮蔽复核按域名粒度过滤——跳转规则多域名部分冲突时仅
// 移除冲突域名，剩余域名仍生成跳转；全部冲突时整条跳过（保持 G-2 语义）。
func TestGenerateCaddyConfig_httpsRedirect_filtersShadowedDomains(t *testing.T) {
	tests := []struct {
		name           string
		redirectDomain string
		port80Domain   string
		wantHosts      []string // 期望的跳转 matcher；nil 表示整条跳过
	}{
		{
			name:           "部分冲突仅移除冲突域名，兄弟域名仍跳转",
			redirectDomain: "a.example.test, b.example.test",
			port80Domain:   "b.example.test",
			wantHosts:      []string{"a.example.test"},
		},
		{
			name:           "全部冲突整条跳过",
			redirectDomain: "x.example.test, y.example.test",
			port80Domain:   "x.example.test, y.example.test",
			wantHosts:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useTemporaryCertDir(t)
			_, database := newClusterTestService(t)
			certPEM, keyPEM := matchingCertificatePair(t, "a.example.test", "b.example.test", "x.example.test", "y.example.test")
			seedGenerationRule(t, database, "lb_redir_scope", false)
			seedGenerationRule(t, database, "lb_80_scope", false)
			if _, err := database.Exec(`UPDATE lb_rules SET domain=?, listen_port=443,
				enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
				WHERE caddy_id='lb_redir_scope'`, tt.redirectDomain, certPEM, keyPEM); err != nil {
				t.Fatalf("enable TLS redirect: %v", err)
			}
			if _, err := database.Exec(`UPDATE lb_rules SET domain=?, listen_port=80 WHERE caddy_id='lb_80_scope'`, tt.port80Domain); err != nil {
				t.Fatalf("enable port-80 rule: %v", err)
			}

			// When
			generated := generateCaddyConfigFromStore(database)

			// Then
			if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
				t.Fatalf("generate config: %s", message)
			}
			routes := httpRoutesFromServer(t, generated, "http_80")
			redirect := findRouteByID(t, routes, "lb_redir_scope_redirect")
			if tt.wantHosts == nil {
				if redirect != nil {
					t.Fatalf("全部域名被遮蔽仍生成跳转路由: %#v", redirect)
				}
			} else {
				if redirect == nil {
					t.Fatalf("部分遮蔽时兄弟域名必须仍生成跳转路由: %#v", routes)
				}
				assertEqual(t, routeMatcher(t, redirect)["host"], tt.wantHosts)
			}
			// 80 端口规则自身的代理路由必须保留（未被 terminal 301 遮蔽）
			if findRouteByID(t, routes, "lb_80_scope") == nil {
				t.Fatalf("80 端口规则代理路由缺失: %#v", routes)
			}
		})
	}
}

// Round 30 F-2: 渲染层遮蔽比较必须与保存侧规范化口径（db.CanonicalDomains）一致。
// 导入态大小写混合域名（"ShadowMixed.TEST"）与 80 规则 "shadowmixed.test" 在
// Caddy host matcher 下同义（大小写不敏感），比较失配会让遮蔽漏洞经导入路径复发。
func TestGenerateCaddyConfig_httpsRedirect_normalizesImportedDomainComparison(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "shadowmixed.test", "keep.test")
	seedGenerationRule(t, database, "lb_redir_mixed", false)
	seedGenerationRule(t, database, "lb_80_mixed", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='ShadowMixed.TEST, keep.test', listen_port=443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_redir_mixed'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET domain='shadowmixed.test', listen_port=80 WHERE caddy_id='lb_80_mixed'`); err != nil {
		t.Fatalf("enable port-80 rule: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then: shadowmixed.test 被识别为冲突并移除，keep.test 仍生成跳转
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_80")
	redirect := findRouteByID(t, routes, "lb_redir_mixed_redirect")
	if redirect == nil {
		t.Fatalf("keep.test 必须仍生成跳转路由: %#v", routes)
	}
	assertEqual(t, routeMatcher(t, redirect)["host"], []string{"keep.test"})
	if findRouteByID(t, routes, "lb_80_mixed") == nil {
		t.Fatalf("80 端口规则代理路由缺失: %#v", routes)
	}
}

func findRouteByID(t *testing.T, routes []interface{}, id string) map[string]interface{} {
	t.Helper()
	for _, routeValue := range routes {
		route := mustMap(t, routeValue, "route")
		if routeID, _ := route["@id"].(string); routeID == id {
			return route
		}
	}
	return nil
}

// Round 32 F-3: 路径规则上游为「空但非 nil 的数组」（DB 存量 upstreams_json="[]"
// 形态）必须与 nil 一致回退主上游——此前仅 nil 回退，空数组触发
// buildHTTPHandleChain "no enabled upstreams" 使全量渲染硬失败、预校验却放行
// （不对称），现统一为 len(upstreams)==0 判定。
func TestGenerateSingleRuleCaddyConfig_pathRuleEmptyUpstreamArray_fallsBackToMainUpstreams(t *testing.T) {
	// Given
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{
		{SortOrder: 1, MatchType: "prefix", Path: "/api", Upstreams: []UpstreamConfig{}},
	}

	// When
	routes := renderedHTTPRoutes(t, GenerateSingleRuleCaddyConfig(rule))

	// Then: 路径路由回退主上游（与既有 nil 上游用例同语义），整份配置无生成错误
	if len(routes) != 2 {
		t.Fatalf("expected path route + main route; got %d", len(routes))
	}
	apiMatcher := routeMatcher(t, routes[0])
	assertEqual(t, apiMatcher["path"], []string{"/api", "/api/*"})
	assertUpstreamDials(t, reverseProxyHandler(t, routes[0])["upstreams"], []string{"10.0.0.10:8080", "10.0.0.11:8080"})
}

// Round 32 F-3: 单规则生成 map 的 error 值必须是哨兵 error 本身（非字符串），
// handlers 侧 errors.Is 特判依赖该类型；buildHTTPHandleChain 产出点经 %w
// 包装哨兵，errors.Is 亦可命中。
func TestGenerateSingleRuleCaddyConfig_zeroUpstreams_returnsErrNoEnabledUpstreamsSentinel(t *testing.T) {
	// Given
	rule := SingleRuleConfig{CaddyID: "lb_zero", Protocol: "tcp", ListenPort: 9000}

	// When
	config := GenerateSingleRuleCaddyConfig(rule)
	genErr, isErr := config["error"].(error)

	// Then
	if !isErr {
		t.Fatalf("error 键应为 error 类型，实际 %T", config["error"])
	}
	if !errors.Is(genErr, ErrNoEnabledUpstreams) {
		t.Fatalf("应命中 ErrNoEnabledUpstreams 哨兵，实际: %v", genErr)
	}

	// When 路径上游为空且主上游亦为空 → buildHTTPHandleChain 产出点
	_, chainErr := buildHTTPHandleChain(rule, []UpstreamConfig{})

	// Then: %w 包装后 errors.Is 仍命中
	if chainErr == nil {
		t.Fatal("空上游必须返回错误")
	}
	if !errors.Is(chainErr, ErrNoEnabledUpstreams) {
		t.Fatalf("buildHTTPHandleChain 错误必须可经 errors.Is 命中哨兵，实际: %v", chainErr)
	}
}
