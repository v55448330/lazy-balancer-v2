package services

import (
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
