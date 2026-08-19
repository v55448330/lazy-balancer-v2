package services

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
)

// R43 F-A: 跳转收集此前按上游裸计数（len(upstreams)==0），与规则渲染跳过的
// 启用上游口径不一致——全部上游被禁用的启用规则不渲染任何端口路由，却仍生成
// terminal 301 跳转，域名被跳到无服务的 TLS 端口。跳转收集必须按启用上游判定。
func TestGenerateCaddyConfig_skips_redirect_route_when_all_upstreams_disabled(t *testing.T) {
	useTemporaryCertDir(t)
	certPEM, keyPEM := matchingCertificatePair(t, "deadend.test")
	seed := func(t *testing.T, database *sql.DB, caddyID string, upstreamEnabled int) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,'http','deadend.test',443,'weighted_round_robin',1,1,1,'manual',?,?,1)`,
			caddyID, caddyID, certPEM, keyPEM); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,?,'http')", caddyID, upstreamEnabled); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
		// 同库放一条正常 80 规则，保证 http_80 服务器存在（跳转路由的宿主）。
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,enable_compress)
			VALUES (?,'plain','http','plain.test',80,'weighted_round_robin',1,1)`, caddyID+"_plain"); err != nil {
			t.Fatalf("seed plain rule: %v", err)
		}
		if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9001,1,1,'http')", caddyID+"_plain"); err != nil {
			t.Fatalf("seed plain upstream: %v", err)
		}
	}
	render := func(t *testing.T, upstreamEnabled int) string {
		t.Helper()
		_, database := newClusterTestService(t)
		seed(t, database, "lb_redir", upstreamEnabled)
		generated := generateCaddyConfigFromStore(database)
		if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("generate config: %s", message)
		}
		configJSON, err := json.Marshal(generated)
		if err != nil {
			t.Fatalf("marshal generated config: %v", err)
		}
		return string(configJSON)
	}

	t.Run("全部上游禁用时规则被跳过且不生成跳转", func(t *testing.T) {
		configJSON := render(t, 0)
		if strings.Contains(configJSON, "lb_redir_redirect") {
			t.Fatalf("全部上游禁用的规则不应生成跳转路由: %s", configJSON)
		}
		if strings.Contains(configJSON, "http_443") {
			t.Fatalf("全部上游禁用的规则不应生成 443 服务器: %s", configJSON)
		}
	})

	t.Run("存在启用上游时正常生成跳转（对照）", func(t *testing.T) {
		configJSON := render(t, 1)
		if !strings.Contains(configJSON, "lb_redir_redirect") {
			t.Fatalf("存在启用上游的 TLS 跳转规则应生成跳转路由: %s", configJSON)
		}
	})
}
