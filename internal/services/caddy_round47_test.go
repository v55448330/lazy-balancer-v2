package services

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
)

// R47 C-发现3: acme 证书候选查询此前全库全量拉取 cert_jobs（无规则过滤、无
// status 过滤）——已删除规则的残留行、disabled 任务、非 acme 规则的历史 PEM
// 都会在每次全量生成时载入内存。过滤前移后：只有「启用 + TLS + acme_dns」规则
// 名下的未禁用任务进入候选集，且合法规则的证书仍正常加载。
func TestGenerateCaddyConfig_acmeCertQueryFiltersCandidates(t *testing.T) {
	// Given 一条合法 acme 规则 + 各类应被排除的 cert_jobs 行
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "acme-ok.test")
	seedRule := func(caddyID, domain string, listenPort int) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source)
			VALUES (?,?,'http',?,?,'weighted_round_robin',1,1,1,'acme_dns')`,
			caddyID, caddyID, domain, listenPort); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')", caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	seedRule("lb_acme_ok", "acme-ok.test", 443)
	seedRule("lb_acme_off", "acme-off.test", 8443)
	seedRule("lb_manual_ok", "manual.test", 9443)
	if _, err := database.Exec("UPDATE lb_rules SET enabled=0 WHERE caddy_id='lb_acme_off'"); err != nil {
		t.Fatalf("disable rule lb_acme_off: %v", err)
	}
	if _, err := database.Exec("UPDATE lb_rules SET tls_source='manual' WHERE caddy_id='lb_manual_ok'"); err != nil {
		t.Fatalf("switch lb_manual_ok to manual tls: %v", err)
	}
	seedJob := func(ruleID, domain, status string) {
		t.Helper()
		if _, err := database.Exec("INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES (?,?,?,?,?)",
			ruleID, domain, status, certPEM, keyPEM); err != nil {
			t.Fatalf("seed cert job (%s,%s,%s): %v", ruleID, domain, status, err)
		}
	}
	seedJob("lb_acme_ok", "acme-ok.test", "issued")   // 合法候选
	seedJob("lb_gone", "gone.test", "issued")         // 已删除规则的残留行
	seedJob("lb_acme_ok", "extra.test", "disabled")   // 已禁用任务
	seedJob("lb_manual_ok", "manual.test", "issued")  // 非 acme 规则的任务
	seedJob("lb_acme_off", "acme-off.test", "issued") // 禁用规则的任务

	// When 直接执行候选查询
	type candidate struct{ ruleID, domain string }
	queryCandidates := func(database *sql.DB) []candidate {
		t.Helper()
		rows, err := database.Query(acmeCertCandidatesQuery)
		if err != nil {
			t.Fatalf("run acme cert candidates query: %v", err)
		}
		defer rows.Close()
		var got []candidate
		for rows.Next() {
			var c candidate
			var id int64
			var status, cert, key string
			var updated float64
			if err := rows.Scan(&c.ruleID, &id, &c.domain, &status, &cert, &key, &updated); err != nil {
				t.Fatalf("scan candidate: %v", err)
			}
			got = append(got, c)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate candidates: %v", err)
		}
		return got
	}

	// Then 只剩合法规则的未禁用任务
	got := queryCandidates(database)
	if len(got) != 1 || got[0].ruleID != "lb_acme_ok" || got[0].domain != "acme-ok.test" {
		t.Fatalf("candidates=%+v, want only (lb_acme_ok, acme-ok.test)", got)
	}

	// And 合法规则的证书仍正常进入生成配置（tls_connection_policies any_tag）
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	configJSON, err := json.Marshal(generated)
	if err != nil {
		t.Fatalf("marshal generated config: %v", err)
	}
	if !strings.Contains(string(configJSON), `"any_tag":["lb_acme_ok"]`) {
		t.Fatalf("generated config missing TLS policy for lb_acme_ok: %s", configJSON)
	}
}
