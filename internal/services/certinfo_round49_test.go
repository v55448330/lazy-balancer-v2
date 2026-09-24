package services

import (
	"strings"
	"testing"
	"time"
)

// F49-P5-14（第 49 轮审计）：getACMECertInfo 的候选查询未扫 domain 列——
// CertificateCandidate.Domain 恒为空，SelectCertificate 的「同过期精确匹配
// 优先」决胜层失效：同 NotAfter 时退化为 updated_at/id 决胜，规则证书信息
// 会展示域名超集的新任务证书而非精确匹配证书。
func TestGetRuleCertInfo_prefersExactDomainMatchOnExpiryTie(t *testing.T) {
	_, database := newClusterTestService(t)

	// Given: 同 NotAfter 两候选——精确匹配任务（旧 updated_at）与超集 SAN 任务（新）
	now := time.Now().UTC()
	notAfter := now.Add(60 * 24 * time.Hour)
	exactCert, exactKey := certificatePairForDomains(t, now.Add(-time.Hour), notAfter, "tie.example.test")
	coverCert, coverKey := certificatePairForDomains(t, now.Add(-time.Hour), notAfter, "tie.example.test", "api.tie.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_tie','tie','tie.example.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_tie','tie.example.test','issued',?,?,'2026-01-01 00:00:00')`, exactCert, exactKey); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_tie','tie.example.test,api.tie.example.test','issued',?,?,'2026-06-01 00:00:00')`, coverCert, coverKey); err != nil {
		t.Fatal(err)
	}

	// When
	info := GetRuleCertInfo("lb_tie")

	// Then: 同过期时精确域名匹配优先（updated_at 更新不得压过精确匹配）
	if info == nil {
		t.Fatal("info is nil")
	}
	if strings.Contains(info.Domains, "api.tie.example.test") {
		t.Fatalf("domains=%q, want 精确匹配任务的证书（不含 api.tie.example.test）", info.Domains)
	}
}
