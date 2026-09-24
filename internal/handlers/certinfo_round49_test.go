package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// generateTestCertForDomains 生成多 SAN 测试证书（generateTestCert 的多域名形）。
func generateTestCertForDomains(notBefore, notAfter time.Time, domains ...string) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil
}

// F49-P5-14（第 49 轮审计）：批量 GetRulesCertInfo 的候选查询未扫 domain 列，
// 与单规则路径同型缺陷——「同过期精确匹配优先」决胜层失效（测试与
// services.TestGetRuleCertInfo_prefersExactDomainMatchOnExpiryTie 同形）。
func TestGetRulesCertInfo_prefersExactDomainMatchOnExpiryTie(t *testing.T) {
	// Given: 同 NotAfter 两候选——精确匹配任务（旧）与超集 SAN 任务（新）
	h := newBackupTestHandlers(t)
	now := time.Now()
	notAfter := now.Add(60 * 24 * time.Hour)
	exactCert, exactKey, err := generateTestCertForDomains(now.Add(-time.Hour), notAfter, "tie-batch.test")
	if err != nil {
		t.Fatalf("generate exact cert: %v", err)
	}
	coverCert, coverKey, err := generateTestCertForDomains(now.Add(-time.Hour), notAfter, "tie-batch.test", "api.tie-batch.test")
	if err != nil {
		t.Fatalf("generate covering cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_batch_tie','tie','tie-batch.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_batch_tie','tie-batch.test','issued',?,?,'2026-01-01 00:00:00')`, exactCert, exactKey); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_batch_tie','tie-batch.test,api.tie-batch.test','issued',?,?,'2026-06-01 00:00:00')`, coverCert, coverKey); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_batch_tie"]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then: 同过期时精确域名匹配优先
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var resp struct {
		Data map[string]*struct {
			Domains string `json:"domains"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	info := resp.Data["lb_batch_tie"]
	if info == nil {
		t.Fatalf("rule info missing: %s", response.Body.String())
	}
	if strings.Contains(info.Domains, "api.tie-batch.test") {
		t.Fatalf("domains=%q, want 精确匹配任务的证书（不含 api.tie-batch.test）", info.Domains)
	}
}
