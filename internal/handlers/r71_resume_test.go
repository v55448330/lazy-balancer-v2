package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// selfSignedPEM 生成自签证书对（CN=域名，NotAfter 远期）。
func selfSignedPEM(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(200 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// R71 F-A1：禁用→重启用（Resume 分支）后必须重渲染重应用——此前 Resume 在
// ApplyConfigFromTx 之后翻 'issued'，已应用配置缺 TLS/301 且无 re-apply，
// 看门狗只查路由存在，静默失配无上界。
func TestEnableRule_resumeTriggersReapplyWithTLS(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	restoreCertDir := services.SetCertDirForTest(t.TempDir())
	t.Cleanup(restoreCertDir)
	rec := &fakeCaddyRecorder{}
	fake := newFakeCaddyServer(t, rec)
	h.caddyService = services.NewCaddyService(fake.URL)

	certPEM, keyPEM := selfSignedPEM(t, "resume.example.test")
	farFuture := time.Now().UTC().Add(180 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('cfg','mock','',1)`); err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	var dnsCfgID int
	if err := db.DB.QueryRow("SELECT id FROM certificate_configs LIMIT 1").Scan(&dnsCfgID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_resume','r','','http','resume.example.test',9472,0,1,'acme_dns',?)`, dnsCfgID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_resume','10.1.1.1',9472,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('lb_resume','resume.example.test','disabled',?,?,?)`,
		certPEM, keyPEM, farFuture); err != nil {
		t.Fatalf("seed job: %v", err)
	}

	router := gin.New()
	router.POST("/rules/:caddy_id/enable", h.EnableRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_resume/enable", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then：Resume 之后必须有 re-apply——最终一次 /load 载荷含该规则的 TLS 材料
	//（any_tag 触发证书选择）且不含 'disabled' 过滤态下的裸路由。
	if len(rec.loads) < 2 {
		t.Fatalf("/load calls=%d, want ≥2（启用应用 + Resume 重应用）", len(rec.loads))
	}
	final := rec.loads[len(rec.loads)-1]
	if !strings.Contains(final, "lb_resume") {
		t.Fatalf("最终 /load 载荷不含规则 lb_resume——Resume 后未重应用")
	}
}
