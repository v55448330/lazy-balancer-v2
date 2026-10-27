package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

type certificateListEntry struct {
	ID        int     `json:"id"`
	RuleID    string  `json:"rule_id"`
	Domain    string  `json:"domain"`
	Status    string  `json:"status"`
	ExpiresAt string  `json:"expires_at"`
	NotAfter  *string `json:"not_after"`
}

// GET /certificates 聚合清单必须与 /certificates/jobs 同一到期语义：导入/旧备份/
// 集群快照留下的 downloaded/cleanup_* 任务持有证书材料但 expires_at 为 NULL 时，
// 聚合清单此前原样返回空到期时间，而任务列表/规则证书卡由 PEM 派生 not_after——
// MCP/自动化消费者会把同一任务读成「没有到期时间」。
func TestListCertificates_derivesNotAfterFromPEMWhenExpiresAtNull(t *testing.T) {
	h := newBackupTestHandlers(t)
	notAfter := time.Now().UTC().Add(720 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM, err := generateTestCert("legacy-null-expiry.test", time.Now().Add(-time.Hour), notAfter)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, expires_at)
		VALUES ('lb_cert_null_exp','legacy-null-expiry.test','downloaded',?,?,NULL)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	// 回归形状：正常行 expires_at 非空
	withExpiry := time.Now().UTC().Add(240 * time.Hour).Truncate(time.Second)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, expires_at)
		VALUES ('lb_cert_with_exp','with-expiry.test','issued',?,?,?)`, certPEM, keyPEM, withExpiry.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates", h.ListCertificates)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/certificates?page_size=100", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Certificates []certificateListEntry `json:"certificates"`
			Total        int64                  `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Total != 2 {
		t.Fatalf("total=%d, want 2（分页总数不受派生字段影响）", resp.Data.Total)
	}
	byRule := map[string]certificateListEntry{}
	for _, cert := range resp.Data.Certificates {
		byRule[cert.RuleID] = cert
	}

	legacyEntry, ok := byRule["lb_cert_null_exp"]
	if !ok {
		t.Fatalf("缺少 legacy 行: %+v", resp.Data.Certificates)
	}
	if legacyEntry.ExpiresAt != "" {
		t.Fatalf("expires_at=%q, want 空（库值保持原契约）", legacyEntry.ExpiresAt)
	}
	if legacyEntry.NotAfter == nil {
		t.Fatalf("not_after 为空：NULL expires_at 必须由 PEM 派生（与 /certificates/jobs 同口径）")
	}
	derived, err := time.Parse(time.RFC3339, *legacyEntry.NotAfter)
	if err != nil {
		t.Fatalf("not_after=%q 无法解析: %v", *legacyEntry.NotAfter, err)
	}
	if got, want := derived.UTC(), notAfter; !got.Equal(want) {
		t.Fatalf("not_after=%v, want PEM 到期 %v", got, want)
	}

	withExpiryEntry := byRule["lb_cert_with_exp"]
	if withExpiryEntry.NotAfter == nil {
		t.Fatalf("expires_at 非空时 not_after 也必须给出")
	}
	if parsed, err := time.Parse(time.RFC3339, *withExpiryEntry.NotAfter); err != nil || !parsed.UTC().Equal(withExpiry) {
		t.Fatalf("not_after=%v (err=%v), want 库值 %v", withExpiryEntry.NotAfter, err, withExpiry)
	}
}

// 畸形形状：PEM 不可解析且 expires_at 为空时不得伪造到期时间。
func TestListCertificates_unparsablePEMLeavesNotAfterNull(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, expires_at)
		VALUES ('lb_cert_bad_pem','bad-pem.test','downloaded','not-a-cert','not-a-key',NULL)`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/certificates", h.ListCertificates)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Certificates []certificateListEntry `json:"certificates"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Certificates) != 1 {
		t.Fatalf("certificates=%+v, want 1", resp.Data.Certificates)
	}
	if resp.Data.Certificates[0].NotAfter != nil {
		t.Fatalf("not_after=%v, want null（坏 PEM 不得派生出到期时间）", *resp.Data.Certificates[0].NotAfter)
	}
}
