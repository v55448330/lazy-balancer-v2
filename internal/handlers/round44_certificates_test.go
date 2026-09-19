package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// CERT44-2（第 44 轮审计）：批量签发（all=true）此前绕过单规则同款冷却门，
// 5 分钟内 failed 的任务被立即重排队、反复消耗 CA 配额——须逐目标套用
// certJobRetryBlocked，冷却中的任务跳过并在响应计数中单列 skipped_cooldown。
func TestCERT44_2_IssueCertificate_batchSkipsCooldownFailedJobs(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	// Given：两条 ACME 规则各有一个 failed 任务——cool44 失败于 1 分钟前（冷却中），
	// ready44 失败于 10 分钟前（已过 5 分钟冷却）
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES
			('lb_cool44','cool','http','cool.example',8443,1,1,'acme_dns'),
			('lb_ready44','ready','http','ready.example',9443,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at) VALUES
			('lb_cool44','cool.example','failed','cooldown marker',datetime('now','-1 minutes')),
			('lb_ready44','ready.example','failed','stale failure',datetime('now','-10 minutes'));
	`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	// When：批量全量重签
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	// Then：冷却中的任务不被重排队且响应单列 skipped_cooldown；冷却外任务照常入队
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"skipped_cooldown":1`) {
		t.Fatalf("body=%s, want skipped_cooldown=1", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":1`) {
		t.Fatalf("body=%s, want queued=1（冷却外任务照常重排）", response.Body.String())
	}
	var status, message string
	if err := db.DB.QueryRow("SELECT status,message FROM cert_jobs WHERE rule_id='lb_cool44'").Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || message != "cooldown marker" {
		t.Fatalf("cooldown job=(%q,%q), want 原样保留不被重排队", status, message)
	}
}

// CERT44-6（第 44 轮审计）：/certificates/parse 的证书日期此前按 UTC 直出，
// 与规则证书卡 formatDate 的本地时区口径不一致（Asia/Shanghai 下偏差一天）——
// 须按配置时区（services.CurrentLocation）渲染。
func TestCERT44_6_parseTLSCertificate_rendersDatesInConfiguredTimezone(t *testing.T) {
	// Given：配置时区 Asia/Shanghai，证书 NotAfter=Asia/Shanghai 2026-01-01 00:30
	// （即 UTC 2025-12-31T16:30:00Z；UTC 直出会得 2025-12-31）
	previous := services.CurrentLocation()
	if _, err := services.ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = services.ConfigureLocation(previous.String()) })
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSignedCertForCERT44(t, "parse44.test",
		time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 30, 0, 0, shanghai))

	// When
	info, err := parseTLSCertificate(certPEM, keyPEM)

	// Then：按配置时区渲染日期
	if err != nil {
		t.Fatalf("parseTLSCertificate: %v", err)
	}
	if info.NotAfter != "2026-01-01" {
		t.Fatalf("not_after=%q, want 2026-01-01（按配置时区渲染）", info.NotAfter)
	}
	if info.NotBefore != "2025-12-30" {
		t.Fatalf("not_before=%q, want 2025-12-30（按配置时区渲染）", info.NotBefore)
	}
}

// selfSignedCertForCERT44 生成指定有效期的自签证书+私钥 PEM 对（CERT44-6 用）。
func selfSignedCertForCERT44(t *testing.T, domain string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(44),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}
