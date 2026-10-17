package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

type blockingCertificateWorker struct {
	stopOnce sync.Once
	stop     chan struct{}
	exited   chan struct{}
}

func (w *blockingCertificateWorker) Start() {
	<-w.stop
	close(w.exited)
}

func (w *blockingCertificateWorker) Stop() {
	w.stopOnce.Do(func() { close(w.stop) })
}

type idleSyncWorker struct{}

func (idleSyncWorker) Start() {}
func (idleSyncWorker) Stop()  {}

func TestRuntimeLifecycle_StopACME_waitsForWorkerExit(t *testing.T) {
	// Given
	worker := &blockingCertificateWorker{stop: make(chan struct{}), exited: make(chan struct{})}
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() certificateWorker { return worker })
	lifecycle.StartACME()

	// When
	lifecycle.StopACME()

	// Then
	select {
	case <-worker.exited:
	default:
		t.Fatal("StopACME returned before the certificate worker exited")
	}
}

// U1-P3-9/U7-P3-1（第 62 轮审计）：StopACME 必须与 StartACME 的注入对称，
// 清除 services 侧 active 指针——否则 demote/停机后任务引擎证书单轮体
// （cert-manual-poll 等）继续驱动已停服务（重复到期日志/无角色门补扫）。
// 可观察口径：注入生效时 CertManualCheckOnce 真实消费服务（到期汇总日志），
// StopACME 后同一入口零行为。
func TestRuntimeLifecycle_StopACME_clearsActiveCertificateService(t *testing.T) {
	// Given：临时库 + 一张已过期手动证书，注入真实证书服务
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		// U12-F12（第 78 轮）：仅复位指针会泄漏本测试打开的三个 *sql.DB——
		// 先关闭再恢复外层句柄。
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize db: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert) VALUES ('lb_stopacme','stopacme','stopacme.test','http',8080,1,1,'manual',?)`, expiredManualCertPEM(t)); err != nil {
		t.Fatalf("seed expired manual cert rule: %v", err)
	}
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() certificateWorker { return services.NewCertificateService() })
	lifecycle.StartACME()

	// 正向对照：注入生效——单轮体产出到期汇总日志
	buf.Reset()
	services.CertManualCheckOnce()
	if !strings.Contains(buf.String(), "TLS Certificate Check: 1 expired") {
		t.Fatalf("after StartACME the manual check should consume the active service, log=%q", buf.String())
	}

	// When
	lifecycle.StopACME()

	// Then：active 指针已清除——同一入口不再驱动已停服务
	buf.Reset()
	services.CertManualCheckOnce()
	if strings.Contains(buf.String(), "TLS Certificate Check") {
		t.Fatalf("active certificate service survived StopACME (U1-P3-9/U7-P3-1), log=%q", buf.String())
	}
}

func expiredManualCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stopacme.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
