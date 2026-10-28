package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
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

type countingSyncWorker struct {
	starts atomic.Int32
	stops  atomic.Int32
}

func (w *countingSyncWorker) Start() { w.starts.Add(1) }
func (w *countingSyncWorker) Stop()  { w.stops.Add(1) }

// Shutdown 后 StartSync 必须成为 no-op——进程退出与 taskengine
// daemon 换代并发时，已 teardown 的同步循环不得被重新拉起。
func TestRuntimeLifecycle_ShutdownGatesLaterStarts(t *testing.T) {
	worker := &countingSyncWorker{}
	lifecycle := newRuntimeLifecycle(worker, func() lifecycleWorker {
		return &blockingCertificateWorker{stop: make(chan struct{}), exited: make(chan struct{})}
	})
	lifecycle.StartSync()
	lifecycle.StartSync() // 重复启动由 worker 自身幂等，此处只断言生命周期门

	shutdownForTest(lifecycle)
	if got := worker.stops.Load(); got != 1 {
		t.Fatalf("StopSync invocations=%d, want 1", got)
	}

	lifecycle.StartSync() // Shutdown 后必须被 stopped 门拒绝
	if got := worker.starts.Load(); got != 2 {
		t.Fatalf("StartSync after Shutdown must be a no-op: starts=%d (before shutdown=2)", got)
	}
	shutdownForTest(lifecycle) // 幂等
	if got := worker.stops.Load(); got != 1 {
		t.Fatalf("second Shutdown must not stop again: stops=%d", got)
	}
}

func TestRuntimeLifecycle_StopACME_waitsForWorkerExit(t *testing.T) {
	// Given
	worker := &blockingCertificateWorker{stop: make(chan struct{}), exited: make(chan struct{})}
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker { return worker })
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

// blockedStopCertificateWorker 是生产形态的 Stop：Start 虽已进入等待轮询，
// Stop 自身还要做不可预算的收尾（services.CertificateService.Stop 末尾
// <-s.done），在收尾被长时间占用时永远不返回。
type blockedStopCertificateWorker struct {
	release chan struct{}
	started chan struct{}
}

func (w *blockedStopCertificateWorker) Start() { close(w.started) }

func (w *blockedStopCertificateWorker) Stop() { <-w.release }

// Given 证书 worker 的 Stop 自身阻塞（生产形态：Stop 内部等待 Start 退出）。
// When ShutdownWithTimeout 以 50ms 预算调用。
// Then 必须在预算内返回——Stop 的等待不得落在超时 select 之前，也不得持锁
// 拖住换代钩子（旧实现先调 Stop 再无界等待，超时分支永不可达）。
func TestRuntimeLifecycle_ShutdownWithTimeoutBoundsBlockingStop(t *testing.T) {
	worker := &blockedStopCertificateWorker{release: make(chan struct{}), started: make(chan struct{})}
	t.Cleanup(func() { close(worker.release) })
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker { return worker })
	lifecycle.StartACME()
	<-worker.started

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownWithTimeout 未在超时预算内返回（Stop 的阻塞落在超时等待之前）")
	}

	// 停止已放弃等待，但启动门仍生效：后续 StartSync/StartACME 不得拉起新代。
	var syncs countingSyncWorker
	lifecycle.syncService = &syncs
	lifecycle.StartSync()
	if got := syncs.starts.Load(); got != 0 {
		t.Fatalf("Shutdown 后 StartSync 启动了 %d 次，want 0", got)
	}
}

// StopACME 必须与 StartACME 的注入对称，
// 清除 services 侧 active 指针——否则 demote/停机后任务引擎证书单轮体
// （cert-manual-poll 等）继续驱动已停服务（重复到期日志/无角色门补扫）。
// 可观察口径：注入生效时 CertManualCheckOnce 真实消费服务（到期汇总日志），
// StopACME 后同一入口零行为。
func TestRuntimeLifecycle_StopACME_clearsActiveCertificateService(t *testing.T) {
	// Given：临时库 + 一张已过期手动证书，注入真实证书服务
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		// 仅复位指针会泄漏本测试打开的三个 *sql.DB——
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

	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker { return services.NewCertificateService() })
	lifecycle.StartACME()

	// 观察口：CertRenewalScanOnce 依赖活动证书服务实例（缺失即返回
	// ErrTaskSkipped 哨兵）。CertManualCheckOnce 已与该指针解耦（停机后仍执行
	// 只读巡检），不再能作为「实例已摘除」的观察口。
	// 正向对照：注入生效——扫描进入真实服务路径（不返回 skipped 哨兵）。
	if err := services.CertRenewalScanOnce(context.Background()); errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("after StartACME the renewal scan should reach the active service, err=%v", err)
	}

	// When
	lifecycle.StopACME()

	// Then ①：active 指针已清除——续期扫描回到 skipped 哨兵
	if err := services.CertRenewalScanOnce(context.Background()); !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("active certificate service survived StopACME: cert-renewal-scan would keep driving a stopped service, err=%v", err)
	}
	// Then ②（交叉断言）：手动到期巡检不依赖实例，停机后照常执行——停机
	// 不得把「手动证书即将到期」这条唯一信号一起关掉。
	buf.Reset()
	services.CertManualCheckOnce()
	if !strings.Contains(buf.String(), "TLS Certificate Check") {
		t.Fatalf("manual expiry check must keep running after StopACME (independent of service instance), log=%q", buf.String())
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

// blockingStopSyncWorker 是生产形态的同步停止：SyncService.Stop 取消 ctx 后
// 无 deadline 地等 pullWG（在途拉取客户端 30s + apply 的 DB 写），关停期完全
// 可能超过整个 compose grace。
type blockingStopSyncWorker struct {
	release     chan struct{}
	entered     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
	stops       atomic.Int32
}

func (w *blockingStopSyncWorker) Start() {}
func (w *blockingStopSyncWorker) Stop() {
	w.stops.Add(1)
	w.enterOnce.Do(func() { close(w.entered) })
	<-w.release
}

// releaseNow 放行阻塞中的 Stop（幂等：清理与用例内放行可同时注册）。
func (w *blockingStopSyncWorker) releaseNow() { w.releaseOnce.Do(func() { close(w.release) }) }

// Given 从节点同步停止阻塞（在途 pull 未返回）。
// When ShutdownWithTimeout 以 50ms 预算调用。
// Then 必须在预算内返回——同步段的无预算等待不得排在有预算段之前并吃掉整个
// 关停窗口（旧实现 Shutdown 内直调 StopSync，`<-done` 无界）。
func TestRuntimeLifecycle_ShutdownWithTimeoutBoundsBlockingSyncStop(t *testing.T) {
	worker := &blockingStopSyncWorker{release: make(chan struct{}), entered: make(chan struct{})}
	t.Cleanup(worker.releaseNow)
	lifecycle := newRuntimeLifecycle(worker, func() lifecycleWorker {
		return &blockedStopCertificateWorker{release: make(chan struct{}), started: make(chan struct{})}
	})
	lifecycle.StartSync()

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownWithTimeout 未在预算内返回（同步停止仍是无预算等待）")
	}
}

// Given 引擎排空路径（daemon defer）已发起同步停止且仍在途（弃留 goroutine）。
// When 进程关停路径再次进入 ShutdownWithTimeout。
// Then 只允许一次 syncService.Stop（单飞），且关停按预算返回——旧实现在
// l.mu 上等同一个 `<-done`，与其后弃留的 daemon goroutine 互相卡死。
func TestRuntimeLifecycle_ShutdownSyncStopIsSingleFlight(t *testing.T) {
	worker := &blockingStopSyncWorker{release: make(chan struct{}), entered: make(chan struct{})}
	t.Cleanup(worker.releaseNow)
	lifecycle := newRuntimeLifecycle(worker, func() lifecycleWorker {
		return &blockedStopCertificateWorker{release: make(chan struct{}), started: make(chan struct{})}
	})
	lifecycle.StartSync()

	daemonDone := make(chan struct{})
	go func() {
		defer close(daemonDone)
		lifecycle.StopSync() // 弃留的 daemon 收尾
	}()
	<-worker.entered

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownWithTimeout 未在预算内返回（与在途同步停止争锁）")
	}
	if got := worker.stops.Load(); got != 1 {
		t.Fatalf("syncService.Stop 调用 %d 次，want 1（单飞：不得二次进入停止）", got)
	}
	worker.releaseNow() // 放行后弃留的 daemon 收尾才会返回
	<-daemonDone
}

// shutdownForTest 是固定预算的关停辅助（同包测试可访问未导出符号）：产品
// 文件只保留 ShutdownWithTimeout 的预算派生入口——固定预算调用若进产品符号
// 表，会被误当生产入口而绕过 shutdown.segment() 的预算切分。
func shutdownForTest(l *runtimeLifecycle) { l.ShutdownWithTimeout(acmeStopSegmentMax) }

// 关停预算的「段内锁等待」必须同样有界：并发停止长期持有证书启停互斥时，
// ShutdownWithTimeout 不得无界阻塞在锁上——否则最坏关停墙钟 =
// 25s + 一个停止预算，正好等于 compose stop_grace_period，设计余量归零。
func TestShutdownWithTimeout_lockWaitCountsAgainstBudget(t *testing.T) {
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker {
		return &blockingCertificateWorker{stop: make(chan struct{}), exited: make(chan struct{})}
	})
	// 模拟并发 StopACME 长期持有证书启停互斥。
	if !lifecycle.acquireACMEOps(time.Second) {
		t.Fatal("测试用启停互斥获取失败")
	}
	t.Cleanup(lifecycle.releaseACMEOps)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownWithTimeout 在证书启停锁上无界等待（段内锁等待未计入关停预算）")
	}
}

// 在途停止句柄不得被后续停止覆写：第二个停止若用自己的 finished 覆盖
// acmeStopDone，其快速完成会让 StartACME 误判前一个停止（仍在 PauseAndDrain
// 旧队列）也已收尾而拉起新一代。
func TestStopACME_keepsInFlightStopHandle(t *testing.T) {
	second := newStubLifecycleWorker()
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() lifecycleWorker { return second })

	inFlight := make(chan struct{})
	lifecycle.mu.Lock()
	lifecycle.acmeStopDone = inFlight
	lifecycle.mu.Unlock()
	var releaseOnce sync.Once
	releaseInFlight := func() {
		releaseOnce.Do(func() {
			lifecycle.mu.Lock()
			if lifecycle.acmeStopDone == inFlight {
				lifecycle.acmeStopDone = nil
			}
			lifecycle.mu.Unlock()
			close(inFlight)
		})
	}
	t.Cleanup(releaseInFlight)

	// 第二次停止：本代无 worker，但有一个已完成的 done 句柄——旧实现会为它
	// 登记新一代 finished 并在快速完成后清空跟踪字段。
	settled := make(chan struct{})
	close(settled)
	lifecycle.mu.Lock()
	lifecycle.certDone = settled
	lifecycle.mu.Unlock()
	lifecycle.stopACMEWithin(20 * time.Millisecond)

	lifecycle.mu.Lock()
	tracked := lifecycle.acmeStopDone
	lifecycle.mu.Unlock()
	if tracked != inFlight {
		t.Fatal("后续停止覆写了在途停止句柄——StartACME 会观测到错误的收尾信号")
	}

	// And 在途停止收尾前 StartACME 必须等待（不得立即装配新一代）。
	startReturned := make(chan struct{})
	go func() {
		defer close(startReturned)
		lifecycle.StartACME()
	}()
	select {
	case <-second.started:
		t.Fatal("在途停止未收尾时启动了新一代——在途 Stop 会关闭新队列")
	case <-time.After(150 * time.Millisecond):
	}
	releaseInFlight()
	select {
	case <-second.started:
	case <-time.After(2 * time.Second):
		t.Fatal("在途停止收尾后新一代仍未启动")
	}
	<-startReturned
}
