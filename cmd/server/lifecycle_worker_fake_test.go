package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lifecycleWorkerFake 是关停/生命周期测试共用的可配置 worker，取代此前六份
// 手写同构夹具（blockingCertificateWorker / blockedStopCertificateWorker /
// blockingStopSyncWorker / blockingStopRecordWorker / stubLifecycleWorker /
// stuckCertificateWorker）。两个模式枚举 + 一个计数开关正交组合出全部生产形态：
//
//	Start 三态：
//	  fakeStartImmediate       Start 立即返回（默认）。
//	  fakeStartPendsUntilStop  Start 阻塞到 Stop 被调用、随后返回——生产证书
//	                           worker「Start 内等待轮询退出」的形态。
//	  fakeStartBlocksOnRelease Start 信号后阻塞到 Release——不响应停止的卡死
//	                           形态（collect 阻塞在 http.Client / DB busy_timeout）。
//	Stop 三态：
//	  fakeStopImmediate       Stop 立即返回（默认）。
//	  fakeStopBlocksOnRelease Stop 记账后阻塞到 Release——收尾被长时间占用的
//	                          生产形态（SyncService.Stop 等 pullWG、
//	                          CertificateService.Stop 末尾 <-s.done）。
//	  fakeStopUnblocksStart   释放 fakeStartPendsUntilStop 的 Start 并立即返回。
//	recordStops 开关：Stop 进入时对 stopCount 计数（单飞断言用）。
//
// 信号通道统一为「进入即关」：Started/StopEntered 在方法体首行关闭（等待方
// 断言「已进入」而不是「已返回」）；Exited 在 Start 返回时关闭。Release 经
// releaseNow 幂等放行（t.Cleanup 与用例内放行可同时注册）。
type lifecycleWorkerFake struct {
	startMode   fakeStartMode
	stopMode    fakeStopMode
	recordStops bool

	started     chan struct{}
	stopped     chan struct{}
	stopEntered chan struct{}
	exited      chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	unblockOnce sync.Once
	stopGate    chan struct{}
	stopCount   atomic.Int32
}

type fakeStartMode uint8

const (
	fakeStartImmediate fakeStartMode = iota
	fakeStartPendsUntilStop
	fakeStartBlocksOnRelease
)

type fakeStopMode uint8

const (
	fakeStopImmediate fakeStopMode = iota
	fakeStopBlocksOnRelease
	fakeStopUnblocksStart
)

func newLifecycleWorkerFake(startMode fakeStartMode, stopMode fakeStopMode) *lifecycleWorkerFake {
	return &lifecycleWorkerFake{
		startMode:   startMode,
		stopMode:    stopMode,
		started:     make(chan struct{}),
		stopped:     make(chan struct{}),
		stopEntered: make(chan struct{}),
		exited:      make(chan struct{}),
		release:     make(chan struct{}),
		stopGate:    make(chan struct{}),
	}
}

func (w *lifecycleWorkerFake) Start() {
	close(w.started)
	switch w.startMode {
	case fakeStartPendsUntilStop:
		<-w.stopGate
	case fakeStartBlocksOnRelease:
		<-w.release
	}
	close(w.exited)
}

func (w *lifecycleWorkerFake) Stop() {
	close(w.stopEntered)
	if w.recordStops {
		w.stopCount.Add(1)
	}
	switch w.stopMode {
	case fakeStopBlocksOnRelease:
		<-w.release
	case fakeStopUnblocksStart:
		w.unblockOnce.Do(func() { close(w.stopGate) })
	}
	close(w.stopped)
}

// releaseNow 幂等放行 Release（t.Cleanup 与用例内放行可同时注册）。
func (w *lifecycleWorkerFake) releaseNow() { w.releaseOnce.Do(func() { close(w.release) }) }

// assertNewGenerationBlockedUntilStopSettles 断言「在途停止收尾前新一代不得
// 启动、收尾后必须启动」：StartACME 在 goroutine 内请求，先钉 150ms 内不启动
// （在途 queue.Stop 会关掉新一代队列——证书签发静默停摆的回归形态），放行
// settle 后 2s 内必须启动。返回时 StartACME 已返回。
func assertNewGenerationBlockedUntilStopSettles(t *testing.T, lifecycle *runtimeLifecycle, newGenStarted <-chan struct{}, settle func()) {
	t.Helper()
	startReturned := make(chan struct{})
	go func() {
		defer close(startReturned)
		lifecycle.StartACME()
	}()
	select {
	case <-newGenStarted:
		t.Fatal("在途停止未收尾时启动了新一代——在途 Stop 会关闭新队列")
	case <-time.After(150 * time.Millisecond):
	}
	settle()
	select {
	case <-newGenStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("在途停止收尾后新一代仍未启动")
	}
	<-startReturned
}
