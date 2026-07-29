package main

import (
	"sync"
	"testing"
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
