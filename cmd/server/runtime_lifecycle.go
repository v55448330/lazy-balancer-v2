package main

import (
	"sync"

	"lazy-balancer-v2/internal/services"
)

type certificateWorker interface {
	Start()
	Stop()
}

type syncWorker interface {
	Start()
	Stop()
}

type runtimeLifecycle struct {
	mu          sync.Mutex
	syncService syncWorker
	certFactory func() certificateWorker
	certService certificateWorker
	certDone    chan struct{}
}

func newRuntimeLifecycle(syncService syncWorker, certFactory func() certificateWorker) *runtimeLifecycle {
	return &runtimeLifecycle{syncService: syncService, certFactory: certFactory}
}

func (l *runtimeLifecycle) StartACME() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.certService != nil {
		return
	}
	if queue := services.GetCAQueueManager(); queue != nil {
		queue.Start()
	}
	worker := l.certFactory()
	done := make(chan struct{})
	l.certService = worker
	l.certDone = done
	go func() {
		defer close(done)
		worker.Start()
	}()
}

func (l *runtimeLifecycle) StopACME() {
	l.mu.Lock()
	if queue := services.GetCAQueueManager(); queue != nil {
		queue.Stop()
	}
	worker := l.certService
	done := l.certDone
	l.certService = nil
	l.certDone = nil
	if worker != nil {
		worker.Stop()
	}
	l.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (l *runtimeLifecycle) StartSync() { l.syncService.Start() }
func (l *runtimeLifecycle) StopSync()  { l.syncService.Stop() }

func (l *runtimeLifecycle) Shutdown() {
	l.StopSync()
	l.StopACME()
}
