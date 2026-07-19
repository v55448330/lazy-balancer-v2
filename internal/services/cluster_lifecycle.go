package services

import "sync"

type RuntimeLifecycle struct {
	mu          sync.Mutex
	syncService *SyncService
	certFactory func() *CertificateService
	certService *CertificateService
}

func NewRuntimeLifecycle(syncService *SyncService, certFactory func() *CertificateService) *RuntimeLifecycle {
	return &RuntimeLifecycle{syncService: syncService, certFactory: certFactory}
}

func (l *RuntimeLifecycle) StartACME() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.certService != nil {
		return
	}
	if queue := GetCAQueueManager(); queue != nil {
		queue.Start()
	}
	l.certService = l.certFactory()
	go l.certService.Start()
}

func (l *RuntimeLifecycle) StopACME() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if queue := GetCAQueueManager(); queue != nil {
		queue.Stop()
	}
	if l.certService != nil {
		l.certService.Stop()
		l.certService = nil
	}
}

func (l *RuntimeLifecycle) StartSync() { l.syncService.Start() }
func (l *RuntimeLifecycle) StopSync()  { l.syncService.Stop() }

func (l *RuntimeLifecycle) Shutdown() {
	l.StopSync()
	l.StopACME()
}
