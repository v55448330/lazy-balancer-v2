package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// CRSBundledVersion is the CRS release baked into the container image; it is
// only used to seed security_crs_version when the row does not exist yet.
const CRSBundledVersion = "v4.28.0"

var ErrCRSUpdateRunning = errors.New("CRS 更新任务正在进行中")

type CRSUpdateStatus string

const (
	CRSStatusIdle        CRSUpdateStatus = "idle"
	CRSStatusChecking    CRSUpdateStatus = "checking"
	CRSStatusDownloading CRSUpdateStatus = "downloading"
	CRSStatusInstalling  CRSUpdateStatus = "installing"
	CRSStatusReloading   CRSUpdateStatus = "reloading"
	CRSStatusSuccess     CRSUpdateStatus = "success"
	CRSStatusFailed      CRSUpdateStatus = "failed"
)

var (
	crsLiveDir      = "/app/waf/crs"
	crsSnapshotDir  = "/app/data/crs"
	crsDistDir      = "/app/waf.dist/crs"
	crsUpdateLogDir = "/app/logs"
)

const crsTimeLayout = "2006-01-02 15:04:05"

type crsTaskState struct {
	status     CRSUpdateStatus
	trigger    string
	startedAt  time.Time
	finishedAt time.Time
	message    string
	version    string
}

// CRSUpdateStatusSnapshot is the point-in-time view served to handlers.
type CRSUpdateStatusSnapshot struct {
	Status     string
	Trigger    string
	StartedAt  string
	FinishedAt string
	Message    string
	Version    string
}

// CRSUpdateManager runs CRS manual/auto updates single-flight and persists
// terminal state in security_crs_version.
type CRSUpdateManager struct {
	mu           sync.Mutex
	running      bool
	state        crsTaskState
	runDone      chan struct{}
	ruleCount    int
	hasRuleCount bool

	reloader        func() error
	fetchLatestTag  func(ctx context.Context) (string, error)
	downloadTarball func(ctx context.Context, tag, destPath string) error
	crsDir          string

	latestMu         sync.Mutex
	latestTag        string
	latestKnown      bool
	latestFetchedAt  time.Time
	latestRefreshing bool

	schedulerMu       sync.Mutex
	schedulerStop     chan struct{}
	schedulerDone     chan struct{}
	schedulerInterval time.Duration
}

var (
	crsUpdateManager     *CRSUpdateManager
	crsUpdateManagerOnce sync.Once
)

func newCRSUpdateManager(reloader func() error) *CRSUpdateManager {
	return &CRSUpdateManager{
		reloader:          reloader,
		fetchLatestTag:    defaultFetchCRSLatestTag,
		downloadTarball:   defaultDownloadCRSTarball,
		crsDir:            crsLiveDir,
		ruleCount:         -1,
		schedulerInterval: time.Hour,
		state:             crsTaskState{status: CRSStatusIdle},
	}
}

// InitCRSUpdateManager initializes the singleton with the Caddy reloader.
func InitCRSUpdateManager(reloader func() error) {
	crsUpdateManagerOnce.Do(func() {
		crsUpdateManager = newCRSUpdateManager(reloader)
		// Seed the version row at init so the scheduler never finds an empty
		// table on fresh installs while the card displays auto-update as ON.
		ensureCRSVersionRow()
	})
}

func GetCRSUpdateManager() *CRSUpdateManager {
	return crsUpdateManager
}

func ResetCRSUpdateManagerForTest() {
	if crsUpdateManager != nil {
		crsUpdateManager.StopScheduler()
	}
	crsUpdateManager = nil
	crsUpdateManagerOnce = sync.Once{}
}

// SetCRSAutoUpdate toggles the auto-update flag without touching the stored
// version; a missing row is seeded with the image-bundled version.
func SetCRSAutoUpdate(enabled bool) error {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, ?)",
		CRSBundledVersion, enabled,
	); err != nil {
		return fmt.Errorf("初始化 CRS 版本记录: %w", err)
	}
	if _, err := db.DB.Exec("UPDATE security_crs_version SET auto_update=? WHERE id=1", enabled); err != nil {
		return fmt.Errorf("更新 CRS 自动更新开关: %w", err)
	}
	return nil
}

func ensureCRSVersionRow() {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, TRUE)",
		CRSBundledVersion,
	); err != nil {
		log.Printf("crs update: failed to ensure version row: %v", err)
	}
}

func currentCRSVersion() string {
	var version string
	if err := db.DB.QueryRow("SELECT version FROM security_crs_version WHERE id=1").Scan(&version); err != nil || version == "" {
		return CRSBundledVersion
	}
	return version
}

// StartUpdate begins an async update; only one may run at a time.
func (m *CRSUpdateManager) StartUpdate(trigger string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrCRSUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	m.state = crsTaskState{status: CRSStatusChecking, trigger: trigger, startedAt: time.Now().UTC()}
	done := m.runDone
	m.mu.Unlock()

	go func() {
		defer close(done)
		m.run(trigger)
	}()
	return nil
}

func (m *CRSUpdateManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *CRSUpdateManager) setStage(status CRSUpdateStatus, message string) {
	m.mu.Lock()
	m.state.status = status
	m.state.message = message
	m.mu.Unlock()
	level := "INFO"
	if status == CRSStatusFailed {
		level = "ERROR"
	}
	writeCRSUpdateLog(level, string(status), message)
}

// run executes the full update pipeline synchronously.
func (m *CRSUpdateManager) run(trigger string) {
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	ensureCRSVersionRow()
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET trigger=?, started_at=datetime('now'), finished_at=NULL WHERE id=1",
		trigger,
	); err != nil {
		log.Printf("crs update: failed to mark start: %v", err)
	}

	m.setStage(CRSStatusChecking, "查询最新 CRS 版本")
	tag, err := m.fetchLatestTag(context.Background())
	if _, dbErr := db.DB.Exec("UPDATE security_crs_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
		log.Printf("crs update: failed to record last_checked: %v", dbErr)
	}
	if err != nil {
		m.fail(err, false)
		return
	}
	writeCRSUpdateLog("INFO", string(CRSStatusChecking), fmt.Sprintf("最新版本 %s，当前版本 %s", tag, currentCRSVersion()))

	if tag == currentCRSVersion() {
		writeCRSUpdateLog("INFO", string(CRSStatusSuccess), "已是最新版本，无需更新")
		if _, err := db.DB.Exec(
			"UPDATE security_crs_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), consecutive_failures=0 WHERE id=1",
		); err != nil {
			log.Printf("crs update: failed to record latest-version skip: %v", err)
		}
		m.mu.Lock()
		m.state.status = CRSStatusSuccess
		m.state.message = "已是最新版本"
		m.state.finishedAt = time.Now().UTC()
		m.mu.Unlock()
		RecordAuditLog("system", "更新", "CRS 规则库", FormatAuditDetail("已是最新版本 "+tag, AuditResultPart("success")), "")
		return
	}

	m.mu.Lock()
	m.state.version = tag
	m.mu.Unlock()

	if err := m.downloadAndInstall(tag); err != nil {
		m.fail(err, true)
		return
	}

	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET version=?, updated_at=datetime('now'), update_status='success', message='', finished_at=datetime('now'), consecutive_failures=0 WHERE id=1",
		tag,
	); err != nil {
		log.Printf("crs update: failed to record success: %v", err)
	}
	m.rescanRuleCount()
	m.mu.Lock()
	m.state.status = CRSStatusSuccess
	m.state.message = ""
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeCRSUpdateLog("INFO", string(CRSStatusSuccess), fmt.Sprintf("CRS 已更新到 %s", tag))
	RecordAuditLog("system", "更新", "CRS 规则库", FormatAuditDetail("版本："+tag, AuditResultPart("success")), "")
}

func (m *CRSUpdateManager) fail(cause error, restore bool) {
	if restore {
		m.restoreBackup()
		if err := m.reloader(); err != nil {
			log.Printf("crs update: reload after restore failed: %v", err)
		}
	}
	// 连续失败计数 +1：仅首次失败写操作审计，后续重试只写组件日志（R35 I1），
	// 避免代理持续故障时每小时刷一条操作日志稀释审计线索。
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='failed', message=?, finished_at=datetime('now'), consecutive_failures=consecutive_failures+1 WHERE id=1",
		cause.Error(),
	); err != nil {
		log.Printf("crs update: failed to record failure: %v", err)
	}
	var failures int
	if err := db.DB.QueryRow("SELECT consecutive_failures FROM security_crs_version WHERE id=1").Scan(&failures); err != nil {
		failures = 1 // 计数读取失败时保守按首次失败处理（审计照常写入）
	}
	m.mu.Lock()
	_ = m.state.trigger
	m.state.status = CRSStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeCRSUpdateLog("ERROR", string(CRSStatusFailed), cause.Error())
	if failures <= 1 {
		RecordAuditLog("system", "更新", "CRS 规则库", FormatAuditDetail(cause.Error(), AuditResultPart("failed")), "")
	}
}

// StatusSnapshot returns the in-memory task view, falling back to the stored
// terminal state when no update has run since process start.
func (m *CRSUpdateManager) StatusSnapshot() CRSUpdateStatusSnapshot {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state.trigger != "" || !state.startedAt.IsZero() {
		return snapshotFromState(state)
	}
	return storedStatusSnapshot()
}
