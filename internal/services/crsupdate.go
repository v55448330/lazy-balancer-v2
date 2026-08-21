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

	// overridesBakCreated 标记本次运行已在迁移分支创建 zz-user-overrides.conf.bak
	// （R39 1.1）：restoreBackup 只消费本运行创建的 bak——三-1 跨运行保全的恢复
	// 副本在下次成功更新前始终可用，三-2 也不会把 overrides 还原到两版本之前。
	// 每次 downloadAndInstall 开始时重置，迁移分支创建成功后置位。
	overridesBakCreated bool

	reloader        func() error
	fetchLatestTag  func(ctx context.Context) (string, error)
	downloadTarball func(ctx context.Context, tag, destPath string, progress downloadProgressFunc) error
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

	// 起点角色复查（R54-N5）：调度器 tick 的 is_master 守卫与更新启动之间存在
	// demote 竞态窗口——tick 越过守卫、更新刚发出时节点被降级，从节点继续执行
	// 会写本地版本行、替换规则树并 reload，瞬时打破只读不变量。
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,0) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		m.setStage(CRSStatusFailed, "当前节点为从节点，终止 CRS 更新")
		return
	}

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
		RecordAuditLog("system", "更新", "CRS规则库", FormatAuditDetail("已是最新版本 "+tag, AuditResultPart("success")), "")
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
	RecordAuditLog("system", "更新", "CRS规则库", FormatAuditDetail("版本："+tag, AuditResultPart("success")), "")
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
	// 先读当前计数，审计判定用「当前计数+1」（与 UPDATE 落库同一数值来源）：
	// UPDATE 失败时判定不会回退到旧计数，避免第 2 次失败重复写审计（R36 F3）。
	var failures int
	if err := db.DB.QueryRow("SELECT consecutive_failures FROM security_crs_version WHERE id=1").Scan(&failures); err != nil {
		failures = 0 // 计数读取失败时保守按首次失败处理（审计照常写入）
	}
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET update_status='failed', message=?, finished_at=datetime('now'), consecutive_failures=consecutive_failures+1 WHERE id=1",
		cause.Error(),
	); err != nil {
		log.Printf("crs update: failed to record failure: %v", err)
	}
	m.mu.Lock()
	m.state.status = CRSStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeCRSUpdateLog("ERROR", string(CRSStatusFailed), cause.Error())
	if failures+1 <= 1 {
		RecordAuditLog("system", "更新", "CRS规则库", FormatAuditDetail(cause.Error(), AuditResultPart("failed")), "")
	}
}

// downloadTarballLogged 包装下载 seam 写更新日志（R57）：开始行由下载函数的
// (0, total) 开始信号触发，携带完整来源 URL（含 ghfast 代理前缀），
// Content-Length 已知时附预计大小；进度行经节流闭包按 10%（总量已知）/5MB
// （未知）步进；完成行记录落盘字节与耗时。stage 沿用下载阶段的 downloading。
func (m *CRSUpdateManager) downloadTarballLogged(ctx context.Context, tag, destPath string) error {
	logLine := func(message string) { writeCRSUpdateLog("INFO", string(CRSStatusDownloading), message) }
	startedAt := time.Now()
	progress := newDownloadProgressLogger(crsTarballSourceURL(tag), logLine)
	if err := m.downloadTarball(ctx, tag, destPath, progress); err != nil {
		return err
	}
	logDownloadCompletion(logLine, destPath, startedAt)
	return nil
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
