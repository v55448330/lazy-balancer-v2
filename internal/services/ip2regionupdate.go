package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

var ErrIP2RegionUpdateRunning = errors.New("IP2Region 更新任务正在进行中")

type IP2RegionUpdateStatus string

const (
	IP2RegionStatusIdle        IP2RegionUpdateStatus = "idle"
	IP2RegionStatusChecking    IP2RegionUpdateStatus = "checking"
	IP2RegionStatusDownloading IP2RegionUpdateStatus = "downloading"
	IP2RegionStatusInstalling  IP2RegionUpdateStatus = "installing"
	IP2RegionStatusReloading   IP2RegionUpdateStatus = "reloading"
	IP2RegionStatusSuccess     IP2RegionUpdateStatus = "success"
	IP2RegionStatusFailed      IP2RegionUpdateStatus = "failed"
)

// IP2RegionUpdateManager runs ip2region xdb updates single-flight and persists
// terminal state in security_ip2region_version.
type IP2RegionUpdateManager struct {
	mu      sync.Mutex
	running bool
	state   ip2RegionTaskState
	runDone chan struct{}

	reloader       func() error
	fetchLatestTag func(ctx context.Context) (tag string, err error)
	downloadXDB    func(ctx context.Context, tag, destPath string) error

	schedulerMu       sync.Mutex
	schedulerStop     chan struct{}
	schedulerDone     chan struct{}
	schedulerInterval time.Duration
}

var (
	ip2RegionUpdateManager     *IP2RegionUpdateManager
	ip2RegionUpdateManagerOnce sync.Once
)

func newIP2RegionUpdateManager(reloader func() error) *IP2RegionUpdateManager {
	return &IP2RegionUpdateManager{
		reloader:          reloader,
		fetchLatestTag:    defaultFetchIP2RegionLatestTag,
		downloadXDB:       defaultDownloadIP2RegionXDB,
		schedulerInterval: time.Hour,
		state:             ip2RegionTaskState{status: IP2RegionStatusIdle},
	}
}

// InitIP2RegionUpdateManager initializes the singleton with the Caddy reloader.
func InitIP2RegionUpdateManager(reloader func() error) {
	ip2RegionUpdateManagerOnce.Do(func() {
		ip2RegionUpdateManager = newIP2RegionUpdateManager(reloader)
		ensureIP2RegionVersionRow()
	})
}

func GetIP2RegionUpdateManager() *IP2RegionUpdateManager {
	return ip2RegionUpdateManager
}

func ResetIP2RegionUpdateManagerForTest() {
	if ip2RegionUpdateManager != nil {
		ip2RegionUpdateManager.StopScheduler()
	}
	ip2RegionUpdateManager = nil
	ip2RegionUpdateManagerOnce = sync.Once{}
}

// SetIP2RegionAutoUpdate toggles the auto-update flag without touching the
// stored version; a missing row is seeded with the fallback version.
func SetIP2RegionAutoUpdate(enabled bool) error {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'unknown', ?)",
		enabled,
	); err != nil {
		return fmt.Errorf("初始化 IP2Region 版本记录: %w", err)
	}
	nextUpdate := ""
	if enabled {
		nextUpdate = time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET auto_update=?, next_update=? WHERE id=1", enabled, nextUpdate); err != nil {
		return fmt.Errorf("更新 IP2Region 自动更新开关: %w", err)
	}
	return nil
}

func ensureIP2RegionVersionRow() {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'unknown', FALSE)",
	); err != nil {
		log.Printf("ip2region update: failed to ensure version row: %v", err)
	}
}

func currentIP2RegionVersion() string {
	var version string
	if err := db.DB.QueryRow("SELECT version FROM security_ip2region_version WHERE id=1").Scan(&version); err != nil || version == "" {
		return "unknown"
	}
	return version
}

// StartUpdate begins an async update; only one may run at a time.
func (m *IP2RegionUpdateManager) StartUpdate(trigger string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrIP2RegionUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	m.state = ip2RegionTaskState{status: IP2RegionStatusChecking, trigger: trigger, startedAt: time.Now().UTC()}
	done := m.runDone
	m.mu.Unlock()

	go func() {
		defer close(done)
		m.run(trigger)
	}()
	return nil
}

func (m *IP2RegionUpdateManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *IP2RegionUpdateManager) setStage(status IP2RegionUpdateStatus, message string) {
	m.mu.Lock()
	m.state.status = status
	m.state.message = message
	m.mu.Unlock()
	level := "INFO"
	if status == IP2RegionStatusFailed {
		level = "ERROR"
	}
	writeIP2RegionUpdateLog(level, string(status), message)
}

// run executes the full update pipeline synchronously.
func (m *IP2RegionUpdateManager) run(trigger string) {
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	ensureIP2RegionVersionRow()
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET trigger=?, started_at=datetime('now'), finished_at=NULL WHERE id=1",
		trigger,
	); err != nil {
		log.Printf("ip2region update: failed to mark start: %v", err)
	}

	m.setStage(IP2RegionStatusChecking, "查询最新 ip2region 版本")
	tag, err := m.fetchLatestTag(context.Background())
	if _, dbErr := db.DB.Exec("UPDATE security_ip2region_version SET last_checked=datetime('now') WHERE id=1"); dbErr != nil {
		log.Printf("ip2region update: failed to record last_checked: %v", dbErr)
	}
	if err != nil {
		m.fail(err)
		return
	}
	writeIP2RegionUpdateLog("INFO", string(IP2RegionStatusChecking), fmt.Sprintf("最新版本 %s，当前版本 %s", tag, currentIP2RegionVersion()))

	if tag == currentIP2RegionVersion() {
		writeIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), "已是最新版本，无需更新")
		if _, err := db.DB.Exec(
			"UPDATE security_ip2region_version SET update_status='success', message='已是最新版本', finished_at=datetime('now') WHERE id=1",
		); err != nil {
			log.Printf("ip2region update: failed to record latest-version skip: %v", err)
		}
		m.mu.Lock()
		m.state.status = IP2RegionStatusSuccess
		m.state.message = "已是最新版本"
		m.state.finishedAt = time.Now().UTC()
		m.mu.Unlock()
		if trigger == "auto" {
			RecordAuditLog("system", "自动更新", "IP2Region 数据库", FormatAuditDetail("已是最新版本 "+tag, AuditResultPart("success")), "")
		}
		return
	}

	m.mu.Lock()
	m.state.version = tag
	m.mu.Unlock()

	if err := m.downloadAndInstall(tag); err != nil {
		m.fail(fmt.Errorf("安装 ip2region xdb 失败: %w", err))
		return
	}

	m.setStage(IP2RegionStatusReloading, "重载 Caddy 配置")
	if err := m.reloader(); err != nil {
		m.fail(fmt.Errorf("重载 Caddy 配置失败: %w", err))
		return
	}

	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET version=?, updated_at=datetime('now'), update_status='success', message='', finished_at=datetime('now') WHERE id=1",
		tag,
	); err != nil {
		log.Printf("ip2region update: failed to record success: %v", err)
	}
	SetIP2RegionVersion(tag)
	m.mu.Lock()
	m.state.status = IP2RegionStatusSuccess
	m.state.message = ""
	m.state.version = tag
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), fmt.Sprintf("ip2region 已更新到 %s", tag))
	if trigger == "auto" {
		RecordAuditLog("system", "自动更新", "IP2Region 数据库", FormatAuditDetail("版本："+tag, AuditResultPart("success")), "")
	}
}

func (m *IP2RegionUpdateManager) fail(cause error) {
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET update_status='failed', message=?, finished_at=datetime('now') WHERE id=1",
		cause.Error(),
	); err != nil {
		log.Printf("ip2region update: failed to record failure: %v", err)
	}
	m.mu.Lock()
	trigger := m.state.trigger
	m.state.status = IP2RegionStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeIP2RegionUpdateLog("ERROR", string(IP2RegionStatusFailed), cause.Error())
	if trigger == "auto" {
		RecordAuditLog("system", "自动更新", "IP2Region 数据库", FormatAuditDetail(cause.Error(), AuditResultPart("failed")), "")
	}
}

// downloadAndInstall downloads, validates and atomically swaps in the new xdb.
func (m *IP2RegionUpdateManager) downloadAndInstall(tag string) error {
	m.setStage(IP2RegionStatusDownloading, fmt.Sprintf("下载 %s", tag))
	stagingDir := filepath.Join(filepath.Dir(ip2regionLivePath), ".staging")
	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("清理 staging 目录: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("创建 staging 目录: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(stagingDir); err != nil {
			log.Printf("ip2region update: failed to clean staging dir: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	staged := filepath.Join(stagingDir, "ip2region_v4.xdb")
	if err := m.downloadXDB(ctx, tag, staged); err != nil {
		return fmt.Errorf("下载 ip2region xdb: %w", err)
	}

	m.setStage(IP2RegionStatusInstalling, "校验并安装数据库")
	if err := validateIP2RegionXDB(staged); err != nil {
		return err
	}
	if err := os.Rename(staged, ip2regionLivePath); err != nil {
		return fmt.Errorf("安装 ip2region xdb: %w", err)
	}
	Reload()
	return nil
}

// validateIP2RegionXDB opens the staged xdb and performs a probe search.
func validateIP2RegionXDB(path string) error {
	searcher, err := openIP2RegionSearcher(path)
	if err != nil {
		return fmt.Errorf("校验 ip2region xdb: %w", err)
	}
	defer searcher.Close()
	if _, err := searcher.Search("114.114.114.114"); err != nil {
		return fmt.Errorf("校验 ip2region xdb 搜索失败: %w", err)
	}
	return nil
}
