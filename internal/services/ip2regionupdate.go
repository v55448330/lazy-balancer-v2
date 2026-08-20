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

// errIP2RegionReload 标记「安装后内存热换失败」（R46 B-F1）：此时磁盘已是新库
// 而内存 searcher 仍是旧库，run() 须走与 reloader 失败相同的回滚路径，不得按
// 普通安装失败直接落库（磁盘/内存/DB 会三方分叉）。
var errIP2RegionReload = errors.New("重载 ip2region 内存索引失败")

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

	// bakCreated 标记本次运行已创建 ip2region.xdb.bak（R40 F1，镜像 CRS 的
	// overridesBakCreated，crsinstall.go:51/:139/:245）：rollbackXDB 只消费本
	// 运行创建的 bak——跨运行崩溃窗口（rename 成功后、reloader 前崩溃）残留的
	// 陈旧 .bak 是旧 xdb 唯一副本，非本运行创建时视为无需回滚，不得消费。
	// 每次 run() 开始时重置，downloadAndInstall 备份成功后置位。
	bakCreated bool

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

	// 每次运行重置：rollbackXDB 仅消费本运行创建的 .bak（R40 F1）。
	m.bakCreated = false

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
			"UPDATE security_ip2region_version SET update_status='success', message='已是最新版本', finished_at=datetime('now'), consecutive_failures=0 WHERE id=1",
		); err != nil {
			log.Printf("ip2region update: failed to record latest-version skip: %v", err)
		}
		m.mu.Lock()
		m.state.status = IP2RegionStatusSuccess
		m.state.message = "已是最新版本"
		m.state.finishedAt = time.Now().UTC()
		m.mu.Unlock()
		RecordAuditLog("system", "更新", "IP数据库", FormatAuditDetail("已是最新版本 "+tag, AuditResultPart("success")), "")
		return
	}

	m.mu.Lock()
	m.state.version = tag
	m.mu.Unlock()

	installErr := m.downloadAndInstall(tag)
	if installErr != nil && !errors.Is(installErr, errIP2RegionReload) {
		m.fail(fmt.Errorf("安装 ip2region xdb 失败: %w", installErr))
		return
	}

	m.setStage(IP2RegionStatusReloading, "重载 Caddy 配置")
	// R46 B-F1：安装后内存热换失败视同 reloader 失败进入同一回滚路径（磁盘已是
	// 新库、内存仍是旧库，直接按 failed 落库会重演三方分叉）；此时不再调用
	// reloader，直接回滚。memSwitched 记录内存 searcher 是否已切到新库，供
	// fail-open 的 message 注明「内存未切换、重启后生效」。
	reloadErr := installErr
	memSwitched := installErr == nil
	if reloadErr == nil {
		reloadErr = m.reloader()
	}
	if reloadErr != nil {
		// 回滚旧 xdb 并再次重载（镜像 CRS fail() 路径，R39 1.2）：reloader 失败
		// 时磁盘与内存 searcher 都还原到更新前状态，避免「磁盘已是新库、DB 记录
		// 旧版本+failed」的长期不一致。回滚或重试失败仅记录，不改变失败落库。
		restored, rbErr := m.rollbackXDB()
		switch {
		case rbErr != nil:
			// R45 F1-A：回滚升级链（rename→copy→dist）全部失败——磁盘已是新库，
			// 若按 failed+旧版本落库会重演三方分叉；改走 fail-open 让 DB
			// 跟随实际状态，rbErr 记录到组件日志供排查。
			log.Printf("ip2region update: rollback xdb failed, fail-open with new xdb recorded: %v", rbErr)
			m.successAfterReloadFailOpen(tag, reloadErr, memSwitched)
			return
		case restored:
			if rErr := m.reloader(); rErr != nil {
				log.Printf("ip2region update: reload after rollback failed: %v", rErr)
			}
			if errors.Is(reloadErr, errIP2RegionReload) {
				m.fail(reloadErr)
			} else {
				m.fail(fmt.Errorf("重载 Caddy 配置失败: %w", reloadErr))
			}
			return
		default:
			// R44 F1 fail-open：bakCreated==false（全新部署首次更新，无旧 live
			// 可备份）且 dist 也缺失，无任何「更新前基线」可回退。此时磁盘已是
			// 新库，若仍按 failed 落库会重演「磁盘/内存新库、DB 记
			// failed+旧版本」的三方不一致；按成功落库让 DB 追上实际状态。
			m.successAfterReloadFailOpen(tag, reloadErr, memSwitched)
			return
		}
	}
	os.Remove(ip2regionLivePath + ".bak")

	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET version=?, updated_at=datetime('now'), update_status='success', message='', finished_at=datetime('now'), consecutive_failures=0 WHERE id=1",
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
	RecordAuditLog("system", "更新", "IP数据库", FormatAuditDetail("版本："+tag, AuditResultPart("success")), "")
}

func (m *IP2RegionUpdateManager) fail(cause error) {
	// 连续失败计数 +1：仅首次失败写操作审计，后续重试只写组件日志（R35 I1），
	// 避免代理持续故障时每小时刷一条操作日志稀释审计线索。
	// 先读当前计数，审计判定用「当前计数+1」（与 UPDATE 落库同一数值来源）：
	// UPDATE 失败时判定不会回退到旧计数，避免第 2 次失败重复写审计（R36 F3）。
	var failures int
	if err := db.DB.QueryRow("SELECT consecutive_failures FROM security_ip2region_version WHERE id=1").Scan(&failures); err != nil {
		failures = 0 // 计数读取失败时保守按首次失败处理（审计照常写入）
	}
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET update_status='failed', message=?, finished_at=datetime('now'), consecutive_failures=consecutive_failures+1 WHERE id=1",
		cause.Error(),
	); err != nil {
		log.Printf("ip2region update: failed to record failure: %v", err)
	}
	m.mu.Lock()
	m.state.status = IP2RegionStatusFailed
	m.state.message = cause.Error()
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeIP2RegionUpdateLog("ERROR", string(IP2RegionStatusFailed), cause.Error())
	if failures+1 <= 1 {
		RecordAuditLog("system", "更新", "IP数据库", FormatAuditDetail(cause.Error(), AuditResultPart("failed")), "")
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
	// TOFU 完整性基线在格式验证成功之后记录（R33 F6）：验证前的坏工件留下基线
	// 会让下次同 tag 好下载误报。记录失败不阻断安装。
	if ierr := recordDownloadIntegrity(ip2RegionXDBSourceURL(tag), staged, "IP数据库"); ierr != nil {
		log.Printf("ip2region update: failed to record download integrity: %v", ierr)
	}
	// R39 1.2：rename 前备份旧 xdb，reloader 失败时可回滚（镜像 CRS 的
	// restoreBackup 路径），与 CRS 更新侧保持对称。
	liveBak := ip2regionLivePath + ".bak"
	if _, err := os.Stat(ip2regionLivePath); err == nil {
		if err := copyFile(ip2regionLivePath, liveBak); err != nil {
			return fmt.Errorf("备份旧 ip2region xdb: %w", err)
		}
		m.bakCreated = true
	}
	if err := os.Rename(staged, ip2regionLivePath); err != nil {
		// 安装未发生：清理备份，避免陈旧 .bak 干扰后续运行的回滚判断。
		os.Remove(liveBak)
		return fmt.Errorf("安装 ip2region xdb: %w", err)
	}
	// R46 B-F1：rename 后内存热换失败不得静默吞掉——磁盘已是新库而内存仍是旧
	// 库，必须按安装失败处理（sentinel 标记），由 run() 走与 reloader 失败相同
	// 的回滚路径。Reload 失败时旧 searcher 保持服役（ip2region.go Reload 语义）。
	if err := reloadIP2RegionSearcher(); err != nil {
		return fmt.Errorf("%w: %v", errIP2RegionReload, err)
	}
	return nil
}

// rollbackXDB 将本次更新前备份的旧 xdb 还原到 live 路径并热换内存 searcher
// （R39 1.2，镜像 CRS 的 restoreBackup）。返回 restored=true 表示磁盘/内存已
// 回到「更新前基线」，调用方按 failed 落库即三方一致；restored=false 且 err=nil
// 表示无任何基线可用，由调用方按 fail-open 处理（R44 F1）。
//
// 基线优先级：本运行创建的 .bak > dist 发行版副本。陈旧 .bak（跨运行崩溃窗口
// 的保全副本）永不消费（R40 F1）；bakCreated==false 时回退到 ip2regionDistPath
// ——全新部署首次更新无旧 live 可备份，dist 即「更新前状态」的权威副本。dist
// 也缺失时不做任何改动，返回 restored=false。
//
// .bak 还原升级链（R45 F1-A，R46 B-F4 口径修正）：rename 失败（非权限类的瞬
// 时故障，如偶发 IO 错误）不等于基线丢失——.bak 仍在磁盘，升级为 copyFile 还
// 原；权限类失败（目录不可写）下 copyFile 需要同一目录的写权限、必然同败，
// 会直接落到 dist 回退；全部失败才返回 error，由调用方走 fail-open（DB 必须
// 跟随实际状态，不得记 failed+旧版本重演三方分叉）。
//
// 每级的内存热换同样计入该级成败（R46 B-F1）：还原磁盘后 Reload 失败视为该级
// 还原失败，继续升级；全部级别热换失败最终落入 error→fail-open，调用方在
// message 中注明内存 searcher 未切换、重启后生效。
func (m *IP2RegionUpdateManager) rollbackXDB() (restored bool, err error) {
	if m.bakCreated {
		bak := ip2regionLivePath + ".bak"
		if _, err := os.Stat(bak); err == nil {
			if err := osRename(bak, ip2regionLivePath); err == nil {
				if err := reloadIP2RegionSearcher(); err == nil {
					return true, nil
				} else {
					log.Printf("ip2region update: reload after rename restore failed (%v), escalating to next restore level", err)
				}
			} else {
				log.Printf("ip2region update: rename bak to live failed (%v), trying copy restore (permission-class failures will fall through to dist)", err)
			}
			if err := copyFile(bak, ip2regionLivePath); err == nil {
				if err := reloadIP2RegionSearcher(); err == nil {
					// copy 还原不消费 .bak：成功后清理，与 rename 消费语义对齐，
					// 避免残留陈旧副本干扰后续运行判断。
					if rErr := os.Remove(bak); rErr != nil {
						log.Printf("ip2region update: failed to remove bak after copy restore: %v", rErr)
					}
					return true, nil
				} else {
					log.Printf("ip2region update: reload after copy restore failed (%v), escalating to dist fallback", err)
				}
			} else {
				log.Printf("ip2region update: copy restore from bak failed: %v", err)
			}
		}
	}
	if _, err := os.Stat(ip2regionDistPath); err != nil {
		return false, nil
	}
	if err := copyFile(ip2regionDistPath, ip2regionLivePath); err != nil {
		return false, fmt.Errorf("回退到发行版 ip2region xdb: %w", err)
	}
	if err := reloadIP2RegionSearcher(); err != nil {
		return false, fmt.Errorf("发行版回退后重载 ip2region 内存索引: %w", err)
	}
	return true, nil
}

// successAfterReloadFailOpen 在「reloader 失败但无任何回退基线」时按成功落库
// （R44 F1 fail-open）：磁盘已是新库，DB 记录 success+新 tag 让三方一致；
// message 保留 reloader 错误以便排查 Caddy 侧问题，审计同样记成功但附带上该
// 警告。落库前与 restored 分支对称补一次 reloader 重试（R45 F1-C）：重试成功
// 则 Caddy 即刻追上新库、按无警告成功落库；仍失败则在 message 中注明 Caddy
// 侧 GeoIP 停留在旧库、待下次任意成功重载后生效。memSwitched=false（安装热换
// 失败，R46 B-F1）时 message 还须注明内存 searcher 未切换、重启后生效——否则
// DB 记 success 而内存仍是旧库，重启前无任何可见痕迹。
func (m *IP2RegionUpdateManager) successAfterReloadFailOpen(tag string, reloadErr error, memSwitched bool) {
	warn := ""
	if rErr := m.reloader(); rErr != nil {
		log.Printf("ip2region update: fail-open reload retry failed: %v", rErr)
		warn = fmt.Sprintf("已生效，但重载 Caddy 配置失败: %v（Caddy 侧待下次重载生效）", reloadErr)
	} else {
		log.Printf("ip2region update: fail-open reload retry succeeded, caddy caught up to %s", tag)
	}
	if !memSwitched {
		if warn != "" {
			warn += "；"
		}
		warn += "内存 searcher 未切换，重启后生效"
	}
	if _, err := db.DB.Exec(
		"UPDATE security_ip2region_version SET version=?, updated_at=datetime('now'), update_status='success', message=?, finished_at=datetime('now'), consecutive_failures=0 WHERE id=1",
		tag, warn,
	); err != nil {
		log.Printf("ip2region update: failed to record fail-open success: %v", err)
	}
	SetIP2RegionVersion(tag)
	m.mu.Lock()
	m.state.status = IP2RegionStatusSuccess
	m.state.message = warn
	m.state.version = tag
	m.state.finishedAt = time.Now().UTC()
	m.mu.Unlock()
	writeIP2RegionUpdateLog("INFO", string(IP2RegionStatusSuccess), fmt.Sprintf("ip2region 已更新到 %s（%s）", tag, warn))
	RecordAuditLog("system", "更新", "IP数据库", FormatAuditDetail("版本："+tag+"（"+warn+"）", AuditResultPart("success")), "")
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
