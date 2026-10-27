package db

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqlite "github.com/glebarez/go-sqlite"
)

var sqliteHeaderMagic = []byte("SQLite format 3\x00")

// nextQuarantinePath 返回不与现存文件冲突的隔离目标路径：<path>.corrupt.<unix秒>；
// 同秒已有同名隔离文件时追加 -1/-2/… 序号（同秒两次隔离不再静默覆盖
// 此前的取证文件——Unix rename 对已存在目标是直接替换）。stat-then-rename 的
// 窗口仅存在于启动单线程路径，极端竞态下回退为旧的覆盖行为，不劣于修复前。
func nextQuarantinePath(path string) string {
	base := fmt.Sprintf("%s.corrupt.%d", path, time.Now().Unix())
	for i := 1; ; i++ {
		candidate := base
		if i > 1 {
			// 后缀从 -1 起（i-1）——旧式 i 使序号
			// 跳号（base→base-2，base-1 永不生成）。
			candidate = fmt.Sprintf("%s-%d", base, i-1)
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		} else if err != nil {
			// 持久 Stat 错误（父路径 ENOTDIR/EACCES 等）——记日志返回现值，
			// 不得无界自旋。后续 Rename 失败由调用方处理。
			log.Printf("nextQuarantinePath: stat %s: %v（返回现值候选路径）", candidate, err)
			return candidate
		}
	}
}

// quarantineRename 是 os.Rename 的注入缝（测试覆盖伴生文件改名失败路径）。
var quarantineRename = os.Rename

// quarantineCompanions 把主库 path 的 -wal/-shm 伴生文件一并改名为
// <companion>.corrupt.<unix秒>。伴生文件承载未检查点化页与共享
// 内存：主库改名后若静默留下旧 WAL，重建的新库下次打开会重放脏 WAL，再现
// 损坏。因此任一伴生文件改名失败必须返回错误（由调用方中止重建/响亮失败），
// 不得忽略。缺失伴生文件按正常路径跳过。
func quarantineCompanions(path string) error {
	var errs []error
	for _, companion := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(companion); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("stat %s: %w", filepath.Base(companion), err))
			}
			continue
		}
		if err := quarantineRename(companion, nextQuarantinePath(companion)); err != nil {
			errs = append(errs, fmt.Errorf("quarantine companion %s: %w", filepath.Base(companion), err))
		}
	}
	return errors.Join(errs...)
}

// quarantineCorruptSQLiteFile 检查 path 指向的库文件：存在、非空、且前
// 16 字节不是 SQLite 魔数（头部页被清零/覆写的损坏形态）时，连同可能
// 残留的 -wal/-shm 伴生文件一并改名为 <path>.corrupt.<unix秒> 隔离，
// 返回隔离后的主文件路径；空文件（待建库）与头部有效的库原样保留。
func quarantineCorruptSQLiteFile(path string) (string, error) {
	header := make([]byte, len(sqliteHeaderMagic))
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	n, readErr := io.ReadFull(f, header)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return "", errors.Join(readErr, closeErr)
	}
	if n == 0 || (n == len(sqliteHeaderMagic) && bytes.Equal(header, sqliteHeaderMagic)) {
		return "", nil
	}
	// 先隔离 -wal/-shm，主文件最后改名：伴生失败时主库仍在原位且调用方
	// 中止重建，不会在残留旧 WAL 的同名路径新建空库。故障解除后可原样重试。
	if err := quarantineCompanions(path); err != nil {
		return "", err
	}
	quarantined := nextQuarantinePath(path)
	if err := os.Rename(path, quarantined); err != nil {
		return "", fmt.Errorf("quarantine corrupted database file: %w", err)
	}
	return quarantined, nil
}

// reportMetricsQuarantine 记录隔离重建的完整后果：进程日志 + 系统审计
// （审计库就绪后落 audit_log，审计页可见）。metrics 库同库承载
// security_events 与 threat 大屏 rollup，隔离会丢弃安全事件历史——必须显式
// 告知丢弃范围与隔离文件位置，不能只留一行 "metrics history reset"。
func reportMetricsQuarantine(cause, quarantinePath string) {
	detail := fmt.Sprintf("问题: metrics 库损坏（%s）；已隔离为 %s 并重建——指标历史与安全事件历史（security_events / security_event_rollup / security_event_target_rollup）一并丢弃，需从隔离文件人工取证",
		cause, filepath.Base(quarantinePath))
	log.Print(detail)
	recordSystemAudit("库自愈", "指标库", detail)
}

const MetricsDBFilename = "lazy-balancer-metrics.db"

func InitializeMetricsDB(dataDir string) (err error) {
	dbPath := filepath.Join(dataDir, MetricsDBFilename)
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to secure metrics data directory: %w", err)
	}
	// 先清扫历史隔离文件（含崩循环残留）：每基础名留最新 3 份，防止
	// 取证文件无界累积；本轮新隔离叠加其上，下次启动再收敛。
	gcQuarantinedMetricsFiles(dbPath)
	if err := prepareSQLiteDatabase(dbPath); err != nil {
		return fmt.Errorf("failed to secure metrics database: %w", err)
	}
	// 损坏自愈（生产事故：宿主丢写致页 1 清零 → Ping NOTADB → 启动崩循环
	// 27 分钟无自愈）。
	//
	// 本库**不是**「可丢弃遥测」：同库承载两类数据——①metrics_history（指标
	// 历史，纯遥测，可再生）；②security_events / security_event_rollup /
	// security_event_target_rollup（安全事件历史：攻击取证、触发详情、大屏
	// 预聚合，不可再生，由 security_events_retention_days / _row_cap 独立保留
	// 策略治理，见 services.securityEventsRetentionPolicy）。隔离重建意味着安全
	// 事件历史一并丢弃，必须显式披露（进程日志 + 系统审计留痕），不得只写
	// 「metrics history reset」。隔离文件保留最新 3 份供人工取证。
	//
	// 两段防线——①头部魔数检查（零页 1 形态）；②Ping 报损坏类错误（not a
	// database / malformed，覆盖魔数完好但页 1 内容损坏的形态）时隔离重试
	// 一次。瞬态错误（锁/IO）与重试后再失败均响亮失败。主库/审计库承载不可
	// 再生数据，不走此路径。
	if quarantined, qerr := quarantineCorruptSQLiteFile(dbPath); qerr != nil {
		return fmt.Errorf("failed to inspect metrics database file: %w", qerr)
	} else if quarantined != "" {
		reportMetricsQuarantine("bad SQLite header", quarantined)
	}

	db, err := openAndPingMetricsDB(dbPath)
	if err != nil {
		if !isCorruptionError(err) {
			return err
		}
		quarantined, qerr := quarantineMetricsFileUnconditionally(dbPath)
		if qerr != nil {
			return errors.Join(err, qerr)
		}
		reportMetricsQuarantine(fmt.Sprintf("integrity check failed on open: %v", err), quarantined)
		db, err = openAndPingMetricsDB(dbPath)
		if err != nil {
			return err
		}
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, db.Close())
		}
	}()

	if err := initMetricsSchema(db); err != nil {
		return err
	}
	if err := secureSQLiteArtifacts(dbPath); err != nil {
		return fmt.Errorf("failed to secure metrics database artifacts: %w", err)
	}
	generation, err := ensureMetricsDBGeneration(db)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics database generation: %w", err)
	}

	MetricsDB = db
	metricsDBGeneration.set(db, generation)
	return nil
}

// metricsDBGenerationKey 是 metrics_meta 里的创建代际键。
const metricsDBGenerationKey = "db_generation"

// metricsDBGeneration 记录当前 MetricsDB 句柄对应的库创建代际 token。代际在
// 库文件创建时铸一次并随库持久（metrics_meta 表）：同一库文件重开/进程重启
// 代际不变；损坏隔离重建产生新库文件 → 新代际。摄取侧据此判定「旧 offset 属于
// 已丢弃的旧库」并从文件头重新摄取（安全事件 offset 复位判据）。
// 句柄绑定：仅当查询时 MetricsDB 仍是记录的那个句柄才返回代际——测试/嵌入
// 形态直换包级句柄时不会读到前一个库的陈旧代际。
type metricsDBGenerationState struct {
	mu  sync.Mutex
	db  *sql.DB
	gen string
}

var metricsDBGeneration metricsDBGenerationState

func (g *metricsDBGenerationState) set(database *sql.DB, generation string) {
	g.mu.Lock()
	g.db, g.gen = database, generation
	g.mu.Unlock()
}

func (g *metricsDBGenerationState) get() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db == nil || g.db != MetricsDB {
		return ""
	}
	return g.gen
}

// MetricsDBGeneration 返回当前 metrics 库的创建代际 token（库未装配/句柄已
// 被替换时为空串）。只读、无锁竞争（每 tick 一次）。
func MetricsDBGeneration() string { return metricsDBGeneration.get() }

// ensureMetricsDBGeneration 返回库文件当前的创建代际；老库（升级前没有
// metrics_meta 行）在首次初始化时铸一个新值并持久，之后保持不变。
func ensureMetricsDBGeneration(database *sql.DB) (string, error) {
	var generation string
	err := database.QueryRow(`SELECT value FROM metrics_meta WHERE key=?`, metricsDBGenerationKey).Scan(&generation)
	if err == nil && generation != "" {
		return generation, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	buf := make([]byte, 16)
	if _, rerr := rand.Read(buf); rerr != nil {
		return "", rerr
	}
	generation = hex.EncodeToString(buf)
	if _, ierr := database.Exec(`INSERT OR REPLACE INTO metrics_meta (key, value) VALUES (?, ?)`, metricsDBGenerationKey, generation); ierr != nil {
		return "", ierr
	}
	return generation, nil
}

// sqlite 扩展错误码的低 8 位为主码（>0xff 为扩展位）；仅用主码判定损坏类。
const (
	sqliteCodeCorrupt = 11 // SQLITE_CORRUPT
	sqliteCodeNotADB  = 26 // SQLITE_NOTADB
)

// isCorruptionError 区分损坏类错误（值得隔离重建）与瞬态错误（锁/IO，
// 隔离只会白白丢弃好数据）。优先按驱动类型化错误码判定（glebarez/go-sqlite
// 的 *sqlite.Error 经 errors.As 可穿透 database/sql 与 fmt.Errorf 包装链），
// 字符串 Contains 仅作兜底（驱动消息措辞变化不得让损坏库错过隔离）。
func isCorruptionError(err error) bool {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() & 0xff {
		case sqliteCodeCorrupt, sqliteCodeNotADB:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "not a database") || strings.Contains(msg, "malformed")
}

// quarantineMetricsFileUnconditionally 无条件隔离现存非空库文件及其
// -wal/-shm 伴生文件（Ping 已判损坏，无需再做头部检查）。
func quarantineMetricsFileUnconditionally(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() == 0 {
		return "", nil
	}
	// 先隔离 -wal/-shm，主文件最后改名：伴生失败时主库仍在原位且调用方
	// 中止重建，不会在残留旧 WAL 的同名路径新建空库。故障解除后可原样重试。
	if err := quarantineCompanions(path); err != nil {
		return "", err
	}
	quarantined := nextQuarantinePath(path)
	if err := os.Rename(path, quarantined); err != nil {
		return "", fmt.Errorf("quarantine corrupted database file: %w", err)
	}
	return quarantined, nil
}

// quarantineKeepPerBase 是启动 GC 对每个基础名（主库/-wal/-shm）保留的隔离
// 文件份数：留新删旧，兼顾取证与磁盘无界累积。
const quarantineKeepPerBase = 3

// quarantineFileOrder 从隔离文件名解析 (unix 秒, 同秒序号)，用于「按文件名
// 时间」排序。os.Rename 保留源文件 mtime，隔离发生的
// 时刻只记录在文件名里——按 ModTime 排序会把源 mtime 较旧的最新隔离件误判
// 为最老而删除。解析失败（非本函数生成的形态）返回 false，排到最后。
var quarantineFileNamePattern = regexp.MustCompile(`\.corrupt\.(\d+)(?:-(\d+))?$`)

func quarantineFileOrder(path string) (int64, int, bool) {
	match := quarantineFileNamePattern.FindStringSubmatch(path)
	if len(match) != 3 {
		return 0, 0, false
	}
	seconds, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	sequence := 0
	if match[2] != "" {
		if parsed, err := strconv.Atoi(match[2]); err == nil {
			sequence = parsed
		}
	}
	return seconds, sequence, true
}

// gcQuarantinedMetricsFiles 清理历史 metrics 隔离文件：每个基础名仅保留最新
// quarantineKeepPerBase 份 .corrupt.*，更老的删除。启动时调用；尽力而为，
// 删除失败记日志不上抛（GC 失败不得阻断启动/自愈路径），不触碰其他基础名。
func gcQuarantinedMetricsFiles(dbPath string) {
	for _, base := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		matches, err := filepath.Glob(base + ".corrupt.*")
		if err != nil {
			log.Printf("gc quarantined metrics files: glob %s: %v", base+".corrupt.*", err)
			continue
		}
		// 只处理本函数命名的文件（.corrupt.<unix秒>[-序号]）：解析失败的
		// .corrupt.* 是操作者手工留档副本（如 .corrupt.before-restore），按
		// 「未知时间排最后」参与保新删旧会把它当作最旧件优先删除——取证副本
		// 消失且只留一行 GC 日志。
		infos := make([]struct {
			path   string
			second int64
			order  int
		}, 0, len(matches))
		for _, path := range matches {
			seconds, order, parsed := quarantineFileOrder(path)
			if !parsed {
				continue
			}
			infos = append(infos, struct {
				path   string
				second int64
				order  int
			}{path, seconds, order})
		}
		if len(infos) <= quarantineKeepPerBase {
			continue
		}
		sort.Slice(infos, func(i, j int) bool {
			if infos[i].second != infos[j].second {
				return infos[i].second > infos[j].second
			}
			return infos[i].order > infos[j].order
		})
		for _, stale := range infos[quarantineKeepPerBase:] {
			if err := os.Remove(stale.path); err != nil {
				log.Printf("gc quarantined metrics files: remove %s: %v", stale.path, err)
				continue
			}
			log.Printf("gc quarantined metrics files: removed %s", stale.path)
		}
	}
}

func openAndPingMetricsDB(dbPath string) (*sql.DB, error) {
	// MaxIdle == MaxOpen：空闲连接永不驱逐，避免安静期（30s 指标 tick 间）
	// 池收缩到 0 触发「最后一个连接关闭 → checkpoint + 删除 -wal」突发，
	// 下一个 tick 再重建 WAL——该 checkpoint 风暴是页回写暴露于宿主丢写
	// 窗口的放大器。生命周期过期逐连接轮换，5 条常驻下永不触达 last-close。
	db, err := openSQLiteDB(dbPath, sqlitePoolConfig{maxOpen: 5, maxIdle: 5, connMaxLifetime: 30 * time.Minute})
	if err != nil {
		return nil, fmt.Errorf("failed to open metrics database: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping metrics database: %w", err)
	}
	if err := applySQLiteRuntimePragmas(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to apply metrics database pragmas: %w", err)
	}
	return db, nil
}

// metricsRedundantIndexProbes / Drops 冗余索引探测门的观测计数：Probes=每次
// 初始化对 sqlite_master 的探测次数（两条索引各一次），Drops=索引真实在位
// 并执行了 DROP 的次数。仅测试消费。
var (
	metricsRedundantIndexProbes atomic.Int64
	metricsRedundantIndexDrops  atomic.Int64
)

// dropRedundantMetricsIndex 回收存量指标库上的冗余索引：先探测 sqlite_master，
// 仅索引真实在位时执行 DROP——fresh 库与已回收库零 DDL（此前每次初始化无条件
// 两条 DROP INDEX，空转一次 schema 写事务）。索引名来自本文件内固定清单。
func dropRedundantMetricsIndex(db *sql.DB, name string) error {
	metricsRedundantIndexProbes.Add(1)
	var found string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect redundant metrics index %s: %w", name, err)
	}
	metricsRedundantIndexDrops.Add(1)
	if _, err := db.Exec("DROP INDEX " + name); err != nil {
		return fmt.Errorf("drop redundant metrics index %s: %w", name, err)
	}
	return nil
}

func initMetricsSchema(db *sql.DB) error {

	// idx_metrics_rule 与 idx_metrics_rule_timestamp 左前缀重叠（清理）：
	// 初始化时经 dropRedundantMetricsIndex 探测 sqlite_master，仅存量库存在时
	// 一次性回收（fresh 库不创建、已回收库零 DDL）。
	schema := `
	-- 指标库元数据（键值）：db_generation 记录库文件创建代际，随库持久——
	-- 摄取侧以代际变化判定「库已隔离重建」，复位审计日志 offset（见
	-- ensureMetricsDBGeneration）。已有库首次运行补建并铸代际（不触发复位）。
	CREATE TABLE IF NOT EXISTS metrics_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS metrics_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20),
		timestamp DATETIME NOT NULL,
		requests_total INTEGER DEFAULT 0,
		requests_2xx INTEGER DEFAULT 0,
		requests_3xx INTEGER DEFAULT 0,
		requests_4xx INTEGER DEFAULT 0,
		requests_5xx INTEGER DEFAULT 0,
		requests_blocked INTEGER DEFAULT 0,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		-- 以下三列为**废弃列**：metrics_history 的历史查询（handlers/metrics.go
		-- 两条列清单）与前端零消费，延迟只经 live overview 暴露（内存对象，
		-- services.estimateLatencyPercentiles）。保留列避免对既有 metrics 库做
		-- 破坏性表重建；写侧仍写入（列成本可忽略），但新读路径禁止依赖这三列
		-- ——「历史延迟可用」是伪契约。
		latency_p50 INTEGER DEFAULT 0,
		latency_p95 INTEGER DEFAULT 0,
		latency_p99 INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_rule_timestamp ON metrics_history(rule_id, timestamp);

	CREATE TABLE IF NOT EXISTS security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time DATETIME NOT NULL DEFAULT (datetime('now')),
		rule_caddy_id TEXT DEFAULT '',
		policy_id INTEGER DEFAULT 0,
		client_ip TEXT DEFAULT '',
		method TEXT DEFAULT '',
		uri TEXT DEFAULT '',
		event_type TEXT DEFAULT 'waf',
		rule_triggered TEXT DEFAULT '',
		rule_msg TEXT DEFAULT '',
		action TEXT DEFAULT '',
		anomaly_score INTEGER DEFAULT 0,
		rule_name TEXT DEFAULT '',
		policy_name TEXT DEFAULT '',
		transaction_id TEXT DEFAULT '',
		duration_us INTEGER DEFAULT 0,
		precheck_us INTEGER DEFAULT 0,
		request_headers TEXT DEFAULT '',
		request_body TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(event_time DESC);
	CREATE INDEX IF NOT EXISTS idx_security_events_rule ON security_events(rule_caddy_id);
	CREATE INDEX IF NOT EXISTS idx_security_events_action_time ON security_events(action, event_time DESC);
	CREATE INDEX IF NOT EXISTS idx_security_events_ip_time ON security_events(client_ip, event_time DESC);

	-- v2.3.8 威胁大屏预聚合（分钟粒度）：国家/省/攻击族/规则名/动作 五维
	-- 计数，PK 前缀=minute。大屏聚合端点直读此表（毫秒级，与原始表规模
	-- 解耦——2000/s 正常 + 100/s 攻击压力设计，2026-10-17 用户裁定）。
	-- 固化=按需懒固（ensureThreatRollup）：每分钟幂等 DELETE+INSERT。
	CREATE TABLE IF NOT EXISTS security_event_rollup (
		minute TEXT NOT NULL,
		country TEXT NOT NULL DEFAULT '',
		province TEXT NOT NULL DEFAULT '',
		family TEXT NOT NULL DEFAULT '',
		rule TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (minute, country, province, family, rule, action)
	) WITHOUT ROWID;

	-- 被攻击目标（rule_caddy_id）分钟 rollup——与主 rollup
	-- 同批写入，使「TOP 被攻击站点」与总量/国家等卡片同窗口，不再依赖原始表
	-- （原始表受保留期/行帽裁剪；主 rollup 主键无法承载该维度）。
	CREATE TABLE IF NOT EXISTS security_event_target_rollup (
		minute TEXT NOT NULL,
		rule_caddy_id TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (minute, rule_caddy_id)
	) WITHOUT ROWID;
	-- idx_security_event_target_rollup_minute 与 WITHOUT
	-- ROWID 主键 (minute, rule_caddy_id) 的排序前缀完全等价（WHERE minute>=?
	-- 与 GROUP BY minute 本就走主键扫描），删除以省写入/存储成本；存量库由
	-- initMetricsSchema 的探测门一次性回收（fresh 库不创建、已回收库零 DDL）。
	-- 消费面补全（删除论证不得只枚举前缀形态）：①时间窗扫描 WHERE minute>=?；
	-- ②GROUP BY minute 的按分钟聚合；③威胁大屏 top_targets 的
	-- GROUP BY rule_caddy_id（无 minute 上界——宽窗口下为主键全扫 + 临时 B 树
	-- 分组）。①②与主键前缀等价，③不是前缀形态：取消索引后每个窗口 miss 付
	-- 一次分组排序（数十万行量级，大屏 60s 缓存内每窗口一次）。按 rule_caddy_id
	-- 建覆盖索引会重新引入被删除的写入成本，故维持现状（性能取舍，非正确性；
	-- 若未来该查询成为瓶颈，改读主 rollup 的 rule 维度需先确认其口径等价）。

	-- 指标库通用状态表：rollup 固化水位等持久元数据。
	-- 键值单行形态，水位与分钟数据同事务提交——不再以数据行 MAX(minute)
	-- 反推水位（空分钟不产行，MAX 水位会让空分钟永不推进）。
	CREATE TABLE IF NOT EXISTS metrics_state (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	) WITHOUT ROWID;
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to initialize metrics database schema: %w", err)
	}
	for _, name := range []string{"idx_metrics_rule", "idx_security_event_target_rollup_minute"} {
		if err := dropRedundantMetricsIndex(db, name); err != nil {
			return err
		}
	}
	// 幂等迁移：为既有指标库补齐 security_events 缺列（全新库由上面的建表语句
	// 直接带出全部列）。原四个逐字相同的「pragma 查列→缺则
	// ADD COLUMN」函数（migrateSecurityEventsTransactionID/RequestContext/
	// Duration/PrecheckUs）收敛为单一登记点 migrateSecurityEventsColumns。
	if err := migrateSecurityEventsColumns(db); err != nil {
		return fmt.Errorf("failed to migrate metrics database schema: %w", err)
	}
	// transaction_id 的幂等唯一部分索引（WHERE != ''）让重复事务写入被
	// OR IGNORE 静默去重，同时保留历史遗留空 transaction_id 行不受唯一约束影响。
	// 存量重复行：启动期去重（保留每事务最早行）后照常建索引
	// 台账裁定：去重后再建索引，不靠跳过——跳过会让 offset 重建/轮转补采把
	// 重复事件重新入库并重复喂 autoban/rollup）。
	if err := ensureSecurityEventsTransactionIndex(db); err != nil {
		return err
	}
	if err := migrateMetricsHistoryBlocked(db); err != nil {
		return err
	}
	return nil
}

// securityEventsTransactionIndexSQL 是事务唯一索引的 DDL 单源（探测形状与
// 建立共用；口径见 uniqueIndexState 的「同名非唯一索引」说明）。
const securityEventsTransactionIndexSQL = `CREATE UNIQUE INDEX idx_security_events_transaction ON security_events(transaction_id) WHERE transaction_id != ''`

// ensureSecurityEventsTransactionIndex 在建立唯一部分索引前检查存量重复事务。
// 发现重复时不再 WARN+跳过（跳过期间 INSERT OR IGNORE 失去
// 唯一约束兜底，offset 重建/轮转补采会把重复事件重新入库并重复喂
// autoban/rollup）——改为启动期一次性去重：每个非空 transaction_id 保留
// 最早行（MIN(id)，即首次摄取的事件），删除其余重复行后照常建索引，摄取
// 幂等链自启动起恒成立。空串与 NULL 不属于索引约束域，不受影响。
// securityEventsTransactionIndexScans / Skips 启动期查重路径的观测计数：
// Scans=真正执行了全表 GROUP BY 查重的次数（每库一次），Skips=命中
// sqlite_master 唯一索引直接跳过的次数（每次重启 +1）。仅测试消费。
var (
	securityEventsTransactionIndexScans atomic.Int64
	securityEventsTransactionIndexSkips atomic.Int64
)

func ensureSecurityEventsTransactionIndex(db *sql.DB) error {
	// 先探测索引是否已在位：唯一索引一旦建立，重复事务在写入侧即被拒绝，
	// 全表 GROUP BY 查重（security_events 全表扫描，事件表百万行时启动白付
	// 数秒）没有任何可发现对象——直接跳过。存量库（索引缺失）才进入查重+建
	// 索引路径。
	_, matches, err := uniqueIndexState(db, "idx_security_events_transaction", securityEventsTransactionIndexSQL)
	if err != nil {
		return fmt.Errorf("failed to inspect security_events transaction index: %w", err)
	}
	if matches {
		securityEventsTransactionIndexSkips.Add(1)
		return nil
	}
	securityEventsTransactionIndexScans.Add(1)
	rows, err := db.Query(`SELECT transaction_id, COUNT(*) FROM security_events
		WHERE transaction_id != '' GROUP BY transaction_id HAVING COUNT(*)>1`)
	if err != nil {
		return fmt.Errorf("failed to inspect duplicate security_events transaction IDs: %w", err)
	}
	var duplicates []string
	for rows.Next() {
		var transactionID string
		var count int
		if err := rows.Scan(&transactionID, &count); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan duplicate security_events transaction IDs: %w", err)
		}
		duplicates = append(duplicates, fmt.Sprintf("%s×%d", transactionID, count))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate duplicate security_events transaction IDs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close duplicate security_events transaction ID rows: %w", err)
	}
	if len(duplicates) > 0 {
		// 去重：保留每事务最早行（首次摄取），删除其余重复行。事件为追加型
		// 历史，同 transaction_id 的重复行语义等价，保留最早行与「INSERT OR
		// IGNORE 命中时保留既有行」的运行时口径一致。
		result, err := db.Exec(`DELETE FROM security_events WHERE transaction_id != '' AND id NOT IN (
			SELECT MIN(id) FROM security_events WHERE transaction_id != '' GROUP BY transaction_id)`)
		if err != nil {
			return fmt.Errorf("failed to deduplicate security_events transaction IDs: %w", err)
		}
		removed, _ := result.RowsAffected()
		log.Printf("WARN: security_events 表存在重复 transaction_id（%s），已去重删除 %d 行（保留每事务最早行）并继续创建唯一索引", strings.Join(duplicates, ", "), removed)
	}
	if err := ensureUniqueIndex(db, "idx_security_events_transaction", securityEventsTransactionIndexSQL); err != nil {
		return fmt.Errorf("failed to create security_events transaction index: %w", err)
	}
	return nil
}

// securityEventsLegacyColumns 存量指标库补列清单（单一登记点）。各列引入背景：
// transaction_id（幂等去重键，上方部分索引依赖）、request_headers/request_body
// （v2.2.3 事件请求上下文，摄入落库 64KB 截断；request_body 仅策略开
// log_request_body 后有值）、duration_us（v2.3.3 安全处理耗时——blocked_counter
// 在链首注入 timing ID 请求头，摄取管道按 ID 查耗时表写入）、precheck_us
// （v2.3.3 预检段耗时快照——触发详情弹框「预检+WAF」分解）。
var securityEventsLegacyColumns = []struct{ column, ddl string }{
	{"transaction_id", "TEXT DEFAULT ''"},
	{"request_headers", "TEXT DEFAULT ''"},
	{"request_body", "TEXT DEFAULT ''"},
	{"duration_us", "INTEGER DEFAULT 0"},
	{"precheck_us", "INTEGER DEFAULT 0"},
}

// migrateSecurityEventsColumns 幂等补齐 security_events 缺列（仅服务存量库；
// 新库由 initMetricsSchema fresh CREATE 直接带出，双通道一致）。
func migrateSecurityEventsColumns(db *sql.DB) error {
	for _, col := range securityEventsLegacyColumns {
		var colCount int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_events') WHERE name=?", col.column).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check security_events.%s: %w", col.column, err)
		}
		if colCount == 0 {
			if _, err := db.Exec("ALTER TABLE security_events ADD COLUMN " + col.column + " " + col.ddl); err != nil {
				return fmt.Errorf("failed to add security_events.%s: %w", col.column, err)
			}
		}
	}
	return nil
}

// migrateMetricsHistoryBlocked 处理 metrics_history 的 requests_blocked 列——
// 2026-09-15 用户裁定:部署不做老库兼容,缺列直接 DROP 重建该表(7 天缓存
// 数据,重建零成本;**security_events 不动**——事件历史是用户数据)。
// 老库行无 blocked 累计值且与 lazybalancer 新计数器(从 0 起)不连续,
// 保留反而产生误导性历史。
func migrateMetricsHistoryBlocked(db *sql.DB) error {
	var colCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('metrics_history') WHERE name='requests_blocked'").Scan(&colCount); err != nil {
		return fmt.Errorf("failed to check metrics_history.requests_blocked: %w", err)
	}
	if colCount > 0 {
		return nil
	}
	if _, err := db.Exec("DROP TABLE IF EXISTS metrics_history"); err != nil {
		return fmt.Errorf("failed to drop legacy metrics_history: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE metrics_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20),
		timestamp DATETIME NOT NULL,
		requests_total INTEGER DEFAULT 0,
		requests_2xx INTEGER DEFAULT 0,
		requests_3xx INTEGER DEFAULT 0,
		requests_4xx INTEGER DEFAULT 0,
		requests_5xx INTEGER DEFAULT 0,
		requests_blocked INTEGER DEFAULT 0,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		-- 以下三列为**废弃列**：metrics_history 的历史查询（handlers/metrics.go
		-- 两条列清单）与前端零消费，延迟只经 live overview 暴露（内存对象，
		-- services.estimateLatencyPercentiles）。保留列避免对既有 metrics 库做
		-- 破坏性表重建；写侧仍写入（列成本可忽略），但新读路径禁止依赖这三列
		-- ——「历史延迟可用」是伪契约。
		latency_p50 INTEGER DEFAULT 0,
		latency_p95 INTEGER DEFAULT 0,
		latency_p99 INTEGER DEFAULT 0
	)`); err != nil {
		return fmt.Errorf("failed to recreate metrics_history: %w", err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp)"); err != nil {
		return fmt.Errorf("failed to recreate metrics_history index: %w", err)
	}
	// DROP 重建丢失
	// idx_metrics_rule_timestamp(原 schema 块在旧表建,重建后消失)——
	// 重建后至重启前历史查询全表扫描。同步重建。
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_metrics_rule_timestamp ON metrics_history(rule_id, timestamp)"); err != nil {
		return fmt.Errorf("failed to recreate metrics_history rule index: %w", err)
	}
	return nil
}

// cleanupMetricsHistoryBatch 是历史清理的单批删除行数：镜像姊妹实现
// securityEventsRetentionDeleteBatch（internal/services/securityevents_retention.go）
// 的教训——大批量单语句 DELETE 长时间持指标库写锁，阻塞摄取 tick。
// 同库同故障形态，同口径分批。做成 var 以便测试收缩批次观察多批行为。
var cleanupMetricsHistoryBatch = 5000

// CleanupMetricsHistory 按 retentionDays 分批删除过期的 metrics_history 行。
// 本函数无 ctx（沿用既有调用方签名）：循环以 RowsAffected==0 自然终止——
// 摄取侧只写入 datetime('now') 新鲜行，过期行总量单调递减，批批有推进。
// MetricsDB 为 nil（库未装配/已关闭，嵌入与测试直调可达）时早退 nil——
// 与同族导出函数守卫口径一致（PurgeOrphanMetricsHistory/PurgeTaskRuns 先例）。
func CleanupMetricsHistory(retentionDays int) error {
	if MetricsDB == nil {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02 15:04:05")
	for {
		res, err := MetricsDB.Exec(
			"DELETE FROM metrics_history WHERE id IN (SELECT id FROM metrics_history WHERE timestamp < ? LIMIT ?)",
			cutoff, cleanupMetricsHistoryBatch,
		)
		if err != nil {
			return fmt.Errorf("delete expired metrics history: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("count deleted metrics history rows: %w", err)
		}
		if affected == 0 {
			return nil
		}
		// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT（与
		// securityEventsRetentionCleanup 同口径）。
		time.Sleep(10 * time.Millisecond)
	}
}
