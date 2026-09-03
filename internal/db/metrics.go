package db

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sqlite "github.com/glebarez/go-sqlite"
)

var sqliteHeaderMagic = []byte("SQLite format 3\x00")

// nextQuarantinePath 返回不与现存文件冲突的隔离目标路径：<path>.corrupt.<unix秒>；
// 同秒已有同名隔离文件时追加 -1/-2/… 序号（C4-F3：同秒两次隔离不再静默覆盖
// 此前的取证文件——Unix rename 对已存在目标是直接替换）。stat-then-rename 的
// 窗口仅存在于启动单线程路径，极端竞态下回退为旧的覆盖行为，不劣于修复前。
func nextQuarantinePath(path string) string {
	base := fmt.Sprintf("%s.corrupt.%d", path, time.Now().Unix())
	for i := 1; ; i++ {
		candidate := base
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d", base, i)
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
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
	quarantined := nextQuarantinePath(path)
	if err := os.Rename(path, quarantined); err != nil {
		return "", fmt.Errorf("quarantine corrupted database file: %w", err)
	}
	for _, companion := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(companion); err == nil {
			_ = os.Rename(companion, nextQuarantinePath(companion))
		}
	}
	return quarantined, nil
}

func InitializeMetricsDB(dataDir string) (err error) {
	dbPath := filepath.Join(dataDir, "lazy-balancer-metrics.db")
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to secure metrics data directory: %w", err)
	}
	// 先清扫历史隔离文件（含崩循环残留，C4-F3）：每基础名留最新 3 份，防止
	// 取证文件无界累积；本轮新隔离叠加其上，下次启动再收敛。
	gcQuarantinedMetricsFiles(dbPath)
	if err := prepareSQLiteDatabase(dbPath); err != nil {
		return fmt.Errorf("failed to secure metrics database: %w", err)
	}
	// 损坏自愈（生产事故：宿主丢写致页 1 清零 → Ping NOTADB → 启动崩循环
	// 27 分钟无自愈）。metrics 库是可丢弃遥测：两段防线——①头部魔数检查
	// （零页 1 形态）；②Ping 报损坏类错误（not a database / malformed，
	// 覆盖魔数完好但页 1 内容损坏的形态）时隔离重试一次。瞬态错误（锁/
	// IO）与重试后再失败均响亮失败。主库/审计库承载不可再生数据，不走
	// 此路径。
	if quarantined, qerr := quarantineCorruptSQLiteFile(dbPath); qerr != nil {
		return fmt.Errorf("failed to inspect metrics database file: %w", qerr)
	} else if quarantined != "" {
		log.Printf("CRITICAL: metrics database file corrupted (bad SQLite header); quarantined as %s and recreated — metrics history reset", filepath.Base(quarantined))
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
		log.Printf("CRITICAL: metrics database failed integrity check on open (%v); quarantined as %s and recreated — metrics history reset", err, filepath.Base(quarantined))
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

	MetricsDB = db
	return nil
}

// sqlite 扩展错误码的低 8 位为主码（>0xff 为扩展位）；仅用主码判定损坏类。
const (
	sqliteCodeCorrupt = 11 // SQLITE_CORRUPT
	sqliteCodeNotADB  = 26 // SQLITE_NOTADB
)

// isCorruptionError 区分损坏类错误（值得隔离重建）与瞬态错误（锁/IO，
// 隔离只会白白丢弃好数据）。优先按驱动类型化错误码判定（glebarez/go-sqlite
// 的 *sqlite.Error 经 errors.As 可穿透 database/sql 与 fmt.Errorf 包装链），
// 字符串 Contains 仅作兜底（C4-F2：驱动消息措辞变化不得让损坏库错过隔离）。
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
	quarantined := nextQuarantinePath(path)
	if err := os.Rename(path, quarantined); err != nil {
		return "", fmt.Errorf("quarantine corrupted database file: %w", err)
	}
	for _, companion := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(companion); err == nil {
			_ = os.Rename(companion, nextQuarantinePath(companion))
		}
	}
	return quarantined, nil
}

// quarantineKeepPerBase 是启动 GC 对每个基础名（主库/-wal/-shm）保留的隔离
// 文件份数：留新删旧，兼顾取证与磁盘无界累积（C4-F3）。
const quarantineKeepPerBase = 3

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
		if len(matches) <= quarantineKeepPerBase {
			continue
		}
		infos := make([]struct {
			path    string
			modTime time.Time
		}, 0, len(matches))
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				log.Printf("gc quarantined metrics files: stat %s: %v", path, err)
				continue
			}
			infos = append(infos, struct {
				path    string
				modTime time.Time
			}{path, info.ModTime()})
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].modTime.After(infos[j].modTime) })
		for _, stale := range infos[quarantineKeepPerBase:] {
			if err := os.Remove(stale.path); err != nil {
				log.Printf("gc quarantined metrics files: remove %s: %v", stale.path, err)
			}
		}
	}
}

func openAndPingMetricsDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("failed to open metrics database: %w", err)
	}
	// MaxIdle == MaxOpen：空闲连接永不驱逐，避免安静期（30s 指标 tick 间）
	// 池收缩到 0 触发「最后一个连接关闭 → checkpoint + 删除 -wal」突发，
	// 下一个 tick 再重建 WAL——该 checkpoint 风暴是页回写暴露于宿主丢写
	// 窗口的放大器。生命周期过期逐连接轮换，5 条常驻下永不触达 last-close。
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
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

func initMetricsSchema(db *sql.DB) error {

	schema := `
	CREATE TABLE IF NOT EXISTS metrics_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20),
		timestamp DATETIME NOT NULL,
		requests_total INTEGER DEFAULT 0,
		requests_2xx INTEGER DEFAULT 0,
		requests_3xx INTEGER DEFAULT 0,
		requests_4xx INTEGER DEFAULT 0,
		requests_5xx INTEGER DEFAULT 0,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		latency_p50 INTEGER DEFAULT 0,
		latency_p95 INTEGER DEFAULT 0,
		latency_p99 INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_rule ON metrics_history(rule_id);
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
		request_headers TEXT DEFAULT '',
		request_body TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(event_time DESC);
	CREATE INDEX IF NOT EXISTS idx_security_events_rule ON security_events(rule_caddy_id);
	CREATE INDEX IF NOT EXISTS idx_security_events_action_time ON security_events(action, event_time DESC);
	CREATE INDEX IF NOT EXISTS idx_security_events_ip_time ON security_events(client_ip, event_time DESC);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to initialize metrics database schema: %w", err)
	}
	// 幂等迁移：为既有指标库补齐 transaction_id 列（全新库由上面的建表语句直接带出）。
	// 幂等唯一索引（部分索引 WHERE transaction_id != ''）让重复事务写入被 OR IGNORE
	// 静默去重，同时保留历史遗留空 transaction_id 行不受唯一约束影响。
	if err := migrateSecurityEventsTransactionID(db); err != nil {
		return fmt.Errorf("failed to migrate metrics database schema: %w", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_security_events_transaction ON security_events(transaction_id) WHERE transaction_id != ''`); err != nil {
		return fmt.Errorf("failed to create security_events transaction index: %w", err)
	}
	// 幂等迁移：事件请求上下文两列（v2.2.3 安全事件增强）——request_headers 恒由
	// 摄入落库（8KB 截断），request_body 仅策略开 log_request_body 后有值（64KB
	// 截断）；新库由上方建表语句直接带出。
	if err := migrateSecurityEventsRequestContext(db); err != nil {
		return fmt.Errorf("failed to migrate metrics database schema: %w", err)
	}
	return nil
}

func migrateSecurityEventsRequestContext(db *sql.DB) error {
	for _, col := range []string{"request_headers", "request_body"} {
		var colCount int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_events') WHERE name=?", col).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check security_events.%s: %w", col, err)
		}
		if colCount == 0 {
			if _, err := db.Exec(fmt.Sprintf("ALTER TABLE security_events ADD COLUMN %s TEXT DEFAULT ''", col)); err != nil {
				return fmt.Errorf("failed to add security_events.%s: %w", col, err)
			}
		}
	}
	return nil
}

func migrateSecurityEventsTransactionID(db *sql.DB) error {
	var colCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_events') WHERE name='transaction_id'").Scan(&colCount); err != nil {
		return fmt.Errorf("failed to check security_events.transaction_id: %w", err)
	}
	if colCount == 0 {
		if _, err := db.Exec("ALTER TABLE security_events ADD COLUMN transaction_id TEXT DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add security_events.transaction_id: %w", err)
		}
	}
	return nil
}

// cleanupMetricsHistoryBatch 是历史清理的单批删除行数：镜像姊妹实现
// securityEventsRetentionDeleteBatch（internal/services/securityevents_retention.go）
// 的 R33 F9 教训——大批量单语句 DELETE 长时间持指标库写锁，阻塞摄取 tick。
// 同库同故障形态，同口径分批（D3-F1）。做成 var 以便测试收缩批次观察多批行为。
var cleanupMetricsHistoryBatch = 5000

// CleanupMetricsHistory 按 retentionDays 分批删除过期的 metrics_history 行。
// 本函数无 ctx（沿用既有调用方签名）：循环以 RowsAffected==0 自然终止——
// 摄取侧只写入 datetime('now') 新鲜行，过期行总量单调递减，批批有推进。
func CleanupMetricsHistory(retentionDays int) error {
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
		// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT（R33 F9，与
		// securityEventsRetentionCleanup 同口径）。
		time.Sleep(10 * time.Millisecond)
	}
}
