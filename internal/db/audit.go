package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const auditDBFilename = "lazy-balancer-audit.db"

func InitializeAuditDB(dataDir string) error {
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to create audit data directory: %w", err)
	}
	path := filepath.Join(dataDir, auditDBFilename)
	if err := prepareSQLiteDatabase(path); err != nil {
		return fmt.Errorf("failed to secure audit database: %w", err)
	}
	auditDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return fmt.Errorf("failed to open audit database: %w", err)
	}
	auditDB.SetMaxOpenConns(5)
	auditDB.SetMaxIdleConns(2)
	auditDB.SetConnMaxLifetime(30 * time.Minute)
	if err := auditDB.Ping(); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to ping audit database: %w", err)
	}
	if err := applySQLiteRuntimePragmas(auditDB); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to apply audit database pragmas: %w", err)
	}
	if _, err := auditDB.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR(100),
			action VARCHAR(50) NOT NULL,
			resource VARCHAR(100),
			detail TEXT,
			ip_address VARCHAR(45),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
		CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
	`); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to create audit schema: %w", err)
	}
	if err := secureSQLiteArtifacts(path); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to secure audit database artifacts: %w", err)
	}
	AuditDB = auditDB
	if err := migrateLegacyAuditLogs(DB, path); err != nil {
		// R46 C-2: 初始化中途失败时缓冲的系统事件原样保留（下次启动重放），
		// 此处仅留痕条数，不静默丢弃。
		log.Printf("audit log migration failed (%v); %d buffered system audit entries retained for next startup", err, systemAuditBufferLen())
		return err
	}
	migrateAuditVocabulary()
	flushSystemAuditLogs()
	return nil
}

// 操作日志词汇标准（R47 起为系统标准）：操作标签 ≤4 词、事件对象 ≤5 词
// （词制：中文按字计、连续英文/数字串算 1 词、空白不计）。存量旧词条在此
// 一次性归一——筛选下拉取自 audit_log 去重值，不迁移则旧词条永久残留。
// 幂等：旧值不存在时零命中。新事件由 services.RecordAuditLog 入口告警 +
// audit_vocabulary_test.go 硬卡控。
var auditVocabularyRenames = []struct {
	oldAction, newAction     string
	oldResource, newResource string
}{
	// 动作+对象联动改名
	{"清理证书指纹失败", "清理失败", "集群节点", "证书指纹"},
	{"清理证书指纹", "清理", "集群节点", "证书指纹"},
	// 动作改名
	{"下载完整性告警", "校验阻断", "", ""},
	{"校验告警", "校验阻断", "", ""},
	{"手动同步失败", "同步失败", "", ""},
	{"下载完整性", "下载校验", "", ""},
	{"配置不一致", "配置漂移", "", ""},
	{"CA限流", "签发限流", "", ""},
	{"导入部分失败", "部分失败", "", ""},
	{"更新访问地址", "更新地址", "", ""},
	{"更新资料", "更新信息", "", ""},
	{"错误", "应用失败", "", ""},
	// 动作不变、对象改名的联动条目
	{"重载", "", "Caddy配置", "Caddy服务"},
	{"重载失败", "", "Caddy配置", "Caddy服务"},
	// 对象改名
	{"", "", "证书签发任务", "证书任务"},
	{"", "", "完整性记录文件损坏", "完整性记录"},
	{"", "", "从节点登录票据", "登录票据"},
	{"", "", "集群登录票据", "登录票据"},
	{"", "", "负载均衡规则", "负载规则"},
	{"", "", "DNS提供商配置", "DNS配置"},
	{"", "", "集群注册令牌", "注册令牌"},
	{"", "", "Caddy 配置", "Caddy配置"},
	{"", "", "IP2Region 数据库", "IP数据库"},
	{"", "", "ip2region 数据库", "IP数据库"},
	{"", "", "IP2Region数据库", "IP数据库"},
	{"", "", "CRS 规则库", "CRS规则库"},
	{"", "", "配置同步", "集群同步"},
	{"", "", "Caddy全局配置", "Caddy配置"},
	{"", "", "ACME全局设置", "ACME配置"},
	{"", "", "HTTPS 访问", "基础设置"},
}

func migrateAuditVocabulary() {
	for _, r := range auditVocabularyRenames {
		var sets, wheres []string
		var setArgs, whereArgs []any
		if r.newAction != "" {
			sets = append(sets, "action=?")
			setArgs = append(setArgs, r.newAction)
		}
		if r.oldAction != "" {
			wheres = append(wheres, "action=?")
			whereArgs = append(whereArgs, r.oldAction)
		}
		if r.newResource != "" {
			sets = append(sets, "resource=?")
			setArgs = append(setArgs, r.newResource)
		}
		if r.oldResource != "" {
			wheres = append(wheres, "resource=?")
			whereArgs = append(whereArgs, r.oldResource)
		}
		query := "UPDATE audit_log SET " + strings.Join(sets, ", ") + " WHERE " + strings.Join(wheres, " AND ")
		res, err := AuditDB.Exec(query, append(setArgs, whereArgs...)...)
		if err != nil {
			log.Printf("audit vocabulary migration failed (%s): %v", query, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("audit vocabulary migration: %d rows normalized (%s)", n, query)
		}
	}
}

// R45 F-2: 启动迁移跑在 InitializeAuditDB 之前，且 db 不能反向依赖
// services.RecordAuditLog（import 环）——迁移期的系统事件先入内存缓冲，审计库
// 就绪后统一落 audit_log 表，与 UI 操作日志同源。
type systemAuditEntry struct {
	action   string
	resource string
	detail   string
}

var systemAuditBuffer struct {
	mu      sync.Mutex
	entries []systemAuditEntry
}

// R46 C-2: 缓冲设上限，审计库长期不可用（或 flush 反复失败）时丢弃最旧条目并
// 告警，避免内存无界增长。
const systemAuditBufferCap = 10000

func recordSystemAudit(action, resource, detail string) {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	systemAuditBuffer.entries = append(systemAuditBuffer.entries, systemAuditEntry{action, resource, detail})
	trimSystemAuditBufferLocked()
}

func systemAuditBufferLen() int {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	return len(systemAuditBuffer.entries)
}

func trimSystemAuditBufferLocked() {
	if overflow := len(systemAuditBuffer.entries) - systemAuditBufferCap; overflow > 0 {
		kept := make([]systemAuditEntry, systemAuditBufferCap)
		copy(kept, systemAuditBuffer.entries[overflow:])
		systemAuditBuffer.entries = kept
		log.Printf("system audit buffer overflow: dropped %d oldest entries", overflow)
	}
}

// flushSystemAuditLogs 将缓冲的系统事件写入审计库并清空缓冲；审计库未就绪或单条
// 写失败时条目按原顺序留回缓冲（R46 C-2：等待下次 flush 重试，不再静默丢事件），
// 与 services.RecordAuditLog 的 best-effort 语义一致。
func flushSystemAuditLogs() {
	systemAuditBuffer.mu.Lock()
	entries := systemAuditBuffer.entries
	systemAuditBuffer.entries = nil
	systemAuditBuffer.mu.Unlock()
	if len(entries) == 0 {
		return
	}
	if AuditDB == nil {
		systemAuditBuffer.mu.Lock()
		systemAuditBuffer.entries = append(entries, systemAuditBuffer.entries...)
		trimSystemAuditBufferLocked()
		systemAuditBuffer.mu.Unlock()
		return
	}
	var failed []systemAuditEntry
	for _, entry := range entries {
		if _, err := AuditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system', ?, ?, ?, '')",
			entry.action, entry.resource, entry.detail); err != nil {
			log.Printf("system audit log write failed: %v", err)
			failed = append(failed, entry)
		}
	}
	if len(failed) > 0 {
		systemAuditBuffer.mu.Lock()
		systemAuditBuffer.entries = append(failed, systemAuditBuffer.entries...)
		trimSystemAuditBufferLocked()
		systemAuditBuffer.mu.Unlock()
	}
}

func migrateLegacyAuditLogs(mainDB *sql.DB, auditPath string) error {
	if mainDB == nil {
		return nil
	}
	ctx := context.Background()
	conn, err := mainDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	var tableCount int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'").Scan(&tableCount); err != nil {
		return err
	}
	if tableCount == 0 {
		return nil
	}
	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS audit_migration", auditPath); err != nil {
		return fmt.Errorf("failed to attach audit database: %w", err)
	}
	defer conn.ExecContext(ctx, "DETACH DATABASE audit_migration")

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO audit_migration.audit_log
		(id, username, action, resource, detail, ip_address, created_at)
		SELECT id, username, action, resource, detail, ip_address, created_at FROM main.audit_log`); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to copy audit logs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	var mismatch int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.audit_log src
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_migration.audit_log dst
			WHERE dst.id = src.id
			  AND dst.username IS src.username
			  AND dst.action IS src.action
			  AND dst.resource IS src.resource
			  AND dst.detail IS src.detail
			  AND dst.ip_address IS src.ip_address
			  AND dst.created_at IS src.created_at
		)`).Scan(&mismatch); err != nil {
		return fmt.Errorf("failed to verify audit migration: %w", err)
	}
	if mismatch > 0 {
		return fmt.Errorf("audit migration conflict: %d source rows differ from destination", mismatch)
	}
	if _, err := mainDB.Exec("DROP TABLE audit_log"); err != nil {
		return fmt.Errorf("failed to remove legacy audit table: %w", err)
	}
	return nil
}
