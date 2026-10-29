package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const AuditDBFilename = "lazy-balancer-audit.db"

func InitializeAuditDB(dataDir string) error {
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to create audit data directory: %w", err)
	}
	path := filepath.Join(dataDir, AuditDBFilename)
	if err := prepareSQLiteDatabase(path); err != nil {
		return fmt.Errorf("failed to secure audit database: %w", err)
	}
	// 池尺寸有意与 metrics 不统一：metrics 要求 MaxIdle==MaxOpen（安静期
	// last-close 会触发 checkpoint + 删 -wal 风暴，见 openAndPingMetricsDB）；
	// 审计库写更稀疏且库文件小得多，last-close 的单次 checkpoint 成本可忽略，
	// 允许收缩到 2 条空闲连接把句柄还给系统。主库 10/5 的余量服务面板并发读。
	auditDB, err := openSQLiteDB(path, sqlitePoolConfig{maxOpen: 5, maxIdle: 2, connMaxLifetime: 30 * time.Minute})
	if err != nil {
		return fmt.Errorf("failed to open audit database: %w", err)
	}
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
		-- username/resource 不建索引：列表筛选是 COALESCE 包裹 + LIKE 前导通配
		--（handlers.buildAuditLogFilters），索引对该形态不可用；时间范围过滤走
		-- idx_audit_log_created（裸列比较），每请求全表 COUNT 已由 5s 进程缓存
		-- 收敛（cachedAuditLogTotal，响应以 total_stale 披露）。
	`); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to create audit schema: %w", err)
	}
	if err := secureSQLiteArtifacts(path); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to secure audit database artifacts: %w", err)
	}
	previousAuditDB := AuditDB
	AuditDB = auditDB
	if err := migrateLegacyAuditLogs(DB, path); err != nil {
		// 初始化中途失败时缓冲的系统事件原样保留（下次启动重放），
		// 此处仅留痕条数，不静默丢弃。
		log.Printf("audit log migration failed (%v); %d buffered system audit entries retained for next startup", err, systemAuditBufferLen())
		// 半初始化的句柄不得留在包级变量上：先恢复进入前的值（可能为
		// nil），再关闭刚开出的句柄——否则后续调用方会对着迁移失败的库继续
		// 写入，且连接/-wal 句柄泄漏到进程结束。
		AuditDB = previousAuditDB
		if closeErr := auditDB.Close(); closeErr != nil {
			log.Printf("audit database handle close after failed init: %v", closeErr)
		}
		return err
	}
	migrateAuditVocabulary()
	flushSystemAuditLogs()
	return nil
}

// 操作日志词汇标准：操作标签 ≤4 词、事件对象 ≤5 词
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

// 归一表只服务于存量数据迁移（下方 migrateAuditVocabulary）。写点侧的口径：
// 新事件必须使用规范名——audit_vocabulary_test.go 的词数门只查词数，规范名
// 由 audit_vocabulary_migration_test.go 的字面量扫描看守（谓词
// 生产零消费，导出已删除）。

// 归一化的一次性 marker。此前每次启动都无条件执行 30 条
// UPDATE（16 条仅按 resource 命中且该列无索引），已收敛库每启动白跑一轮全表
// 扫描/不动点循环。marker 存于审计库（归一对象在审计库内，生命周期随库文件
// 一致），值为归一表指纹而非布尔——未来增删改名条目时指纹变化会自动重跑，
// 不会因「已迁移」旗标而永久跳过新条目。
const auditVocabularyMarkerName = "audit_vocabulary_migrated"

const auditMigrationStateTable = `CREATE TABLE IF NOT EXISTS audit_migration_state (
	name TEXT PRIMARY KEY,
	fingerprint TEXT NOT NULL
)`

// auditLegacyConflictMarkerName 是「主库旧审计表与审计库处于已知冲突态」的
// 状态标记名：指纹（行数/MIN/MAX/SUM(id)）命中即跳过重复跨库复制与全表校验，
// 冲突解除（主表被人工删除）时自动清除。
const auditLegacyConflictMarkerName = "legacy_audit_conflict_fingerprint"

// auditLegacyConflictSkips 观测：已知冲突态指纹命中而跳过重复迁移的启动次数。
var auditLegacyConflictSkips atomic.Int64

// auditVocabularyFingerprint 是归一表内容指纹（条目与两侧字段逐字节参与）。
func auditVocabularyFingerprint() string {
	var builder strings.Builder
	for _, r := range auditVocabularyRenames {
		builder.WriteString(r.oldAction)
		builder.WriteByte(0)
		builder.WriteString(r.newAction)
		builder.WriteByte(0)
		builder.WriteString(r.oldResource)
		builder.WriteByte(0)
		builder.WriteString(r.newResource)
		builder.WriteByte('\n')
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(builder.String())))
}

// auditVocabularyMigrated 报告 marker 是否已按当前指纹置位。
func auditVocabularyMigrated(fingerprint string) bool {
	var stored string
	err := AuditDB.QueryRow(`SELECT fingerprint FROM audit_migration_state WHERE name=?`, auditVocabularyMarkerName).Scan(&stored)
	if err != nil {
		// 表缺失（首次启动）或行缺失都视为未迁移；真实读错误同样按未迁移处理，
		// 迁移自身会再试并在失败时留日志（不阻断启动）。
		return false
	}
	return stored == fingerprint
}

// 归一表存在链式条目（如 ("重载","Caddy 配置") 单趟只能
// 命中对象改名条目变 ("重载","Caddy配置")——联动条目在表序上已越过），单趟
// 循环需两次启动才收敛——循环至不动点（整趟零改动）使单次启动归一终态。
// 趟数上限=条目数+1：无环表每趟严格推进，超限即未来编辑引入环，WARN 防御
// 死循环（不改写结果，残留中间态词条下次启动继续收敛）。
// marker 命中当前指纹时直接返回，零 UPDATE。
func migrateAuditVocabulary() {
	if AuditDB == nil {
		return
	}
	fingerprint := auditVocabularyFingerprint()
	if auditVocabularyMigrated(fingerprint) {
		return
	}
	if _, err := AuditDB.Exec(auditMigrationStateTable); err != nil {
		log.Printf("audit vocabulary migration marker unavailable (%v); running normalization anyway", err)
	}
	maxPasses := len(auditVocabularyRenames) + 1
	for range maxPasses {
		// failed 逐趟复位：失败只判定「本趟」——前一趟的瞬时失败若已恢复且
		// 后续趟无改动，允许落 marker；本趟仍有失败则不得置位（下次启动重试）。
		failed := false
		changed := false
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
				failed = true
				continue
			}
			if n, _ := res.RowsAffected(); n > 0 {
				changed = true
				log.Printf("audit vocabulary migration: %d rows normalized (%s)", n, query)
			}
		}
		if !changed {
			// 失败时不置位 marker——下次启动重试（残留中间态继续收敛）。
			if !failed {
				if _, err := AuditDB.Exec(`INSERT INTO audit_migration_state (name, fingerprint) VALUES (?, ?)
					ON CONFLICT(name) DO UPDATE SET fingerprint=excluded.fingerprint`, auditVocabularyMarkerName, fingerprint); err != nil {
					log.Printf("audit vocabulary migration marker write failed: %v", err)
				}
			}
			return
		}
	}
	log.Printf("audit vocabulary migration did not converge after %d passes (rename table cycle?)", maxPasses)
}

// 启动迁移跑在 InitializeAuditDB 之前，且 db 不能反向依赖
// services.RecordAuditLog（import 环）——迁移期的系统事件先入内存缓冲，审计库
// 就绪后统一落 audit_log 表，与 UI 操作日志同源。
type systemAuditEntry struct {
	action   string
	resource string
	detail   string
	// once 标记「同详情全生命周期只落一条」的一次性判据：flush 时 audit_log
	// 已有逐字相同的系统审计即跳过。用于只能人工处置的启动迁移僵持态——
	// 该状态每次启动都重新进入，不设判据会逐字重写同一条审计，audit_log 随
	// 重启线性增长；详情里的行 id/指纹集合变化（新脏数据）自然产生新详情并重报。
	once bool
}

var systemAuditBuffer struct {
	mu      sync.Mutex
	entries []systemAuditEntry
}

// 缓冲设上限，审计库长期不可用（或 flush 反复失败）时丢弃最旧条目并
// 告警，避免内存无界增长。
const systemAuditBufferCap = 10000

func recordSystemAudit(action, resource, detail string) {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	systemAuditBuffer.entries = append(systemAuditBuffer.entries, systemAuditEntry{action: action, resource: resource, detail: detail})
	trimSystemAuditBufferLocked()
}

func recordSystemAuditOnce(action, resource, detail string) {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	systemAuditBuffer.entries = append(systemAuditBuffer.entries, systemAuditEntry{action, resource, detail, true})
	trimSystemAuditBufferLocked()
}

// systemAuditAlreadyRecorded 报告 audit_log 是否已有一条逐字相同的系统审计
// （username='system'）。查询失败按「未记录」处理（fail-open：最多多留一条
// 审计，不影响正确性）；action 列有索引，同 action 的系统审计量级极小，
// 逐字比对成本可忽略。
func systemAuditAlreadyRecorded(entry systemAuditEntry) bool {
	var one int
	err := AuditDB.QueryRow(`SELECT 1 FROM audit_log WHERE username='system' AND action=? AND resource=? AND detail=? LIMIT 1`,
		entry.action, entry.resource, entry.detail).Scan(&one)
	return err == nil
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
// 写失败时条目按原顺序留回缓冲。留回不等于会被重试：唯一的生产调用点是
// InitializeAuditDB 的末尾（每进程只跑一次），离开该函数后不存在第二次 flush，
// 留回的条目随进程退出消失——即单次尝试语义，失败即丢弃。因此写失败必须当场
// 打日志明示丢弃条数，不静默。与 services.RecordAuditLog 的 best-effort 语义一致。
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
		systemAuditBuffer.entries = entries
		trimSystemAuditBufferLocked()
		systemAuditBuffer.mu.Unlock()
		return
	}
	var failed []systemAuditEntry
	for _, entry := range entries {
		// 一次性判据：同详情系统审计已落库即跳过（僵持态每次启动重新缓冲，
		// 不跳过会随重启线性重复）。同批先落的行也参与判重，同进程重复缓冲
		// 同样收敛。
		if entry.once && systemAuditAlreadyRecorded(entry) {
			continue
		}
		if _, err := AuditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system', ?, ?, ?, '')",
			entry.action, entry.resource, entry.detail); err != nil {
			log.Printf("system audit log write failed: %v", err)
			failed = append(failed, entry)
		}
	}
	if len(failed) > 0 {
		systemAuditBuffer.mu.Lock()
		// 留回缓冲（顺序保持）仍对外可见（测试/后续显式 flush 可重放），但
		// 生产路径不会再有 flush——丢弃条数必须写明，避免日志与真实留存量
		// 对不上时误判为「已重试成功」。
		systemAuditBuffer.entries = append(failed, systemAuditBuffer.entries...)
		trimSystemAuditBufferLocked()
		remaining := len(systemAuditBuffer.entries)
		systemAuditBuffer.mu.Unlock()
		log.Printf("system audit log: %d entries could not be written and are dropped (single-attempt flush, no retry in this process); %d entries left in the in-memory buffer",
			len(failed), remaining)
	}
}

// legacyAuditTableFingerprint 是主库旧审计表的廉价内容指纹（行数/MIN/MAX/
// SUM(id)）：仅判定「是否还是上次核对的同一批数据」，不复用于正确性判定。
func legacyAuditTableFingerprint(ctx context.Context, conn *sql.Conn) (string, error) {
	var rows, minID, maxID, sumID int64
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(id),0), COALESCE(MAX(id),0), COALESCE(SUM(id),0) FROM main.audit_log`).Scan(&rows, &minID, &maxID, &sumID); err != nil {
		return "", fmt.Errorf("failed to fingerprint legacy audit table: %w", err)
	}
	return fmt.Sprintf("rows=%d;min=%d;max=%d;sum=%d", rows, minID, maxID, sumID), nil
}

// auditMigrationStateValue 读审计库迁移状态标记（表/行缺失或读失败均返回空，
// 调用方按「无标记」处理——标记只影响性能，不影响正确性）。
func auditMigrationStateValue(name string) string {
	if AuditDB == nil {
		return ""
	}
	var stored string
	if err := AuditDB.QueryRow(`SELECT fingerprint FROM audit_migration_state WHERE name=?`, name).Scan(&stored); err != nil {
		return ""
	}
	return stored
}

// writeAuditMigrationState 幂等写迁移状态标记（审计库未就绪时跳过并留痕）。
func writeAuditMigrationState(name, fingerprint string) {
	if AuditDB == nil {
		return
	}
	if _, err := AuditDB.Exec(auditMigrationStateTable); err != nil {
		log.Printf("audit migration state unavailable (%v); marker %s not persisted", err, name)
		return
	}
	if _, err := AuditDB.Exec(`INSERT INTO audit_migration_state (name, fingerprint) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET fingerprint=excluded.fingerprint`, name, fingerprint); err != nil {
		log.Printf("audit migration state write failed (%s): %v", name, err)
	}
}

// clearAuditMigrationState 删除迁移状态标记；仅在标记存在时删除（收敛库零写）。
func clearAuditMigrationState(name string) {
	if AuditDB == nil || auditMigrationStateValue(name) == "" {
		return
	}
	if _, err := AuditDB.Exec(`DELETE FROM audit_migration_state WHERE name=?`, name); err != nil {
		log.Printf("audit migration state clear failed (%s): %v", name, err)
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
		// 迁移已完成/冲突已解除（主表已被人工删除）：清除已知冲突态标记，
		// 后续启动零写。
		clearAuditMigrationState(auditLegacyConflictMarkerName)
		return nil
	}
	// 已知冲突态（主库旧表与审计库来自不同时点/节点，仅人工恢复旧主库副本
	// 可达）持久化：人工处理前不再每启动重跑「ATTACH + INSERT OR IGNORE 全表
	// 复制 + 两次全表 mismatch 校验」——历史库可达数十万行。指纹只作跳过判据
	//（廉价 COUNT/MIN/MAX/SUM(id)），正确性仍由首次核对与人工核对承担。
	fingerprint, err := legacyAuditTableFingerprint(ctx, conn)
	if err != nil {
		return err
	}
	if stored := auditMigrationStateValue(auditLegacyConflictMarkerName); stored != "" && stored == fingerprint {
		auditLegacyConflictSkips.Add(1)
		log.Printf("WARN: 主库旧审计表与审计库仍处于已知冲突态（%s），跳过重复复制与校验并保留主库 audit_log 表；人工核对完成后删除该表即可完成迁移", fingerprint)
		return nil
	}
	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS audit_migration", auditPath); err != nil {
		return fmt.Errorf("failed to attach audit database: %w", err)
	}
	defer func() {
		// DETACH 失败曾静默忽略——连接归还池仍挂
		// audit_migration schema，本次迁移虽已提交，
		// 但失败须留痕便于排查连接池污染。
		if _, err := conn.ExecContext(ctx, "DETACH DATABASE audit_migration"); err != nil {
			log.Printf("migrateLegacyAuditLogs: DETACH audit_migration 失败（连接归还池仍挂 schema）: %v", err)
		}
	}()

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
		// 冲突=主库 audit_log 与审计库来自不同时点/节点（仅人工恢复旧主库
		// 副本可达）。此前直接返回错误 → InitializeAuditDB 上抛 → 进程无法
		// 启动且无不改库的恢复路径。改为服务可用优先：保留主库旧表（不
		// DROP，冲突行留作人工核对依据）+ WARN 日志 + 系统审计留痕（审计页
		// 可见，每次启动一条直至人工处理）；无冲突行已由上方 INSERT OR
		// IGNORE 并入（幂等，不覆盖目标库既有行）。
		detail := fmt.Sprintf("启动迁移：旧审计表与审计库存在 %d 行冲突，已跳过迁移并保留主库 audit_log 表（冲突行需人工核对；确认后可手动删除主库 audit_log 表完成迁移）", mismatch)
		log.Print("WARN: " + detail)
		recordSystemAudit("启动迁移", "操作日志", detail)
		writeAuditMigrationState(auditLegacyConflictMarkerName, fingerprint)
		return nil
	}
	// 无冲突：清除可能存在的旧冲突标记后删除旧表（收敛库零写）。
	clearAuditMigrationState(auditLegacyConflictMarkerName)
	if _, err := mainDB.Exec("DROP TABLE audit_log"); err != nil {
		// 数据已全量并入审计库且逐列校验通过（上方 mismatch=0），此处的
		// DROP 只是清理动作。删除失败（典型：另一连接持主库写锁）若上抛会
		// 让服务无法启动，而数据事实上已迁移安全。降级为 WARN + 系统审计
		// 留痕并保留旧表：下次启动的复制路径 INSERT OR IGNORE 幂等，
		// mismatch 仍为 0，DROP 自然重试。
		detail := fmt.Sprintf("启动迁移：旧审计表已迁移完成但删除失败，已保留主库 audit_log 表待下次启动重试（%v）", err)
		log.Print("WARN: " + detail)
		recordSystemAudit("启动迁移", "操作日志", detail)
		return nil
	}
	return nil
}
