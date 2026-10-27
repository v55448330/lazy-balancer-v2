package services

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 证书任务日志并入任务日志体系——挂靠
// {任务日志目录}/certjobs/（与 tasks/*.log 同根：大小上限共用
// task_log_size_mb、保留清理由 log-cleanup housekeeping 统一扫描）。
// 目录**惰性求值**——taskengine.LogDir() 注入恒晚于包
// 初始化，曾以包级 IIFE 固化致生产恒回退 /app/logs 根（脱离 housekeeping
// 清理面）。LogDir 未注入（测试环境）回退 /app/logs。
const legacyCertJobLogRoot = "/app/logs"

// certJobLogMigrated 旧目录一次性迁移门：SetLogDir 后首次
// 使用时把固化期写入旧根的 certjob-*.log（含轮转代 .1-.5/.gz）搬入新目录。
// atomic 而非 sync.Once：测试可复位重放（Once 值拷贝触发 vet noCopy）。
var certJobLogMigrated atomic.Bool

// CertJobLogDir 证书任务日志目录（读侧同源入口——logstats 统计与
// GetCertJobLogs 均经 CertJobLogPath/CertJobLogDir 取值）。
func CertJobLogDir() string {
	dir := taskengine.LogDir()
	if dir == "" {
		return legacyCertJobLogRoot
	}
	target := filepath.Join(dir, "certjobs")
	if certJobLogMigrated.CompareAndSwap(false, true) {
		migrateLegacyCertJobLogs(filepath.Dir(dir), target)
	}
	return target
}

// migrateLegacyCertJobLogs 一次性迁移：源=任务日志目录的父目录（容器内即
// /app/logs——tasks 的宿主根，与固化期 certjob-* 的实际落点）。
// 扫描/搬移失败记日志继续（旧文件残留无害——读侧已切新目录，
// 清理面按新目录扫描）；目标同名文件已存在视为新数据，跳过不覆盖。
func migrateLegacyCertJobLogs(legacyRoot, target string) {
	entries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return // 旧目录不存在（全新部署）——零迁移
	}
	moved := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "certjob-") || !strings.Contains(name, ".log") {
			continue
		}
		if moved == 0 {
			// 首个待迁文件出现才建目标目录（全新部署零建目录副作用）
			if mkErr := os.MkdirAll(target, 0o755); mkErr != nil {
				certJobLogWarnf("cert job log: migrate mkdir %s failed: %v", target, mkErr)
				return
			}
		}
		dst := filepath.Join(target, name)
		if _, err := os.Stat(dst); err == nil {
			continue // 新目录已有同名文件（升级后已写入）——不覆盖
		}
		if err := os.Rename(filepath.Join(legacyRoot, name), dst); err != nil {
			certJobLogWarnf("cert job log: migrate legacy %s failed: %v", name, err)
			continue
		}
		moved++
	}
	if moved > 0 {
		Logf("info", "证书任务日志迁移完成：旧目录 %s → %s 共 %d 个文件", legacyRoot, target, moved)
	}
}

const maxRotatedFiles = 5

// CertJobLogMaxRotatedFiles 导出证书任务日志写侧的保留份数契约
// handlers 的 logRotatedBackups 与展示层必须与写侧同源——此前
// 靠测试读取本文件源码文本（`const maxRotatedFiles = 5`）钉住，改注释/加类型
// 声明即误红，且第三个 writer 出现时漏验。导出 getter 让契约以数值断言。
func CertJobLogMaxRotatedFiles() int { return maxRotatedFiles }

// certJobLogWarnf 是轮转失败告警的测试接缝（var 而非直接 log.Printf，镜像
// finalizeTimeout 等先例：测试捕获告警调用，生产代码不得改写）。
var certJobLogWarnf = log.Printf

// CertJobFileLogger writes certificate issuance logs to
// {任务日志目录}/certjobs/certjob-{ruleID}.log with size-based rotation.
// Keeps up to 5 rotated backups (.1 through .5).
type CertJobFileLogger struct {
	ruleID string
}

// certJobLogWriteLocks 按 ruleID 串行化写与轮转（2026-09-05 证书域审计
// 裁定）：每次写日志都新建实例（Issue 的 jobLogger / WriteCertJobLog*），实例级
// 锁防不了跨实例并发轮转的 check-then-rename 交错——两个实例同时越过大小阈值
// 时，后者的 os.Rename(path, path+".1") 会覆盖前者刚轮转出的 .1，丢一整代
// 历史。条目随最后持有者释放回收（refCountedLockTable）：规则可反复创建/删除，
// 只增不删的表会按历史规则总数无界增长。
//
// 键口径 = certJobLogFileComponent(ruleID)：housekeeping
// 从文件名反解 ruleID，只能拿到已编码的主体；若写侧用原始值取锁，写与清理会持
// 不同互斥量，轮转/删除交错可覆盖 .1 代或删除未过期代。旧实现用剔除非法字符的
// 主体（sanitizePathComponent），不可逆致 `lb.dot` 与 `lbdot` 共文件共锁。
var certJobLogWriteLocks refCountedLockTable // file component -> entry

func lockCertJobLog(ruleID string) *refCountedLock {
	return certJobLogWriteLocks.acquire(certJobLogFileComponent(ruleID))
}

// NewCertJobFileLogger creates a logger bound to a specific rule.
func NewCertJobFileLogger(ruleID string) *CertJobFileLogger {
	return &CertJobFileLogger{ruleID: ruleID}
}

// CertJobLogPath returns the log file path for the given rule ID.
func CertJobLogPath(ruleID string) string {
	return filepath.Join(CertJobLogDir(), fmt.Sprintf("certjob-%s.log", certJobLogFileComponent(ruleID)))
}

// certJobLogFileComponent 证书任务日志文件名主体：与规则访问日志同构的可逆编码
// （encodeFileComponent）。字母表内 ID 原样保留（既有文件命名零变化）；
// 带点等存量 ID 编码为 "%"+hex，使 `lb.dot`/`lbdot` 落不同文件与不同写锁
// （旧剔除实现让二者共文件：签发日志跨规则混写、保留期清理互相删除）。
// 反解见 logrotate.certJobLogRuleIDFromName（旧文件名仍可解析）。
func certJobLogFileComponent(ruleID string) string {
	return encodeFileComponent(ruleID)
}

func (l *CertJobFileLogger) write(level, stage, message string) {
	// 跨实例按 ruleID 串行化（见 certJobLogWriteLocks 注释）。
	unlock := lockCertJobLog(l.ruleID)
	unlock.Lock()
	defer unlock.Unlock()

	path := CertJobLogPath(l.ruleID)

	timestamp := time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05")
	line := taskengine.TruncateTaskLogLine(fmt.Sprintf("%s [%s] %s - %s", timestamp, level, stage, message)) + "\n"

	// 轮转判定计入待写入行——size+len(line) 超阈即在写入
	// 前轮转，磁盘上活动文件恒 ≤ 上限。尺寸滚动唯一负责方为本写入侧（5 代移位），
	// log-cleanup 仅负责保留期清理，不再参与尺寸轮转。
	if _, err := taskengine.RotateTaskLogBeforeWrite(path, int64(len(line)), maxRotatedFiles); err != nil {
		certJobLogWarnf("cert job log: rotate %s failed: %v", path, err)
	}

	if err := os.MkdirAll(CertJobLogDir(), 0755); err != nil {
		Logf("error", "cert job log: failed to create dir: %v", err)
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		Logf("error", "cert job log: failed to open %s: %v", path, err)
		return
	}
	writeCertJobLogLine(f, path, line)
}

// writeCertJobLogLine 写一行并关闭，写/关闭错误经 Logf 留痕（磁盘配额
// 耗尽/只读降级时 OpenFile 可成功而后续写入失败，此前两类错误被静默吞没，
// 日志与 cert_jobs 状态分叉且无告警）。不改变签发结果。
func writeCertJobLogLine(dst io.WriteCloser, path, line string) {
	if _, err := fmt.Fprint(dst, line); err != nil {
		Logf("error", "cert job log: write %s failed: %v", path, err)
	}
	if err := dst.Close(); err != nil {
		Logf("warn", "cert job log: close %s failed: %v", path, err)
	}
}

// Log implements the acme.Logger interface (info level).
func (l *CertJobFileLogger) Log(stage, message string) {
	l.write("INFO", stage, message)
}

// WriteCertJobLog is a package-level helper for code paths that only have a
// jobID (e.g. failJob, markJobWaitingCA). It resolves the ruleID from the
// database and delegates to a CertJobFileLogger.
func WriteCertJobLog(jobID int, level, stage, message string) {
	var ruleID string
	if err := db.DB.QueryRow("SELECT rule_id FROM cert_jobs WHERE id=?", jobID).Scan(&ruleID); err != nil {
		Logf("error", "cert job log: failed to lookup rule_id for job %d: %v", jobID, err)
		return
	}
	NewCertJobFileLogger(ruleID).write(level, stage, message)
}

func WriteCertJobLogByRule(ruleID, level, stage, message string) {
	if ruleID == "" {
		return
	}
	NewCertJobFileLogger(ruleID).write(level, stage, message)
}

func RemoveCertJobLogFiles(ruleID string) error {
	// Cert-新1:持写锁——写路径串行化写与轮转,但删除路径
	// 此前无锁:删除时在途签发 goroutine 尾部日志重建孤儿文件(certjob-<rule>.log)。
	// 文件名主体已改为可逆编码；旧实现剔除非法字符产出的历史文件
	// （如 `lb.dot` → certjob-lbdot.log）与新文件名不同，此处不顺手删除——
	// 旧名与「剔除后同名的另一条规则」（lbdot）无法区分，误删会清掉他人日志。
	// 历史文件由保留期清理（taskLogsHousekeeping 可解析旧名）自然淘汰。
	lock := lockCertJobLog(ruleID)
	lock.Lock()
	defer lock.Unlock()
	path := CertJobLogPath(ruleID)
	// 仓内轮转只做 rename（rotateTaskLogFile 不压缩），但 logstats 读侧承认
	// 外部 logrotate 留下的整文件 gzip 归档形态（<base>.gz）；删除规则时
	// 连历史压缩代（.N.gz）一并清理，否则残留孤儿文件只能靠保留期兜底。
	candidates := make([]string, 0, 2*maxRotatedFiles+2)
	candidates = append(candidates, path, path+".gz")
	for index := 1; index <= maxRotatedFiles; index++ {
		candidates = append(candidates,
			fmt.Sprintf("%s.%d", path, index),
			fmt.Sprintf("%s.%d.gz", path, index))
	}
	var cleanupErrors []error
	for _, candidate := range candidates {
		if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("删除证书任务日志 %s: %w", candidate, err))
		}
	}
	return errors.Join(cleanupErrors...)
}
