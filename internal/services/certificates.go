package services

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

type CertificateService struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	recoverJobs func(context.Context)
	// deploymentRetry 登记一次部署重试；返回错误表示本轮**未登记**（暂停/
	// 停止/规则补偿屏障）。可观测结果是补扫计数与摘要行的正确性前提。
	deploymentRetry     func(int, issuedCertificate, time.Duration) error
	timerMu             sync.Mutex
	deploymentTimers    map[int]*deploymentTimer
	deploymentCallbacks map[int]map[*deploymentTimer]struct{}
	// delayedReloads 承载「未来生效证书」的一次性延迟重载定时器（同 jobID
	// 唯一，重复登记替换旧 timer）。与 deploymentTimers 分表：前者不得被
	// 部署重试的取消/替换语义波及，但必须与部署定时器族共享 stop/pause
	// 生命周期，否则服务停止后仍会留下待触发的定时器。
	delayedReloads  map[int]*delayedReloadTimer
	timersPaused    bool
	stopping        bool
	retryDeployment func(context.Context, int) error
	// started 标记 Start() 已进入：done 只由 Start 的 defer 关闭，
	// 未启动即 Stop 会永久阻塞。生产唯一调用方保证先 Start，但契约不应依赖
	// 调用顺序；未启动时 Stop 直接返回（cancel 已生效，后续 Start 立即退出）。
	started atomic.Bool
	// expiryAlertGate 手动证书过期提醒的当日去重门——同一证书
	// 同日同档位只告警一次;nil 时放行不抑制(测试直构防御)。
	expiryAlertGate *manualCertExpiryAlertGate
	// cancelWaitTimeout 上限取消部署重试时的在途等待；0 走默认 30s。测试可覆盖。
	cancelWaitTimeout time.Duration
}

// 手动证书过期提醒档位(数值即深浅,深档可覆盖浅档的当日记录)。
const (
	manualCertExpiryLevelExpiringSoon = 1 // 临期(warn)
	manualCertExpiryLevelExpired      = 2 // 已过期(critical)
)

// manualCertExpiryAlertGate 按「证书 ID + 日期」记忆进程内已告警档位:
// 同一证书同一天同档/浅档不重复告警(10min 扫描不再刷屏);档位加深
// (临期→已过期)当日可再告(新事件);跨日重新告警。进程内状态,重启后
// 当日重告一次(可接受,胜过持久化复杂度)。
type manualCertExpiryAlertGate struct {
	mu        sync.Mutex
	activeDay string
	seen      map[string]manualCertExpiryAlertRecord
}

type manualCertExpiryAlertRecord struct {
	day   string
	level int
}

func newManualCertExpiryAlertGate() *manualCertExpiryAlertGate {
	return &manualCertExpiryAlertGate{seen: map[string]manualCertExpiryAlertRecord{}}
}

// shouldAlert 判定本次扫描是否应告警:是则记录并返回 true。nil 接收者
// 防御性放行(不抑制)。map 以证书 ID 为键；日界滚动时整体清空，已删除
// 规则的残留 ID 不会跨日累积。
func (g *manualCertExpiryAlertGate) shouldAlert(caddyID string, level int, now time.Time) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	day := now.Format("2006-01-02")
	if g.activeDay != day {
		// 日界滚动时丢弃前一天全部证书键：删除规则的历史 ID 不得跨日累积。
		g.activeDay = day
		g.seen = make(map[string]manualCertExpiryAlertRecord)
	} else if g.seen == nil {
		g.seen = make(map[string]manualCertExpiryAlertRecord)
	}
	if record, ok := g.seen[caddyID]; ok && record.day == day && record.level >= level {
		return false
	}
	g.seen[caddyID] = manualCertExpiryAlertRecord{day: day, level: level}
	return true
}

type deploymentTimer struct {
	timer    *time.Timer
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	ruleID   string
	canceled bool
}

// delayedReloadTimer 是未来生效证书的一次性重载登记项：只需 timer 与取消位。
type delayedReloadTimer struct {
	timer    *time.Timer
	canceled bool
}

var (
	certificateServiceMu sync.Mutex
	certificateService   *CertificateService
)

type certJobSnapshot struct {
	id                       int
	ruleID                   string
	domain                   string
	status                   string
	message                  sql.NullString
	expiresAt                sql.NullTime
	certPEM                  sql.NullString
	keyPEM                   sql.NullString
	caProviderID             int
	renewalAttempts          int
	caAvailableAfter         sql.NullTime
	lastErrorCode            sql.NullString
	deploymentAttempts       int
	deploymentAvailableAfter sql.NullTime
	createdAt                sql.NullTime
	updatedAt                sql.NullTime
}

// CertJobsSnapshot is an opaque cert_jobs restore point used to compensate a
// failed UpdateRule ACME enqueue after an UPSERT may have replaced old state.
// preserved 记录 restore 因行级 epoch 守卫而保留的快照后成果：
// 这些行与快照不一致，补偿重排队必须按当前行状态判定，不得沿用
// 快照状态把它们当作在途任务转 queued 重签。map 随快照值共享，restore 填充后
// 同一 snapshot 的 requeue 可见（两条调用在同一补偿流程内串行执行）。
type CertJobsSnapshot struct {
	ruleID    string
	jobs      []certJobSnapshot
	preserved map[int]struct{}
}

// SnapshotCertJobsForRule captures all cert_jobs rows for UpdateRule ACME
// enqueue compensation.
func SnapshotCertJobsForRule(ruleID string) (CertJobsSnapshot, error) {
	snapshot := CertJobsSnapshot{ruleID: ruleID, preserved: make(map[int]struct{})}
	rows, err := db.DB.Query(`SELECT id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,COALESCE(ca_provider_id,0),
		COALESCE(renewal_attempts,0),ca_available_after,last_error_code,COALESCE(deployment_attempts,0),deployment_available_after,created_at,updated_at
		FROM cert_jobs WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return CertJobsSnapshot{}, fmt.Errorf("query certificate job snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var job certJobSnapshot
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.message, &job.expiresAt,
			&job.certPEM, &job.keyPEM, &job.caProviderID, &job.renewalAttempts, &job.caAvailableAfter,
			&job.lastErrorCode, &job.deploymentAttempts, &job.deploymentAvailableAfter, &job.createdAt, &job.updatedAt); err != nil {
			return CertJobsSnapshot{}, fmt.Errorf("scan certificate job snapshot: %w", err)
		}
		snapshot.jobs = append(snapshot.jobs, job)
	}
	if err := rows.Err(); err != nil {
		return CertJobsSnapshot{}, fmt.Errorf("iterate certificate job snapshot: %w", err)
	}
	return snapshot, nil
}

// canonicalDatetime 把快照中的 DATETIME 列值绑定为与规范写路径一致的墙钟
// 字符串：直接绑 sql.NullTime 会让 modernc 驱动按默认布局落库为
// `2006-01-02 15:04:05+00:00`，而 rescan（rescanDroppedDeploymentRetries）
// 的 time.Parse("2006-01-02 15:04:05") 是该格式唯一解析点——失败即丢一个
// 部署退避窗口（自愈：下次失败会以规范格式重写，但 attempts 可能额外 +1）。
// 写侧归一让 restore round-trip 格式稳定，消除该窗口。
func canonicalDatetime(v sql.NullTime) any {
	if !v.Valid {
		return nil
	}
	return CanonicalDatetimeValue(v.Time)
}

// CanonicalDatetimeValue 把时刻归一为 cert_jobs DATETIME 列的规范墙钟串
// （UTC、无时区标识），与 canonicalDatetime 同一布局。所有 cert_jobs 时间列
// 写点必须共用：直接绑 time.Time 会落成 `+00:00` 形态，与 API 文档声明的
// 「UTC 墙钟串（无时区标识）」及 rescan 的解析布局不一致。
func CanonicalDatetimeValue(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// RestoreCertJobsForRule restores UPSERT-overwritten rows and removes jobs
// created after SnapshotCertJobsForRule captured the rule state.
func RestoreCertJobsForRule(snapshot CertJobsSnapshot) error {
	return restoreCertJobsForRule(context.Background(), snapshot)
}

func restoreCertJobsForRule(ctx context.Context, snapshot CertJobsSnapshot) error {
	// 恢复是「整规则回滚 cert_jobs」，必须与同规则的部署/文件回滚事务
	// 互斥——DeployLock 是证书部署链（certissuer 快速路径 confirmCertificateDeployment
	// / deployIssuedCertificate + 失败时的文件回滚）的串行锁。不取锁时，
	// 补偿窗口内刚完成的部署提交（含 WriteCertFiles+reload+状态落库）会被旧快照
	// 覆盖，磁盘/Caddy 与 DB 分叉。
	// 统一锁序：CaddyOpLock → DeployLock → DB 事务。本函数
	// 只取 DeployLock（函数体不触碰 CaddyOpLock），调用点持锁形态分两族——
	// UpdateRule/EnableRule 补偿在 caddyOpMu 临界区内调本函数（=CaddyOpLock→
	// DeployLock，规范序）；DeleteRule 后台补偿不持任何全局锁（单锁无环）。
	// 部署侧同序（certissuer 部署临界区先取 CaddyOpLock 再取 DeployLock），
	// 两侧不再构成 AB-BA。全部调用点都不持 DeployLock（无重入死锁）。
	// 等待无 ctx 上限：部署链本身有界（waitDoneOrTimeout/caddyReloader 有超时），
	// 宁可多等一轮也不在部署在途时回滚。
	unlock := DeployLock(snapshot.ruleID)
	defer unlock()

	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin certificate job restore: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 时代校验：快照后规则可能被并发删除（重试 DeleteRule、
	// 配置导入整树替换）或以同 caddy_id 重建为新域名。规则不存在时 DELETE+INSERT
	// 只会写入幽灵行（cert_jobs 对 lb_rules 无外键）；域名与快照最新任务不一致时
	// DELETE+INSERT 会摧毁新化身的任务状态。两种情形都没有可恢复对象，按补偿完成
	// 收尾（返回 nil，调用方释放租约）。判定必须是保守的：只有规则明确仍属于
	// 快照时代（最新快照任务与当前规则域名规范化一致）才允许恢复。
	var ruleDomain string
	var ruleEnabled, ruleEnableTLS bool
	var ruleTLSSource string
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(domain,''), IIF(enabled IN ('1',1),1,0), COALESCE(enable_tls,0), COALESCE(tls_source,'manual')
		FROM lb_rules WHERE caddy_id=?`, snapshot.ruleID).Scan(&ruleDomain, &ruleEnabled, &ruleEnableTLS, &ruleTLSSource)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load rule for certificate job restore: %w", err)
	}
	if !certJobsSnapshotEraMatchesRule(snapshot, ruleDomain) {
		return nil
	}
	// 规则态也是「快照后的真实成果」的判据：规则已退出「启用 ACME」（禁用/
	// 关 TLS/改证书来源）时，其任务行的 disabled 是规则写点留下的终态——恢复
	// 成快照状态（queued/waiting_ca）会让已禁用规则的任务重新进入队列。
	ruleACMEActive := ruleEnabled && ruleEnableTLS && ruleTLSSource == "acme_dns"
	// 已知竞态：DeleteRule drain 超时启动的后台补偿不持
	// caddyOpMu，其分钟级退避窗口内用户可能对同一规则 DeleteCertJob
	// 成功——下方恢复无法区分「用户显式删除」与「DeleteRule
	// 事务删除」，会把刚删的快照行复活。评估过按「快照后显式删除」收窄
	// 恢复（跳过缺失 id 的 re-INSERT）：缺失 id 同时可能来自从节点 apply
	// 整树替换等路径，且本函数与 UpdateRule/EnableRule 补偿共享（后者
	// 依赖清除失败入队新建的行），收窄会引入分叉语义，收益
	// 不抵复杂度。恢复是保守选择：复活行来自规则自身快照时代、非损坏
	// 数据，续签链因此保持完整；补偿退避有界，窗口过后用户可再次删除。
	//
	// 行级 epoch 守卫：DeployLock 只挡住「恢复期间」的并发部署，
	// 挡不住快照之后、取锁之前已经落库的签发/部署成果。逐行比对当前行与快照行
	// ——当前行携带快照没有的证书材料（快照后完成了签发/续期），或已推进到
	// issued 而快照不是（快照后完成了部署提交），即视为真实成果，跳过该行回滚。
	// 判定不使用 updated_at：被 UPSERT 覆写的行同样会推进 updated_at，用它区分
	// 会把本函数要修的覆写误判成新成果。
	currentRows, err := loadCertJobStatesTx(ctx, tx, snapshot.ruleID)
	if err != nil {
		return fmt.Errorf("load certificate jobs for restore: %w", err)
	}
	currentByID := make(map[int]certJobState, len(currentRows))
	currentByDomain := make(map[string]certJobState, len(currentRows))
	for _, row := range currentRows {
		currentByID[row.id] = row
		currentByDomain[row.domain] = row
	}
	snapshotIDs := make(map[int]struct{}, len(snapshot.jobs))
	for _, job := range snapshot.jobs {
		snapshotIDs[job.id] = struct{}{}
	}
	// preserved 中的当前行保持原样：不回滚、也不插入快照行。
	preserved := make(map[int]struct{}, len(currentRows))
	for _, job := range snapshot.jobs {
		row, exists := currentByID[job.id]
		if !exists || !certJobRowPreservedOnRestore(row, job, ruleACMEActive) {
			continue
		}
		preserved[job.id] = struct{}{}
		if snapshot.preserved != nil {
			snapshot.preserved[job.id] = struct{}{}
		}
		Logf("warn", "证书任务恢复跳过 %d：快照后已完成签发/部署或规则已退出启用 ACME，保留当前状态(=%s)不回滚", job.id, row.status)
	}
	// 快照之后新建的行：沿用「清除失败入队新建行」语义（UpdateRule/EnableRule
	// 补偿依赖），但带证书材料的行是真实签发成果，保留。
	for _, row := range currentRows {
		if _, fromSnapshot := snapshotIDs[row.id]; fromSnapshot {
			continue
		}
		if strings.TrimSpace(row.certPEM) != "" || strings.TrimSpace(row.keyPEM) != "" {
			preserved[row.id] = struct{}{}
			if snapshot.preserved != nil {
				snapshot.preserved[row.id] = struct{}{}
			}
			Logf("warn", "证书任务恢复保留快照后新建任务 %d：已携带证书材料", row.id)
		}
	}
	for _, row := range currentRows {
		if _, keep := preserved[row.id]; keep {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM cert_jobs WHERE id=?", row.id); err != nil {
			return fmt.Errorf("clear certificate job %d for restore: %w", row.id, err)
		}
	}
	for _, job := range snapshot.jobs {
		if _, keep := preserved[job.id]; keep {
			continue
		}
		// 同域行被保留（唯一索引 rule_id+domain）：保留行是更新的成果，跳过插入。
		if row, exists := currentByDomain[job.domain]; exists {
			if _, keep := preserved[row.id]; keep {
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO cert_jobs (id,rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,
			renewal_attempts,ca_available_after,last_error_code,deployment_attempts,deployment_available_after,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, job.id, job.ruleID, job.domain, job.status, job.message,
			canonicalDatetime(job.expiresAt), job.certPEM, job.keyPEM, job.caProviderID, job.renewalAttempts, canonicalDatetime(job.caAvailableAfter),
			job.lastErrorCode, job.deploymentAttempts, canonicalDatetime(job.deploymentAvailableAfter), canonicalDatetime(job.createdAt), canonicalDatetime(job.updatedAt)); err != nil {
			return fmt.Errorf("restore certificate job %d: %w", job.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit certificate job restore: %w", err)
	}
	return nil
}

// certJobState 是恢复流程行级 epoch 判定所需的当前行最小视图
// （含部署退避簿记：快照后由部署失败推进的 attempts/窗口同样是真实成果）。
type certJobState struct {
	id                       int
	status                   string
	certPEM, keyPEM          string
	domain                   string
	deploymentAttempts       int
	deploymentAvailableAfter sql.NullTime
}

// loadCertJobStatesTx 在恢复事务内读出该规则当前全部 cert_jobs 行的判定视图
// （按 id 升序，保证日志顺序稳定）。
func loadCertJobStatesTx(ctx context.Context, tx *sql.Tx, ruleID string) ([]certJobState, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, status, COALESCE(cert_pem,''), COALESCE(key_pem,''), COALESCE(domain,''),
		COALESCE(deployment_attempts,0), deployment_available_after
		FROM cert_jobs WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []certJobState
	for rows.Next() {
		var state certJobState
		if err := rows.Scan(&state.id, &state.status, &state.certPEM, &state.keyPEM, &state.domain,
			&state.deploymentAttempts, &state.deploymentAvailableAfter); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return states, nil
}

// certJobRowPreservedOnRestore 判定当前行是否必须在恢复中保留（不回滚）：
// ①行级 epoch（快照后完成签发/部署）；②规则已退出「启用 ACME」且当前行是
// disabled——禁用/改来源写点发生在快照之后，恢复成快照状态会让已禁用规则的
// 任务重新可被周期扫描入队（补偿链的分钟级退避窗口内无 caddyOpMu，与
// DisableRule/UpdateRule 并发）。
func certJobRowPreservedOnRestore(current certJobState, snapshot certJobSnapshot, ruleACMEActive bool) bool {
	if certJobStateAdvancedSinceSnapshot(current, snapshot) {
		return true
	}
	return !ruleACMEActive && current.status == "disabled"
}

// certJobStateAdvancedSinceSnapshot 判定当前行是否承载了快照之后才产生的签发/
// 部署成果：证书材料与快照不同（新签发/续期写入了新 PEM），或材料
// 相同但已推进到 issued（快照后完成了部署提交），或材料相同但部署退避簿记
// 已推进（快照后部署失败推进了 deployment_attempts/后续窗口）。命中即不回滚
// 该行——否则刚完成的续期/部署会被旧快照抹掉，磁盘/Caddy 与 DB 分叉，退避
// 窗口也会被提前。无材料的行恒不视为推进：状态/重试次数的变化正是本函数要修的
// UPSERT 覆写形态。
func certJobStateAdvancedSinceSnapshot(current certJobState, snapshot certJobSnapshot) bool {
	currentCert := strings.TrimSpace(current.certPEM)
	currentKey := strings.TrimSpace(current.keyPEM)
	if currentCert == "" && currentKey == "" {
		return false
	}
	if currentCert != strings.TrimSpace(snapshot.certPEM.String) || currentKey != strings.TrimSpace(snapshot.keyPEM.String) {
		return true
	}
	if current.status == "issued" && snapshot.status != "issued" {
		return true
	}
	// 部署退避簿记同属「快照后的真实成果」：部署链在同一份材料上连续失败时只推进
	// deployment_attempts 并把窗口后移（状态/材料不变，见 deploymentFailedFrom /
	// advanceCertificateDeploymentWindow）。按快照整行重写会把它回退——退避窗口
	// 提前（多一次部署 + 一次 /load），窗口还可能从有值退回 NULL，使该行只剩补扫/
	// 重启通道。无材料的行已在上面提前返回：材料是部署失败写回的伴随物，无材料
	// 即不是部署链成果（状态/重试次数的变化正是本函数要修的 UPSERT 覆写形态）。
	if current.deploymentAttempts > snapshot.deploymentAttempts {
		return true
	}
	if current.deploymentAvailableAfter.Valid &&
		(!snapshot.deploymentAvailableAfter.Valid || current.deploymentAvailableAfter.Time.After(snapshot.deploymentAvailableAfter.Time)) {
		return true
	}
	return false
}

// certJobsSnapshotEraMatchesRule 判定规则当前状态是否仍属于快照时代：快照按 id
// 升序排列，最新（最后一条）任务的域名即快照时刻规则的 ACME 身份；与规则当前
// 域名规范化比较，不一致（含无快照任务、域名不可规范化）一律视为时代不明，
// 保守跳过恢复。
func certJobsSnapshotEraMatchesRule(snapshot CertJobsSnapshot, ruleDomain string) bool {
	if len(snapshot.jobs) == 0 {
		return false
	}
	canonicalRule, err := CanonicalACMEDomains(ruleDomain)
	if err != nil {
		return false
	}
	canonicalJob, err := CanonicalACMEDomains(snapshot.jobs[len(snapshot.jobs)-1].domain)
	if err != nil {
		return false
	}
	return canonicalJob == canonicalRule
}

// ruleExistsForCertCompensation 报告补偿目标规则是否仍然存在。
func ruleExistsForCertCompensation(ctx context.Context, ruleID string) (bool, error) {
	var one int
	err := db.DB.QueryRowContext(ctx, "SELECT 1 FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check rule existence for certificate compensation: %w", err)
	}
	return true, nil
}

func requeueCertJobsSnapshot(ctx context.Context, snapshot CertJobsSnapshot, manager *CAQueueManager) error {
	var ruleDomain string
	var enabled, enableTLS bool
	var tlsSource string
	if err := db.DB.QueryRowContext(ctx, `SELECT domain,IIF(enabled IN ('1',1),1,0),enable_tls,COALESCE(tls_source,'manual') FROM lb_rules WHERE caddy_id=?`, snapshot.ruleID).
		Scan(&ruleDomain, &enabled, &enableTLS, &tlsSource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 规则已被并发删除：没有可补偿对象，按成功收尾——
			// 返回错误会把补偿拖入永久退避循环且租约永不释放。
			return nil
		}
		return fmt.Errorf("load rule for certificate job requeue: %w", err)
	}
	if !enabled || !enableTLS || tlsSource != "acme_dns" {
		return nil
	}
	canonicalRule, err := CanonicalACMEDomains(ruleDomain)
	if err != nil {
		// 非法 ACME 域（导入可产生——导入校验不验 ACME 域合法性）的
		// 规则本就无法重排队（createOrRequeue 同样拒绝非法域），返回错误会把
		// 补偿拖入永久退避循环且租约永不释放——与 ErrNoRows/禁用分支同为放弃语义。
		Logf("warn", "证书任务补偿重排队放弃：规则 %s 域名不可规范化: %v", snapshot.ruleID, err)
		return nil
	}
	for _, job := range snapshot.jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if JobIsTerminal(job.status) {
			continue
		}
		canonicalJob, err := CanonicalACMEDomains(job.domain)
		if err != nil || canonicalJob != canonicalRule {
			continue
		}
		// 材料在身且处于部署生命周期（downloaded/cleanup_dns/cleanup_warning，
		// 即 JobLifecycleDownloaded 全集，与启动恢复 requeueNonTerminalCertJobs 的
		// lifecycle==Downloaded && hasCertMaterial 同口径）的快照任务走 Issue 快速
		// 路径重部署——转 'queued' 会丢弃已签发证书并触发整轮重签（只认
		// 'downloaded'；放宽到部署生命周期全集：cleanup_* 任务材料同样
		// 已落库、只差部署）。'downloaded' 保持原状态直接入队（与 requeueCanceledJob
		// 同口径）；cleanup_* 先归一化为 'downloaded'——Issue 快速路径只认
		// issued/downloaded。'queued'+材料不在例外内（显式重签请求全量重签
		// BY-DESIGN，材料是上轮残留）。
		//
		// 联动：入队决策读当前行而不是快照——restore 的行级 epoch 守卫会
		// 保留快照之后的真实成果（行已推进为 downloaded/issued 并携带新材料），
		// 若仍按快照状态判定，刚签发完成的任务会被当作在途任务转 'queued' 触发
		// 整轮重签，白烧 CA 配额并丢弃有效证书。只有被 restore 保留的行与快照
		// 分叉（snapshot.preserved），其余行沿用快照状态——不给正常路径额外增加
		// 每任务一次读（补偿流程与队列执行存在既有时序耦合）。
		liveStatus := job.status
		hasMaterial := job.certPEM.Valid && job.keyPEM.Valid && CertJobMaterialUsable(job.status, job.certPEM.String, job.keyPEM.String)
		if _, preserved := snapshot.preserved[job.id]; preserved {
			if status, material, found, stateErr := loadCertJobDeploymentState(job.id); stateErr != nil {
				Logf("warn", "证书任务补偿重排队：读取任务 %d 当前状态失败，按快照状态处理: %v", job.id, stateErr)
			} else if !found {
				// 行已不存在（并发删除/迁移）——没有可重排队的对象。
				continue
			} else {
				liveStatus, hasMaterial = status, material
				if JobIsTerminal(liveStatus) {
					continue
				}
			}
		}
		materialFastPath := hasMaterial && JobLifecycle(liveStatus) == JobLifecycleDownloaded
		// 材料快速路径的两个分支都必须把部署窗口推到 now 并落库。部署补扫
		// （rescanDroppedDeploymentRetries）只收 status='downloaded' 且
		// deployment_available_after 非空的行——此前补偿保持/归一化到 downloaded 却不写
		// 该列（补偿 downloaded 快照常为 NULL），队列未激活或 provider 不可用时任务
		// 两条补扫通道都不收，只能等重启恢复；provider 不可用分支还会被 failJob 摘掉。
		deploymentReadyAfter := time.Now().UTC().Format("2006-01-02 15:04:05")
		switch {
		case materialFastPath && liveStatus != "downloaded":
			if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "downloaded", map[string]any{
				"message":                    "补偿重排队：证书材料已落库，转快速部署",
				"deployment_available_after": deploymentReadyAfter,
			}); err != nil {
				if !errors.Is(err, ErrJobTransitionConflict) {
					return fmt.Errorf("transition restored certificate job %d to downloaded: %w", job.id, err)
				}
				continue
			}
		case materialFastPath:
			// 已是 'downloaded'：只推进部署窗口（不写 status，状态机写点仍单一来源）。
			// 写点必须复用单源——此前这里只推窗口而漏写 updated_at，重试冷却门
			// （以 updated_at 为基准）看不到本轮重排，形成「补扫可见但冷却门不可见」
			// 的半套状态。
			if _, err := PushCertJobDeploymentWindow(db.DB, job.id, CertJobDeploymentWindowPush{
				Message: "补偿重排队：证书材料已落库，等待重新部署",
				Where:   "status='downloaded'",
			}); err != nil {
				return fmt.Errorf("restore deployment window for certificate job %d: %w", job.id, err)
			}
		case !materialFastPath:
			// 所有重签发入队路径落库态均为 'queued'（queuedJobStillExists 复核依赖此不变量）：
			// 快照保留快照时刻的在途状态（waiting_ca/creating_*/validating 等），不归一化
			// 直接入队会在 provider 失效 drain 时被复核跳过（status≠'queued'），任务滞留
			// 队列外直到重启。入队前归一化转换，与 requeueStrandedJobs /
			// requeueWaitingCAJobs / 启动恢复同型；waiting_ca 冷却扫描等并发路径已接管
			// 该行时 CAS 冲突，按既有语义跳过入队由接管方负责。材料例外见上：仅部署
			// 生命周期（JobLifecycleDownloaded）+ 材料在身的任务转 'downloaded'。
			if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "queued", map[string]any{"message": "补偿重排队"}); err != nil {
				if !errors.Is(err, ErrJobTransitionConflict) {
					return fmt.Errorf("transition restored certificate job %d for requeue: %w", job.id, err)
				}
				continue
			}
		}
		if err := manager.enqueueCompensation(job.caProviderID, job.id, job.ruleID, job.domain); err != nil {
			if errors.Is(err, errCAQueueInactive) {
				// 队列暂停/未激活：状态按上面分支的真实结果描述（此前无条件
				// 谎称「已转 queued」，而材料快速路径实际停在 downloaded）。签发/重签
				// 任务保持 queued 由 Resume/周期巡检的 stranded 扫描接管；只差部署的
				// 任务保持 downloaded 且部署窗口已推到 now，由部署补扫接管。
				// 不得把租约拖入永久退避（DeleteRule 超时补偿的孤儿屏障）。
				if materialFastPath {
					Logf("info", "证书任务补偿重排队延后：CA 队列未激活，任务 %d 保持 downloaded（部署窗口已推到当前时刻，由部署补扫接管）", job.id)
				} else {
					Logf("info", "证书任务补偿重排队延后：CA 队列未激活，任务 %d 保持 queued 待恢复扫描", job.id)
				}
				continue
			}
			if errors.Is(err, errCAProviderUnavailable) {
				if materialFastPath {
					// 只差部署的任务不依赖 provider（部署链直接读库材料），
					// enqueueLocked 已保持可部署态（未 failJob），部署窗口已推到 now，
					// 部署补扫接管。补偿照常收敛、租约释放。
					Logf("warn", "证书任务补偿重排队延后：CA Provider 不可用，任务 %d 保持 downloaded 待部署补扫（不标记 failed）", job.id)
					continue
				}
				// provider 不可用是已定局的业务失败——enqueueLocked 内
				// failJob 已把任务置 failed 并写 job-status/审计。上抛会让补偿退避
				// 循环永久重试（每轮 restore 复活 failed 行再重新失败）且规则租约
				// 永不释放（该规则证书操作持续 409）。按「该任务已定局」跳过并
				// 继续其余任务，补偿一轮收敛、租约释放；provider 恢复后由手动
				// 重试/续签链路接管。
				Logf("warn", "证书任务补偿重排队跳过任务 %d：CA Provider 不可用（已标记 failed，可手动重试）", job.id)
				continue
			}
			return fmt.Errorf("requeue restored certificate job %d: %w", job.id, err)
		}
	}
	return nil
}

func NewCertificateService() *CertificateService {
	ctx, cancel := context.WithCancel(context.Background())
	service := &CertificateService{
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		deploymentRetry:     scheduleCertificateDeploymentRetry,
		deploymentTimers:    make(map[int]*deploymentTimer),
		deploymentCallbacks: make(map[int]map[*deploymentTimer]struct{}),
		delayedReloads:      make(map[int]*delayedReloadTimer),
		expiryAlertGate:     newManualCertExpiryAlertGate(),
	}
	service.retryDeployment = func(ctx context.Context, jobID int) error {
		manager := GetCAQueueManager()
		if manager == nil {
			return fmt.Errorf("Caddy reloader is not initialized")
		}
		manager.mu.Lock()
		reloader := manager.reloader
		manager.mu.Unlock()
		return retryCertificateDeployment(ctx, jobID, reloader)
	}
	service.recoverJobs = service.recoverCertJobs
	certificateServiceMu.Lock()
	certificateService = service
	certificateServiceMu.Unlock()
	return service
}

// waitDoneOrTimeout 有界等待部署定时器/回调退出
// 收敛 cancelDeploymentRetry/pauseDeploymentRetries 的内联同构等待）：回调链条最终
// 调到非 context-aware 的 caddyReloader，挂起时裸等会拖死调用方（签发
// goroutine/取消/暂停/Resume/启动恢复）。超时后放弃等待继续调用方流程——
// 重排侧等于放弃本轮调度：deployment_available_after 已落库，后续补扫/重启可再
// 拾起；DeployLock 按规则串行 + 终态 CAS 保证滞留回调即便最终退出也不会并发部署。
// timeout<=0 回退 30s；调用点统一传 s.cancelWaitTimeout
// （测试缝，同模式同口径）。jobID=0 表示无单任务上下文（全量暂停路径）。
func waitDoneOrTimeout(done <-chan struct{}, timeout time.Duration, jobID int, what string) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	select {
	case <-done:
	case <-time.After(timeout):
		if jobID > 0 {
			Logf("warn", "证书任务 %d：等待%s退出超时（%s），继续后续流程", jobID, what, timeout)
		} else {
			Logf("warn", "等待%s退出超时（%s），继续后续流程", what, timeout)
		}
	}
}

// scheduleDelayedReload 登记一次性延迟 Caddy 重载（未来时钟证书的生效点
// 补充重载）。复用部署重试定时器族的生命周期（服务停止/暂停即不登记、
// 服务 ctx 取消即不执行），但不占用 deploymentTimers——该 map 承载「同
// jobID 唯一部署」不变量，一次性重载与部署重试互不取消、互不替换。
// 服务停止/暂停期跳过登记的边界：不在恢复时补登（一次性定时器无持久化）。
// 收敛路径=重启时的配置物化/重载、下一次任意配置写触发的重载、服务运行后
// 新登记的延迟重载定时器——部署「补扫」不重渲染配置，不是收敛路径。
func (s *CertificateService) scheduleDelayedReload(jobID int, ruleID string, delay time.Duration) {
	s.timerMu.Lock()
	if s.stopping || s.timersPaused {
		s.timerMu.Unlock()
		Logf("warn", "证书任务 %d（规则 %s）：部署定时器已停止/暂停，生效后重载跳过登记（证书文件已随部署生效；收敛路径=重启物化/下一次配置写触发的重载）", jobID, ruleID)
		return
	}
	if s.delayedReloads == nil {
		s.delayedReloads = make(map[int]*delayedReloadTimer)
	}
	// 同一任务重复部署（手动重试/快速路径）只保留最后一次登记，避免同一
	// 生效点堆积多个一次性重载。
	if previous := s.delayedReloads[jobID]; previous != nil {
		previous.canceled = true
		previous.timer.Stop()
	}
	entry := &delayedReloadTimer{}
	s.delayedReloads[jobID] = entry
	ctx := s.ctx
	//scope-exempt: one-shot-deadline-callback —— 单次部署生效延迟重载（canceled/stopping 收口，不跨调用自续）
	entry.timer = time.AfterFunc(delay, func() {
		s.timerMu.Lock()
		if s.delayedReloads[jobID] == entry {
			delete(s.delayedReloads, jobID)
		}
		skipped := entry.canceled || s.stopping || s.timersPaused
		s.timerMu.Unlock()
		if skipped {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		manager := GetCAQueueManager()
		if manager == nil {
			return
		}
		manager.mu.Lock()
		reloader := manager.reloader
		manager.mu.Unlock()
		if reloader == nil {
			return
		}
		// reloader 为 InLock 语义（InitCAQueueManager 契约）——本回调在部署
		// 临界区外触发，须自取 CaddyOpLock。
		CaddyOpLock.Lock()
		defer CaddyOpLock.Unlock()
		if err := reloader(); err != nil {
			Logf("error", "证书任务 %d（规则 %s）生效后重载失败: %v", jobID, ruleID, err)
		}
	})
	s.timerMu.Unlock()
}

// deploymentRetrySchedulable 是「部署重试能否登记」的唯一判据——规则补偿
// 屏障、暂停与停止态都收敛在这里，包级调度入口与 30s 补扫共用，避免两处
// 判据漂移。登记本身仍由 scheduleDeploymentRetry 在锁内二次确认（判据与
// 登记之间可能被暂停打断，二者不可合并为一次非原子检查）。
func (s *CertificateService) deploymentRetrySchedulable(ruleID string) error {
	if manager := GetCAQueueManager(); manager != nil && manager.IsRuleBlocked(ruleID) {
		return ErrCertificateDeploymentRetryBlocked
	}
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if s.stopping || s.timersPaused {
		return ErrCertificateQueueInactive
	}
	return nil
}

func (s *CertificateService) scheduleDeploymentRetry(jobID int, ruleID string, delay time.Duration) error {
	for {
		s.timerMu.Lock()
		if s.stopping || s.timersPaused {
			s.timerMu.Unlock()
			return ErrCertificateQueueInactive
		}
		if previous := s.deploymentTimers[jobID]; previous != nil {
			previous.canceled = true
			previous.cancel()
			stopped := previous.timer.Stop()
			delete(s.deploymentTimers, jobID)
			s.timerMu.Unlock()
			if stopped {
				close(previous.done)
			} else {
				// 与 cancelDeploymentRetries 同口径的有界等待——
				// 回调链条最终调到非 context-aware 的 caddyReloader，挂起
				// 时裸等会拖死调用方（签发 goroutine/Resume/启动恢复）。
				waitDoneOrTimeout(previous.done, s.cancelWaitTimeout, jobID, "pending timer")
			}
			continue
		}
		// pending timer 之外还必须对在途回调去重——回调启动即自摘
		// （下方 AfterFunc 内 delete），只查 deploymentTimers 必然放行第二个并发
		// 回调：Caddy reload 挂起超暂停等待上限（30s）后 Resume/Unblock 补扫会对
		// 同 jobID 再建 timer，与仍在跑的旧回调并发部署同一证书，终态 CAS 败者
		// 的旧快照回滚可能摧毁胜者刚写入的证书文件。不变量：同 jobID 永不并发
		// 部署——取消在途回调并镜像上方 pending 处理（释锁后等待 done）再建新
		// timer，将并发部署降为串行重试。
		if callbacks := s.deploymentCallbacks[jobID]; len(callbacks) > 0 {
			running := make([]*deploymentTimer, 0, len(callbacks))
			for callback := range callbacks {
				callback.canceled = true
				callback.cancel()
				running = append(running, callback)
			}
			s.timerMu.Unlock()
			for _, callback := range running {
				waitDoneOrTimeout(callback.done, s.cancelWaitTimeout, jobID, "在途部署回调")
			}
			// waitDoneOrTimeout 超时后的契约是「放弃本轮调度」。原实现
			// 无条件 continue，仍在 map 中的同一回调会让循环每 cancelWaitTimeout
			// 重复一轮且永不建 timer。回调仍在=本轮放弃：deployment_available_after
			// 已落库，30s 补扫/Resume 会再次拾起；DeployLock 与终态 CAS 保证滞留
			// 回调即便最终退出也不会并发部署同一证书。
			s.timerMu.Lock()
			stillRunning := len(s.deploymentCallbacks[jobID]) > 0
			s.timerMu.Unlock()
			if stillRunning {
				Logf("warn", "证书任务 %d：在途部署回调未在 %s 内退出，放弃本轮部署重试调度（补扫/恢复接管）", jobID, s.cancelWaitTimeout)
				return ErrCertificateDeploymentRetryBusy
			}
			continue
		}
		entry := &deploymentTimer{done: make(chan struct{}), ruleID: ruleID}
		entry.ctx, entry.cancel = context.WithCancel(s.ctx)
		//scope-exempt: one-shot-deadline-callback —— 单次部署重试延迟回调（canceled/stopping 收口，补扫/Resume 兜底）
		entry.timer = time.AfterFunc(delay, func() {
			s.timerMu.Lock()
			if s.deploymentTimers[jobID] == entry {
				delete(s.deploymentTimers, jobID)
			}
			callbacks := s.deploymentCallbacks[jobID]
			if callbacks == nil {
				callbacks = make(map[*deploymentTimer]struct{})
				s.deploymentCallbacks[jobID] = callbacks
			}
			callbacks[entry] = struct{}{}
			stopping := entry.canceled || s.stopping || s.timersPaused
			s.timerMu.Unlock()
			defer func() {
				s.timerMu.Lock()
				delete(s.deploymentCallbacks[jobID], entry)
				if len(s.deploymentCallbacks[jobID]) == 0 {
					delete(s.deploymentCallbacks, jobID)
				}
				s.timerMu.Unlock()
				// 一次性重试正常结束后必须自行 cancel：子 ctx 挂在 s.ctx 的
				// children 表上直到父 ctx 取消，持续部署失败的任务每 30 分钟
				// 重试一次会无界累积（服务停止才释放）。与 caQueue.execute 的
				// defer cancel 同口径。
				entry.cancel()
				close(entry.done)
			}()
			if stopping {
				return
			}
			if err := s.retryDeployment(entry.ctx, jobID); err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.Canceled) {
				Logf("error", "certificate deployment retry failed for job %d: %v", jobID, err)
			}
		})
		s.deploymentTimers[jobID] = entry
		s.timerMu.Unlock()
		return nil
	}
}

func (s *CertificateService) cancelDeploymentRetry(jobID int) {
	s.timerMu.Lock()
	entry := s.deploymentTimers[jobID]
	var pendingDone <-chan struct{}
	if entry != nil {
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			delete(s.deploymentTimers, jobID)
			close(entry.done)
		} else {
			pendingDone = entry.done
		}
	}
	runningDone := make([]<-chan struct{}, 0, len(s.deploymentCallbacks[jobID]))
	for callback := range s.deploymentCallbacks[jobID] {
		callback.canceled = true
		callback.cancel()
		runningDone = append(runningDone, callback.done)
	}
	s.timerMu.Unlock()
	// 在途部署回调退出等待必须有界：回调链条最终调到非 context-aware 的
	// caddyReloader，Caddy admin 请求异常挂起时取消流程会被永久挂起；与
	// CAQueueManager.CancelJob 的 30s 上限同模式。
	// 内联等待收敛到 waitDoneOrTimeout。
	if pendingDone != nil {
		waitDoneOrTimeout(pendingDone, s.cancelWaitTimeout, jobID, "待定部署定时器")
	}
	for _, done := range runningDone {
		waitDoneOrTimeout(done, s.cancelWaitTimeout, jobID, "在途部署回调")
	}
}

func (s *CertificateService) signalCancelDeploymentRetriesForRule(ruleID string) []<-chan struct{} {
	s.timerMu.Lock()
	waitFor := make(map[*deploymentTimer]struct{})
	for jobID, entry := range s.deploymentTimers {
		if entry.ruleID != ruleID {
			continue
		}
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			delete(s.deploymentTimers, jobID)
			close(entry.done)
		} else {
			waitFor[entry] = struct{}{}
		}
	}
	for _, callbacks := range s.deploymentCallbacks {
		for callback := range callbacks {
			if callback.ruleID == ruleID {
				callback.canceled = true
				callback.cancel()
				waitFor[callback] = struct{}{}
			}
		}
	}
	s.timerMu.Unlock()
	done := make([]<-chan struct{}, 0, len(waitFor))
	for entry := range waitFor {
		done = append(done, entry.done)
	}
	return done
}

func (s *CertificateService) pauseDeploymentRetries() {
	s.timerMu.Lock()
	s.timersPaused = true
	var waitFor []<-chan struct{}
	for jobID, entry := range s.deploymentTimers {
		entry.canceled = true
		entry.cancel()
		if entry.timer.Stop() {
			close(entry.done)
		} else {
			waitFor = append(waitFor, entry.done)
		}
		delete(s.deploymentTimers, jobID)
	}
	// 一次性延迟重载同样属于部署定时器族：暂停/停止后不得继续触发。
	// 其无持久化，恢复不补登——收敛路径是重启物化/下一次配置写触发的重载。
	for jobID, entry := range s.delayedReloads {
		entry.canceled = true
		entry.timer.Stop()
		delete(s.delayedReloads, jobID)
	}
	for _, callbacks := range s.deploymentCallbacks {
		for callback := range callbacks {
			callback.canceled = true
			callback.cancel()
			waitFor = append(waitFor, callback.done)
		}
	}
	s.timerMu.Unlock()
	// 在途回调退出等待必须有界：回调链条调到非 context-aware 的 caddyReloader，
	// Caddy admin 请求异常挂起时配置导入/进程 Stop 会被永久挂起。
	// 截止时间在所有回调间**共享**（与 CancelJobsForRule 同构）——逐项各自
	// s.cancelWaitTimeout 会让 N 个在途回调的最坏等待变成 N×30s，配置导入的
	// PauseAndDrain（取 caddyOpMu 之前调用）在该窗口内无界。全量暂停无单任务
	// 上下文（jobID=0），超时只留一行汇总告警后继续调用方流程。
	timeout := s.cancelWaitTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.After(timeout)
	for _, done := range waitFor {
		select {
		case <-done:
		case <-deadline:
			Logf("warn", "等待在途部署回调退出超时（共享截止 %s），继续后续流程", timeout)
			return
		}
	}
}

func (s *CertificateService) resumeDeploymentRetries() {
	s.timerMu.Lock()
	if s.stopping {
		s.timerMu.Unlock()
		return
	}
	s.timersPaused = false
	s.timerMu.Unlock()
	s.rescanDroppedDeploymentRetries()
}

// deploymentWindowNullSettle：downloaded 行重试窗口为 NULL 时的沉降阈值。
// 窗口为 NULL 的正常形态是「部署正在主路径上执行」（persist downloaded 会先
// 把窗口置空），沉降阈值避免补扫与主部署路径抢同一任务；超过阈值仍为 NULL
// 则说明部署失败的状态回写本身没落库（瞬时 DB 故障/服务暂停期），必须由补扫
// 接管——否则该行没有任何周期通道（补扫只收非 NULL 窗口、对账只补缺失文件）。
const deploymentWindowNullSettle = 10 * time.Minute

// rescanDroppedDeploymentRetries 重新调度暂停期间被丢弃、或部署失败状态回写
// 失败而未登记 timer 的部署重试：`downloaded` 需已有 available_after（或窗口
// 为 NULL 且已过沉降阈值）；`cleanup_*`
// 的失败写回可能连窗口列都没更新，仍须由周期补扫拾起。
// 返回本轮实际重排的部署重试数（供 30s 补扫节拍的动作计数摘要）。
// 返回（重排数, error）：读失败必须上抛（30s 补扫任务的失败终态），否则长期读
// 故障下断链部署重试静默停摆而任务监控全绿。单行 Scan 失败记入返回错误（该行
// 不可信），其余行继续收敛。
// 逐条动作失败（部署重试登记 / 材料丢失行重排）与读失败同权：只写应用日志时
// 本轮仍报「补扫完成」，而该行实际上没有回到调度器——任务监控看不到仍有证书
// 工作未恢复（补建/滞留/续期/补扫四条恢复路径必须同口径聚合）。
func (s *CertificateService) rescanDroppedDeploymentRetries(gates ...func() error) (rescheduled int, err error) {
	if db.DB == nil {
		return 0, nil
	}
	settleMinutes := int(deploymentWindowNullSettle / time.Minute)
	rows, err := db.DB.Query(`
		SELECT j.id, COALESCE(j.rule_id,''), COALESCE(j.domain,''), COALESCE(j.ca_provider_id,0), COALESCE(j.deployment_attempts,0),
		       COALESCE(r.domain,''), j.status,
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END,
		       CASE WHEN `+CertJobMaterialPredicateSQL("j")+` THEN 1 ELSE 0 END,
		       COALESCE(j.deployment_available_after,'')
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		-- 前三类都是「材料在库、只差部署」的行（部署重试直接读库材料）；
		-- 第四类是「材料根本没落库」——两类必须互斥，否则在途签发的年轻行会被
		-- 当作材料丢失误重排队。
		WHERE (j.status='downloaded' AND j.deployment_available_after IS NOT NULL
		       AND (`+CertJobMaterialPredicateSQL("j")+`))
		   OR (j.status='downloaded' AND j.deployment_available_after IS NULL
		       AND (`+CertJobMaterialPredicateSQL("j")+`)
		       AND datetime(COALESCE(j.updated_at,j.created_at)) <= datetime('now', '-' || ? || ' minutes'))
		   OR (j.status IN (`+DeploymentCleanupJobStatusSQL+`) AND (`+CertJobMaterialPredicateSQL("j")+`))
		   -- 部署生命周期 + 无证书材料（ACME 已把状态写成 downloaded/cleanup_*，
		   -- 材料却从未持久化：下载完成后的 DNS 清理窗口内进程退出，含硬杀与
		   -- PauseAndDrain 超时后的退出）。这些行原先被下方 hasCertMaterial 守卫
		   -- 一律跳过，没有任何周期通道回收——规则在重启前整条不发布（TLS 渲染
		   -- 不命中材料即跳过规则，避免同端口明文降级）。
		   OR (j.status IN (`+DeploymentLifecycleJobStatusSQL+`)
		       AND `+certJobMissingMaterialPredicateSQL("j")+`
		       AND datetime(COALESCE(j.updated_at,j.created_at)) <= datetime('now', '-' || ? || ' minutes'))
	`, settleMinutes, settleMinutes)
	if err != nil {
		Logf("error", "resume deployment retries: scan failed: %v", err)
		return 0, fmt.Errorf("扫描断链部署重试: %w", err)
	}
	type droppedRetry struct {
		id, providerID, deploymentAttempts int
		ruleID, jobDomain, ruleDomain      string
		status                             string
		applicable, hasCertMaterial        bool
		availableAfter                     string
	}
	var jobs []droppedRetry
	scanFailures := 0
	for rows.Next() {
		var job droppedRetry
		if err := rows.Scan(&job.id, &job.ruleID, &job.jobDomain, &job.providerID, &job.deploymentAttempts, &job.ruleDomain, &job.status, &job.applicable, &job.hasCertMaterial, &job.availableAfter); err != nil {
			Logf("error", "resume deployment retries: scan row failed: %v", err)
			scanFailures++
			continue
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		Logf("error", "resume deployment retries: iterate rows failed: %v", err)
		_ = rows.Close()
		return rescheduled, fmt.Errorf("遍历断链部署重试: %w", err)
	}
	// 逐条动作失败聚合器：与 scanFailures 同在返回值里体现（失败轮）。
	var actionErr error
	// 先关闭读迭代器再写库：SQLite 连接池上行迭代未结束时写入会触发 SQLITE_BUSY。
	if err := rows.Close(); err != nil {
		Logf("error", "resume deployment retries: close rows failed: %v", err)
		return rescheduled, fmt.Errorf("关闭断链部署重试结果集: %w", err)
	}
	// 读失败上抛前仍完成可读行的收敛（部分成果保留），错误携带失败行数。
	defer func() {
		if scanFailures > 0 {
			err = errors.Join(err, fmt.Errorf("断链部署重试扫描有 %d 行读取失败（结果不可信）", scanFailures))
		}
	}()
	for _, job := range jobs {
		if !certJobRuleApplicable(job.applicable, job.ruleDomain, job.jobDomain) {
			continue
		}
		// 写前门（逐项）：本路径的两个写面（无材料行转 queued / 登记部署 timer
		// ——后者到期会写证书文件并重载 Caddy）在降级窗口内必须零写入。
		if gateErr := runCertWaitingCAWriteGate(gates); gateErr != nil {
			return rescheduled, errors.Join(err, gateErr)
		}
		if !job.hasCertMaterial {
			// 部署生命周期 + 无材料：不是「等部署」，是「材料根本没落库」——
			// 转 queued 重新签发是本行唯一的回收通道。
			if requeueErr := s.requeueLostMaterialCertJob(job.id, job.ruleID, job.jobDomain, job.providerID, job.status); requeueErr != nil {
				actionErr = errors.Join(actionErr, requeueErr)
			}
			continue
		}
		// 周期化(30s ticker)后必须跳过已持活跃
		// timer/在途回调的任务——否则每 30s 取消重建会把退避窗口无限推后
		// (timer 永不到期,重试链名存实亡)。原调用面(resume/unblock)暂停
		// 期 timer 已清空,此守卫对其零影响。
		s.timerMu.Lock()
		_, hasTimer := s.deploymentTimers[job.id]
		hasCallback := len(s.deploymentCallbacks[job.id]) > 0
		s.timerMu.Unlock()
		if hasTimer || hasCallback {
			continue
		}
		delay := time.Duration(0)
		if job.availableAfter == "" {
			// 窗口列为 NULL：失败回写未落库（已过沉降阈值，见查询门）。
			// 这是已知形态而非格式漂移，按立即重试处理且不刷 warn。
		} else if t, err := time.Parse("2006-01-02 15:04:05", job.availableAfter); err == nil {
			if remaining := time.Until(t); remaining > 0 {
				delay = remaining
			}
		} else {
			// 格式漂移（直改库/未来写入变更）时 fallback
			// 为立即重试（自愈：失败会重建窗口），但不可无痕——分级 warn 在
			// warn/error 级别下仍进文件日志。
			Logf("warn", "证书任务 %d：deployment_available_after=%q 无法解析，按立即重试处理", job.id, job.availableAfter)
		}
		// 暂停/停止/规则补偿屏障期不进入调度：本轮不会登记任何 timer，
		// 计数与摘要行必须保持一致（包级入口的判据收敛在
		// deploymentRetrySchedulable，此处先看避免逐行调用再丢弃）。
		if err := s.deploymentRetrySchedulable(job.ruleID); err != nil {
			continue
		}
		// 只有真正登记了 timer 才算「部署重建」。暂停/停止/规则补偿屏障
		// 期间本轮未调度——计数与摘要行必须如实反映，否则任务监控会在导入/
		// 删除补偿窗口每 30s 谎报一次动作。
		if retryErr := s.deploymentRetry(job.id, issuedCertificate{ruleID: job.ruleID, providerID: job.providerID, deploymentAttempt: job.deploymentAttempts}, delay); retryErr != nil {
			// 暂停/停止/规则补偿屏障是「本轮不登记」的有意形态，不算失败；
			// 其余（DB/队列/登记错误）必须让本轮进入失败终态。
			if !errors.Is(retryErr, ErrCertificateQueueInactive) && !errors.Is(retryErr, ErrCertificateDeploymentRetryBlocked) {
				Logf("warn", "证书任务 %d：部署重试登记失败（本轮不计入补扫）: %v", job.id, retryErr)
				actionErr = errors.Join(actionErr, fmt.Errorf("证书任务 %d（规则 %s）：部署重试登记失败: %w", job.id, job.ruleID, retryErr))
			}
			continue
		}
		rescheduled++
	}
	return rescheduled, actionErr
}

// requeueLostMaterialCertJob 把「部署生命周期 + 无证书材料」的行转回 queued
// 重新签发（CAS from=当前状态，防止与并发改态抢写）。这类行的形态是 ACME
// 已按阶段日志把状态写成 downloaded/cleanup_*，但材料持久化在其后的
// transitionJob 之前进程退出——部署生命周期行按契约必须保有周期通道，而
// 材料缺失让「部署重试」永远无法成功，只能回到签发。
//
// 守卫与滞留重入队同族：在途任务不得改态（会把执行中的行置回 queued），
// 队列未就绪时不动作（下轮补扫重试）。
// 返回错误仅代表真实的入队/写库失败：队列未就绪（qm==nil）、在途任务、
// CAS 冲突（changed=false）都属「本轮不动作」的有意形态，不算失败。
func (s *CertificateService) requeueLostMaterialCertJob(jobID int, ruleID, domain string, providerID int, fromStatus string) error {
	qm := GetCAQueueManager()
	if qm == nil {
		return nil
	}
	if qm.IsJobActive(jobID) {
		return nil
	}
	_, changed, err := qm.EnqueueIfActive(providerID, jobID, ruleID, domain, func() (int, bool, error) {
		err := transitionJob(db.DB, jobID, deploymentLifecycleJobStatuses, "queued",
			map[string]any{"message": "证书材料未落库（签发中断），已重新排队签发"})
		if errors.Is(err, ErrJobTransitionConflict) {
			return jobID, false, nil
		}
		return jobID, err == nil, err
	})
	if err != nil {
		Logf("warn", "证书任务 %d：材料丢失行重新排队失败（下一周期重试）: %v", jobID, err)
		return fmt.Errorf("证书任务 %d（规则 %s）：材料丢失行重新排队失败: %w", jobID, ruleID, err)
	}
	if !changed {
		return nil
	}
	TaskLogf("cert-waiting-ca", "rescan", "证书任务 %d（规则 %s）：%s 行缺证书材料，已重新排队签发", jobID, ruleID, fromStatus)
	RecordAuditLog("system", "重新签发", "证书任务",
		FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(ruleID), AuditSourcePart("deployment_material_lost")), "")
	return nil
}

func (s *CertificateService) Start() {
	s.started.Store(true)
	defer close(s.done)
	// 仅恢复上次运行遗留任务；四个周期任务统一由任务引擎驱动。
	s.recoverJobs(s.ctx)
	<-s.ctx.Done()
}

// activeCertService 当前证书服务实例（引擎单轮 tick 消费；lifecycle 启动时注入）。
var activeCertService struct {
	sync.Mutex
	svc *CertificateService
}

// SetActiveCertificateService 注入活动实例（nil 清除）。
func SetActiveCertificateService(svc *CertificateService) {
	activeCertService.Lock()
	defer activeCertService.Unlock()
	activeCertService.svc = svc
	if svc != nil {
		// active 注入前引擎可能已首轮跳过（服务未运行）；就绪时重置节拍，
		// 避免续期/手动轮询静默等待完整 6h/10min 周期。
		if te := TaskEngine(); te != nil {
			te.RearmLoop("cert-renewal-scan")
			te.RearmLoop("cert-manual-poll")
		}
	}
}

// lastCertServiceMissing 证书服务缺失状态门（cert-waiting-ca 专用——经
// withActiveCertServiceTick 消费的全局单例状态；另两个证书 tick 刻意不共享：
// CertRenewalScanOnce/CertManualCheckOnce 的「跳过」必须逐轮可观测，
// 见各自实现）：false→true 转换记一次跳过行，缺失持续期静默，true→false
// 转换记一次恢复行（收敛：空转轮逐轮刷行改状态变化行）。
var lastCertServiceMissing atomic.Bool

// certRenewalRoleRecheckHook 续期扫描逐任务角色复核前的测试屏障（生产恒
// nil）：用于在「候选已快照、尚未入队」的窗口内翻转节点角色，
// 钉住 demote 竞争形态（Run 体不消费 ctx，入口角色检查只做一次）。
var certRenewalRoleRecheckHook func()

// withActiveCertServiceTick 引擎单轮 tick 的活动证书服务执行体。**仅**用于
// 工作确实依赖服务实例的任务（cert-waiting-ca：补扫/重排需要服务的定时器族
// 与 DB 锁）；服务缺失时轮次照常 success。手动证书巡检与续期扫描不走这里
// ——它们的「跳过」必须可观测（见 CertManualCheckOnce / CertRenewalScanOnce）。
// 收敛（2026-10-03 裁定）：跳过说明收敛为状态变化行——lastCertServiceMissing
// false→true 转换记一次跳过行，缺失持续期静默，恢复（true→false）记一次恢复行。
func withActiveCertServiceTick(taskID, stage string, fn func(s *CertificateService)) {
	activeCertService.Lock()
	svc := activeCertService.svc
	activeCertService.Unlock()
	if svc == nil {
		if lastCertServiceMissing.CompareAndSwap(false, true) {
			TaskLogf(taskID, stage, "证书服务未运行，跳过本轮（服务恢复后自动继续）")
		}
		return
	}
	if lastCertServiceMissing.CompareAndSwap(true, false) {
		TaskLogf(taskID, stage, "证书服务已恢复")
	}
	fn(svc)
}

// —— 引擎单轮 tick（certificates.go 四 ticker 的循环体；引擎接管节拍）——

// CertRenewalScanOnce 续期扫描（临期证书入队）。
// 前置查询、结果集迭代与入队门禁失败必须上抛（Run 返回 error → task_runs 失败终态）。
// 逐行 Scan/现有证书选择读失败按行跳过并计数，任务日志摘要必须显式披露跳过行数。
// 服务缺失时**不得记成功**：此时续期链完全停摆（ACME 证书到期无人处理），
// 必须落可见业务行并返回 ErrTaskSkipped（task_runs=skipped，非成功）。
func CertRenewalScanOnce(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !certScanDatabaseReady() {
		TaskLogf("cert-renewal-scan", "scan", "数据库未就绪：本轮续期扫描已跳过（装配完成后由周期节拍重试）")
		return taskengine.ErrTaskSkipped
	}
	activeCertService.Lock()
	svc := activeCertService.svc
	activeCertService.Unlock()
	if svc == nil {
		TaskLogf("cert-renewal-scan", "scan", "证书签发任务未运行：本轮续期扫描已跳过（停止期间不会自动续签，请恢复调度以免证书到期）")
		return taskengine.ErrTaskSkipped
	}
	return svc.renewExpiringCertificates(ctx)
}

// CertManualCheckOnce 手动证书到期检查。
// 巡检只读 lb_rules 的手动证书并用告警门去重，不依赖 CA 队列/服务实例——
// 停止「证书签发」调度时手动证书没有自动续签，告警是唯一信号，巡检因此照常
// 执行（服务实例缺失时使用包级去重门）。巡检读失败必须上抛。
func CertManualCheckOnce() error {
	if !certScanDatabaseReady() {
		TaskLogf("cert-manual-poll", "check", "数据库未就绪：本轮手动证书到期检查已跳过（装配完成后由周期节拍重试）")
		return taskengine.ErrTaskSkipped
	}
	activeCertService.Lock()
	svc := activeCertService.svc
	activeCertService.Unlock()
	gate := manualCertExpiryFallbackGate
	if svc != nil && svc.expiryAlertGate != nil {
		gate = svc.expiryAlertGate
	}
	return runManualCertExpiryCheck(gate)
}

// certScanDatabaseReady 报告证书域扫描是否具备可执行的数据库：db.DB 未装配
// （启动早期装配窗口/测试直构顺序）时所有扫描入口统一静默跳过。此前同包口径
// 分叉——certJobsActive/rescanDroppedDeploymentRetries 等返回安全默认，而
// CertRenewalScanOnce/CertManualCheckOnce/CertReconcileOnce 直接 deref db.DB，
// 一旦顺序变化就从「可解释的降级」变成 nil panic。
func certScanDatabaseReady() bool {
	return db.DB != nil
}

// certJobsActive 报告是否存在需要周期通道的证书任务——issued/disabled 之外的
// 状态，外加「failed + ca_available_after 非空」（B2 失败语义统一：退避窗口
// 未到期的失败行由 cert-waiting-ca 30s 补扫按到期重排，属在途信号）；failed +
// 窗口 NULL 是终态（已达上限仅手动重试），不计入。
func certJobsActive() bool {
	if db.DB == nil {
		// 启动/测试装配窗口没有可执行的数据库工作；与查询错误的「宁扫勿漏」
		// 不同，nil DB 必须静默跳过而不是触发 nil dereference。
		return false
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs
		WHERE status NOT IN ('issued','failed','disabled')
		   OR (status = 'failed' AND ca_available_after IS NOT NULL)`).Scan(&n); err != nil {
		return true // 判定失败按有活处理——宁扫勿漏（安全网语义）
	}
	return n > 0
}

// CertWaitingCATickOnce CA 等待/滞留补扫（30s 节拍）。
// 门控（2026-09-29 用户裁定）：无非终态证书任务即退出——零扫描零动作；
// 孤儿任务均为非终态，门控天然覆盖，不漏扫。
// 写前门（与 cert-reconcile / cert-renewal-scan 同族）：三路写路径
// （CA 冷却重排 / 滞留重入队 / 断链部署重建）在每个写点前复用
// certReconcileWriteGate——本轮窗口内的降级/换主/导入排空/停机必须零写入。
// 准入时的角色判定在 30s 巡查窗口内会过期：从节点此后仍按主节点身份改写
// cert_jobs、登记部署 timer（到期写证书文件并重载 Caddy），破坏「从节点零写」
// 不变式。取消 → 包装后的 ctx 错误（cancelled 终态）；降级 → ErrTaskSkipped。
// 摘要行只在有真实动作时落盘并携带分项计数——waiting_ca 冷却可长达 3h，
// 无条件写行会让 30s 轮次空转刷屏（≈2880 行/日）掩盖真正动作行。
// 三路扫描的读失败必须上抛（task_runs 失败终态）——持续性读故障（schema
// 漂移/长期 SQLITE_BUSY）下证书恢复会完全停摆，而此前本任务恒报成功，监控
// 全绿。无动作轮仍不写摘要行（保留零空转语义）；失败轮写一行 failure 摘要。
func CertWaitingCATickOnce(ctx context.Context) error {
	if !certJobsActive() {
		return nil
	}
	writeGate := func() error { return certReconcileWriteGate(ctx) }
	// 中止判定与 CertReconcileOnce 同口径：驱动层可能返回自己的取消包装错误
	// （errors.Is 不可达，ctx.Err 兜底）。
	aborted := func(err error) bool {
		return errors.Is(err, taskengine.ErrTaskSkipped) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			(ctx != nil && ctx.Err() != nil)
	}
	var tickErr error
	withActiveCertServiceTick("cert-waiting-ca", "rescan", func(s *CertificateService) {
		var requeued, disabled, stranded, redeployed int
		var waitingErr, strandedErr, rescanErr error
		if gateErr := writeGate(); gateErr != nil {
			waitingErr = gateErr
		} else {
			requeued, disabled, waitingErr = s.requeueWaitingCAJobs(writeGate)
		}
		// 已中止（降级/取消）就不再进入后续写路径——本轮零写入。
		if !aborted(waitingErr) {
			if gateErr := writeGate(); gateErr != nil {
				strandedErr = gateErr
			} else if qm := GetCAQueueManager(); qm != nil {
				stranded, strandedErr = qm.requeueStrandedQueuedJobs(writeGate)
			}
		}
		if !aborted(waitingErr) && !aborted(strandedErr) {
			if gateErr := writeGate(); gateErr != nil {
				rescanErr = gateErr
			} else {
				redeployed, rescanErr = s.rescanDroppedDeploymentRetries(writeGate)
			}
		}
		tickErr = errors.Join(waitingErr, strandedErr, rescanErr)
		if tickErr != nil {
			if aborted(tickErr) {
				TaskLogf("cert-waiting-ca", "skipped", "补扫中止：%v（部分计数：CA 冷却重排 %d、孤儿禁用 %d、滞留重入队 %d、部署重建 %d——恢复后下一周期重做）",
					tickErr, requeued, disabled, stranded, redeployed)
				return
			}
			// 失败轮结果不可信：摘要如实标注「部分完成」并附原因。
			TaskLogf("cert-waiting-ca", "rescan", "补扫失败（部分计数不可信，下一周期重试）：CA 冷却重排 %d、孤儿禁用 %d、滞留重入队 %d、部署重建 %d：%v",
				requeued, disabled, stranded, redeployed, tickErr)
			return
		}
		if requeued+disabled+stranded+redeployed > 0 {
			TaskLogf("cert-waiting-ca", "rescan", "补扫完成：CA 冷却重排 %d、孤儿禁用 %d、滞留重入队 %d、部署重建 %d", requeued, disabled, stranded, redeployed)
		}
	})
	return tickErr
}

// runCertWaitingCAWriteGate 执行本轮写前门（未提供 gate 的直连调用=无门：
// 供测试与 Resume 等非引擎路径复用既有 helper 语义，不改签名形态）。
func runCertWaitingCAWriteGate(gates []func() error) error {
	if len(gates) == 0 || gates[0] == nil {
		return nil
	}
	return gates[0]()
}

// certReconcileRoleRecheckHook 测试缝：每个对账写点前调用一次——用于在
// 「扫描判定通过 → 写落定」的窗口内制造节点降级/取消，验证写前门。
var certReconcileRoleRecheckHook func()

// certWriteGate 证书域每个写点前的逐项门（对账/续期扫描共用同一实现，
// 只有日志归因与测试缝不同）：
//   - 调度取消（降级/导入排空/停机）：返回包装后的 ctx 错误——终态
//     cancelled，与降级跳过区分；
//   - 节点已切从：返回 ErrTaskSkipped——从节点不得改写证书态（扫描开始时的
//     角色判定在长轮次内会过期，逐项复核才是写侧的唯一事实）。
//
// 角色读取失败不猜测：上抛为失败轮（下一周期重试）。
func certWriteGate(ctx context.Context, scope string, hook func()) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s被中止: %w", scope, err)
		}
	}
	if hook != nil {
		hook()
	}
	roleCtx := ctx
	if roleCtx == nil {
		roleCtx = context.Background()
	}
	isMaster, err := RoleOf(roleCtx, db.DB)
	if err != nil {
		return fmt.Errorf("%s写前复核节点角色: %w", scope, err)
	}
	if !isMaster {
		return taskengine.ErrTaskSkipped
	}
	return nil
}

// certReconcileWriteGate 证书状态对账每个写点前的逐项门（重建证书文件 /
// 禁用孤儿任务 / 补建任务行）。语义见 certWriteGate。
func certReconcileWriteGate(ctx context.Context) error {
	return certWriteGate(ctx, "证书状态对账", certReconcileRoleRecheckHook)
}

// certRenewalWriteGate 续期扫描每个写点前的逐项门。语义见 certWriteGate；
// 测试缝为 certRenewalRoleRecheckHook（在「候选已快照、尚未写」的窗口内翻转
// 节点角色，钉住 demote 竞争形态）。
func certRenewalWriteGate(ctx context.Context) error {
	return certWriteGate(ctx, "证书续期扫描", certRenewalRoleRecheckHook)
}

// backfillIssuedCertExpiry 一次性回填「issued + 材料在库 + expires_at IS NULL」
// 行的到期时间（PEM 派生）。集群聚合端以 expires_at 为门，同证两套到期口径会
// 让已签发证书被误报为缺失/临期。幂等：只碰 NULL 行，写前复核角色。
func backfillIssuedCertExpiry(ctx context.Context) (int, error) {
	rows, err := db.DB.QueryContext(ctx, `SELECT id, COALESCE(cert_pem,'') FROM cert_jobs
		WHERE status='issued' AND expires_at IS NULL AND `+CertJobMaterialPredicateSQL(""))
	if err != nil {
		return 0, fmt.Errorf("查询待回填到期时间的证书任务: %w", err)
	}
	type pendingBackfill struct {
		id       int
		notAfter time.Time
	}
	var updates []pendingBackfill
	for rows.Next() {
		var id int
		var certPEM string
		if err := rows.Scan(&id, &certPEM); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("读取待回填到期时间的证书任务: %w", err)
		}
		notAfter, ok := CertNotAfterFromPEM(certPEM)
		if !ok {
			Logf("warn", "证书任务 %d：expires_at 缺失且 PEM 无法解析，跳过到期回填", id)
			continue
		}
		updates = append(updates, pendingBackfill{id: id, notAfter: notAfter})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("遍历待回填到期时间的证书任务: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("关闭待回填到期时间的证书任务结果: %w", err)
	}
	if len(updates) == 0 {
		return 0, nil
	}
	if gateErr := certReconcileWriteGate(ctx); gateErr != nil {
		return 0, gateErr
	}
	filled := 0
	for _, update := range updates {
		// 长轮次内节点可能降级（SetRole/导入排空）：回填是独立写点，必须与
		// 其余写点同口径在每行写前复核角色，不得只在循环前判定一次。
		if gateErr := certReconcileWriteGate(ctx); gateErr != nil {
			return filled, gateErr
		}
		result, err := db.DB.Exec(`UPDATE cert_jobs SET expires_at=? WHERE id=? AND status='issued' AND expires_at IS NULL`, CanonicalDatetimeValue(update.notAfter), update.id)
		if err != nil {
			return filled, fmt.Errorf("回填证书任务 %d 的到期时间: %w", update.id, err)
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr == nil && affected > 0 {
			filled++
		}
	}
	return filled, nil
}

// CertReconcileOnce 状态对账（缺失证书文件/孤儿任务清理/缺失任务补建）。
// 对账读失败必须上抛（Run 返回 error → task_runs 失败终态），且失败轮
// 摘要不得写「完成」——此前查询失败只 Logf + 摘要仍报「状态对账完成 0」，
// 任务监控呈现假健康。服务缺失不适用（本函数无服务依赖）。
//
// ctx 由引擎 RunContext 驱动（降级/停机/导入排空即取消），四个写点（证书文件
// 重建/到期回填/孤儿清理/任务补建）各自在写前经 certReconcileWriteGate 复核
// ——长轮次内节点降级不得继续写库。
func CertReconcileOnce(ctx context.Context) error {
	if !certScanDatabaseReady() {
		TaskLogf("cert-reconcile", "skipped", "数据库未就绪：本轮状态对账已跳过（装配完成后由周期节拍重试）")
		return taskengine.ErrTaskSkipped
	}
	rebuilt, reconcileErr := reconcileMissingCertFiles(ctx, db.DB)
	filledExpiry, expiryErr := backfillIssuedCertExpiry(ctx)
	swept, sweepErr := sweepOrphanedCertJobs(ctx)
	// 兜底：6h 对账同时补建「启用 ACME 但无任务行」的规则——覆盖
	// 提升窗口之外的行丢失（快照整树替换后残留的中间态）。
	created, backfillErr := BackfillMissingACMECertJobs(ctx, GetCAQueueManager())
	if backfillErr != nil {
		Logf("warn", "证书任务对账补建失败: %v", backfillErr)
	}
	if err := errors.Join(reconcileErr, expiryErr, sweepErr, backfillErr); err != nil {
		// 降级跳过/调度取消不是故障——但轮次未完成，摘要必须如实说明
		// 中止而非「完成」（部分计数不可信）。ctx 已取消同样按中止：
		// 驱动层可能返回自己的取消包装错误（errors.Is 不可达）。
		aborted := errors.Is(err, taskengine.ErrTaskSkipped) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			(ctx != nil && ctx.Err() != nil)
		if aborted {
			TaskLogf("cert-reconcile", "skipped", "状态对账中止：%v（已收敛 %d 个断链、%d 个到期回填、%d 个孤儿、%d 个补建——均为部分计数，恢复后下一周期重做）", err, rebuilt, filledExpiry, swept, created)
			return err
		}
		TaskLogf("cert-reconcile", "reconcile", "状态对账失败：%v（失败轮结果不可信，下一周期重试；已收敛 %d 个断链、%d 个到期回填、%d 个孤儿——均为部分计数）", err, rebuilt, filledExpiry, swept)
		return err
	}
	TaskLogf("cert-reconcile", "reconcile", "状态对账完成：断链重建 %d 个、到期回填 %d 个、孤儿清理 %d 个、任务补建 %d 个（一致时为 0）", rebuilt, filledExpiry, swept, created)
	return nil
}

// requeueWaitingCAJobs re-enqueues cert jobs whose CA retry window (failed +
// ca_available_after) has elapsed. B2 失败语义统一后 waiting_ca 停车状态退役：
// 429/其它失败统一落 failed 并携带退避窗口，本扫描即「failed + 窗口到期重排」
// 的唯一周期属主（首次签发失败的 30 分钟冷却与临期续签仍由续期巡检通道负责）。
// 返回（冷却到期重排队数, 孤儿禁用数）——供 30s 补扫节拍的动作计数摘要
// （无动作不写空转行）。
// 返回（冷却到期重排队数, 孤儿禁用数, error）：查询/迭代/关闭/单行读取失败都
// 必须上抛（调用方 CertWaitingCATickOnce 收敛为 task_runs 失败终态）——此前
// 读失败只打应用日志并按成功轮记账，证书自动恢复静默停摆。
// waitingCACandidate 是 CA 冷却补扫的一行候选（扫描阶段产物）。
type waitingCACandidate struct {
	id           int
	ruleID       string
	domain       string
	caProviderID int
	ruleDomain   string
	ruleBound    bool
}

// scanWaitingCACandidates 在 s.mu 内完成「查询 → 读全量候选 → 关闭结果集」，
// 逐任务处置与入队留给调用方在锁外执行。
//
// 候选谓词（B2 失败语义统一）：status='failed' 且退避窗口（ca_available_after）
// 已到期。窗口 NULL 的 failed 行不收：已达 cert_renewal_attempts 上限的行停止
// 自动重试（仅手动），NULL 只可能来自上限终态/导入/旧备份——上限行有续期巡检
// 的上限分支告警；导入行经导入期归一为 failed（db.NormalizeWaitingCACertJobs），
// 带窗口的行走本补扫自动通道，启动迁移兜底旧库存量。
func (s *CertificateService) scanWaitingCACandidates() ([]waitingCACandidate, []error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := db.DB.Query(`
		SELECT j.id, j.rule_id, COALESCE(j.domain,''), COALESCE(j.ca_provider_id,0),
		       COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status = 'failed'
		  AND j.ca_available_after IS NOT NULL
		  AND datetime(j.ca_available_after) <= datetime('now')
	`)
	if err != nil {
		Logf("error", "waiting_ca scan: query failed: %v", err)
		return nil, nil, fmt.Errorf("扫描 CA 冷却任务: %w", err)
	}
	var jobs []waitingCACandidate
	var scanErrors []error
	for rows.Next() {
		var job waitingCACandidate
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.caProviderID, &job.ruleDomain, &job.ruleBound); err != nil {
			Logf("error", "waiting_ca scan: scan row failed: %v", err)
			scanErrors = append(scanErrors, fmt.Errorf("读取 CA 冷却任务行: %w", err))
			continue
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		Logf("error", "waiting_ca scan: iterate rows failed: %v", err)
		_ = rows.Close()
		return nil, nil, fmt.Errorf("遍历 CA 冷却任务: %w", err)
	}
	// 先关闭读迭代器再写库：SQLite 连接池上行迭代未结束时 UPDATE 会触发 SQLITE_BUSY。
	if err := rows.Close(); err != nil {
		Logf("error", "waiting_ca scan: close rows failed: %v", err)
		return nil, nil, fmt.Errorf("关闭 CA 冷却任务结果集: %w", err)
	}
	return jobs, scanErrors, nil
}

func (s *CertificateService) requeueWaitingCAJobs(gates ...func() error) (requeued, disabled int, err error) {
	qm := GetCAQueueManager()
	if qm == nil {
		return 0, 0, nil
	}

	// 锁粒度：s.mu 只覆盖「查询 → 读全量候选 → 关闭结果集」段（见
	// scanWaitingCACandidates）。逐任务 CAS 写库与入队在锁外执行——waiting_ca
	// 任务多/DB 慢时，补扫轮不得把 6h 节拍的续期扫描（CheckExpiration /
	// checkFailedFirstIssuance 同取 s.mu）推迟到本轮之后。并发安全不依赖该锁：
	// 写侧全程 CAS（transitionJob 的 from-status 白名单 + EnqueueIfActive 去重），
	// 两轮扫描对同一行竞争时只有一方 changed=true。
	jobs, scanErrors, err := s.scanWaitingCACandidates()
	if err != nil {
		return 0, 0, err
	}
	// 读失败不得被记为成功轮：可读行照常处置（部分成果保留），失败行数与原因在
	// 返回时并入错误——与 rescanDroppedDeploymentRetries 同口径（部分成功 +
	// 错误上抛，而不是在两者之间二选一）。否则带外畸形行被静默跳过后，30s 补扫
	// 仍报成功，任务监控看不到「本次扫描不完整」。
	defer func() {
		if len(scanErrors) == 0 {
			return
		}
		Logf("warn", "waiting_ca scan: %d 行读取失败已跳过，其余行照常处置", len(scanErrors))
		err = errors.Join(err, fmt.Errorf("CA 冷却任务扫描有 %d 行读取失败（结果不完整）: %w", len(scanErrors), errors.Join(scanErrors...)))
	}()
	var actionErr error

	for _, job := range jobs {
		// 写前门（逐项）：扫描判定通过 → 写落定之间节点可能已降级/取消，
		// 每个写点前复核（与 certReconcileWriteGate 同源语义）。命中即中止本轮，
		// 已处置的行保留（CAS 写不会回滚已提交部分）。
		if gateErr := runCertWaitingCAWriteGate(gates); gateErr != nil {
			return requeued, disabled, gateErr
		}
		if !certJobRuleApplicable(job.ruleBound, job.ruleDomain, job.domain) {
			// B2 失败语义统一：failed（带退避窗口）行是本扫描的合法候选，
			// 孤儿形态同样收敛到 disabled——from 集合=非终态全集+failed
			//（nonTerminalJobStatuses 不含终态 failed，直接复用会 0 行命中）。
			disableFrom := append(slices.Clone(nonTerminalJobStatuses), "failed")
			if err := transitionJob(db.DB, job.id, disableFrom, "disabled", map[string]any{"message": "关联规则已不再使用当前 ACME 证书任务"}); err != nil {
				if !errors.Is(err, ErrJobTransitionConflict) {
					actionErr = errors.Join(actionErr, fmt.Errorf("禁用孤儿 CA 冷却任务 %d: %w", job.id, err))
					Logf("error", "waiting_ca scan: disable orphaned job %d failed: %v", job.id, err)
				}
				continue
			}
			RecordAuditLog("system", "禁用", "证书任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("ca_cooldown")), "")
			disabled++
			continue
		}
		_, changed, err := qm.EnqueueIfActive(job.caProviderID, job.id, job.ruleID, job.domain, func() (int, bool, error) {
			// 窗口/错误码残留清理与续期巡检的重排迁移同字段集：failed→queued
			// 后若以非 429 原因再次失败，recordJobFailure 会写新窗口/错误码，
			// 旧值不得跨失败轮残留（UI/导出看到与当前轮矛盾的窗口）。
			err := transitionJob(db.DB, job.id, []string{"failed"}, "queued", map[string]any{
				"message":            "冷却结束，重新排队签发",
				"ca_available_after": nil,
				"last_error_code":    nil,
			})
			if errors.Is(err, ErrJobTransitionConflict) {
				return job.id, false, nil
			}
			return job.id, err == nil, err
		})
		if err != nil {
			actionErr = errors.Join(actionErr, fmt.Errorf("重排 CA 冷却任务 %d（规则 %s）: %w", job.id, job.ruleID, err))
			Logf("error", "waiting_ca scan: failed to requeue job %d: %v", job.id, err)
			continue
		}
		if !changed {
			continue
		}
		requeued++
		RecordAuditLog("system", "重新排队", "证书任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("ca_cooldown")), "")
	}
	// 单行读取失败的聚合见扫描阶段末尾的 defer（扫描失败不得记为成功轮）。
	return requeued, disabled, errors.Join(err, actionErr)
}

// recoverCertJobs re-enqueues cert jobs that were not in a terminal state when
// the process last exited. Jobs whose rule or CA provider no longer exist are
// marked as failed.
func (s *CertificateService) recoverCertJobs(ctx context.Context) {
	// 先补建缺失任务行（提升/启动时从端快照只带已签发材料，未签发
	// 规则的 cert_jobs 行在主从切换后不存在），再恢复既有非终态任务。
	if created, err := BackfillMissingACMECertJobs(ctx, GetCAQueueManager()); err != nil {
		Logf("error", "补建缺失证书任务失败: %v", err)
	} else if created > 0 {
		TaskLogf("cert-issuance", "recover", "补建缺失证书任务 %d 个（提升/启动恢复）", created)
	}
	if err := requeueNonTerminalCertJobs(ctx, s.deploymentRetry); err != nil {
		Logf("error", "Failed to recover non-terminal cert jobs: %v", err)
	}
}

// reconcileMissingCertFiles 巡检已签发（issued/downloaded）的 ACME 证书任务，若其磁盘
// 证书/私钥文件缺失，则从数据库 cert_pem/key_pem 重建，避免容器重建或磁盘清理后 Caddy
// 因缺证书文件而拒绝加载。仅覆盖 ACME 任务：手动证书内联在 lb_rules.tls_cert，由启动时
// MaterializeAllCertsFromDB 物化；本函数随证书服务（仅主节点）每 6 小时对账一次。
// 查询/迭代失败必须返回 error（CertReconcileOnce 上抛 → task_runs 失败终态，
// 摘要不再谎报「对账完成」）；单行 Scan 失败仍跳过（该行不可信，其余行可继续收敛），
// 但迭代错误表明结果集不完整，按失败处理。
// ctx 取消即中止（返回包装后的取消错误）；每个重建写点前另经
// certReconcileWriteGate 复核节点角色（扫描期降级不得继续写盘）。
//
// 判据口径（与启动物化**有意不同**，不得据此推断两侧等价）：
//   - 行选择：与 MaterializeAllCertsFromDB 同源（latestApplicableACMECertMaterials），
//     每规则取最新且域名适用的一行；
//   - 写判据：本函数**不比对内容**——只在证书/私钥文件缺失时重建，文件存在即
//     跳过，即使磁盘内容与库内 PEM 不一致（内容修复由 apply/导入的物化路径与
//     启动物化负责，它们的判据是内容 + 权限）。对账的职责是「文件缺失自愈」，
//     每 6h 无条件重写全部证书对会造成无谓写放大。
func reconcileMissingCertFiles(ctx context.Context, dbh *sql.DB) (int, error) {
	materials, scanFailures, selectErr := latestApplicableACMECertMaterials(ctx, dbh, "cert reconcile")
	if selectErr != nil {
		Logf("error", "cert reconcile: query issued certificates failed: %v", selectErr)
		return 0, fmt.Errorf("查询已签发证书任务: %w", selectErr)
	}
	rebuilt := 0
	// 逐行物化失败聚合器：健康行继续重建，失败行让本轮返回错误（失败终态）。
	var actionErr error
	// 单行读失败与逐行物化失败同权（同族 rescan/requeueWaitingCAJobs 口径）：
	// 只写应用日志时本轮仍报「对账完成」，而某行根本没被检查过——运维从任务
	// 监控看不出「本轮有行未检查」。
	if scanFailures > 0 {
		actionErr = errors.Join(actionErr, fmt.Errorf("读取待对账证书任务行: %d 行读取失败（本轮未检查）", scanFailures))
	}
	for _, material := range materials {
		ruleID, domain, certPEM, keyPEM := material.RuleID, material.Domain, material.CertPEM, material.KeyPEM
		certPath, keyPath := CertFilePaths(ruleID)
		if certPath == "" {
			continue
		}
		if fileExists(certPath) && fileExists(keyPath) {
			continue
		}
		// 写前门：扫描判定到落盘之间节点可已降级/轮次可已取消——
		// 从节点写证书文件会与主节点内容分叉（且轮次谎报完成）。
		if gateErr := certReconcileWriteGate(ctx); gateErr != nil {
			Logf("warn", "cert reconcile: 重建证书文件前写门拦截（%s）: %v", ruleID, gateErr)
			if rebuilt > 0 {
				RecordAuditLog("system", "重建", "证书文件", FormatAuditDetail(AuditSourcePart("runtime_reconcile"), fmt.Sprintf("重建 %d 个证书文件", rebuilt)), "")
			}
			return rebuilt, gateErr
		}
		changed, materializeErr := materializeCertPair(ruleID, certPEM, keyPEM)
		if materializeErr != nil {
			Logf("error", "cert reconcile: rebuild certificate files for %s failed: %v", ruleID, materializeErr)
			// 单行物化失败（只读目录/磁盘满/坏 PEM）必须进入失败轮：只写应用日志
			// 时任务日志仍写「状态对账完成 0」，而规则证书文件实际仍缺失，下次
			// Caddy 重载/重启该规则无证书可用。
			actionErr = errors.Join(actionErr, fmt.Errorf("重建证书文件 %s: %w", ruleID, materializeErr))
			continue
		}
		if !changed {
			// 前置 fileExists 检查后仍零写=并发重建已完成，不得重复计数。
			continue
		}
		rebuilt++
		Logf("info", "证书文件缺失，已从数据库重建: %s", domain)
	}
	if rebuilt > 0 {
		RecordAuditLog("system", "重建", "证书文件", FormatAuditDetail(AuditSourcePart("runtime_reconcile"), fmt.Sprintf("重建 %d 个证书文件", rebuilt)), "")
	}

	return rebuilt, actionErr
}
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func RequeueNonTerminalCertJobs() error {
	return requeueNonTerminalCertJobs(context.Background(), scheduleCertificateDeploymentRetry)
}

// CountNonTerminalCertJobs 统计 cert_jobs 中「非终态」任务行数
// （status ∉ {issued,failed,disabled}，与 JobIsTerminal / 启动恢复同源）。
// 唯一消费方是配置导入/还原的披露：证书队列未激活时这些行本窗口不会推进
// 属 fail-safe 的有意行为（不越过用户「停止签发」的意图），但必须让管理员
// 在响应里看到——否则任务列表显示进行中而实际没有 worker。只读统计，不做
// 任何状态推进。
func CountNonTerminalCertJobs(ctx context.Context) (int, error) {
	placeholders := make([]string, 0, len(nonTerminalJobStatuses))
	args := make([]any, 0, len(nonTerminalJobStatuses))
	for _, status := range nonTerminalJobStatuses {
		placeholders = append(placeholders, "?")
		args = append(args, status)
	}
	var count int
	if err := db.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cert_jobs WHERE status IN ("+strings.Join(placeholders, ",")+")",
		args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("统计非终态证书任务: %w", err)
	}
	return count, nil
}

func requeueNonTerminalCertJobs(ctx context.Context, deploymentRetry func(int, issuedCertificate, time.Duration) error) error {
	// waiting_ca 子句已删除（此前按冷却窗口放行）：waiting_ca 由启动迁移
	//（db_migration_cert_failure）先行归一为 failed，配置导入/还原提交后
	// 也经 db.NormalizeWaitingCACertJobs 归一——本查询时库内不存在
	// waiting_ca 行，不再防御（防御反而掩盖归一断链）。
	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.domain, j.status, COALESCE(j.ca_provider_id,0), COALESCE(j.deployment_attempts,0), j.deployment_available_after,
		       COALESCE(r.domain,''), CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END,
		       CASE WHEN `+CertJobMaterialPredicateSQL("j")+` THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status != 'disabled'
	`)
	if err != nil {
		return fmt.Errorf("query non-terminal certificate jobs: %w", err)
	}
	type recoveryJob struct {
		id, providerID, deploymentAttempts int
		ruleID, domain, status, ruleDomain string
		deploymentAvailableAfter           sql.NullTime
		applicable, hasCertMaterial        bool
	}
	var jobs []recoveryJob
	for rows.Next() {
		var job recoveryJob
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.providerID, &job.deploymentAttempts, &job.deploymentAvailableAfter, &job.ruleDomain, &job.applicable, &job.hasCertMaterial); err != nil {
			rows.Close()
			return fmt.Errorf("scan non-terminal certificate job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate non-terminal certificate jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close non-terminal certificate jobs: %w", err)
	}
	// 告警 + 非正回退语义收敛于 GetCertRenewalDays。
	renewalDays := GetCertRenewalDays()
	now := time.Now()
	selectedByRule := make(map[string]CertificateSelection)
	selectionLoaded := make(map[string]bool)

	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if JobIsTerminal(job.status) {
			// 失败任务不得在启动恢复时复活：即使它仍持有之前签发的有效证书，也不能
			// 被"检测到已有有效证书"分支拉回 issued。证书维持之前部署的版本，下一次
			// 尝试只能由续签巡检（CheckExpiration）或手动重签（RetryCertJob）驱动。
			continue
		}
		if job.applicable {
			job.applicable = certJobRuleApplicable(job.applicable, job.ruleDomain, job.domain)
		}
		if !job.applicable {
			if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "disabled", map[string]any{"message": "关联规则已不再使用当前 ACME 证书任务"}); err != nil {
				// CAS 冲突=快照后并发写入方已接管该任务（如 worker 恰在
				// 恢复窗口内迁移状态）——跳过该任务继续恢复其余任务，不得中止
				// 整个循环（creating_*/downloading 无周期巡检救援，中止即滞留到
				// 下次重启）；与 sweepOrphanedCertJobs/requeueWaitingCAJobs 同型。
				// 其余错误仍立即返回。
				if errors.Is(err, ErrJobTransitionConflict) {
					continue
				}
				return fmt.Errorf("disable ineligible recovered certificate job %d: %w", job.id, err)
			}
			continue
		}
		lifecycle := JobLifecycle(job.status)
		// 'queued' 是用户显式触发的重签请求（RetryCertJob
		// 全量重签语义，旧 cert_pem/key_pem 保留在行上）——"检测到已有有效证书"
		// 恢复优化只适用于在途任务（active/waiting_ca），不得把显式重签请求
		// 静默转为 issued，否则请求跨重启消失。queued 任务落到下方重新排队。
		if lifecycle != JobLifecycleDownloaded && lifecycle != JobLifecycleQueued {
			selection, loaded := selectedByRule[job.ruleID]
			if !selectionLoaded[job.ruleID] {
				selection, loaded, err = selectStoredRuleCertificate(ctx, job.ruleID, job.ruleDomain, now)
				if err != nil {
					return fmt.Errorf("select existing certificate for recovered job %d: %w", job.id, err)
				}
				selectionLoaded[job.ruleID] = true
				if loaded {
					selectedByRule[job.ruleID] = selection
				}
			}
			if loaded {
				canonicalSelected, selectedErr := CanonicalACMEDomains(selection.Candidate.Domain)
				canonicalRule, ruleErr := CanonicalACMEDomains(job.ruleDomain)
				if selectedErr == nil && ruleErr == nil && canonicalSelected == canonicalRule && selection.Certificate.NotAfter.After(now.Add(time.Duration(renewalDays)*24*time.Hour)) {
					if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "issued", map[string]any{"message": "检测到已有有效证书，跳过恢复签发"}); err != nil {
						// CAS 冲突同样跳过继续（同上 disable 站点语义）。
						if errors.Is(err, ErrJobTransitionConflict) {
							continue
						}
						return fmt.Errorf("complete recovered certificate job %d with existing certificate: %w", job.id, err)
					}
					continue
				}
			}
		}
		if lifecycle == JobLifecycleDownloaded && job.hasCertMaterial {
			delay := time.Duration(0)
			if job.deploymentAvailableAfter.Valid {
				delay = time.Until(job.deploymentAvailableAfter.Time)
				if delay < 0 {
					delay = 0
				}
			}
			if err := deploymentRetry(job.id, issuedCertificate{ruleID: job.ruleID, providerID: job.providerID, deploymentAttempt: job.deploymentAttempts}, delay); err != nil {
				// 暂停/屏障期的未登记不是故障（Resume/解锁补扫接管），
				// 其余错误必须留痕：否则部署重试断链只表现为「什么都没发生」。
				if !errors.Is(err, ErrCertificateQueueInactive) && !errors.Is(err, ErrCertificateDeploymentRetryBlocked) {
					Logf("warn", "证书任务 %d：恢复链部署重试登记失败（补扫接管）: %v", job.id, err)
				}
			}
			continue
		}

		qm := GetCAQueueManager()
		if qm == nil {
			return fmt.Errorf("CA queue manager not initialized")
		}
		// 复用 EnqueueIfActive 在途守卫（与 Resume/周期巡检/waiting_ca
		// 路径同型）——备份导入 finish 链等场景下滞行执行（retiredQueues zombie）
		// 仍持有同 jobID 时，直接 transition+Enqueue 会造成双执行，且 zombie 晚退的
		// requeueCanceledJob 会把新执行状态打回 'queued'。命中在途任务时跳过
		// 转换/入队/审计，任务由在途执行自身收尾。
		_, changed, err := qm.EnqueueIfActive(job.providerID, job.id, job.ruleID, job.domain, func() (int, bool, error) {
			err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "queued", map[string]any{"message": "等待排队签发"})
			if errors.Is(err, ErrJobTransitionConflict) {
				return job.id, false, nil
			}
			return job.id, err == nil, err
		})
		if err != nil {
			return fmt.Errorf("enqueue recovered certificate job %d: %w", job.id, err)
		}
		if !changed {
			Logf("warn", "cert recovery: job %d still active in CA queue, skip requeue", job.id)
			continue
		}
		RecordAuditLog("system", "恢复排队", "证书任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("startup_recovery")), "")
	}
	return nil
}

// certJobRuleApplicable 判断证书任务是否仍被规则引用：规则存在、启用、开启 TLS 且
// 证书来源为 acme_dns（SQL CASE 结果，即 ruleBound），且任务域名与规则域名规范化后一致。
func certJobRuleApplicable(ruleBound bool, ruleDomain, jobDomain string) bool {
	if !ruleBound {
		return false
	}
	canonicalRule, ruleErr := CanonicalACMEDomains(ruleDomain)
	canonicalJob, jobErr := CanonicalACMEDomains(jobDomain)
	return ruleErr == nil && jobErr == nil && canonicalRule == canonicalJob
}

// sweepOrphanedCertJobs 禁用规则已不再引用的非终态证书任务（域名迁移/规则停用/删除后
// 遗留，启动恢复 requeueNonTerminalCertJobs 只在重启时处理一次），随 6 小时对账巡检执行，
// 避免孤儿任务滞留到重启或被 waiting_ca 重排队白白签发。
// 读/迭代失败必须上抛（fail-visible）——此前只 Logf + return 0，对账轮摘要
// 仍写「孤儿清理 0 个」，任务监控无法区分「一致」与「扫描失败」。
func sweepOrphanedCertJobs(ctx context.Context) (int, error) {
	swept := 0
	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.status, COALESCE(j.domain,''), COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status != 'disabled'
	`)
	if err != nil {
		Logf("error", "cert sweep: query certificate jobs failed: %v", err)
		return 0, fmt.Errorf("查询证书任务: %w", err)
	}
	type orphanCandidate struct {
		id         int
		ruleID     string
		status     string
		jobDomain  string
		ruleDomain string
		ruleBound  bool
	}
	var orphans []orphanCandidate
	for rows.Next() {
		var job orphanCandidate
		if err := rows.Scan(&job.id, &job.ruleID, &job.status, &job.jobDomain, &job.ruleDomain, &job.ruleBound); err != nil {
			rows.Close()
			Logf("error", "cert sweep: scan certificate job failed: %v", err)
			return 0, fmt.Errorf("读取证书任务行: %w", err)
		}
		if JobIsTerminal(job.status) {
			continue
		}
		if !certJobRuleApplicable(job.ruleBound, job.ruleDomain, job.jobDomain) {
			orphans = append(orphans, job)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		Logf("error", "cert sweep: iterate certificate jobs failed: %v", err)
		return 0, fmt.Errorf("遍历证书任务: %w", err)
	}
	rows.Close()
	var sweepErr error
	for _, job := range orphans {
		if err := ctx.Err(); err != nil {
			return swept, errors.Join(sweepErr, fmt.Errorf("孤儿清理被中止: %w", err))
		}
		// 写前门：逐项复核节点角色（扫描开始时的判定在长轮次内会过期）。
		if gateErr := certReconcileWriteGate(ctx); gateErr != nil {
			Logf("warn", "cert sweep: 禁用孤儿任务前写门拦截（job=%d）: %v", job.id, gateErr)
			return swept, errors.Join(sweepErr, gateErr)
		}
		if err := transitionJob(db.DB, job.id, nonTerminalJobStatuses, "disabled", map[string]any{"message": "关联规则已不再使用当前 ACME 证书任务"}); err != nil {
			if errors.Is(err, ErrJobTransitionConflict) {
				continue
			}
			Logf("error", "cert sweep: disable orphaned certificate job %d failed: %v", job.id, err)
			// 单行写失败不再静默放行——失败行意味着残留孤儿，对账摘要
			// 必须按失败轮呈现（swept 只计实际收敛，失败原因并入错误链）。
			sweepErr = errors.Join(sweepErr, fmt.Errorf("禁用孤儿任务 %d: %w", job.id, err))
			continue
		}
		// swept 只计实际收敛的行——消费方 CertReconcileOnce 的
		// 「孤儿清理 %d 个」任务日志行直接取该值，恒 0 即对账失真。
		swept++
		RecordAuditLog("system", "禁用", "证书任务", FormatAuditDetail(AuditJobPart(job.id), AuditRulePart(job.ruleID), AuditSourcePart("runtime_sweep")), "")
	}

	return swept, sweepErr
}
func (s *CertificateService) Stop() {
	s.timerMu.Lock()
	s.stopping = true
	s.timerMu.Unlock()
	// 手动重试入口与后台补扫共用全局服务指针。停止时按实例身份摘除，
	// 防止已停服务继续接受「立即部署」请求；旧代 Stop 不得误清新一代实例。
	certificateServiceMu.Lock()
	if certificateService == s {
		certificateService = nil
	}
	certificateServiceMu.Unlock()
	s.pauseDeploymentRetries()
	s.cancel()
	// done 仅由 Start 的 defer 关闭——Start 未执行的 Stop 不得裸
	// 等待（原实现永久阻塞）。cancel 已生效，若随后 Start 被调用会立即退出。
	if !s.started.Load() {
		return
	}
	<-s.done
}

// ErrCertificateQueueInactive 标记「证书签发任务未运行（队列未激活/已暂停）」
// 导致的入队拒绝。这是运维态而非内部故障：与手工签发的 409 口径一致
// handler 必须映射 409/503 并点明「证书签发任务已停止」，不得
// 折成 500 让规则保存看起来像内部错误。
var ErrCertificateQueueInactive = errors.New("证书签发任务未运行")

// ErrCertificateDeploymentRetryBlocked 标记部署重试因规则处于补偿屏障
// （CA 队列锁定该规则）而未登记。与 ErrCertificateQueueInactive 同为「本轮
// 未调度」的可观测结果：补扫不得把它计成一次成功的部署重建。
var ErrCertificateDeploymentRetryBlocked = errors.New("规则补偿屏障中，部署重试暂不登记")

// ErrCertRuleStateConflict 标记 upsert 时规则当前态守卫拒绝：规则已删除、
// 被禁用、非 ACME 或域名已变更。属并发冲突语义——
// 调用方必须如实呈现（handler 409），不得伪装成 changed=false 的「状态不
// 支持重排」或折成 500 内部错误。
var ErrCertRuleStateConflict = errors.New("规则状态已变更或不再支持 ACME 签发")

// upsertQueuedCertJob 持久化「排队签发」任务行（原 EnqueueIfActive transition
// 闭包单源）。返回任务 id 与是否发生状态迁移。
//
// 规则当前态守卫：INSERT 与冲突 UPDATE 都要求 lb_rules
// 当前行仍是「启用 ACME 且规范化域名匹配」（对照 Retry 路径
// handlers/certjobs.go 的 EXISTS 同口径）——手工签发读规则与 upsert 之间的
// 改域迁移/删除曾可对旧域发起 CA 签发或留下孤儿任务行。手工签发入口持
// caddyOpMu 时本守卫不可达，是其余无锁调用方（补建/恢复）与纵深防御的落库闸。
func upsertQueuedCertJob(ruleID string, list []string, caProviderID int) (int, bool, error) {
	joined := strings.Join(list, ",")
	// 逆序形式单源（services.ReversedCertJobDomain），同包直接复用。
	reversed := ReversedCertJobDomain(joined)
	var id int
	err := db.DB.QueryRow(`
		INSERT INTO cert_jobs (rule_id, domain, status, message, ca_provider_id)
		SELECT ?, ?, 'queued', '等待排队签发', ?
		WHERE EXISTS (
			SELECT 1 FROM lb_rules r
			WHERE r.caddy_id=? AND r.enabled=1 AND r.enable_tls=1
			  AND r.tls_source='acme_dns' AND lower(replace(r.domain,' ','')) IN (?,?)
		)
		ON CONFLICT(rule_id, domain) DO UPDATE SET
			status = 'queued',
			message = '重新排队签发',
			renewal_attempts = 0,
			ca_available_after = NULL,
			last_error_code = NULL,
			ca_provider_id = excluded.ca_provider_id,
			updated_at = datetime('now')
		WHERE cert_jobs.status IN ('waiting_ca','issued','failed','downloaded','disabled')
		  AND EXISTS (
			SELECT 1 FROM lb_rules r
			WHERE r.caddy_id=cert_jobs.rule_id AND r.enabled=1 AND r.enable_tls=1
			  AND r.tls_source='acme_dns' AND lower(replace(r.domain,' ','')) IN (?,?)
		  )
		RETURNING id
	`, ruleID, joined, caProviderID, ruleID, joined, reversed, joined, reversed).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// RETURNING 空有两种成因：①规则当前态守卫拒绝（并发冲突语义，行可
		// 能根本不存在）；②既有行状态不可重排（原语义，changed=false 让上游
		// 归因在途/冷却/屏障）。复核守卫区分两者——①必须上抛
		// ErrCertRuleStateConflict，不得按②吞掉让 handler 报「状态不支持」。
		var ruleOK bool
		if gerr := db.DB.QueryRow(`SELECT EXISTS(
			SELECT 1 FROM lb_rules
			WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns'
			  AND lower(replace(domain,' ','')) IN (?,?)
		)`, ruleID, joined, reversed).Scan(&ruleOK); gerr != nil {
			return 0, false, gerr
		}
		if !ruleOK {
			return 0, false, ErrCertRuleStateConflict
		}
		if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id=? AND domain=?", ruleID, joined).Scan(&id); err != nil {
			return 0, false, err
		}
		return id, false, nil
	}
	return id, err == nil, err
}

// ErrCertRuleBusy 标记「规则证书任务屏障期」导致的入队拒绝——规则正在
// 删除/禁用/更新的取消窗口（BlockJobsForRule 租约）内，瞬时冲突语义。
// 与 ErrCertificateQueueInactive/ErrCertRuleStateConflict 同族：handler 必须
// 映射 409（可重试的并发冲突），不得折成 500 让并发操作看起来像内部故障。
var ErrCertRuleBusy = errors.New("规则证书任务正在变更（删除/禁用/更新中），请稍后重试")

// CreateOrRequeueCertJob creates a queued cert job and verifies it is either
// active in the queue or the caller can report a precise enqueue failure.
func CreateOrRequeueCertJob(ruleID, domains string, caProviderID int, qm *CAQueueManager) (int, error) {
	jobID, _, err := CreateOrRequeueCertJobVerified(ruleID, domains, caProviderID, qm)
	return jobID, err
}

// CreateOrRequeueCertJobVerified is CreateOrRequeueCertJob plus the transition
// signal needed by rule-write compensation. It preserves the raw WithChange
// result for manual issuance, but rejects a no-change result whose job is not
// actually active in a running queue.
// 未入队归因顺序：在途（幂等放行）→ 队列停用（ErrCertificateQueueInactive）
// → 规则屏障（ErrCertRuleBusy）→ 其余（裸错）。屏障归因必须显式——
// EnqueueIfActive 的注释承诺「changed=false 让 handler 走 409」，裸错会
// 折成 500。
func CreateOrRequeueCertJobVerified(ruleID, domains string, caProviderID int, qm *CAQueueManager) (int, bool, error) {
	jobID, changed, err := CreateOrRequeueCertJobWithChange(ruleID, domains, caProviderID, qm)
	if err != nil || changed {
		return jobID, changed, err
	}
	if jobID > 0 && qm != nil && qm.IsJobActive(jobID) {
		return jobID, false, nil
	}
	if qm != nil && !qm.IsActive() {
		return jobID, false, fmt.Errorf("%w（任务 %d 未入队）", ErrCertificateQueueInactive, jobID)
	}
	if qm != nil && qm.IsRuleBlocked(ruleID) {
		return jobID, false, fmt.Errorf("%w（任务 %d 未入队）", ErrCertRuleBusy, jobID)
	}
	return jobID, false, fmt.Errorf("certificate job %d was not queued", jobID)
}

func CreateOrRequeueCertJobWithChange(ruleID, domains string, caProviderID int, qm *CAQueueManager) (int, bool, error) {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return 0, false, fmt.Errorf("invalid ACME domains: %s", domains)
	}
	joined := strings.Join(list, ",")

	// Defensive: if no explicit CA provider was supplied, use the rule's own
	// setting rather than falling back to the global default.
	if caProviderID == 0 {
		var ruleCA int
		if err := db.DB.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&ruleCA); err == nil && ruleCA != 0 {
			caProviderID = ruleCA
		}
	}
	Logf("info", "CreateOrRequeueCertJob rule=%s domain=%s ca_provider_id=%d", ruleID, joined, caProviderID)

	if qm == nil {
		return 0, false, fmt.Errorf("CA queue manager not initialized")
	}
	jobID, changed, err := qm.EnqueueIfActive(caProviderID, 0, ruleID, joined, func() (int, bool, error) {
		return upsertQueuedCertJob(ruleID, list, caProviderID)
	})
	if err != nil {
		return jobID, changed, fmt.Errorf("create or enqueue cert job: %w", err)
	}
	if !changed {
		if jobID != 0 {
			return jobID, false, nil
		}
		if !qm.IsActive() {
			return 0, false, fmt.Errorf("%w（任务未入队）", ErrCertificateQueueInactive)
		}
		// 队列激活但入队被拒且无既有行——唯一剩余成因是规则屏障租约
		// （EnqueueIfActive 的 admission 三分支：在途/停用/屏障）。屏障是
		// 瞬时冲突语义，必须归因为 409 族而非泛化 500。
		if qm.IsRuleBlocked(ruleID) {
			return 0, false, ErrCertRuleBusy
		}
		return 0, false, fmt.Errorf("CA queue is paused")
	}
	// 任务入队即唤醒 cert-waiting-ca（默认调度关闭；全部终态由 Run
	// 体自停）。 勘误：本处不再是「全部创建路径的单点」——规则写路径
	// （EnableRule 的 Create/Retry/Renew）经此收敛；手动重试与删除失败恢复
	// 直调 EnqueueIfActive，唤醒点在 handlers/certjobs.go 同批落地。
	// 入队成功即真实工作，唤醒不重查活跃态（避免瞬时失败漏唤醒）。
	WakeCertWaitingCAForEnqueuedJob()
	return jobID, true, nil
}

// BackfillMissingACMECertJobs 为「启用且启用 ACME 的规则」补建缺失的
// cert_jobs 行。
//
// 主从快照只携带已签发证书材料（cluster_snapshot.go 的 certs 组选），从端
// apply 清空 cert_jobs 后仅回插材料行且统一为 issued；提升时凡「从未签发成功/
// 首发失败/正在签发/证书已过期/材料缺失」的规则在新主节点上没有任务行。续期
// 扫描、首发重试、补扫、对账一律 JOIN cert_jobs，规则存在但行缺失时永不命中
// ——自动签发/续期链静默中断。提升/启动恢复（cert-issuance 唤醒证书服务）与
// 6h 对账都调用本函数收敛。
//
// 任务行先落库（queued），队列激活时才一并入队；队列未激活时行保持 queued，
// 由 Resume 的 requeueLifecycleStrandedJobs / cert-waiting-ca 补扫接管。
// 返回新建/复活的规则数。
func BackfillMissingACMECertJobs(ctx context.Context, qm *CAQueueManager) (int, error) {
	if db.DB == nil {
		return 0, errors.New("数据库未初始化")
	}
	rows, err := db.DB.QueryContext(ctx, `
		SELECT r.caddy_id, COALESCE(r.domain,''), COALESCE(r.ca_provider_id,0)
		FROM lb_rules r
		WHERE r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		  AND trim(COALESCE(r.domain,''))<>''
		  AND NOT EXISTS (
			SELECT 1 FROM cert_jobs j
			WHERE j.rule_id=r.caddy_id AND j.status<>'disabled'
		  )
		ORDER BY r.caddy_id`)
	if err != nil {
		return 0, fmt.Errorf("查询缺失证书任务的 ACME 规则: %w", err)
	}
	type missingJobRule struct {
		ruleID     string
		domain     string
		caProvider int
	}
	var candidates []missingJobRule
	for rows.Next() {
		var candidate missingJobRule
		if err := rows.Scan(&candidate.ruleID, &candidate.domain, &candidate.caProvider); err != nil {
			rows.Close()
			return 0, fmt.Errorf("读取缺失证书任务的规则: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("遍历缺失证书任务的规则: %w", err)
	}
	rows.Close()

	created := 0
	var actionErr error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return created, errors.Join(actionErr, ctx.Err())
		}
		list := normalizeAndValidateDomains(candidate.domain)
		if list == nil {
			// 导入可产生非法 ACME 域（导入校验不验域合法性）——跳过并留痕，
			// 不阻断其余规则的补建。
			Logf("warn", "证书任务补建跳过规则 %s：ACME 域名不可规范化（%q）", candidate.ruleID, candidate.domain)
			continue
		}
		// 写前门：补建=新增任务行（含入队），从节点落定会与主节点重复签发。
		if gateErr := certReconcileWriteGate(ctx); gateErr != nil {
			Logf("warn", "证书任务补建前写门拦截（rule=%s）: %v", candidate.ruleID, gateErr)
			return created, errors.Join(actionErr, gateErr)
		}
		jobID, changed, uerr := upsertQueuedCertJob(candidate.ruleID, list, candidate.caProvider)
		if uerr != nil {
			Logf("error", "证书任务补建失败 rule=%s: %v", candidate.ruleID, uerr)
			if !errors.Is(uerr, ErrCertRuleStateConflict) {
				actionErr = errors.Join(actionErr, fmt.Errorf("补建规则 %s 证书任务: %w", candidate.ruleID, uerr))
			}
			continue
		}
		if changed {
			created++
		}
		if qm == nil || !qm.IsActive() || jobID <= 0 {
			continue
		}
		// 行已 queued：transition 返回 changed=true 只表示「允许入队」。
		if _, _, eerr := qm.EnqueueIfActive(candidate.caProvider, jobID, candidate.ruleID, strings.Join(list, ","), func() (int, bool, error) {
			return jobID, true, nil
		}); eerr != nil {
			actionErr = errors.Join(actionErr, fmt.Errorf("补建后入队规则 %s 任务 %d: %w", candidate.ruleID, jobID, eerr))
			Logf("warn", "证书任务补建后入队失败 rule=%s job=%d（行保持 queued，恢复补扫接管）: %v", candidate.ruleID, jobID, eerr)
		}
	}
	if created > 0 {
		Logf("info", "证书任务补建：为 %d 个启用 ACME 规则创建排队任务", created)
		RecordAuditLog("system", "创建", "证书任务", FormatAuditDetail(AuditSourcePart("promote_or_startup"), fmt.Sprintf("为 %d 个启用 ACME 规则补建证书任务", created)), "")
	}
	return created, actionErr
}

// HasCertJob reports whether any certificate job row exists for the given
// rule and domain, regardless of status. It is used to avoid re-creating
// jobs when one already exists (in any state); the existing ON CONFLICT
// and queue/renewal logic handle the rest.
func HasCertJob(ruleID, domains string) bool {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return false
	}
	joined := strings.Join(list, ",")

	var exists bool
	err := db.DB.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM cert_jobs
			WHERE rule_id = ? AND domain = ?
		)
	`, ruleID, joined).Scan(&exists)
	if err != nil {
		Logf("error", "HasCertJob query failed for rule %s: %v", ruleID, err)
		return false
	}
	return exists
}

// renewExpiringCertificates 续期扫描。ctx 由引擎 RunContext 透传：配置导入/
// 还原的排空序列（PauseScheduling → CancelInFlightRuns → WaitInFlightRuns）
// 只有消费 ctx 的 tick 才能被中止；入口与逐任务写点前均复核 ctx + 节点角色
// （入口判定在最长 6h 的扫描窗口内会过期）。
func (s *CertificateService) renewExpiringCertificates(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	qm := GetCAQueueManager()

	// 新2:COALESCE 口径对齐全域(NULL 视为主节点）+
	// 失败留痕(对照,此前静默跳过整个过期检查)。
	isMaster, err := RoleOf(ctx, db.DB)
	if err != nil {
		Logf("error", "cert expiration loop: failed to read cluster role, skipping this cycle: %v", err)
		// 角色读取失败=本轮什么都没做，必须进入任务失败终态
		// （此前只落应用日志，任务监控显示 success）。
		TaskLogf("cert-renewal-scan", "scan", "扫描失败：读取节点角色失败（%v），本轮未执行续期，下一周期重试", err)
		return fmt.Errorf("读取节点角色: %w", err)
	}
	if !isMaster {
		// 降级终态统一为 skipped 哨兵（与 crs/threat 同构）：从节点中止非故障，
		// 但 return nil 会把「未执行」记成 success（任务监控假健康）。
		TaskLogf("cert-renewal-scan", "skipped", "节点为从节点，本轮续期扫描未执行（从节点不签发）")
		return taskengine.ErrTaskSkipped
	}

	// CheckExpiration locks s.mu internally; the loop below only touches the
	// DB and the queue, so holding s.mu here would deadlock the renewal.
	maxAttempts := getCertRenewalAttempts()
	jobs, skippedExpiring, scanErr := s.CheckExpiration(ctx)
	firstIssuance, skippedFirstIssuance, firstErr := s.checkFailedFirstIssuance(ctx, maxAttempts)
	if scanErr != nil || firstErr != nil {
		// 候选查询/遍历失败时结果集不可信，
		// 摘要行必须如实报「扫描失败」并终止本轮（错误细节已入应用日志），
		// 下一周期重试——此前吞成「无临期证书」会让任务监控呈现假健康。
		detail := scanErr
		if detail == nil {
			detail = firstErr
		} else if firstErr != nil {
			detail = errors.Join(scanErr, firstErr)
		}
		// 取消/超时不是故障：导入排空（PauseScheduling → CancelInFlightRuns →
		// WaitInFlightRuns）与停机都会取消 ctx，摘要必须与「查询/遍历出错」区分，
		// 否则一次正常排空在任务监控里呈现为续期扫描失败。
		if ctxErr := ctx.Err(); ctxErr != nil {
			TaskLogf("cert-renewal-scan", "scan", "续期中止：扫描阶段已取消（%v），本轮未入队任何任务", ctxErr)
			return detail
		}
		TaskLogf("cert-renewal-scan", "scan", "扫描失败：续期候选查询/遍历出错（%v），本轮未执行续期，下一周期重试", detail)
		return detail
	}
	jobs = append(jobs, firstIssuance...)
	scanSkipped := skippedExpiring + skippedFirstIssuance
	skippedNote := ""
	if scanSkipped > 0 {
		skippedNote = fmt.Sprintf("（另 %d 行扫描失败已跳过）", scanSkipped)
	}
	if len(jobs) == 0 {
		TaskLogf("cert-renewal-scan", "scan", "扫描完成：无临期证书、无待重试签发任务%s", skippedNote)
		return nil
	}
	domains := make([]string, 0, len(jobs))
	capped := 0
	for _, j := range jobs {
		domains = append(domains, j.Domain)
		if j.RenewalAttempts >= maxAttempts {
			capped++
		}
	}
	// 已达上限任务每轮仍被选出（warn 形态，
	// 自动重试不可达），摘要须分档标注——否则「待重试」口径失真。全部未达
	// 上限时保持原文案（不追加空括注）。
	if capped > 0 {
		TaskLogf("cert-renewal-scan", "scan", "检测到 %d 个临期/待重试证书任务（其中 %d 个已达重试上限，仅手动重签可达）：%s%s", len(jobs), capped, strings.Join(domains, "、"), skippedNote)
	} else {
		TaskLogf("cert-renewal-scan", "scan", "检测到 %d 个临期/待重试证书任务：%s%s", len(jobs), strings.Join(domains, "、"), skippedNote)
	}
	var actionErr error

	for idxRenewalJob, j := range jobs {
		// 逐任务写前门（ctx + 节点角色）必须早于**任何**写点：上限分支的
		// waiting_ca → failed 终态迁移与审计行、以及下方入队迁移都在其后。
		// 入口一次角色检查覆盖不了最长 6h 的扫描窗口——降级/导入排空/停机
		// 落在窗口内时，从节点仍会写本地库与审计（破坏「从节点零写」）。
		if gateErr := certRenewalWriteGate(ctx); gateErr != nil {
			remaining := len(jobs) - idxRenewalJob
			if errors.Is(gateErr, taskengine.ErrTaskSkipped) {
				TaskLogf("cert-renewal-scan", "scan", "续期中止：扫描期间节点已切换为从节点，剩余 %d 个任务本轮未入队（从节点不签发）", remaining)
			} else {
				TaskLogf("cert-renewal-scan", "scan", "续期中止：写前复核失败（%v），剩余 %d 个任务本轮未执行，下一周期重试", gateErr, remaining)
			}
			Logf("warn", "Renewal: 写前门拦截（任务 %d，剩余 %d 个未处理）: %v", j.ID, remaining, gateErr)
			if errors.Is(gateErr, taskengine.ErrTaskSkipped) {
				if actionErr != nil {
					return actionErr
				}
				return taskengine.ErrTaskSkipped
			}
			return errors.Join(actionErr, gateErr)
		}
		if j.RenewalAttempts >= maxAttempts {
			// B2 失败语义统一：waiting_ca 停车状态已退役（迁移后存量无此状态，
			// 失败统一落 failed 且达上限时窗口已为 NULL）——不再有 waiting_ca→
			// failed 的终局转换可做；issued/failed 一律留 warn 痕使「仅手动重试
			// 可达」对操作者可见（幂等：每 6h 一条，重置 renewal_attempts 才会
			// 再进自动重试）。
			Logf("warn", "证书任务 %d 已达最大重试次数（%d），仅手动重试可达", j.ID, maxAttempts)
			continue
		}

		if qm == nil {
			Logf("error", "Renewal: CA queue manager not initialized")
			TaskLogf("cert-renewal-scan", "scan", "续期中止：CA 队列未初始化，剩余 %d 个任务本轮未入队", len(jobs)-idxRenewalJob)
			return errors.Join(actionErr, errors.New("CA 队列未初始化"))
		}
		message := "等待排队续期"
		action := "续签排队"
		source := "renewal"
		if !j.ExpiresAt.Valid && j.Status == "failed" {
			message = "首次签发失败，冷却结束自动重试"
			action = "重试排队"
			source = "first_issuance_retry"
		}
		_, changed, err := qm.EnqueueIfActive(j.CAProviderID, j.ID, j.RuleID, j.Domain, func() (int, bool, error) {
			// 冷却残留必须与 recordJobFailure（统一失败写侧）的字段集对齐：
			// failed→queued 后若以非 429 原因再次失败，会写入新窗口/错误码，
			// 旧值不得跨失败轮残留（导出/备份/未来消费方看到矛盾字段）。
			err := transitionJob(db.DB, j.ID, []string{"issued", "failed"}, "queued", map[string]any{
				"message":            message,
				"ca_available_after": nil,
				"last_error_code":    nil,
			})
			if errors.Is(err, ErrJobTransitionConflict) {
				return j.ID, false, nil
			}
			return j.ID, err == nil, err
		})
		if err != nil {
			actionErr = errors.Join(actionErr, fmt.Errorf("续期入队任务 %d（规则 %s）: %w", j.ID, j.RuleID, err))
			Logf("error", "Renewal: failed to update job %d status: %v", j.ID, err)
			continue
		}
		if !changed {
			// 摘要行已宣告「检测到 N 个临期/待重试任务」，但!changed
			// 有三条出口——在途守卫（良性）、队列暂停（导入 PauseAndDrain/
			// 生命周期停止）、规则删除屏障。后两者此前完全静默：任务本轮没
			// 入队也无任何痕迹，最多推迟一个 6h 扫描周期。在途仍保持静默。
			switch {
			case !qm.IsActive():
				Logf("warn", "证书任务 %d 续期未入队：CA 队列已暂停（导入/生命周期暂停中），待恢复后的扫描重试", j.ID)
			case qm.IsRuleBlocked(j.RuleID):
				Logf("warn", "证书任务 %d 续期未入队：规则 %s 处于删除屏障，解除后由后续扫描重试", j.ID, j.RuleID)
			}
			continue
		}
		RecordAuditLog("system", action, "证书任务", FormatAuditDetail(AuditJobPart(j.ID), AuditRulePart(j.RuleID), AuditSourcePart(source)), "")
	}
	return actionErr
}

// manualCertExpiryCheckMu 串行化手动证书巡检的扫描体：包级巡检（服务实例
// 缺失/停止调度时仍要告警）与实例方法共享同一临界区，避免并发轮次重复读表
// 与重复告警判定。
var manualCertExpiryCheckMu sync.Mutex

// manualCertExpiryFallbackGate 服务实例缺失时的手动证书告警去重门：巡检不
// 依赖队列/服务实例，停止「证书签发」调度不应让 10 分钟一次的巡检失去去重。
var manualCertExpiryFallbackGate = newManualCertExpiryAlertGate()

// runManualCertExpiryCheck 是手动证书到期巡检的包级实现：只读 lb_rules 的
// 手动证书并用告警门去重，与 CA 队列/证书服务实例无关。生产入口是
// CertManualCheckOnce；实例方法形态仅存在于测试夹具（certificates_test.go）。
func runManualCertExpiryCheck(gate *manualCertExpiryAlertGate) error {
	manualCertExpiryCheckMu.Lock()
	defer manualCertExpiryCheckMu.Unlock()
	if gate == nil {
		gate = manualCertExpiryFallbackGate
	}

	// all manual certificates into memory, then close cursor before parsing
	// 与其余全部扫描/渲染口径对齐（enabled=1）——禁用规则的证书
	// 不进入任何 TLS 连接策略，此前漏筛 enabled 会每天对禁用规则产出
	// 问题「证书已过期」并每 10 分钟计数一次，稀释真实告警。
	rows, err := db.DB.Query(`
		SELECT caddy_id, name, domain, tls_cert 
		FROM lb_rules 
		WHERE enable_tls = 1 AND COALESCE(enabled,0) = 1
		  AND COALESCE(tls_source,'manual') = 'manual' AND tls_cert != ''
	`)
	if err != nil {
		Logf("error", "Failed to query TLS certificates for expiration check: %v", err)
		// 读失败上抛（对齐 cert-renewal-scan/cert-reconcile）——失败轮
		// 结果不可信，任务日志留失败行 + 返回 error（task_runs 失败终态）；
		// 此前仅应用日志 + return，任务监控呈现假健康。
		TaskLogf("cert-manual-poll", "check", "巡检失败：手动证书查询出错（%v），本轮未执行到期检查，下一周期重试", err)
		return fmt.Errorf("查询手动证书: %w", err)
	}
	type certInfo struct {
		caddyID string
		name    string
		domain  string
		certPEM string
	}
	var certs []certInfo
	// 单行读失败计数（必须在循环前声明：摘要与返回值都要用它）。
	scanFailCount := 0
	for rows.Next() {
		var c certInfo
		if err := rows.Scan(&c.caddyID, &c.name, &c.domain, &c.certPEM); err != nil {
			// 静默 continue 会让证书过期检查遗漏，必须记录告警；行数还必须进
			// 摘要——「无过期无临期」是对事实的断言，有行没检查过就不能这么说。
			Logf("warn", "Warning: scan failed during expiration check, skipping row: %v", err)
			scanFailCount++
			continue
		}
		certs = append(certs, c)
	}
	// 显式检查 rows.Err 和 rows.Close 错误，避免迭代期间错误被吞没。
	if err := rows.Err(); err != nil {
		Logf("warn", "cert expiration check: iteration error: %v", err)
		// 迭代失败结果集不可信——失败行 + 上抛（同查询失败口径）。
		TaskLogf("cert-manual-poll", "check", "巡检失败：手动证书遍历出错（%v），本轮结果不可信，下一周期重试", err)
		_ = rows.Close()
		return fmt.Errorf("遍历手动证书: %w", err)
	}
	if err := rows.Close(); err != nil {
		Logf("warn", "cert expiration check: close rows failed: %v", err)
	}

	now := time.Now()
	var expiredCount, expiringSoonCount, parseFailCount int
	// alerted 表示本轮有告警真正越过去重门（首次/加深）——任务日志摘要必须与
	// 应用日志同门：异常持续期每 10 分钟一轮的重复摘要会把同任务的事件行挤掉
	// （任务日志只保留 5 代），而告警本身已按日去重。
	alerted := false

	// （读取失败不静默）+ （非正回退）收敛于既有 helper；
	// 告警级别随 helper 统一为 error（原内联 warn 级漂移）。
	warnDays := GetCertExpiryThreshold()
	for _, c := range certs {
		block, _ := pem.Decode([]byte(c.certPEM))
		if block == nil {
			parseFailCount++
			Logf("warn", "cert expiration check: invalid certificate PEM for rule %s (%s)", c.caddyID, c.name)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			parseFailCount++
			Logf("warn", "cert expiration check: failed to parse certificate for rule %s (%s): %v", c.caddyID, c.name, err)
			continue
		}

		daysUntilExpiry := CertDaysRemaining(cert.NotAfter, now)
		// 到期状态判定收敛 CertificateExpiryStatus 单源
		// （天粒度；过期优先于临期）——与 certinfo 列表/任务列表同结论。
		switch CertificateExpiryStatus(cert.NotAfter, now, warnDays) {
		case "expired":
			// 同一证书同日同档只告一次(10min 扫描周期去重);
			// 计数不受门禁影响,汇总如实反映当前状态。
			if gate.shouldAlert(c.caddyID, manualCertExpiryLevelExpired, now) {
				alerted = true
				Logf("error", "⚠️ 问题: TLS certificate expired for rule '%s' (domain: %s, caddy_id: %s). Expired on %s",
					c.name, c.domain, c.caddyID, cert.NotAfter.Format("2006-01-02"))
			}
			expiredCount++
		case "expiring":
			if gate.shouldAlert(c.caddyID, manualCertExpiryLevelExpiringSoon, now) {
				alerted = true
				Logf("warn", "cert expiration check: TLS certificate expiring soon for rule '%s' (domain: %s, caddy_id: %s). Expires in %d days (%s)",
					c.name, c.domain, c.caddyID, daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
			}
			expiringSoonCount++
		}
	}

	// ③：解析失败行计数进摘要（对照续期扫描 skippedNote 口径）——
	// 此前仅应用日志 warn，任务日志零痕迹，损坏证书长期无人察觉。
	skippedNote := ""
	switch {
	case parseFailCount > 0 && scanFailCount > 0:
		skippedNote = fmt.Sprintf("（另 %d 行解析失败、%d 行读取失败已跳过）", parseFailCount, scanFailCount)
	case parseFailCount > 0:
		skippedNote = fmt.Sprintf("（另 %d 行解析失败已跳过）", parseFailCount)
	case scanFailCount > 0:
		skippedNote = fmt.Sprintf("（另 %d 行读取失败已跳过）", scanFailCount)
	}
	if (expiredCount > 0 || expiringSoonCount > 0) && alerted {
		Logf("info", "TLS Certificate Check: %d expired, %d expiring within %d days", expiredCount, expiringSoonCount, warnDays)
		// SPEC §6.5：业务结论镜像到任务日志。收敛与告警同一去重门——异常
		// 持续期只在首次/加深轮留一行，全正常轮与重复轮零日志（原「每 10
		// 分钟一条摘要」会把任务日志真正的事件行挤掉）。
		TaskLogf("cert-manual-poll", "check", "手动证书到期检查：%d 张已过期、%d 张临期（阈值 %d 天）%s", expiredCount, expiringSoonCount, warnDays, skippedNote)
	} else if (parseFailCount > 0 || scanFailCount > 0) && expiredCount == 0 && expiringSoonCount == 0 {
		// 「无过期无临期」是对事实的断言，只有统计真为 0 才允许说：此前本分支
		// 只看 parseFailCount，当异常证书当日已告警（alerted=false）而同轮另有
		// 解析失败行时会写出与本轮事实相反的结论。
		TaskLogf("cert-manual-poll", "check", "手动证书到期检查：无过期无临期（阈值 %d 天）%s", warnDays, skippedNote)
	}
	// 单行读失败让本轮进入失败终态（同族 rescan/对账口径）：摘要已如实标注跳过
	// 行数，返回值再把「结果不可信」交给 task_runs——只靠摘要文案时自动化监控
	// 仍只能看到 success。
	if scanFailCount > 0 {
		return fmt.Errorf("手动证书巡检：%d 行读取失败（本轮结果不可信）", scanFailCount)
	}
	return nil
}

// certRenewalGuaranteedGrace 是续签保护区：证书剩余有效期跌到该值时一律允许
// 续签。它同时是「两次自动续签之间的最小节奏」——同一张证书不会被比每 7 天
// 更频繁地重新签发（寿命不足 14 天的证书按半寿命收敛，见
// certRenewalWindowForLifetime），避免把自动续签逼到到期边界。
const certRenewalGuaranteedGrace = 7 * 24 * time.Hour

// certRenewalWindowForLifetime 返回证书实际寿命下本轮可执行的续签窗口（单源）。
//
// 窗口门决定首次入队：剩余有效期跌到窗口即续签。签发成功后剩余有效期回到证书
// 寿命 L，因此相邻两次自动续签的自然间隔就是 L−W：W 一旦接近 L（CA 实际签发
// 88.5 天 + 窗口 88 天时 L−W=12h），每轮扫描都整轮重签（每日/亚日级），约 5 次
// 即触发 CA 重复证书限流——签发失败后自动续签链终止，再约一个寿命后证书到期、
// HTTPS fail-closed。写侧/导入/读侧已把 W 收敛到 CertRenewalDaysMax（基于 90 天
// 规划寿命），但 CA 实际寿命不可预知（CA 策略变更/自定义 CA/短寿命证书），
// 扫描侧必须再以真实寿命守一道：
//
//   - W ≤ L − 最小节奏：配置可执行，窗口门原样（正常配置零行为变化）；
//   - W > L − 最小节奏：配置在真实寿命下不可执行（按窗口入队会密集重签）→
//     退到保护区，只在到期前 grace 内续签，节奏 L−grace ≥ 最小节奏，既不会
//     每日重签，也不会把续签推迟到到期边界。
//
// 最小节奏取保护区（7 天）；L 不足 14 天时按半寿命收敛，保证收敛值不超过寿命
// 本身。库值不被改写——收敛只作用于本轮扫描，由调用方显性告警。
func certRenewalWindowForLifetime(window, lifetime time.Duration) time.Duration {
	if window <= 0 || lifetime <= 0 {
		return window
	}
	minCadence := certRenewalGuaranteedGrace
	if half := lifetime / 2; half < minCadence {
		minCadence = half
	}
	headroom := lifetime - minCadence
	if window <= headroom {
		return window
	}
	effective := certRenewalGuaranteedGrace
	if effective > headroom {
		effective = headroom
	}
	return effective
}

// certRenewalWindowWarnInterval 限频：同一规则每小时最多一条告警——扫描周期
// 最短 6h，但手动触发/多规则场景不应刷屏。
const certRenewalWindowWarnInterval = time.Hour

// renewalWarnGate 是按规则限频的告警闸门：同一规则的窗口收敛告警每小时最多一条。
type renewalWarnGate struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// due 报告该规则本轮是否允许告警（并记录本次时刻）。
func (g *renewalWarnGate) due(ruleID string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last == nil {
		g.last = make(map[string]time.Time)
	}
	// 窗口判定与过期回收单源在 throttleWarnAllowed（规则名键集有界，保留期
	// 同窗口——本门的历史键只在规则消失前不再刷新，回收避免长期累积）。
	return throttleWarnAllowed(g.last, ruleID, now, certRenewalWindowWarnInterval, certRenewalWindowWarnInterval)
}

var certRenewalWindowWarnGate renewalWarnGate

// warnRenewalWindowNotExecutable 显性留痕「配置窗口在真实寿命下被收敛」——
// 收敛不是静默行为：运维需要知道续签节奏为何与配置不符（库值保持原样）。
func warnRenewalWindowNotExecutable(ruleID string, windowDays int, effective, lifetime time.Duration) {
	if !certRenewalWindowWarnGate.due(ruleID, time.Now()) {
		return
	}
	Logf("warn", "证书规则 %s：续签时间 %d 天在证书实际寿命 %s 下不可执行（按窗口入队会每日/亚日级重签并触发 CA 重复证书限流）；本轮改为到期前 %s 内续签，请把续签时间调小",
		ruleID, windowDays, lifetime.Truncate(time.Hour), effective.Truncate(time.Hour))
}

// scanRenewalCandidates：CheckExpiration 与
// checkFailedFirstIssuance 的同构行扫描体收敛单份——规范域名比对（规则/任务
// 域名不一致跳过该行）+ 已有证书判读（选中证书域名匹配且有效期晚于续期窗口则
// 跳过）+ 行收集。warnPrefix 仅区分 Scan 失败告警的来源扫描
// 「不静默」口径，同 checkManualCertExpiration）。
//
// 逐行 Scan 失败计数返回（scanSkipped），
// 迭代级 rows.Err() 显式上抛——此前两者都只进应用日志甚至完全静默，巡检
// 摘要把失败轮伪装成「无候选」。
func scanRenewalCandidates(ctx context.Context, rows *sql.Rows, days int, warnPrefix string) (jobs []models.CertJob, scanSkipped int, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	window := time.Duration(days) * 24 * time.Hour
	selectedByRule := make(map[string]CertificateSelection)
	selectionLoaded := make(map[string]bool)
	selectionFailed := make(map[string]bool)
	for rows.Next() {
		// 逐行取消检查：候选集在千行规模下逐行做域名规范化 + 逐规则证书选择，
		// 取消只在循环结束才生效等于让导入排空等整轮扫描（见 CheckExpiration）。
		if ctxErr := ctx.Err(); ctxErr != nil {
			return jobs, scanSkipped, fmt.Errorf("%s: %w", warnPrefix, ctxErr)
		}
		var j models.CertJob
		var ruleDomain string
		if err := rows.Scan(
			&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.ExpiresAt, &j.CAProviderID, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode, &ruleDomain,
		); err != nil {
			scanSkipped++
			Logf("warn", "%s: scan failed, skipping row: %v", warnPrefix, err)
			continue
		}
		canonicalRule, ruleErr := CanonicalACMEDomains(ruleDomain)
		canonicalJob, jobErr := CanonicalACMEDomains(j.Domain)
		if ruleErr != nil || jobErr != nil || canonicalRule != canonicalJob {
			continue
		}
		selection, selected := selectedByRule[j.RuleID]
		if selectionFailed[j.RuleID] {
			// 同规则已发生读失败：本轮剩余行一律不进入候选（避免用 selection 零值
			// 误判「没有可用证书」而重复重签），失败已计过一次。
			continue
		}
		if !selectionLoaded[j.RuleID] {
			var err error
			selection, selected, err = selectStoredRuleCertificate(ctx, j.RuleID, ruleDomain, now)
			if err != nil {
				selectionFailed[j.RuleID] = true
				// 与相邻 Scan 失败同口径计数：读失败的行被移出候选集后，
				// 巡检摘要必须体现「有行未扫描」，不得只报「扫描完成：无临期证书」。
				scanSkipped++
				Logf("error", "Failed to select current certificate for rule %s: %v", j.RuleID, err)
				continue
			}
			selectionLoaded[j.RuleID] = true
			if selected {
				selectedByRule[j.RuleID] = selection
			}
		}
		if selected {
			canonicalSelected, selectedErr := CanonicalACMEDomains(selection.Candidate.Domain)
			if selectedErr == nil && canonicalSelected == canonicalRule {
				// 窗口门按证书实际寿命收敛（单源 certRenewalWindowForLifetime）：
				// 配置窗口与真实寿命接近时，原样入队会让相邻两次续签间隔退化到
				// 小时级（每日/亚日级整轮重签 → CA 重复证书限流 → 续签链终止）。
				lifetime := selection.Certificate.NotAfter.Sub(selection.Certificate.NotBefore)
				effective := certRenewalWindowForLifetime(window, lifetime)
				if effective != window {
					warnRenewalWindowNotExecutable(j.RuleID, days, effective, lifetime)
				}
				if selection.Certificate.NotAfter.After(now.Add(effective)) {
					continue
				}
			}
		}
		// 抖动闸门（2026-10-30 裁定）：入队判据 = expires_at − renewalDays −
		// jitter(rule_id) ≤ now（即 expires_at 晚于 now+窗口+自身抖动的行本轮
		// 跳过），各规则的入队时刻按 rule_id 确定性摊开在 6h 区间，不再在窗口
		// 边界扎堆。jitter 单源 certjitter.go（前后端同算法+固定向量表）；前端
		// 「自动重签时间」显示同一时刻。无 expires_at 的行（首次签发重试）旁路。
		// 收敛只发生在 PEM 分支（恒弱于原始窗口），本门不会把已判到期的行拦回。
		if j.ExpiresAt.Valid && j.ExpiresAt.Time.After(now.Add(window).Add(certRenewalJitter(j.RuleID))) {
			continue
		}
		jobs = append(jobs, j)
	}
	// 迭代级错误（连接中断/结果集截断）此前被完全吞掉——显式
	// 上抛让巡检按「扫描失败」终止本轮而非按截断结果集续期。
	if err := rows.Err(); err != nil {
		return jobs, scanSkipped, fmt.Errorf("%s: iterate rows: %w", warnPrefix, err)
	}
	return jobs, scanSkipped, nil
}

// CheckExpiration 返回临期/待重试候选。ctx 由续期巡检的 RunContext 透传并
// 贯穿**整个**装载阶段（查询 + 逐候选证书选择），取消即中止——否则导入排空的
// WaitInFlightRuns 要等最长 6h 的候选装载跑完才返回。
func (s *CertificateService) CheckExpiration(ctx context.Context) ([]models.CertJob, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	// 告警 + 非正回退语义收敛于 GetCertRenewalDays。
	days := GetCertRenewalDays()

	// 历史/导入的 issued + NULL expires_at 也必须进入候选扫描。
	// scanRenewalCandidates 会按 PEM 的真实 NotAfter 跳过仍在窗口外的证书；
	// 临期或材料缺失的行则进入续期，不再因 NULL 永久失联。
	//
	// 预筛窗口按「窗口 + 抖动上界」放宽 +6h（certRenewalJitter，2026-10-30 裁定）：
	// 各规则的入队时刻按 rule_id 确定性提前最多 6h，预筛不放宽会把这些行整轮
	// 排除、抖动沦为死字母；逐行闸门在 scanRenewalCandidates 按各规则自身抖动收敛。
	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.domain, j.status, j.expires_at, COALESCE(j.ca_provider_id,0), COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''),r.domain
		FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE (
			(j.expires_at IS NOT NULL
			 AND datetime(j.expires_at) <= datetime('now', '+' || ? || ' days', '+' || ? || ' seconds')
			 AND j.status IN ('issued', 'failed'))
			OR (j.expires_at IS NULL AND j.status = 'issued')
		  )
		  -- B2 失败语义统一：waiting_ca 退役。failed 行按退避窗口门控——
		  -- 窗口在未来的行（含 429 Retry-After，最长 3h）不进入续期候选，
		  -- 到期（或 NULL=已达上限，仅告警不重排）的行照常选出。
		  AND (j.status != 'failed' OR j.ca_available_after IS NULL OR datetime(j.ca_available_after) <= datetime('now'))
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		ORDER BY j.expires_at ASC
	`, days, certRenewalJitterWindowSeconds)
	if err != nil {
		// 查询失败显式上抛（此前 return nil 被巡检当成「无候选」
		// 并写假成功摘要）。
		Logf("error", "Failed to query expiring certificates: %v", err)
		return nil, 0, fmt.Errorf("query expiring certificates: %w", err)
	}
	defer rows.Close()

	return scanRenewalCandidates(ctx, rows, days, "cert expiration check")
}

const firstIssuanceRetryCooldownMinutes = 30

// checkFailedFirstIssuance 返回首次签发失败（expires_at IS NULL，从未签发成功）、
// 已过冷却期、退避窗口已到期（或 NULL）且未达最大重试次数的证书任务，供续期
// 巡检自动重试。窗口门与 CheckExpiration 的 failed 行门控同口径：窗口仍在未来
// 的行（含 429 Retry-After）不进入候选，否则首发失败行会绕过退避窗口反复撞 CA。
// 规则筛选与已有证书判读逻辑与 CheckExpiration 保持一致。
// 查询/遍历失败显式上抛（同 CheckExpiration），不得吞成「无候选」。
func (s *CertificateService) checkFailedFirstIssuance(ctx context.Context, maxAttempts int) ([]models.CertJob, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	// 告警 + 非正回退语义收敛于 GetCertRenewalDays。
	days := GetCertRenewalDays()

	rows, err := db.DB.QueryContext(ctx, `
		SELECT j.id, j.rule_id, j.domain, j.status, j.expires_at, COALESCE(j.ca_provider_id,0), COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''),r.domain
		FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status = 'failed'
		  AND j.expires_at IS NULL
		  AND COALESCE(j.renewal_attempts,0) < ?
		  AND datetime(COALESCE(j.updated_at,j.created_at)) <= datetime('now', '-' || ? || ' minutes')
		  AND (j.ca_available_after IS NULL OR datetime(j.ca_available_after) <= datetime('now'))
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		ORDER BY j.updated_at ASC
	`, maxAttempts, firstIssuanceRetryCooldownMinutes)
	if err != nil {
		Logf("error", "Failed to query failed first-issuance certificates: %v", err)
		return nil, 0, fmt.Errorf("query failed first-issuance certificates: %w", err)
	}
	defer rows.Close()

	return scanRenewalCandidates(ctx, rows, days, "failed first-issuance check")
}

// selectStoredRuleCertificate 是「规则现有证书选择」的入口（测试缝：var 而非
// 函数声明——注入读失败以验证续期扫描的失败行归因；生产恒为本实现）。
var selectStoredRuleCertificate = func(ctx context.Context, ruleID, ruleDomains string, now time.Time) (CertificateSelection, bool, error) {
	candidates, err := loadCertificateCandidates(ctx, db.DB, ruleID, CertJobMaterialPredicateSQL(""))
	if err != nil {
		return CertificateSelection{}, false, err
	}
	selection, selected := selectCertificate(candidates, ruleDomains, now)
	return selection, selected, nil
}
