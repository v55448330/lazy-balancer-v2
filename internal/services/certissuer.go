package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/retryafter"

	xacme "golang.org/x/crypto/acme"
)

// CertIssuer coordinates ACME certificate issuance: creates/updates cert_jobs,
// runs the ACME flow, persists cert+key to DB, and triggers Caddy reload.
type CertIssuer struct {
	caddyReloader   func() error
	deploymentRetry func(int, issuedCertificate, time.Duration) error
	dataDir         string
}

const maxCertificateDeploymentAttempts = 10

type issuedCertificate struct {
	ruleID            string
	certPEM           string
	keyPEM            string
	notAfter          time.Time
	providerID        int
	deploymentAttempt int
}

type certificateDeploymentError struct {
	err error
}

func (e *certificateDeploymentError) Error() string { return e.err.Error() }
func (e *certificateDeploymentError) Unwrap() error { return e.err }

// certificateRoleError marks post-issuance role confirmation failures. They
// are lifecycle/infrastructure interruptions, not CA failures, and must not
// consume renewal attempts when the queue classifies the returned error.
type certificateRoleError struct {
	err error
}

func (e *certificateRoleError) Error() string { return e.err.Error() }
func (e *certificateRoleError) Unwrap() error { return e.err }

func checkCertificateIssuanceRole(ctx context.Context) error {
	isMaster, err := RoleOf(ctx, db.DB)
	if err != nil {
		return &certificateRoleError{err: fmt.Errorf("读取主从角色失败: %w", err)}
	}
	if !isMaster {
		return &certificateRoleError{err: errors.New("节点已切换为从节点，停止保存签发结果")}
	}
	return nil
}

// CAProviderRateLimitError indicates the CA rejected the request with 429.
type CAProviderRateLimitError struct {
	RetryAfter time.Duration
	Reason     string
}

func (e *CAProviderRateLimitError) Error() string {
	return fmt.Sprintf("CA rate limited (429), retry after %v: %s", e.RetryAfter, e.Reason)
}

// parseRetryAfter parses an HTTP header value into a duration.
//
// 解析实现单源在 internal/retryafter.Parse（与 dnsprovider/internal/retry.After
// 共用同一份代码与同一张测试表）；本函数只保留包内调用点与 now=time.Now()
// 的绑定。语义（delay-seconds/HTTP-date、不可解析或非正归零）以该包为准，
// 任一侧不再各自维护副本。
func parseRetryAfter(header string) time.Duration {
	return retryafter.Parse(header, time.Now())
}

// computeBackoff returns the cooling duration based on attempt count and CA.
// CA 提示分支与自有阶梯同封顶 3h——超大
// 提示值不再令冷却期越过证书过期点(attempts 停 1,maxAttempts 升级兜底
// 永不触发的形态闭合)。
func computeBackoff(attempts int, retryAfter time.Duration) time.Duration {
	const maxBackoff = 3 * time.Hour
	if retryAfter > 0 {
		return min(retryAfter, maxBackoff)
	}
	switch attempts {
	case 1:
		return time.Hour
	case 2:
		return 2 * time.Hour
	default:
		return 3 * time.Hour
	}
}

// NewCertIssuer creates a new CertIssuer. The reloader is called after a
// certificate is successfully issued so Caddy picks up the new cert.
// reloader 契约：全部调用点都在部署临界区内、已持
// CaddyOpLock（锁序 CaddyOpLock → DeployLock）——必须注入 InLock 变体
// （生产=GenerateAndApplyConfigForceInLock，cmd/server/main.go）；注入自取
// CaddyOpLock 的 Force 变体即重入死锁（非可重入锁）。nil=跳过重载。
func NewCertIssuer(reloader func() error, dataDir ...string) *CertIssuer {
	issuer := &CertIssuer{caddyReloader: reloader, deploymentRetry: scheduleCertificateDeploymentRetry}
	if len(dataDir) > 0 {
		issuer.dataDir = dataDir[0]
	}
	return issuer
}

// scheduleCertificateDeploymentRetry 是包级部署重试调度入口。返回值即「本轮
// 是否登记了 timer」：暂停/停止/规则补偿屏障都会使它为非 nil，
// 调用方（补扫、恢复链）据此如实计数与留痕，不再把未调度谎报成部署重建。
func scheduleCertificateDeploymentRetry(jobID int, material issuedCertificate, delay time.Duration) error {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		Logf("warn", "certificate deployment retry skipped for job %d: certificate service is not initialized", jobID)
		return ErrCertificateQueueInactive
	}
	if err := service.deploymentRetrySchedulable(material.ruleID); err != nil {
		return err
	}
	return service.scheduleDeploymentRetry(jobID, material.ruleID, delay)
}

func signalCancelCertificateDeploymentRetriesForRule(ruleID string) []<-chan struct{} {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		return service.signalCancelDeploymentRetriesForRule(ruleID)
	}
	return nil
}

func cancelCertificateDeploymentRetry(jobID int) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.cancelDeploymentRetry(jobID)
	}
}

func pauseCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.pauseDeploymentRetries()
	}
}

func resumeCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.resumeDeploymentRetries()
	}
}

// rescanDroppedCertificateDeploymentRetries 触发证书服务补扫被规则阻塞丢弃的
// 部署重试；供 caqueue 解锁后调用，与 resumeCertificateDeploymentRetries 同走
// 全局函数通道（避免服务层互相直接持有）。
func rescanDroppedCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.rescanDroppedDeploymentRetries()
	}
}

// ErrCertificateDeploymentRetryBusy marks a manual retry refused because an
// earlier deployment callback for the same job is still unwinding; the service
// is running and reporting it as "stopped" would misdiagnose the condition.
var ErrCertificateDeploymentRetryBusy = errors.New("证书部署重试回调仍在退出中")

// RetryCertificateDeploymentNow 手动重试入口：把 downloaded
// 任务的部署重试立即重排（取消挂起的退避 timer 并在当前时刻执行一次部署）。
// 返回 nil 表示 timer 已登记；服务停止返回 ErrCertificateQueueInactive，旧回调
// 未退出返回 ErrCertificateDeploymentRetryBusy，规则处于补偿屏障返回
// ErrCertificateDeploymentRetryBlocked。deployment_available_after
// 已由调用方推到 now，启动恢复/周期补扫仍会接手，不会丢失。
func RetryCertificateDeploymentNow(jobID int, ruleID string) error {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		Logf("warn", "证书服务未运行：任务 %d 的部署重试将在服务启动/补扫时执行", jobID)
		return ErrCertificateQueueInactive
	}
	// 与包级调度入口/30s 补扫同一判据：规则补偿屏障期（删除/更新/禁用的补偿
	// 租约内）一律不登记部署 timer，否则手动「立即部署」会破例空转一次，
	// 与「屏障期不调度」的不变量分叉。
	if err := service.deploymentRetrySchedulable(ruleID); err != nil {
		return err
	}
	return service.scheduleDeploymentRetry(jobID, ruleID, 0)
}

// certIssuedByOtherCA 报告已签发证书是否**明确**来自另一个已知 CA 厂商。
// 只对两个内置厂商（Let's Encrypt / ZeroSSL）做正向识别，其余一律返回 false：
// 快速路径宁可持续重部署一张仍然有效的旧证书，也不因 issuer 文案差异
// （中间证书改名、自建 CA、代理 CA）白白消耗一次签发配额。
func certIssuedByOtherCA(certPEM, providerType string) bool {
	if strings.TrimSpace(certPEM) == "" {
		return false
	}
	leaf, err := parseCertificateLeaf(certPEM)
	if err != nil || leaf == nil {
		return false
	}
	// issuer Organization + CommonName 一起看：Let's Encrypt 的中间证书以两位
	// 字母加编号的代号命名（不同年份换代），厂商归属只在 Organization 里
	// （"Let's Encrypt"）；ZeroSSL 同列（"ZeroSSL"）。小写后子串匹配，避免
	// 文案大小写/空格差异。
	issuer := strings.ToLower(strings.Join(append(append([]string{}, leaf.Issuer.Organization...), leaf.Issuer.CommonName), " "))
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case ProviderLetsEncrypt:
		return strings.Contains(issuer, "zerossl")
	case ProviderZeroSSL:
		return strings.Contains(issuer, "let's encrypt") || strings.Contains(issuer, "isrg")
	default:
		return false
	}
}

func retryCertificateDeployment(ctx context.Context, jobID int, reloader func() error) error {
	var material issuedCertificate
	var expiresAt sql.NullTime
	// 部署重试须接受与 confirmCertificateDeployment 相同的可部署状态集：启动恢复把
	// cleanup_dns/cleanup_warning 任务调度到这里，若只收 'downloaded' 会因定时器静默
	// 吞掉 ErrNoRows 而永久卡死；放宽后重试循环才能推进（成功→issued，反复失败→failed）。
	if err := db.DB.QueryRowContext(ctx, `SELECT rule_id, COALESCE(cert_pem,''), COALESCE(key_pem,''), expires_at,
		COALESCE(ca_provider_id,0), COALESCE(deployment_attempts,0)
		FROM cert_jobs WHERE id=? AND status IN (`+DeploymentLifecycleJobStatusSQL+`)`, jobID).Scan(
		&material.ruleID, &material.certPEM, &material.keyPEM, &expiresAt,
		&material.providerID, &material.deploymentAttempt,
	); err != nil {
		return fmt.Errorf("load downloaded certificate for deployment: %w", err)
	}
	material.notAfter = expiresAt.Time
	if !expiresAt.Valid {
		// 旧备份/导入可能携带 downloaded + 证书材料但 expires_at=NULL。
		// 从 PEM 恢复唯一权威有效期；成功部署会随材料回写该列，后续续期可见。
		notAfter, err := parseCertNotAfter(material.certPEM)
		if err != nil {
			return fmt.Errorf("load downloaded certificate expiry from PEM: %w", err)
		}
		material.notAfter = notAfter
	}
	manager := GetCAQueueManager()
	if manager != nil && manager.IsRuleBlocked(material.ruleID) {
		return context.Canceled
	}
	return NewCertIssuer(reloader).deployIssuedCertificate(ctx, jobID, material)
}

// deploymentFailureWriteback 是部署失败状态回写的测试缝（默认 transitionJob），
// 用于覆盖「状态回写本身失败」的形态。
var deploymentFailureWriteback = transitionJob

// deploymentPersistenceWriteback 是部署前置「材料落库 + 状态转 downloaded」写入的
// 测试缝（默认 transitionJob），用于覆盖 CAS 冲突的两类归因：并发胜者已提交终态
// （材料陈旧、保持 raw）与自身进度写丢失（行仍非终态、必须落材料并登记重试）。
var deploymentPersistenceWriteback = transitionJob

// deploymentFailureFromStatuses 返回部署失败回写允许的源状态集合：常规部署链为
// deploymentPersistenceJobStatuses（部署生命周期 + downloading）——后者覆盖
// 「downloaded 进度写因瞬时 DB 故障未落库、行仍停在 downloading」的形态，否则
// 首查 0 行提前返回会让刚签发的材料只存在内存、任务滞留 active 且无周期通道；
// 快速重部署链额外允许 issued——该链先以 issued→downloaded 的进度写进入部署生命
// 周期，若这次进度写本身因瞬时 DB 故障未落库，失败回写若仍拒绝 issued 就只剩
// WARN，行会停在 issued 而磁盘是旧材料（文件对账只补缺失文件、不比对内容），
// 只有重启/升主才能收敛。
func deploymentFailureFromStatuses(includeIssued bool) []string {
	if !includeIssued {
		return deploymentPersistenceJobStatuses
	}
	statuses := make([]string, 0, len(deploymentPersistenceJobStatuses)+1)
	statuses = append(statuses, deploymentPersistenceJobStatuses...)
	statuses = append(statuses, "issued")
	return statuses
}

// advanceCertificateDeploymentWindow 在状态回写失败后独立推进部署重试的簿记列
// （message/attempts/窗口），不依赖状态 CAS：30s 补扫的 downloaded 分支只收
// 非 NULL 窗口，窗口停在 NULL 会让该行失去全部周期通道，直到进程重启/升主。
// 状态谓词固定为部署生命周期（不含 issued）：补扫只收 downloaded/cleanup_*，
// 对 issued 行写簿记既不会被任何通道消费，还会让并发胜者已提交的成功任务
// 背上「部署失败」文案。
func advanceCertificateDeploymentWindow(jobID, attempt int, message, availableAfter string) {
	if db.DB == nil {
		return
	}
	from := deploymentLifecycleJobStatuses
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	args := []any{message, attempt, availableAfter, jobID}
	for _, status := range from {
		args = append(args, status)
	}
	if _, err := db.DB.Exec("UPDATE cert_jobs SET message=?, deployment_attempts=?, deployment_available_after=?, updated_at=datetime('now') WHERE id=? AND status IN ("+placeholders+")", args...); err != nil {
		Logf("warn", "cert job %d: advance deployment retry window failed (补扫/重启恢复接管): %v", jobID, err)
	}
}

func (s *CertIssuer) deploymentFailed(jobID int, material issuedCertificate, message string, err error) error {
	return s.deploymentFailedFrom(jobID, material, message, err, deploymentFailureFromStatuses(false))
}

func (s *CertIssuer) deploymentFailedFrom(jobID int, material issuedCertificate, message string, err error, from []string) error {
	var previousAttempt int
	// 使用 QueryRowContext 以响应 worker 取消信号（此处函数无 ctx，用 Background 兜底）。
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	args := []any{jobID}
	for _, status := range from {
		args = append(args, status)
	}
	if queryErr := db.DB.QueryRowContext(context.Background(), "SELECT COALESCE(deployment_attempts,0) FROM cert_jobs WHERE id=? AND status IN ("+placeholders+")", args...).Scan(&previousAttempt); queryErr != nil {
		// 0 行=行已不存在，或状态不在可回写集合（终态 issued/failed/disabled 由
		// 并发胜者推进；queued/waiting_ca 由队列/CA 退避链维护）：本回调材料已无
		// 归属，保持 raw 返回。留一个显式磁盘日志行——此前该分支静默返回，
		// certjob-*.log 里完全看不到「部署失败但无处回写」的痕迹。
		WriteCertJobLog(jobID, "ERROR", "deployment_failed_no_row",
			fmt.Sprintf("部署失败但任务不在可回写状态（材料未落库，状态由其他链路维护/行已不存在）: %v", err))
		return &certificateDeploymentError{err: errors.Join(err, queryErr)}
	}
	if material.deploymentAttempt > previousAttempt {
		previousAttempt = material.deploymentAttempt
	}
	attempt := previousAttempt + 1
	// 封顶后不落 failed 终态。写文件/reload 连续失败时材料已在库、
	// expires_at 已前进；failed 会把任务从全部自动通道摘除（部署重试只收
	// downloaded/cleanup_*、启动恢复对 JobIsTerminal 直接 continue、文件对账
	// 只重建 issued/downloaded），而续期扫描按已前进的 expires_at 跳过 →
	// 旧证书到期后 TLS 长时间中断（DB 报新证有效）。保留可部署态并放慢为
	// 30 分钟慢速重试：磁盘/权限/重载恢复后自动收敛，材料不丢、不重签。
	const blockedDeploymentRetryDelay = 30 * time.Minute
	delay := certificateDeploymentBackoff(attempt)
	capped := attempt >= maxCertificateDeploymentAttempts
	if capped {
		delay = blockedDeploymentRetryDelay
	}
	storedMessage := fmt.Sprintf("部署失败 [attempt=%d/%d]: %s", displayDeploymentAttempt(attempt), maxCertificateDeploymentAttempts, message)
	if capped {
		storedMessage += fmt.Sprintf("；证书材料已保留，转入 %d 分钟慢速重试（磁盘/重载恢复后自动收敛）", int(blockedDeploymentRetryDelay.Minutes()))
	}
	storedMessage = truncateJobMessage(storedMessage)
	availableAfter := time.Now().UTC().Add(delay).Format("2006-01-02 15:04:05")
	// 材料随失败落库——首签发 confirm/persist 瞬时
	// 失败改走本重试链时,材料仅在内存;不落库则任务回 downloaded 但
	// 补扫 hasCertMaterial=0 跳过,永久不可达只能重签烧 CA 配额。
	// 已持久化场景(材料来自库读)同值重写,幂等无害。
	fields := map[string]any{
		"message":                    storedMessage,
		"deployment_attempts":        attempt,
		"deployment_available_after": availableAfter,
	}
	if material.certPEM != "" {
		fields["cert_pem"] = material.certPEM
		fields["key_pem"] = material.keyPEM
		fields["expires_at"] = CanonicalDatetimeValue(material.notAfter)
		fields["ca_provider_id"] = material.providerID
	}
	updateErr := deploymentFailureWriteback(db.DB, jobID, from, "downloaded", fields)
	// 部署失败必须落 certjob-*.log（此前部署链零 WriteCertJobLog，
	// 磁盘日志只剩签发阶段，排障需反查 DB）。ERROR 行业务行恒写；状态回写失败
	// （CAS 冲突/DB 故障）补 WARN 行，且不改变部署失败语义与签发结果。
	WriteCertJobLog(jobID, "ERROR", "deployment_failed", storedMessage)
	if updateErr != nil {
		Logf("warn", "cert job %d deployment status writeback failed (status=downloaded, attempt=%d): %v", jobID, attempt, updateErr)
		WriteCertJobLog(jobID, "WARN", "deployment_status_update_failed", fmt.Sprintf("部署失败状态回写失败 [attempt=%d/%d]: %v", displayDeploymentAttempt(attempt), maxCertificateDeploymentAttempts, updateErr))
		// 状态回写失败不得让窗口列停在 NULL：补扫只收非 NULL 窗口，独立簿记
		// UPDATE（无状态 CAS）让周期通道仍然可达。
		advanceCertificateDeploymentWindow(jobID, attempt, storedMessage, availableAfter)
		RecordAuditLog("system", "部署失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("status_writeback_failed")), "")
	}
	// 内存重试调度与 DB 状态解耦：状态回写失败也必须登记 timer——回调会重读
	// 行状态，行已被并发胜者推进到 issued 时 SELECT 不到而自然 no-op，不会
	// 重复部署；反之只有 WARN 不留 timer 时该行再无任何周期通道。
	if s.deploymentRetry != nil {
		material.deploymentAttempt = attempt
		// 异步再调度。此处常在部署回调 goroutine 内被同步调用——
		// 若同步进入 scheduleDeploymentRetry，会命中 的在途回调
		// 等待分支，等待对象恰是自己（done 只在本回调的 defer 关闭）→ 同
		// goroutine 自锁，重试链永久断裂并毒化 Resume/导入/启动恢复。起独立
		// goroutine 后等待变为跨 goroutine（回调返回即 done 关闭），「同
		// jobID 永不并发部署」不变量由该等待继续保证。
		go func() {
			if err := s.deploymentRetry(jobID, material, delay); err != nil {
				// 暂停/屏障期未登记由 Resume/解锁补扫接管（deployment_available_after
				// 已落库），其余错误必须留痕，避免重试链静默断裂。
				if !errors.Is(err, ErrCertificateQueueInactive) && !errors.Is(err, ErrCertificateDeploymentRetryBlocked) {
					Logf("warn", "证书任务 %d：部署失败后的重试登记失败（补扫接管）: %v", jobID, err)
				}
			}
		}()
	}
	if updateErr == nil && attempt == maxCertificateDeploymentAttempts {
		// 封顶只留一条审计（后续每 30 分钟慢速重试不再刷屏）；结果码说明
		// 任务未终态、材料保留。
		RecordAuditLog("system", "部署失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("slow_retry")), "")
	}
	return &certificateDeploymentError{err: errors.Join(err, updateErr)}
}

// displayDeploymentAttempt 钳制展示用的尝试次数：封顶后计数器仍随 30 分钟
// 慢速重试累加（落库计数保留真实值，重试链需要它），但 `[attempt=57/10]`
// 会让用户误以为「超出配额却仍在重试」。展示值不超过上限。
func displayDeploymentAttempt(attempt int) int {
	return min(attempt, maxCertificateDeploymentAttempts)
}

func certificateDeploymentBackoff(attempt int) time.Duration {
	// 阶梯 = 1s×2^(attempt-1)，循环守卫为「当前值 < 5min 才继续加倍」——所以
	// 上限不是 5min 而是 512s：attempt 9 = 256s、attempt 10 起 = 512s（8.5min），
	// 由 TestCertificateDeploymentBackoff_ladderUpperBound 钉住实测值。
	// 与 30min 慢速重试（blockedDeploymentRetryDelay，重试预算用尽后接管）之间
	// 存在 8.5min → 30min 的间隔断层：这是有意的（快速重试段覆盖「磁盘/重载
	// 短暂故障」，超预算段只做低频收敛，避免长期故障反复重载 Caddy）。
	// 原实现在循环后还有一道 `> 5min → 5min` 钳制：调用方在 attempt≥
	// maxCertificateDeploymentAttempts 时已改用 30min 慢速重试，钳制对全部
	// 可达输入都不可达（死代码），删除。
	delay := time.Second
	for i := 1; i < attempt && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	return delay
}

// jobLogger writes issuance progress to cert job log files and updates cert_jobs.status.
// from 是进度迁移的允许源态集合：主签发路径为 nonTerminalJobStatuses——
// 「终态不可逆」不能只靠队列在途+部署 CAS 运行时保证，进度写点必须有静态防线
// （并发部署回调先把行提交为 issued 时，进度日志不得把它拉回 in-flight）。
// 快速重部署路径（redeployDownloadedInLock）需要 issued→downloaded，构造时
// 显式换 {issued,downloaded} 白名单。
type jobLogger struct {
	jobID  int
	ruleID string
	file   *CertJobFileLogger
	from   []string
}

func (l *jobLogger) Log(stage, message string) {
	l.file.Log(stage, message)
	message = truncateJobMessage(message)
	from := l.from
	if len(from) == 0 {
		from = nonTerminalJobStatuses
	}
	if err := transitionJob(db.DB, l.jobID, from, stage, map[string]any{"message": message}); err != nil {
		Logf("error", "cert job %d status update failed: %v", l.jobID, err)
	}
}

// LogFileOnly 只写任务日志文件，不改 cert_jobs 行状态（签发错误路径
// 的 defer DNS 清理块使用——失败行被推进到 cleanup_dns（Downloaded 生命周期）
// 会被「材料在身部署生命周期」判据误判为部署失败折回 issued）。实现
// acme.FileOnlyLogger 可选接口。
func (l *jobLogger) LogFileOnly(stage, message string) {
	l.file.Log(stage, message)
}

// Issue obtains a certificate for the given rule and domains using the
// provided CA provider. The caller (queue manager) must pass a valid jobID.
func (s *CertIssuer) Issue(ctx context.Context, jobID int, ruleID, domains string, provider models.CAProvider) error {
	if jobID <= 0 {
		return fmt.Errorf("invalid job ID: %d", jobID)
	}

	domainList := normalizeAndValidateDomains(domains)
	if domainList == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}
	for _, domain := range domainList {
		if !isValidACMEIssuanceDomain(domain) {
			return fmt.Errorf("ACME证书域名不符合公共 CA 签发要求（仅小写字母/数字/连字符标签，且至少两级）: %s", domain)
		}
	}

	logger := &jobLogger{jobID: jobID, ruleID: ruleID, file: NewCertJobFileLogger(ruleID)}

	// Fast path: a previous attempt completed ACME issuance and persisted a
	// valid certificate, but file deployment failed. Redeploy instead of
	// re-issuing through the CA. Skipped when the job is disabled, the rule is
	// disabled, or the certificate was issued by a different CA vendor than the
	// rule's current provider (then a fresh issuance is required).
	// 判据分两段：①解析后的 provider id 相等（规则与任务两侧的 0 先归一）；
	// ②证书 issuer 与当前 provider 类型不矛盾。②覆盖「同一 provider 行改类型
	// （letsencrypt↔zerossl，id 不变、不触碰 cert_jobs）」——只比 id 时这种
	// 切换不会被发现，会把旧厂商证书直接重部署；issuer 无法识别（自建 CA/
	// 解析失败/未知类型）时按「不矛盾」处理，避免因识别不确定性白烧 CA 订单。
	var jobStatus string
	var jobProviderID int
	var deploymentAttempt int
	var ruleEnabled bool
	var ruleProviderID int
	var jobDomain, ruleDomain string
	// 使用 QueryRowContext 以响应 worker 取消信号。首查故障必须与「行不存在」
	// 区分（见下）：瞬时 DB 故障静默回落完整签发会白烧 CA 订单/DNS 写入。
	jobStateErr := issueJobStateQuery(ctx, jobID, &jobStatus, &jobProviderID, &deploymentAttempt, &ruleEnabled, &ruleProviderID, &jobDomain, &ruleDomain)
	if jobStateErr != nil && !errors.Is(jobStateErr, sql.ErrNoRows) {
		// 与下方材料读失败分支同口径：保持现态、不重签，由 30s 补扫 /
		// 6h 对账重读接管（返回部署类错误——handleQueueExecutionError 不改写状态）。
		Logf("error", "证书任务 %d：读取任务状态失败，保持现态不重签（由补扫/对账接管）: %v", jobID, jobStateErr)
		WriteCertJobLog(jobID, "WARN", "job_state_read_failed", "读取证书任务状态失败（保持现态，不重新签发）: "+jobStateErr.Error())
		return &certificateDeploymentError{err: fmt.Errorf("read certificate job state: %w", jobStateErr)}
	}
	if jobStateErr == nil &&
		(jobStatus == "issued" || jobStatus == "downloaded") && ruleEnabled {
		// 域名适用性：规则改域后旧行的 domain 是当时集合的快照。这类「不适用
		// 却带材料」的行若继续走快速路径，confirmCertificateDeployment 会以
		// 「域名不再匹配」失败 → failJob 对 downloaded+材料保留部署态 → 30s
		// 补扫再调度，形成最长约 6h 的无效部署重试，并占住规则的新签发（补建
		// 要求无任何非 disabled 行）。
		// 这是**并发兜底**：主改域路径由 UpdateRule 先退役旧域任务
		// （retireCertJobsForDomain），残留形态再由 6h 对账 sweepOrphanedCertJobs
		// 收口；本分支只处理「任务入队后被并发推进到 issued/downloaded」的
		// 窗口内形态——不得据此认为改域自愈已在此收口。
		if !certJobRuleApplicable(true, ruleDomain, jobDomain) {
			Logf("warn", "证书任务 %d：任务域名 %q 与规则 %s 当前域名 %q 不匹配，退役旧任务并补建新任务", jobID, jobDomain, ruleID, ruleDomain)
			// 走 approved 状态写入口（CAS from=issued/downloaded）；并发流转
			// （如 worker 已推进）不阻断补建尝试。
			retireErr := transitionJob(db.DB, jobID, []string{"issued", "downloaded"}, "disabled", map[string]any{"message": "规则域名已变更，旧任务不再适用"})
			if retireErr != nil && !errors.Is(retireErr, ErrJobTransitionConflict) {
				Logf("error", "证书任务 %d：退役域名不匹配的旧任务失败: %v", jobID, retireErr)
				return fmt.Errorf("disable stale certificate job: %w", retireErr)
			}
			if retireErr != nil {
				Logf("warn", "证书任务 %d：退役时状态已被并发流转（%v），按现状继续补建", jobID, retireErr)
			} else {
				// 用户可见状态变化（issued/downloaded→disabled）必须进操作审计：
				// sweep 与材料丢失重排同族都有审计行，本分支此前只有 warn 日志。
				// 并发流转（CAS 落败）未由本执行改态，不记审计。
				RecordAuditLog("system", "禁用", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(ruleID), AuditSourcePart("domain_mismatch")), "")
			}
			if _, backfillErr := BackfillMissingACMECertJobs(ctx, GetCAQueueManager()); backfillErr != nil {
				Logf("warn", "证书任务 %d：域名不匹配旧任务退役后补建失败（对账/重启接管）: %v", jobID, backfillErr)
			}
			return nil
		}
		existingCert, existingKey, materialErr := readFastPathIssuedMaterial(ctx, jobID)
		if materialErr != nil && !errors.Is(materialErr, sql.ErrNoRows) {
			// 读失败（瞬时 DB 故障）不得静默回落完整签发：静默会白烧一张新 CA
			// 订单，而库里材料可能完好。两条接管通道按当前状态分流：
			//   - downloaded/cleanup_*：按部署重试语义收敛（deploymentFailed 的
			//     from 集合），任务保持部署生命周期 + 退避窗口，补扫/重启接管重读。
			//   - issued：已部署完成，不在 deploymentFailed 的 from 集合——走该链
			//     必然 CAS 失败且留下「部署失败状态回写失败」噪音，日志还谎称
			//     「转部署重试」。保持 issued（不重签、不改状态），如实说明由
			//     文件对账/续期扫描接管，返回部署类错误让队列不改写状态。
			// 行不存在（ErrNoRows）维持既有回落语义（外层首查已存在性，此处
			// 只覆盖并发删除窗口）。
			if jobStatus == "issued" {
				Logf("warn", "证书任务 %d：已签发任务的材料读取失败，保持 issued 不重签（由文件对账/续期扫描接管）: %v", jobID, materialErr)
				WriteCertJobLog(jobID, "WARN", "issued_material_read_failed", "读取已签发证书材料失败（保持 issued，由文件对账接管）: "+materialErr.Error())
				return &certificateDeploymentError{err: fmt.Errorf("read issued certificate material: %w", materialErr)}
			}
			Logf("warn", "证书任务 %d：快速路径读取已签发材料失败，转部署重试（不重签）: %v", jobID, materialErr)
			material := issuedCertificate{ruleID: ruleID, providerID: jobProviderID, deploymentAttempt: deploymentAttempt}
			return s.deploymentFailed(jobID, material, "读取已签发证书材料失败: "+materialErr.Error(), fmt.Errorf("read issued certificate material: %w", materialErr))
		}
		if materialErr == nil && existingCert != "" && existingKey != "" {
			// 告警 + 非正回退语义收敛于 GetCertRenewalDays。
			renewalDays := GetCertRenewalDays()
			if notAfter, perr := parseCertNotAfter(existingCert); perr == nil && time.Until(notAfter) > time.Duration(renewalDays)*24*time.Hour {
				// 规则/任务两侧的 ca_provider_id=0 都表示「跟随默认」：任务行在
				// 补偿重排队、导入回插、集群恢复等通道可能仍是 0（正常签发会把
				// 解析结果写回），此时不能拿 0 与规则侧解析出的具体 ID 直接比较
				// 而误判为"提供商已切换"——否则本应只重部署的任务会走完整 ACME
				// 重签，白烧一次 CA 订单与 DNS 挑战。两侧都经同一默认解析后比较。
				resolvedRuleProvider, resolveErr := ResolveCAProviderID(ruleProviderID)
				resolvedJobProvider := jobProviderID
				if resolveErr == nil && resolvedJobProvider == 0 {
					resolvedJobProvider, resolveErr = ResolveCAProviderID(resolvedJobProvider)
				}
				if resolveErr == nil && resolvedRuleProvider == resolvedJobProvider &&
					!certIssuedByOtherCA(existingCert, provider.Provider) {
					material := issuedCertificate{ruleID: ruleID, certPEM: existingCert, keyPEM: existingKey, notAfter: notAfter, providerID: jobProviderID, deploymentAttempt: deploymentAttempt}
					return s.redeployDownloadedInLock(ctx, jobID, material, logger)
				}
			}
		}
	}

	// check: verify the CA provider is reachable before starting the
	// real issuance flow. If the CA is down (e.g. ZeroSSL 504), fail fast and
	// let the retry scheduler handle the next attempt.
	// 预检（testCAProvider）内含 ZeroSSL EAB 自动获取（10s 界、持久化）与
	// 账户注册验证，返回的 client 携带 EAB 且账户已注册（KID 已缓存）——
	// 下方签发直接复用，Issuer 跳过重复注册（本路径此前自带
	// AutoProvisionZeroSSLEAB + 预检内再 provision + 预检/签发各注册一次，
	// 每次签发 EAB 双调用、ACME 账户双注册）。
	logger.Log("creating_account", fmt.Sprintf("测试 CA 提供商 %s (%s) 连通性", provider.Name, provider.Provider))
	preCheckedClient, err := NewCAProviderService(s.dataDir).testCAProvider(ctx, provider.ID)
	if err != nil {
		// CA 返回 429 时进入限流冷却（waiting_ca），与签发阶段的限流处理保持一致
		if raErr := detectRateLimit(err); raErr != nil {
			return raErr
		}
		// 队列暂停/节点 drain 取消在途执行：不得把取消写成终态 failed——
		// 外层 handleExecutionCancellation 会 requeue；先 failJob 会让终态无法回退。
		if ctx.Err() != nil {
			return fmt.Errorf("CA provider test canceled: %w", err)
		}
		// （复核修正）：审计报告称 from=creating_account 恒不命中，
		// 但上方 logger.Log("creating_account", …) 已先行迁移状态（from=全部
		// 非 disabled），原 CAS 实际可命中——报告前提证伪。改用 failJob（from=
		// 全部非终态）作为防御：若 logger.Log 的状态迁移因瞬时 DB 错误未落库，
		// 精确归因仍能写入，不被 execute 兜底的泛化文案覆盖。
		// 签发未开始，本次执行零新材料产出。
		failJob(jobID, fmt.Sprintf("CA 提供商测试失败: %v", err), false)
		return fmt.Errorf("CA provider test failed: %w", err)
	}
	logger.Log("creating_account", "CA 提供商测试通过")

	// Reset the existing job row (queue manager already created/reused it).
	// from 集合不含终态——终态不可逆由写点静态保证，不只靠队列在途+CAS 运行时序。
	if err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "creating_account", map[string]any{"message": "开始申请证书"}); err != nil {
		return fmt.Errorf("update cert job status: %w", err)
	}

	// Resolve ACME config for the rule.
	var acmeConfigID int
	// 使用 QueryRowContext 以响应 worker 取消信号。
	err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&acmeConfigID)
	if err != nil {
		failJob(jobID, "读取规则 ACME 配置失败", false)
		return fmt.Errorf("read rule acme config: %w", err)
	}

	// ACME 邮箱由预检（phase=email）保证已配置——本路径不再重复读取/校验。

	// Load DNS credentials from the rule's selected provider.
	// enabled 的 NULL 语义与展示/编辑基线同源（COALESCE→启用）：列表
	// （COALESCE(enabled,1)）与规则绑定门都把 NULL 视为启用，签发侧若按
	// enabled=1 判则同一行「显示启用但不可签发」，且 UI 无法一键纠正
	// （开关原值即启用时保存不写列，NULL 永久保留）。
	var dnsCredentialsJSON string
	if acmeConfigID > 0 {
		err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=? AND COALESCE(enabled,1)=1", acmeConfigID).Scan(&dnsCredentialsJSON)
		if err != nil && err != sql.ErrNoRows {
			failJob(jobID, "读取 DNS 凭证配置失败", false)
			return fmt.Errorf("read certificate config: %w", err)
		}
	}
	if dnsCredentialsJSON == "" {
		failJob(jobID, "未选择可用的 DNS 提供商，请先在规则中选择 DNS 凭证", false)
		return fmt.Errorf("no enabled DNS provider selected for rule")
	}

	dnsProvider, err := dnsprovider.NewPersistentProviderFromCredentials(dnsCredentialsJSON, s.dataDir)
	if err != nil {
		failJob(jobID, err.Error(), false)
		return err
	}

	// ACME client 复用预检产物（已注册、KID 已缓存；ZeroSSL EAB 已随预检
	// provision 进 DB 并重载进 client）——不再新建 client 二次注册。
	// acmeEmail 已由预检保证非空（phase=email 先行拒绝）。
	issuer := &acme.Issuer{
		Client:               preCheckedClient,
		Provider:             dnsProvider,
		Logger:               logger,
		RequireRecursiveDNS:  provider.Provider == "zerossl",
		AccountPreRegistered: true,
	}

	// Run the ACME issuance flow
	certPEM, keyPEM, err := issuer.Issue(ctx, domainList)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("certificate issuance canceled: %w", ctx.Err())
		}
		if raErr := detectRateLimit(err); raErr != nil {
			return raErr
		}
		// 此处不再 failJob——错误原样上抛，由队列出口
		// handleQueueExecutionError 统一落 failed（双重 failJob 会让
		// renewal_attempts/窗口/审计各写两遍；首个 CAS 写胜出后第二个
		// 只会静默冲突）。「本次执行零新材料产出」的失败归因也在那里
		// （failJob producedNewMaterial=false）。
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("certificate issuance cancelled: %w", err)
	}

	// Parse certificate expiry
	notAfter, err := parseCertNotAfter(certPEM)
	if err != nil {
		failJob(jobID, err.Error(), false)
		return err
	}
	// 区分 DB 错误与角色变化，避免误报"节点切换为从节点"。
	if err := checkCertificateIssuanceRole(ctx); err != nil {
		return err
	}

	if err := s.deployIssuedCertificate(ctx, jobID, issuedCertificate{
		ruleID: ruleID, certPEM: certPEM, keyPEM: keyPEM,
		notAfter: notAfter, providerID: provider.ID,
	}); err != nil {
		return err
	}

	RecordAuditLog("system", "签发成功", "证书任务", fmt.Sprintf("规则 %s 证书签发成功，过期时间 %s", ruleID, notAfter.Format("2006-01-02")), "")
	return nil
}

// issueJobStateQuery 是 Issue 首查（任务状态 + 规则适用性快照）的测试缝：
// 注入瞬时读故障，钉住「首查失败不得静默回落完整签发」的分流（与
// readFastPathIssuedMaterial 同型）。行不存在返回 sql.ErrNoRows，调用方回落
// 既有的完整签发语义。
var issueJobStateQuery = func(ctx context.Context, jobID int, dest ...any) error {
	return db.DB.QueryRowContext(ctx, `SELECT j.status, COALESCE(j.ca_provider_id,0), COALESCE(j.deployment_attempts,0), COALESCE(r.enabled,0), COALESCE(r.ca_provider_id,0), COALESCE(j.domain,''), COALESCE(r.domain,'')
		FROM cert_jobs j LEFT JOIN lb_rules r ON r.caddy_id = j.rule_id WHERE j.id = ?`, jobID).
		Scan(dest...)
}

// readFastPathIssuedMaterial 读取快速路径复用的已签发材料（测试缝：var 而非
// 直接内联查询——注入读故障钉「读失败不得静默落全签」分支）。行不存在返回
// sql.ErrNoRows，调用方维持既有回落语义。
var readFastPathIssuedMaterial = func(ctx context.Context, jobID int) (certPEM, keyPEM string, err error) {
	err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id=?", jobID).Scan(&certPEM, &keyPEM)
	return certPEM, keyPEM, err
}

// redeployDownloadedInLock 在 CaddyOpLock → DeployLock 临界区内用库里已签发
// 材料重建部署（快速路径主体）。锁的获取/释放收敛在本 helper，作用域显式化：
// 调用方不得再取锁，临界区内的重载回调必须走 InLock 变体（见下方锁序注释）。
func (s *CertIssuer) redeployDownloadedInLock(ctx context.Context, jobID int, material issuedCertificate, logger *jobLogger) error {
	// 锁序：CaddyOpLock → DeployLock。恢复链
	//（UpdateRule/EnableRule 补偿全程持 caddyOpMu=CaddyOpLock →
	// RestoreCertJobsForRule 取 DeployLock）按此序持锁；旧序
	// DeployLock→（reloader 内）CaddyOpLock 与其双向互等成 AB-BA。
	// 本临界区内的重载回调以 InLock 语义调用——生产注入
	// GenerateAndApplyConfigForceInLock（cmd/server/main.go），自取
	// CaddyOpLock 的 Force 变体会重入死锁（非可重入锁）；持锁期间
	// 禁止再新增 CaddyOpLock 获取点。
	CaddyOpLock.Lock()
	unlock := DeployLock(material.ruleID)
	defer func() {
		unlock()
		CaddyOpLock.Unlock()
	}()
	ruleID := material.ruleID
	existingCert, existingKey := material.certPEM, material.keyPEM
	if err := confirmCertificateDeployment(ctx, jobID, material, true); err != nil {
		return err
	}
	// 快速路径改为文件内容比对：证书与私钥文件都与任务中的材料一致时
	// 无需重新部署/重载，直接确认签发任务状态即可。
	// 必须同时校验私钥文件——只比证书会在「cert 已 rename、key 未 rename」
	// 的崩溃窗口里持续跳过重部署，Caddy reload 因 key 不匹配失败且运行期
	// 不自愈（启动物化会修，窗口有界但无谓）。
	certPath, keyPath := CertFilePaths(ruleID)
	deployedCert, certReadErr := os.ReadFile(certPath)
	deployedKey, keyReadErr := os.ReadFile(keyPath)
	if certReadErr == nil && keyReadErr == nil && string(deployedCert) == existingCert && string(deployedKey) == existingKey {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := transitionJob(db.DB, jobID, []string{"downloaded", "issued"}, "issued", map[string]any{
			"message":                    "证书已部署，无需重新部署",
			"expires_at":                 CanonicalDatetimeValue(material.notAfter),
			"deployment_attempts":        0,
			"deployment_available_after": nil,
		}); err != nil {
			return fmt.Errorf("finalize already deployed certificate: %w", err)
		}
		RecordAuditLog("system", "签发成功", "证书任务", fmt.Sprintf("规则 %s 证书已部署，无需重新部署", ruleID), "")
		// 与主部署路径同口径：未来生效证书即使本次无需重写文件，也要登记
		// 生效点重载（否则首次部署写盘后失败的收敛路径会缺这一次补充重载）。
		s.noteFutureNotBefore(jobID, material)
		return nil
	}
	// 快速路径的进度迁移确实需要 issued→downloaded（任务已签发、材料在库），
	// 显式白名单替代全局含终态的 from 集合——主签发路径（Issue）保持
	// nonTerminalJobStatuses 静态防线。
	logger.from = []string{"issued", "downloaded"}
	logger.Log("downloaded", "检测到已签发的有效证书，直接重新部署文件")
	// 本链的失败回写必须同时接受 issued：上面的进度写可能因瞬时 DB 故障未落库，
	// 此时行仍是 issued，若失败回写拒绝 issued 就会停在「issued + 磁盘旧材料」
	// 这一无周期通道的形态。
	redeployFailureStatuses := deploymentFailureFromStatuses(true)
	snapshot, snapshotErr := SnapshotCertFiles([]string{ruleID})
	if snapshotErr != nil {
		return s.deploymentFailedFrom(jobID, material, "读取现有证书文件失败: "+snapshotErr.Error(), fmt.Errorf("snapshot existing certificate files: %w", snapshotErr), redeployFailureStatuses)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := WriteCertFiles(ruleID, existingCert, existingKey); err != nil {
		return s.deploymentFailedFrom(jobID, material, "已有证书重新部署失败: "+err.Error(), fmt.Errorf("redeploy existing certificate: %w", err), redeployFailureStatuses)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	if s.caddyReloader != nil {
		err := s.caddyReloader()
		// 2026-09-07 裁定：fast-path 重载与主路径（536/:539）统一留痕。
		s.auditFastPathReload(jobID, material, err)
		if err != nil {
			return s.deploymentFailedFrom(jobID, material, "重新部署后重载 Caddy 失败: "+err.Error(), fmt.Errorf("reload Caddy after certificate redeploy: %w", err), redeployFailureStatuses)
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	// （cluster 审计，窄场景：运维手改证书文件或
	// 并发新化身分叉残留）：job 状态 "issued" + 磁盘不匹配
	// 的快速路径走到这里时，finalize 的 from-set 必须含 "issued"——
	// 否则 transitionJob CAS 失败 → errors.Join 恢复 → 磁盘回滚到
	// 不匹配状态 → 自愈路径断裂（job 保持 issued、磁盘永远错）。
	err := transitionJob(db.DB, jobID, []string{"downloaded", "issued"}, "issued", map[string]any{
		"message":                    "证书文件重新部署成功",
		"expires_at":                 CanonicalDatetimeValue(material.notAfter),
		"deployment_attempts":        0,
		"deployment_available_after": nil,
	})
	if err != nil {
		return errors.Join(fmt.Errorf("finalize certificate redeploy: %w", err), restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	RecordAuditLog("system", "签发成功", "证书任务", fmt.Sprintf("规则 %s 证书重新部署成功", ruleID), "")
	// 与主部署路径同口径登记生效点重载（noteFutureNotBefore 幂等，非未来
	// 生效时不产生任何登记）。
	s.noteFutureNotBefore(jobID, material)
	return nil
}

func (s *CertIssuer) deployIssuedCertificate(ctx context.Context, jobID int, material issuedCertificate) error {
	// 锁序：CaddyOpLock → DeployLock，与恢复链（持
	// caddyOpMu 的补偿路径 → RestoreCertJobsForRule）同序，消除
	// DeployLock→CaddyOpLock 旧序的 AB-BA 互等。s.caddyReloader 为 InLock
	// 语义（本临界区已持 CaddyOpLock），见 NewCertIssuer 契约。
	CaddyOpLock.Lock()
	unlock := DeployLock(material.ruleID)
	defer func() {
		unlock()
		CaddyOpLock.Unlock()
	}()
	if err := confirmCertificateDeployment(ctx, jobID, material, false); err != nil {
		// ErrNoRows(规则删除/禁用/角色翻转)保持 raw
		// ——材料已无意义,重试无益;其余(瞬时 DB)走 deploymentFailed 重试链,
		// 材料随失败落库(首签发材料仅内存,raw→failJob 终态会永久丢失)。
		if errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return s.deploymentFailed(jobID, material, "证书部署确认失败: "+err.Error(), fmt.Errorf("confirm certificate deployment: %w", err))
	}

	err := deploymentPersistenceWriteback(db.DB, jobID, deploymentLifecycleJobStatuses, "downloaded", map[string]any{
		"cert_pem":                   material.certPEM,
		"key_pem":                    material.keyPEM,
		"expires_at":                 CanonicalDatetimeValue(material.notAfter),
		"ca_provider_id":             material.providerID,
		"deployment_attempts":        0,
		"deployment_available_after": nil,
	})
	if err != nil {
		// CAS 冲突不等于「并发胜者已推进」：先重读行状态再定性。只有终态
		// （issued/failed/disabled，并发部署回调/取消已提交）才保持 raw——本回调
		// 材料已陈旧；行仍在非终态时冲突来自「自身进度写丢失/并发 requeue」，
		// 此时 ACME 材料只在内存，raw 返回会被队列按 CA 签发失败打成终态并永久
		// 丢弃材料 → 改走 deploymentFailed 落材料 + 退避重试。其余（瞬时 DB）
		// 同口径走 deploymentFailed。
		if errors.Is(err, ErrJobTransitionConflict) {
			status, statusErr := readCertJobStatus(jobID)
			if statusErr == nil && JobIsTerminal(status) {
				return fmt.Errorf("persist downloaded certificate: %w", err)
			}
			return s.deploymentFailed(jobID, material, "证书部署落库冲突: "+err.Error(), fmt.Errorf("persist downloaded certificate: %w", err))
		}
		return s.deploymentFailed(jobID, material, "证书部署落库失败: "+err.Error(), fmt.Errorf("persist downloaded certificate: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	snapshot, err := SnapshotCertFiles([]string{material.ruleID})
	if err != nil {
		return s.deploymentFailed(jobID, material, "读取现有证书文件失败: "+err.Error(), fmt.Errorf("snapshot existing certificate files: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := WriteCertFiles(material.ruleID, material.certPEM, material.keyPEM); err != nil {
		RecordAuditLog("system", "写入失败", "证书文件", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("io_error")), "")
		return s.deploymentFailed(jobID, material, "证书文件写入失败: "+err.Error(), fmt.Errorf("write certificate files: %w", err))
	}
	RecordAuditLog("system", "写入", "证书文件", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}

	if s.caddyReloader != nil {
		if err := s.caddyReloader(); err != nil {
			RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID)), "")
			return s.deploymentFailed(jobID, material, "Caddy 重载失败: "+err.Error(), fmt.Errorf("reload Caddy after certificate issuance: %w", err))
		}
		RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
	}

	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		// 终段 DB 失败（如 SQLITE_BUSY）与文件写入失败同走
		// deploymentFailed 重试链（任务回 'downloaded'+退避，兼容 30s 部署
		// 补扫）。已写入的证书文件就是本次部署目标，重试会重新快照并收敛，
		// 回滚旧快照只会让首签发场景在重试成功前无证书可用。
		return s.deploymentFailed(jobID, material, "开启证书事务失败: "+err.Error(), fmt.Errorf("begin certificate transaction: %w", err))
	}
	defer func() { _ = tx.Rollback() }()
	err = transitionJob(tx, jobID, deploymentLifecycleJobStatuses, "issued", map[string]any{
		"message":                    "签发成功",
		"renewal_attempts":           0,
		"ca_available_after":         nil,
		"last_error_code":            nil,
		"deployment_attempts":        0,
		"deployment_available_after": nil,
	})
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		rollbackErr := tx.Rollback()
		// 并发部署回调（在途回调 × 补扫重试）部署同 jobID 同一份
		// 证书时，CAS 败者的部署前快照可能早于胜者写入——无条件恢复会把磁盘
		// 回退到旧证书，与 DB('issued'+新 PEM)/Caddy 三方静默分叉，且
		// reconcileMissingCertFiles 不比对内容，分叉持续到下次续签。终态 CAS
		// 冲突（含任务中途被 disabled）保持既有补偿语义：胜者已提交且磁盘同
		// 物料时跳过恢复，否则恢复快照并由 failJob 归因（issued/disabled 为
		// 终态，failJob no-op）。
		if errors.Is(err, ErrJobTransitionConflict) {
			var cleanupErr error
			if deploymentCommittedByConcurrentWinner(jobID, material) {
				Logf("warn", "certificate job %d: finalization lost CAS race to a concurrent deployment of identical material; keeping winner's files, skipping snapshot restore", jobID)
			} else {
				cleanupErr = restoreCertificateDeployment(snapshot, s.caddyReloader)
			}
			// 本次执行已产出新材料（deployIssuedCertificate 此前已把 cert_pem/
			// key_pem 落库、行进入部署生命周期）——failJob(producedNewMaterial=
			// true) 允许按部署延迟降级（保持可部署态）；错误以
			// certificateDeploymentError 上抛，队列出口不再二次改写状态
			//（避免第二个 failJob 把已降级为部署延迟的行打成终态 failed）。
			failJob(jobID, "证书部署确认失败: "+err.Error(), true)
			return &certificateDeploymentError{err: errors.Join(fmt.Errorf("finalize issued certificate: %w", err), rollbackErr, cleanupErr)}
		}
		// 真实 DB 失败（transition/提交出错，如 SQLITE_BUSY）不得走
		// 上面的 failJob——会把已签发落库证书搁浅为 failed，rescan 只扫
		// downloaded、续期只扫临期，自动恢复通道全部错过（首签发无证书最长
		// ~60 天，手动重试整轮重签烧配额）。改走与文件写入失败相同的
		// deploymentFailed 重试链（任务回 'downloaded'+退避，兼容 30s 补扫）。
		return errors.Join(s.deploymentFailed(jobID, material, "证书部署确认失败: "+err.Error(), fmt.Errorf("finalize issued certificate: %w", err)), rollbackErr)
	}
	s.noteFutureNotBefore(jobID, material)
	return nil
}

// certificateNotBeforeReloadMargin 是未来时钟证书「生效后延迟重载」的余量：
// 证书到 NotBefore 才被客户端接受，重载刻意错开生效点少许，避免时钟面
// 恰好压线时的边界抖动。
const certificateNotBeforeReloadMargin = time.Minute

// notBeforeReloadScheduler 生效后延迟重载登记通道（测试缝；生产=
// scheduleCertificateNotBeforeReload）。
var notBeforeReloadScheduler = scheduleCertificateNotBeforeReload

// noteFutureNotBefore 部署完成后检查未来时钟证书：NotBefore > now 时部署
// 本身照常生效（文件已写、已重载），但证书要被客户端接受须等到生效点——
// 告警留痕并登记一次 NotBefore+余量时刻的延迟重载（复用证书服务既有定时器
// 族，不新建调度器）。只告警不阻断：解析失败/服务未运行均降级为 warn 日志。
func (s *CertIssuer) noteFutureNotBefore(jobID int, material issuedCertificate) {
	if material.certPEM == "" {
		return
	}
	notBefore, err := parseCertNotBefore(material.certPEM)
	if err != nil {
		Logf("warn", "证书任务 %d：解析证书生效时间失败（NotBefore 未来时钟检查跳过）: %v", jobID, err)
		return
	}
	delay := time.Until(notBefore.Add(certificateNotBeforeReloadMargin))
	if delay <= 0 {
		return
	}
	effectiveAt := notBefore.UTC().Format("2006-01-02 15:04:05")
	Logf("warn", "证书任务 %d（规则 %s）：证书尚未生效（NotBefore=%s UTC），已登记生效后重载", jobID, material.ruleID, effectiveAt)
	RecordAuditLog("system", "警告", "证书任务", FormatAuditDetail(
		AuditJobPart(jobID), AuditRulePart(material.ruleID),
		fmt.Sprintf("证书尚未生效（生效时间 %s UTC），已登记生效后重载", effectiveAt)), "")
	if notBeforeReloadScheduler != nil {
		notBeforeReloadScheduler(jobID, material.ruleID, delay)
	}
}

// scheduleCertificateNotBeforeReload 生产通道：经证书服务既有定时器族登记
// 一次性生效后重载；服务未运行（队列停用/测试环境）时降级为 warn——证书文件
// 已随本次部署生效，缺的只是生效点的一次补充重载。
// 收敛路径（不登记时）：重启时的配置物化/重载、下一次任意配置写触发的重载、
// 以及服务恢复后新登记的延迟重载定时器——「补扫」不会重渲染配置，不构成
// 收敛路径。边界：暂停期跳过登记不在恢复时补登（一次性定时器无持久化），
// 生效点前若全程无任何写操作且不重启，则本次补充重载缺失（证书文件与配置
// 均已生效，仅少一次重载）。
func scheduleCertificateNotBeforeReload(jobID int, ruleID string, delay time.Duration) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		Logf("warn", "证书服务未运行：任务 %d（规则 %s）的生效后重载跳过登记（证书文件已随部署生效；收敛路径=重启物化/下一次配置写触发的重载/服务运行时的延迟重载定时器）", jobID, ruleID)
		return
	}
	service.scheduleDelayedReload(jobID, ruleID, delay)
}

// deploymentCommittedByConcurrentWinner 报告终态 CAS 冲突是否源于并发部署回调
// 已提交同一份证书：任务状态已推进到终态 issued 且磁盘证书内容与本次部署材料
// 一致。仅用于冲突分支的恢复快照跳过判定 纵深防御）。
func deploymentCommittedByConcurrentWinner(jobID int, material issuedCertificate) bool {
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil || status != "issued" {
		return false
	}
	certPath, _ := CertFilePaths(material.ruleID)
	deployed, err := os.ReadFile(certPath)
	return err == nil && bytes.Equal(deployed, []byte(material.certPEM))
}

// readCertJobStatus 重读任务当前状态，用于区分「并发胜者已推进到终态」与
// 「自身进度写丢失、行仍在非终态」——两者的正确处置相反（前者保持 raw 让材料
// 陈旧回调退出，后者必须落材料并登记重试）。读失败按瞬时 DB 故障上抛，调用方
// 走材料保留路径。
func readCertJobStatus(jobID int) (string, error) {
	var status string
	err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status)
	return status, err
}

// ErrCertificateRoleUndetermined 表示部署确认时「节点角色不可判定」（读
// global_config 失败）。调用方据此走部署重试链而不是按「材料已无意义」丢弃：
// 与 sql.ErrNoRows（任务/规则不可部署、角色已翻转）严格区分。
var ErrCertificateRoleUndetermined = errors.New("无法判定节点角色")

// confirmCertificateDeployment 校验任务与规则的当前状态仍允许落盘这份签发
// 材料。刻意不过滤 r.enable_tls/r.tls_source：与扫描/物化路径
// （certificates.go 的 rescan/renew 查询、certstore.go 的启动物化）统一附加
// `enable_tls=1 AND tls_source='acme_dns'` 的口径不同，本函数只把关「任务与
// 规则是否仍对得上」——已签发材料写盘后不被 manual 渲染消费，保留材料便于
// 规则切回 acme_dns 时直接复用。材料保留取向为有意设计，勿对齐过滤口径。
func confirmCertificateDeployment(ctx context.Context, jobID int, material issuedCertificate, allowIssued bool) error {
	// 角色判据走单源 RoleOf（三态），不再内联 COALESCE(g.is_master,1)=1：
	// SQL 谓词把「角色读失败」与「任务/规则已不可部署」同归 sql.ErrNoRows，
	// 部署失败归因会把 DB 故障读成规则删除/禁用（排障误导，材料还会按
	// 「无意义」丢弃）；且 RoleOf 口径未来收紧（如校验 master_url）不会
	// 传播到部署确认。三态映射：
	//   读失败   → ErrCertificateRoleUndetermined（瞬时，调用方走重试链）
	//   非主节点 → sql.ErrNoRows（角色翻转=材料无意义，与规则删除/禁用同口径）
	master, roleErr := RoleOf(ctx, db.DB)
	if roleErr != nil {
		Logf("warn", "证书部署确认：读取节点角色失败，按瞬时故障交给重试链: %v", roleErr)
		return fmt.Errorf("confirm certificate deployment: %w: %v", ErrCertificateRoleUndetermined, roleErr)
	}
	if !master {
		return fmt.Errorf("confirm certificate deployment: %w（本节点已非主节点）", sql.ErrNoRows)
	}
	var status, jobDomains, ruleDomains string
	err := db.DB.QueryRowContext(ctx, `SELECT j.status, j.domain, r.domain FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.id=? AND j.rule_id=? AND r.enabled=1
	`, jobID, material.ruleID).Scan(&status, &jobDomains, &ruleDomains)
	if err != nil {
		return fmt.Errorf("confirm certificate deployment: %w", err)
	}
	canonicalJobDomains, err := CanonicalACMEDomains(jobDomains)
	if err != nil {
		return fmt.Errorf("confirm certificate job domains: %w", err)
	}
	canonicalRuleDomains, err := CanonicalACMEDomains(ruleDomains)
	if err != nil {
		return fmt.Errorf("confirm certificate rule domains: %w", err)
	}
	if canonicalJobDomains != canonicalRuleDomains {
		return fmt.Errorf("certificate job %d domains no longer match rule", jobID)
	}
	// 可部署源态由 jobLifecycleByStatus 派生（JobLifecycle）：新增/重命名部署
	// 生命周期状态时这里自动跟随，不再维护第三份状态字面量集合。快速重部署链
	// 额外允许 issued（任务已签发、材料在库，只重写磁盘文件）。
	deployable := JobLifecycle(status) == JobLifecycleDownloaded
	if allowIssued {
		deployable = JobLifecycle(status) == JobLifecycleIssued || deployable
	}
	if !deployable {
		return fmt.Errorf("certificate job %d is no longer deployable (status=%s)", jobID, status)
	}
	return nil
}

func restoreCertificateDeployment(snapshot CertFilesSnapshot, reloader func() error) error {
	if err := RestoreCertFiles(snapshot); err != nil {
		return fmt.Errorf("restore previous certificate files: %w", err)
	}
	if reloader != nil {
		err := reloader()
		// 2026-09-07 裁定：回滚重载同口径留痕（成功回滚=DB 态重渲染；失败=旧配置保留）。
		recordSystemReloadAudit("certificate_issued", err)
		if err != nil {
			return fmt.Errorf("reload Caddy after certificate rollback: %w", err)
		}
	}
	return nil
}

func detectRateLimit(err error) *CAProviderRateLimitError {
	if err == nil {
		return nil
	}
	// Check for structured ACME 429 error first. golang.org/x/crypto/acme
	// returns *acme.Error with StatusCode and response headers for CA errors.
	var acmeErr *xacme.Error
	if errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusTooManyRequests {
		retryAfter := time.Duration(0)
		if ra := acmeErr.Header.Get("Retry-After"); ra != "" {
			retryAfter = parseRetryAfter(ra)
		}
		return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
	}

	// Fallback: string matching for providers/wrappers that don't surface the
	// structured *acme.Error. Bare "429" substrings are NOT evidence of rate
	// limiting: domains are embedded in error text (e.g. acme/issuer.go
	// "present dns for 429.example.com") and would misroute the job into the
	// 1-3h waiting_ca cooldown instead of the 30min failure retry. Real CA
	// 429s carry the structured StatusCode above or rate-limit wording.
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "rate limit") && !strings.Contains(msg, "too many") {
		return nil
	}

	// Try to extract a hint from the error text. The ACME library
	// sometimes includes it as "retry after 2026-01-02 03:04:05 +0000 UTC"
	// (Go time.Time.String()) or "retry after 3600s".
	retryAfter := time.Duration(0)
	if d := extractRetryAfterFromError(err.Error()); d > 0 {
		retryAfter = d
	}
	return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
}

// extractRetryAfterFromError attempts to pull a duration out of a
// CA error message. It is a best-effort fallback because golang.org/x/crypto/acme
// does not expose the HTTP response directly.
func extractRetryAfterFromError(errText string) time.Duration {
	lower := strings.ToLower(errText)
	if idx := strings.Index(lower, "retry after"); idx != -1 {
		suffix := errText[idx+len("retry after"):]
		suffix = strings.TrimSpace(suffix)
		// Strip a trailing period or comma （此前只剥句点，注释与
		// 行为不符——逗号结尾的 "3600s," 会整段落入解析失败)。
		suffix = strings.TrimRight(suffix, ".,")
		// Try parsing as seconds if it looks like "3600s".
		if strings.HasSuffix(suffix, "s") {
			if sec, err := strconv.Atoi(strings.TrimSuffix(suffix, "s")); err == nil && sec > 0 {
				return time.Duration(sec) * time.Second
			}
		}
		// Try parsing as an RFC3339 timestamp.
		if t, err := time.Parse(time.RFC3339, suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
		// Try parsing as HTTP date.
		if t, err := time.Parse(http.TimeFormat, suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
		// Try parsing as Go time.Time.String()（"2006-01-02 15:04:05 -0700 MST"，
		// 即上方注释文档化的形态）。此前只试 RFC3339/HTTP-date，该
		// 文档化分支永不命中，退化为自有阶梯（1–3h，偏长）；Go 解析布局虽无
		// 小数秒字段，但解析器接受任意长度的小数秒（标准库特例）。
		if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	return 0
}

// ValidateACMEDomainsForIssuance 是保存/启用/导入侧的签发域名校验：结构校验
// 之上叠加公共 CA 的字符集要求（RFC 1035 LDH、≥2 标签）。缺这道门时
// `foo_bar.example.com`、`localhost`、非 ASCII 域能保存、能启用、能入队，
// 直到签发执行期（Issue 的纵深门）才失败，并消耗 5 次自动重试才停。
//
// 与结构层（normalizeAndValidateDomains）的分工：结构层继续服务任务/规则域
// 比较（CanonicalACMEDomains / certJobRuleApplicable）——历史行可能含下划线，
// 比较层拒绝会让这些行被误判「规则不适用」而遭退役/断链。本函数只用于
// 写入口，不参与比较。
func ValidateACMEDomainsForIssuance(domains string) error {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}
	for _, domain := range list {
		if !isValidACMEIssuanceDomain(domain) {
			return fmt.Errorf("ACME证书域名不符合公共 CA 签发要求（仅小写字母/数字/连字符标签，且至少两级）: %s", domain)
		}
	}
	return nil
}

func CanonicalACMEDomains(domains string) (string, error) {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return "", fmt.Errorf("invalid ACME domains: %s", domains)
	}
	return strings.Join(list, ","), nil
}

// ReversedCertJobDomain 返回双域名集合的逆序形式（"a.com,www.a.com"→
// "www.a.com,a.com"）；非双元素集（单域名/多段/空）原样返回。cert_jobs.domain
// 存排序规范形式，而 lb_rules.domain 保留用户输入顺序，任务匹配需同时覆盖两种
// 排列（lower+replace 归一后按 IN (canonical, reversed) 命中）。
// handlers.rules.reversedACMEDomainForm 与
// handlers.certjobs.reversedCertJobDomain 双份同实现收敛至此唯一源，两侧委托。
func ReversedCertJobDomain(domain string) string {
	if parts := strings.Split(domain, ","); len(parts) == 2 {
		return parts[1] + "," + parts[0]
	}
	return domain
}

// normalizeAndValidateDomains returns a cleaned domain list if it is either
// a single domain or a root domain plus its www subdomain. Otherwise nil.
func normalizeAndValidateDomains(domains string) []string {
	parts := strings.Split(domains, ",")
	var list []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		d := strings.TrimSpace(strings.ToLower(p))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		list = append(list, d)
	}
	if len(list) == 0 || len(list) > 2 {
		return nil
	}
	for _, d := range list {
		if !isValidACMEIssuerDomain(d) {
			return nil
		}
	}
	if len(list) == 1 {
		return list
	}
	// Must be root + www.root (either ordering)
	a, b := list[0], list[1]
	if b == "www."+a || a == "www."+b {
		sort.Strings(list)
		return list
	}
	return nil
}

// isValidACMEIssuerDomain 校验可签发的 DNS 名的结构边界：拒绝通配符/IP、
// 空标签、首尾点/连续点与超长标签。字符集/公共后缀约束在签发入口
// （isValidACMEIssuanceDomain）叠加——本函数同时服务 CanonicalACMEDomains 的
// 任务/规则域比较，历史/测试行里可能含下划线等 CA 不接受但库内已存在的写法，
// 比较层拒绝会让这些行被误判「规则不适用」而遭禁用/断链。
func isValidACMEIssuerDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	if strings.Contains(d, "*") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

// isValidACMEIssuanceDomain 是签发入口的完整校验：在结构校验之上追加
// RFC 1035 LDH 字符集与 ≥2 标签（公开 FQDN）要求。含空格、下划线、非 ASCII
// 或单标签的域名必然被公共 CA 拒绝——必须在发起订单前拦住（否则白烧一次
// 订单/配额，含空格域名还会污染 lower(replace(domain,' ')) 比较）。
func isValidACMEIssuanceDomain(d string) bool {
	if !isValidACMEIssuerDomain(d) {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// parseCertNotAfter extracts the NotAfter time from a PEM certificate chain.
// 单源：委托 CertNotAfterFromPEM（cert_jobs.expires_at 回退、任务列表派生字段
// 与签发链共用同一解析实现，避免两份「解析首块」逻辑在错误/空块行为上漂移）。
// 需要区分「空块」与「解析失败」的调用方请直接用 parseCertTime。
func parseCertNotAfter(certPEM string) (time.Time, error) {
	notAfter, ok := CertNotAfterFromPEM(certPEM)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	return notAfter, nil
}

// parseCertNotBefore extracts the NotBefore time from a PEM certificate chain.
func parseCertNotBefore(certPEM string) (time.Time, error) {
	return parseCertTime(certPEM, func(cert *x509.Certificate) time.Time { return cert.NotBefore })
}

// parseCertTime 是两条取时入口的单源实现（此前 NotBefore/NotAfter 两份逐字
// 相同的解码逻辑，任一侧改动会漂移）。
func parseCertTime(certPEM string, pick func(*x509.Certificate) time.Time) (time.Time, error) {
	cert, err := parseCertificateLeaf(certPEM)
	if err != nil {
		// 空块保留既有文案（"invalid certificate PEM"）；解析失败沿用
		// parseCertificateLeaf 的 "parse certificate: ..." 包装。
		if errors.Is(err, errCertPEMEmpty) {
			return time.Time{}, fmt.Errorf("invalid certificate PEM")
		}
		return time.Time{}, err
	}
	return pick(cert), nil
}

// auditFastPathReload 修正：fast-path 重载审计带 job/rule 归因（对齐主路径粒度）。
func (s *CertIssuer) auditFastPathReload(jobID int, material issuedCertificate, err error) {
	if err != nil {
		RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID)), "")
		return
	}
	RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
}
