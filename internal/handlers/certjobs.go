package handlers

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var certJobOperationLocks [64]sync.Mutex

// retryCertJobPreEnqueueHook 是测试专用钩子：在 SELECT 状态之后、EnqueueIfActive
// 内 UPDATE 之前触发，用于模拟 worker 侧并发状态流转。
var retryCertJobPreEnqueueHook func(jobID int)

// deleteCertJobPreDisableHook 是测试专用钩子：在 DeleteCertJob 的状态 SELECT/守卫
// 之后、disabled 翻转 UPDATE 之前触发，用于模拟 worker 侧并发状态流转
// 回归测试）。
var deleteCertJobPreDisableHook func(jobID int)

// deleteCertJobPreRestoreHook 是测试专用钩子：DELETE 失败后、状态恢复 UPDATE
// 之前触发，用于模拟「行在删除窗口内被并发移离 disabled」。
var deleteCertJobPreRestoreHook func(jobID int)

// certJobLogPathForRule 解析规则的任务日志路径（测试缝：镜像 cancelCertJob 的
// var 先例，测试可重定向到临时目录；生产恒为 services.CertJobLogPath）。
var certJobLogPathForRule = services.CertJobLogPath

var cancelCertJob = func(id int) {
	if qm := services.GetCAQueueManager(); qm != nil {
		qm.CancelJob(id)
	}
}

// certJobLogMaxRotatedBackups 直读 services 写侧保留份数（.1 最新 → .N 最旧）
// ——读侧与写侧同源由消费关系保证（此前 const=logRotatedBackups 靠巧合同值，
// 写侧改保留数时读侧漏同步）。Caddy 日志族保留数仍由 logRotatedBackups 服务。
var certJobLogMaxRotatedBackups = services.CertJobLogMaxRotatedFiles()

// certJobLogsMaxResponseBytes 单响应硬上限（尾窗）。轮转保留份数不改——
// 那是写侧契约（排障需要的历史深度），读侧只约束单次下发的体积。
const certJobLogsMaxResponseBytes = 256 << 10

// maxCertJobPage 是证书任务列表的页码上限：与安全事件列表同口径（1000），
// 避免 page=1000000&page_size=200 触发近两亿行 OFFSET 线性扫描（任何 business
// 用户可构造）。超上限按上限钳制并回 X-Page 标示实际页码。
const maxCertJobPage = 1_000

func certJobOperationLock(id int) *sync.Mutex {
	index := id % len(certJobOperationLocks)
	if index < 0 {
		index += len(certJobOperationLocks)
	}
	return &certJobOperationLocks[index]
}

// certJobListItem 是证书任务列表/详情的统一投影（证书材料本体 cert_pem
// 不外发）——详情与列表字段同源，新消费方（如任务监控详情）不会踩空
// 「列表有、详情无」的字段分叉。
type certJobListItem struct {
	ID                int                 `json:"id"`
	RuleID            string              `json:"rule_id"`
	Domain            string              `json:"domain"`
	CAProviderID      int                 `json:"ca_provider_id"`
	CAProviderName    string              `json:"ca_provider_name,omitempty"`
	Status            string              `json:"status"`
	Message           string              `json:"message"`
	Issuer            string              `json:"issuer"`
	DaysRemaining     int                 `json:"days_remaining"`
	CertificateStatus string              `json:"certificate_status"`
	RenewalAttempts   int                 `json:"renewal_attempts,omitempty"`
	CAAvailableAfter  models.JSONNullTime `json:"ca_available_after,omitempty"`
	LastErrorCode     string              `json:"last_error_code,omitempty"`
	ExpiresAt         models.JSONNullTime `json:"expires_at"`
	// NotAfter 是证书真实到期时刻的派生值：优先库值 expires_at，缺失时由
	// PEM 解析回退。UI 的「有效期/自动重签时间」只认该字段——判 expires_at
	// 会让导入/集群回插的 NULL 有效期行两侧显示分叉（后端已算 days_remaining
	// 却渲染「-」）。
	NotAfter             models.JSONNullTime `json:"not_after"`
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            models.JSONNullTime `json:"updated_at"`
	RetryCooldownSeconds *int64              `json:"retry_cooldown_seconds"`
}

// certJobFirstCertBlockSQL 取 cert_jobs.cert_pem 的首证书块（列别名由调用方给）。
// certificateIssuer 与 CertNotAfterFromPEM 都只解析首块，全链（LE ~6KB）全量传输
// 纯属浪费；INSTR 定位首个 END 边界，空串/单块形态 SUBSTR 原样返回。
// 单源：任务列表与聚合清单（ListCertificates 的 not_after 派生）必须同口径。
const certJobFirstCertBlockSQL = `CASE WHEN INSTR(j.cert_pem,'-----END CERTIFICATE-----') > 0
	     THEN SUBSTR(j.cert_pem, 1, INSTR(j.cert_pem,'-----END CERTIFICATE-----') + 25)
	     ELSE COALESCE(j.cert_pem,'') END`

// certJobListSelectSQL 列表/详情共用的列投影与 provider 联表。
const certJobListSelectSQL = `SELECT j.id, j.rule_id, j.domain, j.status, COALESCE(j.message,'') AS message,
	` + certJobFirstCertBlockSQL + ` AS cert_pem,
	j.expires_at, j.created_at, j.updated_at, COALESCE(j.renewal_attempts,0) AS renewal_attempts, j.ca_available_after, COALESCE(j.last_error_code,'') AS last_error_code, COALESCE(j.ca_provider_id,0) AS ca_provider_id, COALESCE(p.name,'') AS ca_provider_name FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id`

// certJobScanner 抽象 *sql.Rows/*sql.Row 的 Scan（列表逐行与详情单行同源填充）。
type certJobScanner interface {
	Scan(dest ...any) error
}

// scanFrom 从当前行填充投影并计算派生字段（重试冷却/issuer/到期状态）。
// 剩余天数收敛 services.CertDaysRemaining 单源；状态判定收敛
// services.CertificateExpiryStatus（天粒度，与 certinfo 截断天数同口径）。
func (j *certJobListItem) scanFrom(scanner certJobScanner, now time.Time, expiryDays int) error {
	var certPEM string
	if err := scanner.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &certPEM,
		&j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode, &j.CAProviderID, &j.CAProviderName,
	); err != nil {
		return err
	}
	// 下发「此刻剩余秒」（0=现在即可重试；null=永久不可重试），已按 updated_at
	// 扣减流逝部分——前端只需比较 >0，不得再按 updated_at 二次扣减。
	if seconds, retryable := certJobRetryRemainingSeconds(j.Status,
		j.UpdatedAt.NullTime,
		sql.NullTime{Time: j.CreatedAt, Valid: !j.CreatedAt.IsZero()},
		j.CAAvailableAfter.NullTime, now); retryable {
		j.RetryCooldownSeconds = &seconds
	}
	j.Issuer = certificateIssuerCached(certPEM)
	j.CertificateStatus = "unknown"
	notAfter := time.Time{}
	if j.ExpiresAt.Valid {
		notAfter = j.ExpiresAt.Time
	} else if derived, ok := services.CertNotAfterFromPEM(certPEM); ok {
		// expires_at 缺失时由 PEM 回退派生（expires_at 本身仍按原契约下发 null）。
		notAfter = derived
	}
	if !notAfter.IsZero() {
		j.NotAfter = models.JSONNullTime{NullTime: sql.NullTime{Time: notAfter, Valid: true}}
		j.DaysRemaining = services.CertDaysRemaining(notAfter, now)
		j.CertificateStatus = services.CertificateExpiryStatus(notAfter, now, expiryDays)
	}
	return nil
}

func (h *Handlers) ListCertJobs(c *gin.Context) {
	ruleID := c.Query("rule_id")
	// 分页参数统一解析（与安全事件/审计日志同口径）：非整数 400；<1 回默认；
	// 超上限钳到上限（此前越界 400，与同面板其余列表不一致）。
	pageValue, ok := parsePaginationParam(c, "page", 1, maxCertJobPage)
	if !ok {
		return
	}
	pageSize, ok := parsePaginationParam(c, "page_size", 50, 200)
	if !ok {
		return
	}
	page := int64(pageValue)
	offset := (page - 1) * int64(pageSize)
	whereClause := ""
	var filterArgs []interface{}
	if ruleID != "" {
		whereClause = " WHERE j.rule_id = ?"
		filterArgs = append(filterArgs, ruleID)
	}
	// total 与 status_counts 由同一分组语句派生（total=各状态之和）：两次独立
	// 查询在并发入队时会让「横幅显示 queued>0 而列表为空」这类瞬时不一致进入
	// UI。仍非快照隔离（分组语句与分页语句是两条），但同一响应内自洽。
	var total int64
	statusCounts := map[string]int64{}
	statusRows, err := db.DB.Query("SELECT j.status, COUNT(*) FROM cert_jobs j"+whereClause+" GROUP BY j.status", filterArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务状态失败"})
		return
	}
	for statusRows.Next() {
		var status string
		var count int64
		if err := statusRows.Scan(&status, &count); err != nil {
			statusRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务状态失败"})
			return
		}
		statusCounts[status] = count
		total += count
	}
	if err := statusRows.Err(); err != nil {
		statusRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务状态失败"})
		return
	}
	statusRows.Close()
	// 字面量 30 → db.DefaultCertExpiryDays 绑定参数（caddy.go
	// 形态，库值唯一真相单源）。
	// 审计项：过期判定阈值改用 services.GetCertExpiryThreshold 单源边界面——
	// 本处曾裸读 COALESCE 且不做 1-365 边界校验，库值越界（带外直写/旧快照）
	// 会让列表「即将过期」标记与续签扫描口径分叉；单源 helper 越界时显性留痕
	// 并降级治理默认。
	expiryDays := services.GetCertExpiryThreshold()
	query := certJobListSelectSQL + whereClause
	args := append([]interface{}{}, filterArgs...)
	// 排序键必须唯一（created_at DESC, id DESC）：同秒批量入队会让 created_at
	// 完全相等，单键排序下等值区间的顺序由查询计划决定，翻页窗口会在等值区间
	// 重复/漏行。tiebreaker 与 GetCurrentCertJobs 同源（job 列表同一契约）。
	query += " ORDER BY j.created_at DESC, j.id DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		writeInternalError(c, http.StatusInternalServerError, "查询证书任务失败", err)
		return
	}
	defer rows.Close()

	jobs := make([]certJobListItem, 0, pageSize)
	now := time.Now()
	for rows.Next() {
		var j certJobListItem
		if err := j.scanFrom(rows, now, expiryDays); err != nil {
			writeInternalError(c, http.StatusInternalServerError, "读取证书任务失败", err)
			return
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		writeInternalError(c, http.StatusInternalServerError, "读取证书任务失败", err)
		return
	}
	c.Header("X-Page", strconv.FormatInt(page, 10))
	c.Header("X-Page-Size", strconv.Itoa(pageSize))
	c.Header("X-Total", strconv.FormatInt(total, 10))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"list": jobs, "total": total, "page": page, "page_size": pageSize, "status_counts": statusCounts}})
}

// GetCurrentCertJobs returns the latest non-disabled job per requested rule so
// polling does not depend on offset pagination (which drifts under inserts).
func (h *Handlers) GetCurrentCertJobs(c *gin.Context) {
	var req struct {
		RuleIDs []string `json:"rule_ids"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// gin 解析文本含 Go 字段名/英文（只读白名单端点，任意只读凭据可触发）：
		// 响应固定中文文案，细节只进运行日志。
		services.Logf("warn", "GetCurrentCertJobs: 请求体校验失败: %v", err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if len(req.RuleIDs) > 200 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "invalid_request：rule_ids 数量不能超过 200"})
		return
	}
	result := make(map[string]*models.CertJob, len(req.RuleIDs))
	for _, id := range req.RuleIDs {
		result[id] = nil
	}
	if len(req.RuleIDs) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
		return
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(req.RuleIDs)), ",")
	args := make([]interface{}, len(req.RuleIDs))
	for i, id := range req.RuleIDs {
		args[i] = id
	}
	rows, err := db.DB.QueryContext(c.Request.Context(), `SELECT j.id, j.rule_id, j.domain, COALESCE(j.ca_provider_id,0), COALESCE(p.name,''), j.status, COALESCE(j.message,''), COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''), j.expires_at, j.created_at, j.updated_at
		FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id
		WHERE j.rule_id IN (`+placeholders+`) AND j.status <> 'disabled'
		ORDER BY j.rule_id, j.created_at DESC, j.id DESC`, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询证书任务失败"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var job models.CertJob
		if err := rows.Scan(&job.ID, &job.RuleID, &job.Domain, &job.CAProviderID, &job.CAProviderName, &job.Status, &job.Message, &job.RenewalAttempts, &job.CAAvailableAfter, &job.LastErrorCode, &job.ExpiresAt, &job.CreatedAt, &job.UpdatedAt); err != nil {
			writeInternalError(c, http.StatusInternalServerError, "读取证书任务失败", err)
			return
		}
		if result[job.RuleID] == nil {
			result[job.RuleID] = &job
		}
	}
	if err := rows.Err(); err != nil {
		writeInternalError(c, http.StatusInternalServerError, "读取证书任务失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

// cleanupOrphanedCertMaterialAfterJobDelete 在任务行删除后回收该规则的物化证书/
// 私钥文件：判定口径与渲染候选同源（services.CertJobMaterialPredicateSQL，非
// disabled + PEM 非空），规则仍持有手工证书材料时同样保留。调用方 MUST 持
// caddyOpMu（与规则写/渲染物化互斥）。失败只告警不否决已完成的删除——文件残留
// 属卫生问题（下次签发覆盖或规则删除清理），不得把成功的行删除变成 500。
func cleanupOrphanedCertMaterialAfterJobDelete(ruleID string) {
	if ruleID == "" {
		return
	}
	var tlsSource, tlsCert, tlsKey string
	err := db.DB.QueryRow("SELECT COALESCE(tls_source,''), COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id=?", ruleID).
		Scan(&tlsSource, &tlsCert, &tlsKey)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		services.Logf("warn", "DeleteCertJob 读取规则 %s 证书形态失败（跳过文件清理）: %v", ruleID, err)
		return
	}
	if err == nil && tlsSource == "manual" && strings.TrimSpace(tlsCert) != "" && strings.TrimSpace(tlsKey) != "" {
		// 手动证书材料在库（同样会物化到 certs/），不得按「无任务材料」误删。
		return
	}
	var remaining int
	if err := db.DB.QueryRow("SELECT COUNT(1) FROM cert_jobs WHERE rule_id=? AND "+services.CertJobMaterialPredicateSQL(""), ruleID).Scan(&remaining); err != nil {
		services.Logf("warn", "DeleteCertJob 检查规则 %s 剩余证书材料失败（跳过文件清理）: %v", ruleID, err)
		return
	}
	if remaining > 0 {
		return
	}
	if err := services.RemoveCertFiles(ruleID); err != nil {
		services.Logf("warn", "DeleteCertJob 清理规则 %s 的物化证书文件失败: %v", ruleID, err)
	}
}

func certificateIssuer(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	// 与规则证书卡/手动证书校验共用同一显示口径（此前只取 Organization，
	// 同证书在任务列表与证书卡显示不同文案）。
	return services.CertificateIssuerDisplay(cert)
}

// certIssuerCache 按证书 PEM 首块缓存 issuer 解析结果——pem.Decode+
// x509.ParseCertificate 单次约 20-60µs，列表页 50-200 行/请求且
// usePollingTask 周期轮询（多标签页线性叠加），同一证书不应每请求重解析。
// 有界（256 条）；写满整表清空重建（证书总量小，重建代价可忽略）。
var certIssuerCache = struct {
	sync.Mutex
	entries map[string]string
}{entries: map[string]string{}}

const certIssuerCacheMax = 256

func certificateIssuerCached(certPEM string) string {
	if certPEM == "" {
		return ""
	}
	certIssuerCache.Lock()
	defer certIssuerCache.Unlock()
	if issuer, ok := certIssuerCache.entries[certPEM]; ok {
		return issuer
	}
	issuer := certificateIssuer(certPEM)
	if len(certIssuerCache.entries) >= certIssuerCacheMax {
		certIssuerCache.entries = map[string]string{}
	}
	certIssuerCache.entries[certPEM] = issuer
	return issuer
}

func (h *Handlers) RetryCertJob(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	h.retryCertJobByID(c, id)
}

// retryCertJobByID 重试入队核心（2026-10-11 抽取）：RetryCertJob 端点与
// TriggerSystemTask 的 cert-job 行触发分支共用——用户裁定 cert-job 行视为
// 触发任务（可自动调度即可手动调度，证书可重签发）。
func (h *Handlers) retryCertJobByID(c *gin.Context, id int) {
	// 导入窗口门与任务监控 toggle/control 同源。
	// 导入会话持 db.DB 写事务直至 commit，且 CA 队列已 PauseAndDrain——此处的
	// UPDATE（部署窗推进/重入队）要么阻塞在 SQLite 写锁上到 busy_timeout 后
	// 500，要么提交后落到已被全量替换的 cert_jobs 行上，绕过导入的暂停/排空
	// 契约。409 fast-fail（拒绝重试是幂等可重试语义，不改变任何任务状态），
	// 两个入口（RetryCertJob / TriggerSystemTask 的 cert-job 分支）共用本核心。
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "配置导入进行中，暂不能重试证书任务"})
		return
	}
	operationLock := certJobOperationLock(id)
	operationLock.Lock()
	// per-job 锁改为手动配对：部署重排的「登记立即部署」必须落到锁外
	// （scheduleDeploymentRetry 对在途部署回调做有界等待 ≤30s，而删除方是先
	// 取 caddyOpMu 再等本锁——持锁登记会把全局面阻塞到等待超时）。锁序铁律：
	// 先 caddyOpMu 后 operationLock，登记/取消等待一律在两者之外。
	operationLockHeld := true
	releaseOperationLock := func() {
		if operationLockHeld {
			operationLock.Unlock()
			operationLockHeld = false
		}
	}
	defer releaseOperationLock()
	// 失败出口审计：两条路由是 AuditPolicyExplicit，中间件不做自动审计——
	// 出口不补记会让被拒/失败的重试与越权尝试完全不可追溯（同域
	// IssueCertificate.auditFailure 覆盖全部出口）。detail 只放固定归因，
	// 底层错误（SQL/队列内部态）只进运行日志。
	auditFailure := func(result string) {
		recordAudit(c, "重试失败", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditResultPart(result)))
	}
	var ruleID, domain, status string
	var caProviderID, renewalAttempts int
	var updatedAt, createdAt, caAvailableAfter sql.NullTime
	err := db.DB.QueryRow("SELECT rule_id, domain, status, updated_at, created_at, COALESCE(ca_provider_id,0), COALESCE(renewal_attempts,0), ca_available_after FROM cert_jobs WHERE id=?", id).Scan(&ruleID, &domain, &status, &updatedAt, &createdAt, &caProviderID, &renewalAttempts, &caAvailableAfter)
	if dbQueryNotFound(c, err, "任务不存在", "RetryCertJob query job") {
		if err != nil {
			// 与 DeleteCertJob 同档：ErrNoRows=任务不存在，其余读故障
			// （SQLITE_BUSY/连接中断/表不可读）归因查询失败——dbQueryNotFound
			// 对两者都返回 true，不区分就会把瞬时 DB 故障记成「任务不存在」。
			result := "query_failed"
			if errors.Is(err, sql.ErrNoRows) {
				result = "job_not_found"
			}
			auditFailure(result)
		}
		return
	}
	auditFailureWithRule := func(result string) {
		recordAudit(c, "重试失败", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), services.AuditResultPart(result)))
	}
	// 冷却门禁与文案共用同一 now：分别取墙钟会让边界（<1s 剩余）出现
	// 「门禁说冷却中、文案说 0s」的自相矛盾。
	now := time.Now()

	if blocked, statusCode, message := certJobRetryBlocked(status, updatedAt, createdAt, now); blocked {
		result := "cooldown"
		if statusCode == http.StatusConflict {
			result = "permanent"
		}
		auditFailureWithRule(result)
		c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
		return
	}

	// waiting_ca 的 CA 冷却（429 退避 1-3h）有明确到期时间——手动重试默认
	// 不得静默越过：冷却未到期且未显式 force 时 429 并给出剩余时长；
	// force=true（前端确认对话框已明示风险）显式越过并留审计痕迹。
	forceRetry := c.Query("force") == "true"
	// 冷却是否真的未到期——429 判定与「手动越过 CA 冷却」审计片段共用同一
	// 布尔：冷却已自然到期时带 force 的重试并未越过任何东西，记入会让越权
	// 留痕被稀释。
	cooldownActive := certJobCAcooldownActive(status, caAvailableAfter, now)
	if cooldownActive && !forceRetry {
		auditFailureWithRule("ca_cooldown")
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: http.StatusTooManyRequests,
			Message: certJobCAcooldownMessage(caAvailableAfter.Time, now)})
		return
	}

	// 部署生命周期（downloaded/cleanup_dns/cleanup_warning）+ 材料在库的任务
	// 停在部署窗口——转 queued 会丢弃已签发证书并触发整轮重签（同
	// requeueCanceledJob / DeleteCertJob 恢复 / requeueCertJobsSnapshot 的取向）。
	// 改为把部署窗口推到 now 并立即重排部署重试；仅「无材料」的此类任务
	// （脏行）才回落重新签发。
	if rescheduled, err := func() (bool, error) {
		rescheduled, markErr := markDownloadedCertJobDeploymentPending(id, ruleID, domain)
		if markErr != nil || !rescheduled {
			return rescheduled, markErr
		}
		// 窗口已在锁内推进；登记立即部署放到锁外（见 operationLock 注释）。
		releaseOperationLock()
		return true, registerDownloadedCertJobDeploymentRetry(id, ruleID)
	}(); err != nil {
		// 屏障/服务停止时窗口已推进：DB 文案必须如实描述「等待自动部署」，
		// 与响应对齐；busy 不动文案（旧回调仍在跑，任务行保持原消息）。
		if !errors.Is(err, services.ErrCertificateDeploymentRetryBusy) {
			message := "手动重试未触发，等待自动部署"
			if errors.Is(err, services.ErrCertificateDeploymentRetryBlocked) {
				message = "手动重试未触发：规则证书操作被屏障阻塞，等待自动部署"
			}
			if _, updateErr := db.DB.Exec(`UPDATE cert_jobs SET message=?, updated_at=datetime('now') WHERE id=? AND status IN (`+services.DeploymentLifecycleJobStatusSQL+`)`, message, id); updateErr != nil {
				services.Logf("error", "Manual deployment retry message update failed for job %d: %v", id, updateErr)
			}
		}
		statusCode, message := deploymentRetryFailureResponse(err)
		if statusCode >= http.StatusInternalServerError {
			services.Logf("error", "Manual deployment retry failed for job %d: %v", id, err)
		}
		auditFailureWithRule("deployment_retry_failed")
		c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
		return
	} else if rescheduled {
		recordAudit(c, "重试", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status), services.AuditResultPart("deployment_retry")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Deployment retry triggered"})
		return
	}

	qm := services.GetCAQueueManager()
	if qm == nil {
		services.Logf("error", "Manual retry enqueue failed for job %d: CA queue manager not initialized", id)
		auditFailureWithRule("queue_unavailable")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA queue manager not initialized"})
		return
	}
	// cert_jobs.domain 按排序后的规范形式存储，而 lb_rules.domain 保留用户输入顺序，
	// 规则侧用 joined+reversed 双形式匹配（ACME 域名至多根域+www 两个）。
	reversedDomain := reversedCertJobDomain(domain)
	if retryCertJobPreEnqueueHook != nil {
		retryCertJobPreEnqueueHook(id)
	}
	_, changed, err := qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
		result, err := db.DB.Exec(`UPDATE cert_jobs
			SET status='queued', message='重新排队签发', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now')
			WHERE id=? AND status=? AND EXISTS (
				SELECT 1 FROM lb_rules
				WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
			)`, id, status, ruleID, domain, reversedDomain)
		if err != nil {
			return id, false, err
		}
		rowsAffected, err := result.RowsAffected()
		return id, rowsAffected != 0, err
	})
	if err != nil {
		services.Logf("error", "Manual retry enqueue failed for job %d: %v", id, err)
		auditFailureWithRule("enqueue_failed")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to enqueue retry"})
		return
	}
	if !changed {
		// SELECT(:254) 与 UPDATE 之间状态可能被 worker 流转（如 failed→creating_account），
		// 导致 0 行影响；此时归因是并发竞争而非规则禁用，重读当前状态区分文案。
		var currentStatus string
		scanErr := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&currentStatus)
		if errors.Is(scanErr, sql.ErrNoRows) {
			// 行被并发删除（DeleteRule/DeleteCertJob）时归因 404 而非 500
			// （对齐 DeleteCertJob 三分归因）。
			auditFailureWithRule("job_not_found")
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
			return
		}
		if scanErr != nil {
			// 重读失败属瞬时 DB 错误（SQLITE_BUSY 等），归因为规则禁用会误导用户，
			// 显式区分 500。
			services.Logf("error", "RetryCertJob reread job %d status failed: %v", id, scanErr)
			auditFailureWithRule("status_read_failed")
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取任务状态失败"})
			return
		}
		if currentStatus != status {
			auditFailureWithRule("state_changed")
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务状态已变更，请刷新后重试"})
			return
		}
		// EnqueueIfActive 的在途命中同样走!changed 且重读
		// 状态未变，需优先归因"任务正在队列中"，避免误导为规则禁用/配置变更。
		if qm.IsJobActive(id) {
			auditFailureWithRule("in_flight")
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务正在签发队列中，请勿重复操作"})
			return
		}
		auditFailureWithRule("not_retryable")
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务关联规则已禁用、证书配置已变更或队列已暂停"})
		return
	}
	// 手动重试入队成功=有在途证书工作——唤醒 cert-waiting-ca
	// （默认调度关闭，waiting_ca 冷却重排/滞留重入队的唯一属主；此前重试
	// 绕过单点唤醒，任务滞留至 cert-reconcile 周期至多 6h）。
	// 入队成功即真实工作，唤醒入口不重查活跃态（队列可能已快速失败）。
	services.WakeCertWaitingCAForEnqueuedJob()
	auditParts := []string{services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status)}
	if cooldownActive && forceRetry {
		// 越过冷却必须可见（运维逃生通道的留痕义务）；冷却已到期时不记。
		auditParts = append(auditParts, "手动越过 CA 冷却")
	}
	if renewalAttempts > 0 {
		// 重试会把 renewal_attempts 归零（最大重试预算对人工操作重新计）——留痕
		auditParts = append(auditParts, fmt.Sprintf("重试预算已重置（原重试次数 %d）", renewalAttempts))
	}
	auditParts = append(auditParts, services.AuditResultPart("queued"))
	recordAudit(c, "重试", "证书任务", services.FormatAuditDetail(auditParts...))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Retry triggered"})
}

// deploymentRetryFailureResponse 把「手动触发部署重试」登记失败映射为
// HTTP 状态与文案：busy/blocked/inactive 都是可行动冲突（窗口已推进、自动
// 部署会接手），其余为 500。签发端点与证书任务重试端点共用本映射。
func deploymentRetryFailureResponse(err error) (int, string) {
	switch {
	case errors.Is(err, services.ErrCertificateDeploymentRetryBusy):
		return http.StatusConflict, "上一次部署回调仍在退出中，已登记自动部署，稍后自动执行"
	case errors.Is(err, services.ErrCertificateDeploymentRetryBlocked):
		return http.StatusConflict, "规则证书操作被屏障阻塞（规则正在删除或更新），已登记自动部署，请稍后重试"
	case errors.Is(err, services.ErrCertificateQueueInactive):
		status, message := certEnqueueErrorResponse("部署重试未触发", err)
		return status, message + "；已登记自动部署，恢复后自动执行"
	}
	return http.StatusInternalServerError, "触发重新部署失败；已登记自动部署，稍后自动执行"
}

// certJobDeploymentRetryTarget 记录「锁内已推进部署窗口、待锁外登记立即部署」
// 的目标（批量签发用）。登记本身不得在 caddyOpMu 临界区内执行。
type certJobDeploymentRetryTarget struct {
	jobID  int
	ruleID string
	// domain 保留请求/规则原始形态，仅用于批量失败文案归因。
	domain string
}

// markDownloadedCertJobDeploymentPending 是「证书材料已落库、只差部署」快速
// 路径的锁内一半：任务处于部署生命周期（JobLifecycle=downloaded，即
// downloaded/cleanup_dns/cleanup_warning，与 requeueCanceledJob、启动恢复
// requeueNonTerminalCertJobs 同口径）、证书材料在库且关联规则仍处自动签发
// 状态时，只把部署窗口推到 now 并如实改写消息——不做任何调度器交互。
// 返回 false 表示不适用（无材料/状态已变/规则失效），调用方回落重新入队语义。
//
// 登记立即部署由 registerDownloadedCertJobDeploymentRetry 在锁外完成：
// scheduleDeploymentRetry 对同 jobID 串行化（先取消挂起 timer、再对在途部署
// 回调做有界等待），而在途回调自身要取 caddyOpMu 完成规则写/Caddy 应用——
// 持锁登记会互等到 busy 超时（30-60s）。RequeueCanceledJob/cleanup_* 行的
// 签发 worker 已结束（材料已落库），真正的并发面只有部署回调；状态集放宽
// 不放宽并发面（DeployLock + 终态 CAS 仍是最后防线）。
func markDownloadedCertJobDeploymentPending(id int, ruleID, domain string) (bool, error) {
	reversedDomain := reversedCertJobDomain(domain)
	result, err := db.DB.Exec(`UPDATE cert_jobs
		SET deployment_available_after=datetime('now'), message='等待重新部署', updated_at=datetime('now')
		WHERE id=? AND status IN (`+services.DeploymentLifecycleJobStatusSQL+`)
		  AND `+services.CertJobMaterialPredicateSQL("")+`
		  AND EXISTS (
			SELECT 1 FROM lb_rules
			WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
		  )`, id, ruleID, domain, reversedDomain)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rowsAffected > 0, nil
}

// registerDownloadedCertJobDeploymentRetry 是上述快速路径的锁外一半：登记
// 立即部署 timer。调用方必须已释放 caddyOpMu（见
// markDownloadedCertJobDeploymentPending 的锁序说明）。
// deployment_available_after=now 仍可供服务恢复后的补扫接管；但只有实际
// 登记了立即 timer 才允许上层报告「已触发」，停止/忙状态必须返回 409。
// 经 certJobDeploymentRetryRegistrar 单点（生产=RetryCertificateDeploymentNow，
// 测试注入）——签发/重试/删除恢复三个入口共用同一登记缝。
func registerDownloadedCertJobDeploymentRetry(id int, ruleID string) error {
	if err := certJobDeploymentRetryRegistrar(id, ruleID); err != nil {
		// 立即 timer 登记失败时上方 UPDATE 已把消息写成「等待重新部署」，
		// 与 409/500 响应矛盾（报文说失败、DB 说已重排）。窗口推进保留
		// （启动恢复/周期补扫会接手，可用性收益不变），文案改为如实描述
		// 自动接管；响应侧同步点明「已登记自动部署」。
		if _, updateErr := db.DB.Exec(`UPDATE cert_jobs SET message=?, updated_at=datetime('now') WHERE id=? AND status IN (`+services.DeploymentLifecycleJobStatusSQL+`)`, "部署重试未触发，等待自动部署", id); updateErr != nil {
			return errors.Join(err, updateErr)
		}
		return err
	}
	return nil
}

// certJobRetryCooldown 是重试冷却通用策略的 handlers 侧入口——策略单源在
// services.CertJobRetryCooldown（任务监控证书行与证书任务列表必须同口径）。
func certJobRetryCooldown(status string) (time.Duration, bool) {
	return services.CertJobRetryCooldown(status)
}

// certJobRetryRemainingSeconds 是「此刻剩余冷却（秒）」的 handlers 侧入口：
// 通用窗口按 updated_at（缺失回退 created_at）扣减，waiting_ca 并入 CA 限流
// 退避窗口（1–3h，远晚于通用冷却）。策略单源在
// services.CertJobRetryRemainingSeconds——列表下发值与任务监控证书行共用同一
// 判据（0=现在可重试，null=永久不可重试），不得各写一份。
func certJobRetryRemainingSeconds(status string, updatedAt, createdAt, caAvailableAfter sql.NullTime, now time.Time) (int64, bool) {
	return services.CertJobRetryRemainingSeconds(status, updatedAt, createdAt, caAvailableAfter, now)
}

// certJobRetryBlocked 返回任务是否被重试门拦截，以及应返回的 HTTP 状态码。
// 429 =「稍后重试可成功」（执行中/冷却），409 =「永久条件不可重试」（已退役）。
//
// 通用冷却窗口计算必须复用 services.CertJobRetryRemaining（下发剩余秒/任务
// 监控证书行同一判据）——handlers 自算 updated_at 回退与 fail-closed 会与
// 策略源各自漂移（窗口变更后文案说谎）。CA 退避窗口不在本门内：它由
// certJobCAcooldownActive 单独判定，force 才能越过，传入零值 NullTime 使
// CertJobRetryRemaining 只看通用窗口。
func certJobRetryBlocked(status string, updatedAt, createdAt sql.NullTime, now time.Time) (bool, int, string) {
	window, retryable := certJobRetryCooldown(status)
	if !retryable {
		// 永久条件不得用 429（SDK/前端会按限流退避轮询）。规则仍启用但任务行
		// 已退役（历史残留/脏快照）时，唯一恢复路径是让规则重新解析证书任务：
		// 文案必须给出可执行指引，而不是让用户以为需要等冷却。
		return true, http.StatusConflict, "已退役的证书任务不能重试；请先禁用再启用该规则以重新创建签发任务"
	}
	remaining, retryable := services.CertJobRetryRemaining(status, updatedAt, createdAt, sql.NullTime{}, now)
	if retryable && remaining > 0 {
		if status == "failed" {
			return true, http.StatusTooManyRequests, fmt.Sprintf("失败后请等待 %d 分钟再重试", int(window/time.Minute))
		}
		message := "任务正在执行中，请稍后重试"
		// 部署生命周期（downloaded/cleanup_dns/cleanup_warning）签发已完成（证书在库），
		// 停在部署退避窗口——复用在途文案会误导用户以为签发流程卡住，单列部署口径。
		// 冷却到期后再点重试 = 立即重排部署（不重签）。
		if services.JobLifecycle(status) == services.JobLifecycleDownloaded {
			message = "证书已下载完成，正在等待部署生效；稍后可重试以立即重新部署（不会重新签发）"
		}
		return true, http.StatusTooManyRequests, message
	}
	return false, 0, ""
}

// certJobCAcooldownActive 报告任务是否仍处于 CA 限流退避窗口（waiting_ca 且
// ca_available_after 未到期）。「任务重试」与「手动触发签发」两个入口必须共用
// 本判据：同状态同语义却一个要求 force、另一个直接重排，会让规则列表的
// 「重新签发」静默越过冷却、清空 ca_available_after 并继续消耗 CA 配额。
// 策略单源在 services.CertJobCAcooldownActive。
func certJobCAcooldownActive(status string, caAvailableAfter sql.NullTime, now time.Time) bool {
	return services.CertJobCAcooldownActive(status, caAvailableAfter, now)
}

// certJobCAcooldownMessage 是 CA 冷却拦截的统一文案（availableAfter=冷却到期
// 时刻），两个入口的 429 文案必须一致，避免用户以为只有任务重试受限。
// 剩余秒复用 services.CertJobRetryCooldownSeconds（向上取整，<1s 下发 1）——
// 门禁与文案必须用同一 now：原实现对墙钟 Round，使被门禁判定为「冷却中」的
// 任务在下发侧显示「剩余约 0s」，引导用户点一次必然 429 的重试。
func certJobCAcooldownMessage(availableAfter, now time.Time) string {
	seconds := services.CertJobRetryCooldownSeconds(availableAfter.Sub(now))
	return fmt.Sprintf("CA 限流冷却未到期（剩余约 %s）。冷却到期后将自动重排；确需立即重签请确认后强制重试（可能再次被 CA 拒绝）", time.Duration(seconds)*time.Second)
}

// reversedCertJobDomain 交换双域名任务的域名顺序：cert_jobs.domain 存排序
// 规范形式，lb_rules.domain 保留用户输入顺序，匹配需同时覆盖两种排列。
// 单源收敛至 services.ReversedCertJobDomain（与
// rules.reversedACMEDomainForm 同实现，两侧委托）。
func reversedCertJobDomain(domain string) string {
	return services.ReversedCertJobDomain(domain)
}

// certJobDeploymentRetryRegistrar 是「登记立即部署重试」的入口。生产恒为
// services.RetryCertificateDeploymentNow；测试缝用于断言删除失败恢复路径
// 确实重新登记了部署（删除路径已取消挂起的 timer）。
var certJobDeploymentRetryRegistrar = services.RetryCertificateDeploymentNow

// certJobDeleteGuard 返回该状态任务在关联规则仍处自动签发状态时是否受 409
// 守卫及对应文案。disabled 是已退出自动签发链的唯一可删除状态；其余状态
// 一律默认受守卫，避免新增在途状态时再次形成断链旁路。
func certJobDeleteGuard(status string) (bool, string) {
	switch status {
	case "disabled":
		return false, ""
	case "issued", "downloaded":
		return true, "该任务持有有效证书且关联规则仍在自动签发状态，删除后自动续签将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"
	case "failed", "waiting_ca", "queued":
		return true, "该任务仍在自动签发链中（等待签发或等待重试），且关联规则仍在自动签发状态，删除后自动签发将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"
	default:
		return true, "该任务仍在自动签发链中（正在执行或清理 DNS），且关联规则仍在自动签发状态，删除后自动签发将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"
	}
}

func (h *Handlers) DeleteCertJob(c *gin.Context) {
	// 门必须早于 caddyOpMu：导入会话全程持有该锁，排队等待后再按陈旧 id 落库
	// 等价于「导入完成后被旧请求改写导入结果」（导入全量重插 cert_jobs 并保留
	// 原 id，删除会命中导入后同 id 的另一条任务，且可能连带删掉刚物化的证书
	// 文件）。与 retryCertJobByID 共用同一探测。
	if configImportBusy() {
		recordAudit(c, "删除失败", "证书任务", services.FormatAuditDetail(services.AuditResultPart("import_in_progress")))
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "配置导入进行中，暂不能删除证书任务"})
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		recordAudit(c, "删除失败", "证书任务", services.FormatAuditDetail(services.AuditResultPart("invalid_id")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	// 失败出口审计（同 retryCertJobByID）：本路由与重试同为 AuditPolicyExplicit，
	// 中间件不自动记审计——被拒/失败的删除尝试必须可追溯，且 detail 只放固定
	// 归因，底层错误（SQL/文件系统）只进运行日志。
	auditFailure := func(result string) {
		recordAudit(c, "删除失败", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditResultPart(result)))
	}
	// TOCTOU：守卫读规则 enabled 状态后、删除前，EnableRule
	// （持 caddyOpMu）可完成启用并恢复任务，守卫放行被竞态绕过。caddyOpMu
	// 覆盖 查询→守卫→disabled 翻转→删除 全程（取消已移出，见下方取消点），
	// 与 EnableRule 互斥：
	// 删除先完成则 EnableRule 查不到任务行，走 EnableCertJobCreate 重建
	// （续签链不断）；EnableRule 先完成则守卫读到 enabled=1 返回 409。
	// 不变量：'disabled' 对 worker 是终态——所有 worker 侧
	// transitionJob 的 from 列表均排除 'disabled'，翻转后不会被周期路径复活。
	// caqueue.EnqueueIfActive 的调用方并非全部持锁：RetryCertJob 持
	// certJobOperationLock；本函数失败恢复、规则写路径与手工签发
	// （IssueCertificate，自此定向/批量两分支全程持 caddyOpMu）持
	// caddyOpMu；四个周期路径（requeueStrandedJobs/requeueWaitingCAJobs/
	// requeueNonTerminalCertJobs/renewExpiringCertificates）无锁调用——其
	// UPDATE 均按旧状态 CAS 或 from 列表排除 'disabled'，与翻转交错时命中
	// 0 行（先于翻转→翻转 CAS 失败；翻转后→0 行；删除后→行不存在），
	// 语义自洽。
	// caddyOpMu 覆盖 查询→守卫→disabled 翻转
	// →删除 全程（与 EnableRule 的互斥域不变，翻转与 DELETE 仍同一临界区）；
	// 在途取消等待（qm.CancelJob ≤30s）移出临界区（见下方取消点注释），
	// 本函数改手动配对解锁。
	h.caddyOpMu.Lock()
	operationLock := certJobOperationLock(id)
	operationLock.Lock()
	// per-job 锁改为手动配对——失败恢复分支必须在不持有
	// operationLock 的前提下重取 caddyOpMu（锁序铁律：先 caddyOpMu 后
	// operationLock，见恢复点注释），defer 只能通过本闭包释放。
	operationLockHeld := true
	releaseOperationLock := func() {
		if operationLockHeld {
			operationLock.Unlock()
			operationLockHeld = false
		}
	}
	defer releaseOperationLock()
	var ruleID, domain, status, certPEM, keyPEM string
	var caProviderID int
	if err := db.DB.QueryRow("SELECT rule_id, domain, status, COALESCE(ca_provider_id,0), COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id = ?", id).Scan(&ruleID, &domain, &status, &caProviderID, &certPEM, &keyPEM); err != nil {
		h.caddyOpMu.Unlock()
		result := "query_failed"
		if errors.Is(err, sql.ErrNoRows) {
			result = "job_not_found"
		}
		auditFailure(result)
		dbQueryNotFound(c, err, "Job not found", "DeleteCertJob query job")
		return
	}
	// 规则仍在自动签发状态时，删除任何未退役
	// 任务都会让纯周期路径失去续签/签发入口（CreateOrRequeueCertJob 仅由规则
	// 写路径调用），因此 issued/downloaded、等待态、在途执行态与 cleanup_* 全部
	// 409 显式拒绝；运维可先禁用规则或切换证书来源后再删除。disabled 为退役
	// 终态，删除即清理。中断卡死尝试应使用重试/禁用规则流程，而不是删除唯一
	// 任务行。
	// 已知竞态：DeleteRule drain 超时后的后台补偿（不持
	// caddyOpMu）在退避窗口内按规则快照 DELETE+INSERT 恢复 cert_jobs，
	// 可能复活窗口内被本函数删除的行——恢复是保守选择（复活行来自规则自身
	// 快照时代，续签链保持完整；退避有界，窗口过后可再次删除）。
	if guarded, message := certJobDeleteGuard(status); guarded {
		var active int
		if err := db.DB.QueryRow(`SELECT COUNT(1) FROM lb_rules
			WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns'
			  AND lower(replace(domain,' ','')) IN (?,?)`,
			ruleID, domain, reversedCertJobDomain(domain)).Scan(&active); err != nil {
			h.caddyOpMu.Unlock()
			auditFailure("rule_state_read_failed")
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule state"})
			return
		}
		if active > 0 {
			h.caddyOpMu.Unlock()
			auditFailure("guarded_active_rule")
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: message})
			return
		}
	}
	if deleteCertJobPreDisableHook != nil {
		deleteCertJobPreDisableHook(id)
	}
	result, err := db.DB.Exec("UPDATE cert_jobs SET status='disabled', updated_at=datetime('now') WHERE id=? AND status=?", id, status)
	if err != nil {
		h.caddyOpMu.Unlock()
		auditFailure("disable_failed")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to disable job"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		h.caddyOpMu.Unlock()
		auditFailure("disable_verify_failed")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to verify disabled job"})
		return
	}
	if rowsAffected != 1 {
		// SELECT/守卫与 disabled 翻转之间 worker 可能推进状态（放行
		// 的在途态），CAS 命中 0 行属并发竞争而非服务器故障——重读区分归因（对齐
		// RetryCertJob 的 409+重读模式）：行仍在 → 409 刷新重试；行已消失 → 404
		// （与本函数 DELETE 后 0 行的缺失语义一致）；重读失败（瞬时 DB 错误）→ 500。
		var currentStatus string
		scanErr := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&currentStatus)
		if errors.Is(scanErr, sql.ErrNoRows) {
			h.caddyOpMu.Unlock()
			auditFailure("job_not_found")
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
			return
		}
		if scanErr != nil {
			h.caddyOpMu.Unlock()
			services.Logf("error", "DeleteCertJob reread job %d status failed: %v", id, scanErr)
			auditFailure("status_read_failed")
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取任务状态失败"})
			return
		}
		h.caddyOpMu.Unlock()
		auditFailure("state_changed")
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务状态已变更，请刷新后重试"})
		return
	}
	// 取消移出全局 CaddyOpLock 临界区——原顺序
	// 翻转→取消→删除使取消的在途等待（qm.CancelJob ≤30s）让全局 Caddy 写
	// 路径排队（与规则域名迁移同型等待环）。临界区=守卫→翻转→
	// DELETE（翻转与 DELETE 同一临界区、与 EnableRule 互斥）；
	// 顺序对调（删除→取消）依据：worker 全部状态迁移按旧态 CAS 且
	// from 列表排除 'disabled'，删除窗内在途执行不可能复活/改写行；取消先于
	// 失败恢复路径（CancelJob 会清 pending 并取消部署重试——先恢复后取消会把
	// 恢复重入队的条目清掉，恢复语义要求先取消）。per-job operationLock 在
	// 取消等待期间仍持有：等待期间同任务 Retry/重复 Delete 保持互斥；失败
	// 恢复点按锁序（先 caddyOpMu 后 operationLock）释放并按规范顺序重取。
	result, err = db.DB.Exec("DELETE FROM cert_jobs WHERE id = ?", id)
	if err == nil {
		// 删除成功后物化文件可能成为孤儿（含私钥）：规则已无任何仍持有可用材料
		// 的任务行时一并回收。判定与删除同处 caddyOpMu 临界区——与 EnableRule
		// 的建任务/渲染物化互斥，避免「判定无材料 → 并发启用重建任务 → 文件被删」。
		cleanupOrphanedCertMaterialAfterJobDelete(ruleID)
	}
	h.caddyOpMu.Unlock()
	cancelCertJob(id)
	deploymentRegistrationPending := false
	if err != nil {
		deleteErr := err
		// 失败恢复重取 caddyOpMu：恢复写与 EnableRule 的 EnableCertJobCreate
		//（无 CAS 写）互斥需持锁；重取窗口内 EnableRule 可见 disabled
		// 行并 Resume——恢复 CAS（status='disabled'）0 行命中→「恢复已跳过」
		// 并入 deleteErr（500 如实呈现，删除本就失败；行存活+启用=一致终态）。
		// 锁序铁律=先 caddyOpMu 后 operationLock（与入口
		// 同序）。此处若在持 operationLock 时反向取 caddyOpMu，与同 id 连点/同桶
		// （id%64）并发删除构成 AB-BA：对方先取到 caddyOpMu 后在桶锁排队 → 双向
		// 互等，且 caddyOpMu 被永久占用（规则/配置写、Caddy 启停、证书部署
		// reload 全部挂起，只能重启进程）。恢复写与 EnableRule 的
		// EnableCertJobCreate（无 CAS 写）互斥仍需 caddyOpMu：先释放 per-job 锁
		// 再按规范顺序重取——窗口内同任务 Retry 对 disabled 恒 409、重复 Delete
		// 走 CAS 0 行的「已被并发移离 disabled」归因，语义自洽。
		releaseOperationLock()
		h.caddyOpMu.Lock()
		operationLock.Lock()
		operationLockHeld = true
		if deleteCertJobPreRestoreHook != nil {
			deleteCertJobPreRestoreHook(id)
		}
		if services.JobLifecycle(status) == services.JobLifecycleDownloaded && services.CertJobMaterialUsable(status, certPEM, keyPEM) {
			// 与 caqueue requeueCanceledJob 同口径：部署生命周期
			// （downloaded/cleanup_dns/cleanup_warning）+ 证书材料的任务停在部署
			// 窗口——转 'queued' 会丢弃已签发证书并触发整轮重签（Issue 快速路径
			// 只认 issued/downloaded）。原地恢复 'downloaded' 并把重试窗口推到
			// now；删除路径的 cancelCertJob 已取消挂起的部署 timer，恢复成功后
			// 必须显式重新登记立即部署（见下方 deploymentRegistrationPending），
			// 登记失败由启动恢复/周期补扫兜底。
			// 恢复带 status='disabled' 守卫——行在删除窗口
			// 内被并发移离 disabled 时不得覆写其新状态；命中 0 行并入 deleteErr。
			if res, restoreErr := db.DB.Exec("UPDATE cert_jobs SET status='downloaded', deployment_available_after=datetime('now'), message='删除失败，等待恢复部署', updated_at=datetime('now') WHERE id=? AND status='disabled'", id); restoreErr != nil {
				deleteErr = errors.Join(deleteErr, restoreErr)
			} else if n, _ := res.RowsAffected(); n == 0 {
				deleteErr = errors.Join(deleteErr, fmt.Errorf("任务 %d 已被并发移离 disabled，恢复已跳过", id))
			} else {
				deploymentRegistrationPending = true
			}
		} else if status == "issued" || status == "failed" {
			// 同上方守卫口径。
			if res, restoreErr := db.DB.Exec("UPDATE cert_jobs SET status=?, updated_at=datetime('now') WHERE id=? AND status='disabled'", status, id); restoreErr != nil {
				deleteErr = errors.Join(deleteErr, restoreErr)
			} else if n, _ := res.RowsAffected(); n == 0 {
				deleteErr = errors.Join(deleteErr, fmt.Errorf("任务 %d 已被并发移离 disabled，恢复已跳过", id))
			}
		} else if status == "disabled" {
			// disabled 是唯一「删除不受规则启用门守卫」的终态；删除失败时
			// 行必须保持 disabled（原本已退役），不得改写成 failed 制造幽灵
			// 失败行并触发额外签发。
		} else {
			qm := services.GetCAQueueManager()
			var restoreErr error
			changed := false
			if qm == nil {
				restoreErr = errors.New("CA queue manager not initialized")
			} else {
				_, changed, restoreErr = qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
					updateResult, updateErr := db.DB.Exec(`UPDATE cert_jobs SET status='queued', message='删除失败，重新排队签发', updated_at=datetime('now')
						WHERE id=? AND status='disabled' AND EXISTS (
							SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
						)`, id, ruleID, domain, reversedCertJobDomain(domain))
					if updateErr != nil {
						return id, false, updateErr
					}
					rows, rowsErr := updateResult.RowsAffected()
					return id, rows == 1, rowsErr
				})
			}
			if restoreErr != nil || !changed {
				if restoreErr == nil {
					restoreErr = errors.New("job was not restored to active queue")
				}
				// 与上方三分支同构：回退写同样带 status='disabled' 守卫——行在
				// 删除窗口内被并发移离 disabled（worker/恢复路径接管）时不得覆写
				// 其新状态；命中 0 行并入 deleteErr 留痕（500 如实呈现恢复已跳过）。
				if res, failErr := db.DB.Exec("UPDATE cert_jobs SET status='failed', message='删除失败且恢复队列失败', updated_at=datetime('now') WHERE id=? AND status='disabled'", id); failErr != nil {
					restoreErr = errors.Join(restoreErr, failErr)
				} else if n, rowsErr := res.RowsAffected(); rowsErr != nil {
					restoreErr = errors.Join(restoreErr, rowsErr)
				} else if n == 0 {
					restoreErr = errors.Join(restoreErr, fmt.Errorf("任务 %d 已被并发移离 disabled，failed 回退已跳过", id))
				}
				deleteErr = errors.Join(deleteErr, restoreErr)
			} else {
				// 删除失败恢复重入队成功=有在途证书工作——唤醒
				// cert-waiting-ca（与 RetryCertJob/CreateOrRequeueCertJobWithChange
				// 同族收敛：全部入队成功路径必须唤醒唯一属主）。
				// 恢复重入队成功即真实工作，唤醒不重查活跃态。
				services.WakeCertWaitingCAForEnqueuedJob()
			}
		}
		h.caddyOpMu.Unlock()
		// 登记在 caddyOpMu 之外执行：scheduleDeploymentRetry 可能对在途部署
		// 回调做有界等待，持全局锁会拖住规则/配置写与 Caddy 启停。
		if deploymentRegistrationPending {
			if retryErr := certJobDeploymentRetryRegistrar(id, ruleID); retryErr != nil {
				// 窗口已推进，启动恢复/周期补扫会接手；留痕并如实并入 500 明细。
				deleteErr = errors.Join(deleteErr, fmt.Errorf("自动部署登记失败（窗口已推进，周期补扫将接手）: %w", retryErr))
			}
		}
		services.Logf("error", "DeleteCertJob failed for job %d: %v", id, deleteErr)
		auditFailure("delete_failed")
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete job"})
		return
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		// DELETE 已提交（文件清理与队列取消均已完成）：此时报 500 会让用户
		// 误以为未删除并重试（随后 404），且审计缺行。按「已删除但未校验」
		// 继续，留痕并按 200 返回。
		services.Logf("warn", "DeleteCertJob job %d：DELETE 已提交但行数校验失败（按已删除处理）: %v", id, err)
		rowsAffected = -1
	}
	if rowsAffected == 0 {
		auditFailure("job_not_found")
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
		return
	}
	auditParts := []string{services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status)}
	if rowsAffected < 0 {
		auditParts = append(auditParts, services.AuditResultPart("deleted_unverified"))
	}
	recordAudit(c, "删除", "证书任务", services.FormatAuditDetail(auditParts...))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Job deleted"})
}

func (h *Handlers) GetCertJob(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	// 详情与列表共用同一投影（certJobListItem，cert_pem 材料本体除外）——
	// 此前详情字段是列表的真子集，新消费方取 issuer/冷却码/重试次数会踩空。
	var j certJobListItem
	err = j.scanFrom(db.DB.QueryRow(certJobListSelectSQL+" WHERE j.id=?", id), time.Now(), services.GetCertExpiryThreshold())
	if dbQueryNotFound(c, err, "Job not found", "GetCertJob query job") {
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: j})
}

func (h *Handlers) GetCertJobLogs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}

	var ruleID string
	if err := db.DB.QueryRow("SELECT rule_id FROM cert_jobs WHERE id=?", id).Scan(&ruleID); dbQueryNotFound(c, err, "Cert job not found", "GetCertJobLogs query job") {
		return
	}

	logPath := certJobLogPathForRule(ruleID)
	// 按旧→新拼接轮转备份与当前文件（.5 最旧 → .1 最新，对齐写侧
	// maxRotatedFiles=5），每文件保留 128KB/500 行截断；但读取预算收敛到
	// 响应上限：从最新文件开始累计，达到 256KB 即停止读更旧文件（更旧内容
	// 必然落在尾窗之外，读了也会被裁掉）。此前 6 次读 ≈768KB/请求，100 个
	// 失败任务刷新一轮即 ~600 次读、~76MB IO。
	content, truncated, readErr := readCertJobLogTail(logPath, certJobLogMaxRotatedBackups, certJobLogsMaxResponseBytes)
	if readErr != nil {
		// 读不出与「尚无日志」必须可区分（与 services.rulelog 同口径）：
		// 恒 200 空内容会让排障把权限漂移/目录被替换误判为「没有签发记录」。
		services.Logf("warn", "读取证书任务 %d 日志失败（规则 %s，路径 %s）: %v", id, ruleID, logPath, readErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取任务日志失败"})
		return
	}

	if len(content) > certJobLogsMaxResponseBytes {
		content = content[len(content)-certJobLogsMaxResponseBytes:]
		// 丢弃首个残行：截断点落在行中间时首个片段不是完整日志行。
		if idx := strings.Index(content, "\n"); idx >= 0 {
			content = content[idx+1:]
		}
		truncated = true
	}
	if truncated {
		content = "[日志过长，仅显示最近 256KB]\n" + content
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]interface{}{"content": content, "truncated": truncated}})
}

// readCertJobLogTail 从最新（活动文件 → .1 → .2 …）逐份读取，累计达到
// budget 后停止——更旧的轮转内容只可能落在响应尾窗之外。返回值按最旧→最新
// 顺序拼接；truncated 表示确有更旧内容未读取（存在被跳过的备份文件）。
// 文件不存在不是错误（「尚无日志」是正常态），其余 I/O 错误上抛。
func readCertJobLogTail(path string, maxBackups, budget int) (string, bool, error) {
	newestFirst := make([]string, 0, maxBackups+1)
	head, err := readCertJobLogFile(path)
	if err != nil {
		return "", false, err
	}
	newestFirst = append(newestFirst, head)
	total := len(head)
	truncated := false
	for i := 1; i <= maxBackups; i++ {
		if total >= budget {
			for j := i; j <= maxBackups; j++ {
				if _, err := os.Stat(fmt.Sprintf("%s.%d", path, j)); err == nil {
					truncated = true
					break
				}
			}
			break
		}
		backup, err := readCertJobLogFile(fmt.Sprintf("%s.%d", path, i))
		if err != nil {
			return "", false, err
		}
		if backup == "" {
			continue
		}
		newestFirst = append(newestFirst, backup)
		total += len(backup)
	}
	var builder strings.Builder
	builder.Grow(total)
	for i := len(newestFirst) - 1; i >= 0; i-- {
		builder.WriteString(newestFirst[i])
	}
	return builder.String(), truncated, nil
}

// prependTaskLogRotations 按 maxBackups 把 .1～.N 逐代前置到活动日志
// 内容之前，最终顺序恒为最旧→最新→活动文件。普通任务写侧 keep=1，
// 证书任务 keep=5；调用方必须传本族真实保留数，禁止统一扫满证书代数。
// 轮转代数读失败按「该代缺失」处理并留 warn（展示型接口，不因单个历史
// 文件不可读丢掉新一代内容）。
//
// budget 是拼接后的总字节上限（响应 256KiB 预算）：累计长度已达上限即停止读
// 更旧副本，且只取该副本尾部剩余预算的部分——此前每代固定读 128KiB 并整串
// 前置拷贝，单请求最多读 ~640KiB 且在调用方最后一步才截断（多标签页轮询时
// CPU/IO 放大）。更旧内容本来就会被最终截断丢弃，语义不变。
func prependTaskLogRotations(path, content string, maxBackups, budget int) string {
	for i := 1; i <= maxBackups; i++ {
		remaining := budget - len(content)
		if remaining <= 0 {
			break
		}
		backup, err := readCertJobLogFile(fmt.Sprintf("%s.%d", path, i))
		if err != nil {
			services.Logf("warn", "读取任务日志轮转副本失败（%s.%d）: %v", path, i, err)
			continue
		}
		if len(backup) > remaining {
			// 只保留尾部：前缀（最旧内容）会被最终截断丢弃；被切断的首行由
			// 调用方的残行丢弃逻辑处理。
			backup = backup[len(backup)-remaining:]
		}
		if backup != "" {
			content = backup + content
		}
	}
	return content
}

// readCertJobLogFile 读取单个日志文件的尾部窗口（128KB/500 行）。
// 文件不存在返回 ("", nil)；其余 I/O 错误（权限、目录被替换、磁盘只读）
// 必须上抛——吞掉会让「读不出」与「无日志」不可区分。
func readCertJobLogFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("read %s: 路径是目录而非日志文件", path)
	}

	const maxBytes = 128 * 1024
	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek %s: %w", path, err)
	}

	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	data = tailLogWindow(f, data, startOffset)

	const maxLines = 500
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n"), nil
}
