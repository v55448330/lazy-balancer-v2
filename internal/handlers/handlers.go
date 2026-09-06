package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

const compensationTimeout = 10 * time.Second
const minimumPasswordLength = 6

type Handlers struct {
	cfg               *config.Config
	caddyService      *services.CaddyService
	metricsService    *services.MetricsService
	syncService       *services.SyncService
	clusterService    *services.ClusterService
	caProviderService *services.CAProviderService
	removeCertFiles   func(string) error
	caddyOpMu         sync.Mutex
}

type Dependencies struct {
	Config            *config.Config
	CaddyService      *services.CaddyService
	MetricsService    *services.MetricsService
	SyncService       *services.SyncService
	ClusterService    *services.ClusterService
	CAProviderService *services.CAProviderService
}

func (h *Handlers) removeRuleCertFiles(ruleID string) error {
	if h.removeCertFiles != nil {
		return h.removeCertFiles(ruleID)
	}
	return services.RemoveCertFiles(ruleID)
}

func NewHandlers(deps Dependencies) *Handlers {
	return &Handlers{
		cfg:               deps.Config,
		caddyService:      deps.CaddyService,
		metricsService:    deps.MetricsService,
		syncService:       deps.SyncService,
		clusterService:    deps.ClusterService,
		caProviderService: deps.CAProviderService,
	}
}

func compensationContext(requestCtx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(requestCtx), compensationTimeout)
}

func passwordTooShort(password string) bool {
	return password != "" && utf8.RuneCountInString(password) < minimumPasswordLength
}

type EnableCertJobAction int

const (
	EnableCertJobCreate EnableCertJobAction = iota
	EnableCertJobKeep
	EnableCertJobResume
	EnableCertJobRetry
	EnableCertJobRenew
	EnableCertJobInProgress
)

func ShouldRenewIssuedCert(now, expiresAt time.Time, renewalDays int) bool {
	renewalTime := expiresAt.AddDate(0, 0, -renewalDays)
	return !now.Before(renewalTime)
}

func ResolveEnableCertJobAction(hasJob bool, status string, expiresAt *time.Time, now time.Time, renewalDays int) EnableCertJobAction {
	if !hasJob {
		return EnableCertJobCreate
	}
	if (status == "issued" || status == "disabled" || status == "failed") && expiresAt != nil {
		if !ShouldRenewIssuedCert(now, *expiresAt, renewalDays) {
			if status == "issued" {
				return EnableCertJobKeep
			}
			return EnableCertJobResume
		}
		if status == "issued" {
			return EnableCertJobRenew
		}
		return EnableCertJobRetry
	}
	if status == "failed" || status == "disabled" {
		return EnableCertJobRetry
	}
	return EnableCertJobInProgress
}

func boolText(value bool) string {
	if value {
		return "启用"
	}
	return "禁用"
}

// recordCaddyApplyResult persists the last apply outcome and leaves an audit
// trail. Failures keep the previous Caddy config running, so the error must
// survive restarts and async paths to stay visible to operators.
func (h *Handlers) recordCaddyApplyResult(err error) {
	if err == nil {
		if db.DB != nil {
			db.DB.Exec(`UPDATE global_config SET caddy_apply_error='' WHERE id=1 AND caddy_apply_error<>''`)
		}
		return
	}
	wrapped := fmt.Sprintf("Caddy 配置应用失败（旧配置已保留）：%v", err)
	services.Logf("error", "%s", wrapped)
	services.RecordAuditLog("system", "应用失败", "Caddy配置", wrapped, "")
	if db.DB != nil {
		db.DB.Exec(`UPDATE global_config SET caddy_apply_error=? WHERE id=1`, wrapped)
	}
}

// caddyApplyNote returns a response-message suffix describing an apply
// failure; empty string means the config applied cleanly. Callers inside an
// import session (which already holds caddyOpMu) must use
// caddyApplyNoteLocked instead — applyCaddyConfigE is not reentrant.
//
// 重载审计的三个家族（契约：触发重载必须留痕。69d809b4 曾误以为本方法
// 全覆盖而删光其余家族的手动审计，导致删除/启用规则等操作重载不留痕）：
//  1. caddyApplyNote       — 提交后从 DB 重放（security 等）：重载与审计
//     同处一行，不可能遗漏；
//  2. caddyApplyNoteLocked — 已持 caddyOpMu 的后台/会话内路径（Start/
//     Restart Caddy、导入会话内重播种）；
//  3. applyFromTxNote      — 事务内应用（rule 生命周期 ×5、UpdateConfig）：
//     重载发生在 Commit 前、审计只能落在 Commit 后，两点必然分离，由返回
//     的 note 闭包绑定，漏调即编译错误。
//
// 家族 3 的变体（不经 tx 渲染）：PutCaddyConfig（ApplyConfig 原始载荷）与
// 备份导入 ×2（协调器内应用）各自在成功尾部补记，同受契约约束。
func (h *Handlers) caddyApplyNote(c *gin.Context) string {
	if err := h.applyCaddyConfigE(); err != nil {
		recordAudit(c, "重载失败", "Caddy服务", err.Error())
		return "；但 Caddy 配置应用失败：" + err.Error()
	}
	recordAudit(c, "重载", "Caddy服务", "配置变更后自动重载")
	return ""
}

func (h *Handlers) caddyApplyNoteLocked() string {
	err := h.caddyService.GenerateAndApplyConfig()
	h.recordCaddyApplyResult(err)
	if err != nil {
		return "；但 Caddy 配置应用失败：" + err.Error()
	}
	return ""
}

// applyFromTxNote 是家族 3 的统一入口：事务内应用（ApplyConfigFromTx，
// 应用失败即回滚，DB 与运行配置不分叉）。重载发生在 Commit 之前，而提交
// 失败会回滚并恢复运行配置快照——审计必须等 Commit 成功后才落盘，否则会
// 留下从未真正生效的「重载」行。因此这里把「应用」与「审计登记」绑定在
// 同一次调用里，返回提交成功后必须调用的 note：漏调即 unused variable
// 编译错误，69d809b4 式的静默删行在此形态下不再可能。归因明细由调用点
// 提供（txReloadDetail 或固定文案）。
func (h *Handlers) applyFromTxNote(c *gin.Context, tx *sql.Tx, reloadDetail string) (func(), error) {
	// 裁定 ④'：Caddy CLI 层预检（真 validate-only，零运行时副作用）——校验
	// 输入即事务视图的最终渲染。校验器不可用时放行（记日志），事务内应用
	// 仍是最终门控。
	cliValidated := true
	if err := h.caddyService.ValidateTxRenderViaCLI(tx); err != nil {
		if !errors.Is(err, services.ErrCLIValidatorUnavailable) {
			return nil, err
		}
		cliValidated = false
		log.Printf("caddy CLI 校验器不可用，跳过预检（事务内应用仍门控）: %v", err)
	}
	if err := h.caddyService.ApplyConfigFromTx(tx); err != nil {
		// 乱填保障（2026-09-06 补充裁定）：应用失败且配置未经任何 Caddy 级
		// 校验（CLI 不可用 + 传输失败同时发生）——无法排除坏配置，标记为
		// 不可退化提交，调用方必须回滚。
		if !cliValidated && !services.IsConfigRejected(err) {
			return nil, fmt.Errorf("%w: %v", services.ErrUnvalidatedApply, err)
		}
		return nil, err
	}
	return func() { recordAudit(c, "重载", "Caddy服务", reloadDetail) }, nil
}

// txReloadDetail 生成规则生命周期路径的重载审计明细（来源 + 规则归因 + 结果）。
func txReloadDetail(source, ruleID string) string {
	return services.FormatAuditDetail(services.AuditSourcePart(source), services.AuditRulePart(ruleID), services.AuditResultPart("success"))
}

// txApplyFinish 是 finishTxApply 的收尾选项。Resource/AuditAction/AuditDetail/
// SuccessMsg 必填；SuccessStatus 默认 200；ReloadDetail 默认「配置变更后自动重载」。
type txApplyFinish struct {
	Resource      string
	AuditAction   string
	AuditDetail   string
	SuccessMsg    string
	SuccessStatus int
	Data          any
	ReloadDetail  string
}

// finishTxApply 家族 3 统一收尾（2026-09-06 裁定 ①②：只有可渲染配置可落库，
// 杜绝坏配置持久化后重启全停）。调用方完成事务内写库后调用本方法，三分支：
//
//	渲染拒绝（Caddy 4xx / 生成失败）→ 不提交（调用方 defer 回滚）+ 失败审计
//	  + 400「Caddy 配置应用失败，<Resource>未保存: <原因>」；
//	传输/系统失败（Caddy down 等）→ 退化家族 1 语义：提交 + 业务审计 + 重载失败
//	  审计 + caddy_apply_error 标记 + 200「<SuccessMsg>；但 Caddy 配置应用失败：…」；
//	成功 → 提交 + 业务审计 + 重载审计 + 200/201。
//
// 本方法自行提交或放行回滚；调用方的 rollback defer 必须容忍 ErrTxDone
// （既有各 defer 均已容忍）。返回后请求即已终结，调用方立即 return。
func (h *Handlers) finishTxApply(c *gin.Context, tx *sql.Tx, f txApplyFinish) {
	reloadNote, applyErr := h.applyFromTxNote(c, tx, reloadDetailFor(f))
	status := f.SuccessStatus
	if status == 0 {
		status = http.StatusOK
	}
	// CLI 拒绝与应用拒绝共用失败文案口径（重载审计详情由 applyFromTxNote 内的
	// note 闭包按 reloadDetailFor(f) 落盘）。
	if applyErr == nil {
		if err := tx.Commit(); err != nil {
			recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("提交事务失败", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
			return
		}
		h.recordCaddyApplyResult(nil) // 运行配置=已提交 DB，清除既往失败标记（与旧 caddyApplyNote 成功路径等价）
		recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
		reloadNote()
		c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg, Data: f.Data})
		return
	}
	if services.IsConfigRejected(applyErr) {
		// CLI 校验拒绝与 admin 4xx 同口径：不落库 + 400 + 失败审计。
		recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("Caddy 校验未通过", applyErr.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过，" + f.Resource + "未保存: " + applyErr.Error()})
		return
	}
	// 乱填保障（2026-09-06 补充裁定）：CLI 不可用 + 应用传输失败 = 未经任何
	// Caddy 级校验——不得退化提交（无法排除坏配置），回滚 + 明确提示。
	if errors.Is(applyErr, services.ErrUnvalidatedApply) {
		recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("Caddy 应用失败且 CLI 校验不可用", applyErr.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 应用失败且 CLI 校验不可用，" + f.Resource + "未保存（服务与运行配置不受影响，恢复 Caddy/CLI 后重试）: " + applyErr.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail("提交事务失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交事务失败: " + err.Error()})
		return
	}
	h.recordCaddyApplyResult(applyErr)
	recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
	recordAudit(c, "重载失败", "Caddy服务", applyErr.Error())
	c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg + "；但 Caddy 配置应用失败：" + applyErr.Error(), Data: f.Data})
}

// reloadDetailFor 返回收尾选项的重载审计明细（默认「配置变更后自动重载」）。
func reloadDetailFor(f txApplyFinish) string {
	if f.ReloadDetail != "" {
		return f.ReloadDetail
	}
	return "配置变更后自动重载"
}

// applyCaddyConfigE serializes against rule/config writes (caddyOpMu) and
// persists the apply outcome; all manual re-apply entry points must use it.
// R72 二十六次 W1-2：改用强制变体——手动重载（HTTP /caddy/reload 与 MCP
// reload_caddy）的语义就是「强制收敛」，必须能击穿 errSameConfig 短路
// （磁盘数据变化而 JSON 相同的场景），否则文档承诺的收敛能力不存在。
func (h *Handlers) applyCaddyConfigE() error {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	err := h.caddyService.GenerateAndApplyConfigForce()
	h.recordCaddyApplyResult(err)
	return err
}

// validateRulePayloadBeforeSave 是规则保存的后端字段层校验（三层校验第 2 层，
// 裁定 2026-09-06 ④'）：协议/端口/策略/域名/上游（主机/端口/权重/协议/查重/
// 启用数）/动态 DNS/健康检查/ACME 引用。Caddy 层由 applyFromTxNote 内的
// CLI 预检（真 validate-only）+ 事务内 ApplyConfigFromTx（最终门控）承担，
// 校验与应用的输入同为事务视图最终渲染——原「候选并入运行配置」的 merged
// /load 探针（validateCaddyConfigBeforeSave，运行时副作用+平行渲染双轨）已撤。
func (h *Handlers) validateRulePayloadBeforeSave(req interface{}) error {
	type requestUpstream struct {
		Host           string
		Port           int
		Weight         int
		Enabled        bool
		Protocol       string
		MaxConnections int
	}

	type requestData struct {
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		DnsServer                     string
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSSource                     string
		ACMEConfigID                  int
		CAProviderID                  int
		TLSCert                       string
		TLSKey                        string
		TLSHTTPRedirect               bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
		RequestBodyMaxSizeMB          int
		UpstreamKeepaliveTimeout      int
		ServerTokensHidden            int
		Upstreams                     []requestUpstream
	}

	var data requestData
	// 审计 B2-S1：TCP/DNS 字段从原始请求（Create/Update 两形态）提取。
	var tcpFields struct {
		enableDnsServer    bool
		tcpHealthCheckPort int
		tcpProxyProtocol   bool
		tcpTryDuration     int
		tcpTryInterval     int
	}
	switch v := req.(type) {
	case models.CreateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol
		tcpFields.tcpTryDuration = v.TCPTryDuration
		tcpFields.tcpTryInterval = v.TCPTryInterval
	case *models.CreateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol
		tcpFields.tcpTryDuration = v.TCPTryDuration
		tcpFields.tcpTryInterval = v.TCPTryInterval
	case models.UpdateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer != nil && *v.EnableDnsServer
		// LB-02：TCP 三字段指针化后直接解引用——UpdateRule 在调用本函数前已完成
		// nil→&existing 合并（rules.go 合并段），指针恒非 nil。
		tcpFields.tcpHealthCheckPort = *v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol != nil && *v.TCPProxyProtocol
		tcpFields.tcpTryDuration = *v.TCPTryDuration
		tcpFields.tcpTryInterval = *v.TCPTryInterval
	case *models.UpdateRuleRequest:
		tcpFields.enableDnsServer = v.EnableDnsServer != nil && *v.EnableDnsServer
		tcpFields.tcpHealthCheckPort = *v.TCPHealthCheckPort
		tcpFields.tcpProxyProtocol = v.TCPProxyProtocol != nil && *v.TCPProxyProtocol
		tcpFields.tcpTryDuration = *v.TCPTryDuration
		tcpFields.tcpTryInterval = *v.TCPTryInterval
	}
	var upstreams []requestUpstream

	switch r := req.(type) {
	case models.CreateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		data.CAProviderID = r.CAProviderID
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		data.RequestBodyMaxSizeMB = r.RequestBodyMaxSizeMB
		data.UpstreamKeepaliveTimeout = r.UpstreamKeepaliveTimeout
		data.ServerTokensHidden = r.ServerTokensHidden
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight,
				Enabled: u.Enabled, Protocol: u.Protocol,
				MaxConnections: u.MaxConnections,
			})
		}
		data.Upstreams = upstreams
	case models.UpdateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		if r.DynamicDNS != nil {
			data.DynamicDNS = *r.DynamicDNS
		}
		data.DnsServer = derefStr(r.DnsServer)
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = derefStr(r.HealthCheckPath)
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		if r.EnableTLS != nil {
			data.EnableTLS = *r.EnableTLS
		}
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		if r.CAProviderID != nil {
			data.CAProviderID = *r.CAProviderID
		}
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		if r.TLSHTTPRedirect != nil {
			data.TLSHTTPRedirect = *r.TLSHTTPRedirect
		}
		if r.EnableCompress != nil {
			data.EnableCompress = *r.EnableCompress
		}
		data.CompressTypes = r.CompressTypes
		if r.EnableActiveHealthCheck != nil {
			data.EnableActiveHealthCheck = *r.EnableActiveHealthCheck
		}
		data.HostHeader = derefStr(r.HostHeader)
		if r.RequestBodyMaxSizeMB != nil {
			data.RequestBodyMaxSizeMB = *r.RequestBodyMaxSizeMB
		}
		if r.UpstreamKeepaliveTimeout != nil {
			data.UpstreamKeepaliveTimeout = *r.UpstreamKeepaliveTimeout
		}
		if r.ServerTokensHidden != nil {
			data.ServerTokensHidden = *r.ServerTokensHidden
		}
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight,
				Enabled: u.Enabled, Protocol: u.Protocol,
				MaxConnections: u.MaxConnections,
			})
		}
		data.Upstreams = upstreams
	default:
		return nil
	}

	if data.Strategy == "" {
		data.Strategy = "weighted_round_robin"
	}
	if data.HealthCheckInterval == 0 {
		data.HealthCheckInterval = 10
	}
	if data.HealthCheckTimeout == 0 {
		data.HealthCheckTimeout = 2
	}
	if data.HealthCheckUnhealthyThreshold == 0 {
		data.HealthCheckUnhealthyThreshold = 3
	}
	if data.HealthCheckHealthyThreshold == 0 {
		data.HealthCheckHealthyThreshold = 2
	}
	if data.CompressTypes == "" {
		data.CompressTypes = "gzip"
	}

	if data.Protocol != "http" && data.Protocol != "tcp" {
		return fmt.Errorf("无效的协议：仅支持 http 或 tcp")
	}

	if data.ListenPort < 1 || data.ListenPort > 65535 {
		return fmt.Errorf("无效的监听端口：必须在 1-65535 之间")
	}

	httpStrategies := map[string]bool{
		"ip_hash": true, "least_conn": true,
		"random": true, "first": true, "weighted_round_robin": true,
		"cookie": true,
	}
	tcpStrategies := map[string]bool{
		"ip_hash": true, "least_conn": true,
		"random": true, "first": true, "weighted_round_robin": true,
	}
	if data.Protocol == "http" && !httpStrategies[data.Strategy] {
		return fmt.Errorf("无效的负载策略：HTTP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first / cookie")
	}
	if data.Protocol == "tcp" && !tcpStrategies[data.Strategy] {
		return fmt.Errorf("无效的负载策略：TCP 规则仅支持 weighted_round_robin / ip_hash / least_conn / random / first")
	}

	if data.Domain != "" && data.Protocol == "http" {
		domains := strings.Split(data.Domain, ",")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if !isValidDomain(d) {
				return fmt.Errorf("无效的域名格式：'%s'", d)
			}
		}
	}

	if len(data.Upstreams) == 0 {
		return fmt.Errorf("至少需要一个上游服务器")
	}

	enabledUpstreamCount := 0
	hostPortSeen := make(map[string]bool)
	for i, u := range data.Upstreams {
		if u.Host == "" {
			return fmt.Errorf("上游 #%d：主机地址不能为空", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("上游 #%d：端口 %d 无效（必须在 1-65535 之间）", i+1, u.Port)
		}
		if u.Weight < 0 {
			return fmt.Errorf("上游 #%d：权重不能为负数", i+1)
		}
		if data.Protocol == "http" {
			if u.Protocol != "" && u.Protocol != "http" && u.Protocol != "https" {
				return fmt.Errorf("上游 #%d：协议 '%s' 无效（HTTP 规则仅支持 http/https）", i+1, u.Protocol)
			}
		} else {
			if u.Protocol != "" && u.Protocol != "tcp" && u.Protocol != "tls" {
				return fmt.Errorf("上游 #%d：协议 '%s' 无效（TCP 规则仅支持 tcp/tls）", i+1, u.Protocol)
			}
		}
		if u.MaxConnections < 0 {
			return fmt.Errorf("上游 #%d：最大连接数不能为负数", i+1)
		}

		key := fmt.Sprintf("%s:%d", u.Host, u.Port)
		if hostPortSeen[key] {
			return fmt.Errorf("上游 %s:%d 重复", u.Host, u.Port)
		}
		hostPortSeen[key] = true

		if !isValidHost(u.Host) {
			return fmt.Errorf("上游 #%d：主机 '%s' 无效", i+1, u.Host)
		}

		if u.Enabled {
			enabledUpstreamCount++
		}
	}

	if enabledUpstreamCount == 0 {
		return fmt.Errorf("至少需要一个启用的上游服务器")
	}

	if data.DynamicDNS && enabledUpstreamCount > 1 {
		return fmt.Errorf("动态 DNS 模式仅支持一个启用的上游（DNS 会解析出多个 IP）")
	}
	if data.DynamicDNS && data.DnsFamily != "ipv4" && data.DnsFamily != "ipv6" && data.DnsFamily != "both" {
		return fmt.Errorf("无效的 DNS 协议栈 '%s'（仅支持 ipv4、ipv6 或 both）", data.DnsFamily)
	}

	if data.HealthCheckPath != "" && !strings.HasPrefix(data.HealthCheckPath, "/") {
		return fmt.Errorf("健康检查路径必须以 / 开头")
	}

	if data.EnableTLS && data.TLSSource == "acme_dns" {
		// R52 F-1/F-3（写侧）→ R53 发现4 共享门：0 值、悬挂 id 与引用已禁用
		// （enabled=0）配置/提供商一律 400——与签发侧 certissuer.go 的
		// AND enabled=1 口径对齐，悬挂/禁用引用会静默落库并在签发期单任务失败。
		if err := validateRuleACMEReferences(acmeReferenceInput{
			EnableTLS: data.EnableTLS, TLSSource: data.TLSSource,
			ACMEConfigID: data.ACMEConfigID, CAProviderID: data.CAProviderID,
		}); err != nil {
			return err
		}
		if data.Domain == "" {
			return fmt.Errorf("ACME DNS 证书需要填写域名")
		}
		if err := services.ValidateACMEDomains(data.Domain); err != nil {
			return err
		}
	}

	if data.HealthCheckInterval < 1 {
		return fmt.Errorf("健康检查间隔必须 ≥ 1 秒")
	}

	if data.HealthCheckTimeout < 1 {
		return fmt.Errorf("健康检查超时必须 ≥ 1 秒")
	}

	return nil
}

// clampAuditRetentionMonthsOnStartup 将存量越界 audit_retention_months 钳位到
// [1,12] 最近边界并记日志（R55 F3）：写侧已加范围校验，历史越界值（超大值使
// 年龄裁剪 datetime 越界静默失效，仅剩条数兜底）在启动时收敛。
// 注：不得移入 caddy.go——TestCaddySectionKeys_matchUpdateSQL 按文本定位
// caddy.go 内首个 "UPDATE global_config SET" 提取 UpdateConfig 的列集合。
func clampAuditRetentionMonthsOnStartup() {
	var months int
	if err := db.DB.QueryRow(`SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1`).Scan(&months); err != nil {
		log.Printf("读取日志保留月数失败，跳过启动钳位: %v", err)
		return
	}
	clamped := months
	if clamped < 1 {
		clamped = 1
	}
	if clamped > 12 {
		clamped = 12
	}
	if clamped == months {
		return
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=? WHERE id=1`, clamped); err != nil {
		log.Printf("钳位日志保留月数失败: %v", err)
		return
	}
	log.Printf("日志保留月数 %d 超出 1-12 范围，已钳位为 %d", months, clamped)
}

func (h *Handlers) ApplyConfigOnStartup() error {
	// R55 F3：存量越界 audit_retention_months 启动钳位（写侧已加 1-12 校验）。
	clampAuditRetentionMonthsOnStartup()
	// Round 29 G-3: 启动路径补存量规则校验（保存/导入/启用路径已有自环与遮蔽拦截），
	// 命中即响亮报错并记审计，但不阻断启动：单条坏规则不应拖垮整个服务，与
	// 「启动应用失败仅记日志保旧配置」的既有取舍一致（main.go 调用侧同样不退出）。
	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		services.Logf("error", "启动校验发现无效规则配置，继续启动（保留旧配置）：%v", err)
		services.RecordAuditLog("system", "启动警告", "系统配置", "启动校验发现无效规则配置："+err.Error(), "")
	}

	// Wait for Caddy to be ready (up to 10 seconds)
	maxRetries := 20
	retryDelay := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		client := &http.Client{Timeout: 2 * time.Second}
		// Round 35 I-21: 即使 err != nil，resp 也可能非 nil（如重定向），需统一关闭。
		resp, err := client.Get(strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/config/") // D5-S3：就绪探针与 GetCaddyStatus 同源取配置地址，不再硬编码 localhost:2019
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil && resp.StatusCode < 500 {
			break
		}
		time.Sleep(retryDelay)
	}

	rows, err := db.DB.Query(`SELECT caddy_id FROM lb_rules WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var caddyID string
		if err := rows.Scan(&caddyID); err != nil {
			return err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	log.Printf("Applying Caddy config on startup (enabled rules: %d)", count)
	if err := h.applyCaddyConfigE(); err != nil {
		// 2026-09-06 裁定 ③：DB 渲染被拒时回退最后已知正确配置——负载均衡
		// 可用性优先。caddy_apply_error 标记已由 applyCaddyConfigE 落下，
		// DB↔运行配置分叉对看门狗/前端横幅保持可见，等待人工修复。
		if fbErr := h.caddyService.ApplyLastKnownGood(); fbErr == nil {
			wrapped := fmt.Sprintf("启动时数据库渲染的配置被 Caddy 拒绝，已回退最后已知正确配置（负载均衡保持可用，运行配置与数据库分叉待修复）：%v", err)
			services.Logf("error", "CRITICAL: %s", wrapped)
			services.RecordAuditLog("system", "启动警告", "系统配置", wrapped, "")
			return nil
		} else {
			log.Printf("last-known-good fallback failed: %v", fbErr)
		}
		return fmt.Errorf("apply Caddy config on startup: %w", err)
	}
	services.RecordAuditLog("system", "载入", "系统配置", fmt.Sprintf("启动时从数据库载入配置并应用 Caddy；启用规则 %d 条", count), "")

	return nil
}

func (h *Handlers) validatePortFromDB(protocol string, port int, excludeCaddyID string) error {
	// Check conflict with existing rules:
	// - HTTP rules may share a port (Caddy routes by host), but cannot share with TCP.
	// - TCP rules are L4 and cannot share a port with any other rule (HTTP or TCP).
	// 仅统计启用中的规则：禁用规则不占用端口，创建/更新时不应被其阻塞；启用时
	// 本函数同样按 enabled=1 过滤，第二条禁用规则启用时会看到第一条已启用而冲突。
	var count int
	var err error
	if excludeCaddyID != "" {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND enabled = 1", port, excludeCaddyID).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND protocol = 'tcp' AND enabled = 1", port, excludeCaddyID).Scan(&count)
		}
	} else {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND enabled = 1", port).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND protocol = 'tcp' AND enabled = 1", port).Scan(&count)
		}
	}
	if err != nil {
		return fmt.Errorf("验证端口时数据库错误: %v", err)
	}

	if count > 0 {
		return fmt.Errorf("端口 %d 已被其他规则占用", port)
	}

	return nil
}
