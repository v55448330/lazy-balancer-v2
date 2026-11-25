package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// clusterMachineBodyLimitBytes 集群机器接口族（注册/上报/模式切换/服务控制）
// 请求体防滥用上限单源；各端点语义常量派生自它。
const clusterMachineBodyLimitBytes int64 = 16 << 10

// registerRequestMaxBytes 限制注册请求体大小：注册端点为公开机器接口
// （无 JWT/API Key 认证），超大体可撑爆审计库。
const registerRequestMaxBytes = clusterMachineBodyLimitBytes

// registrationStatusRejectionRecorder 由 middleware 包注入（middleware 导入
// handlers，反向会成环——与 apiKeyWhitelistCachePurge 同款倒置装配）：注册
// 状态轮询的 handler 级凭证拒绝经 middleware 的认证拒绝审计单源留痕
// （reason/path/ip 一分钟去重）。nil=未装配（单测直连 handlers 时静默跳过）。
var registrationStatusRejectionRecorder func(*gin.Context)

// SetRegistrationStatusRejectionRecorder 装配拒绝留痕钩子（middleware init 注册）。
func SetRegistrationStatusRejectionRecorder(recorder func(*gin.Context)) {
	registrationStatusRejectionRecorder = recorder
}

// registerAuditField 限制写入审计详情的节点字段：截断至 128B（回退合法 UTF-8
// 边界）并去除控制字符（C0、DEL 与 C1 0x80-0x9F——与
// models.NormalizeClusterNodeName 同区间），防未认证请求注入超长内容或伪造
// 日志换行。
func registerAuditField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
	if len(s) <= 128 {
		return s
	}
	cut := 128
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut]
}

func (h *Handlers) GenerateClusterRegisterToken(c *gin.Context) {
	// 与同族写端点同口径：导入窗口内写事务持库锁，此处写入会等满
	// busy_timeout 后 500（语义应为 409）。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	token, expiresAt, err := h.clusterService.GenerateRegisterToken(c.Request.Context(), int(contextUserID(c)), time.Now())
	if err != nil {
		if errors.Is(err, services.ErrNotMasterNode) {
			clusterMasterForbidden(c, err)
			return
		}
		recordAudit(c, "生成", "注册令牌", services.FormatAuditDetail(services.AuditResultPart("failure"), services.AuditRawPart(err.Error())))
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.registrationTokenGenerateFailed", err))
		return
	}
	recordAudit(c, "生成", "注册令牌", services.FormatAuditDetail(services.AuditTextPart("audit.validUntil", expiresAt.UTC().Format("2006-01-02 15:04:05 UTC")), services.AuditResultPart("success")))
	notify.Publish(notify.Event{Type: notify.EvtClusterNodeSettings, Fields: map[string]string{"1": c.GetString("username"), "2": "生成了集群注册令牌", "3": "有效期至 " + expiresAt.UTC().Format("2006-01-02 15:04:05 UTC")}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T("cluster.registrationTokenGenerated"), MessageKey: "cluster.registrationTokenGenerated", Data: gin.H{"token": token, "expires_at": expiresAt.UTC().Format(time.RFC3339)}})
}

func (h *Handlers) RegisterClusterNode(c *gin.Context) {
	// 导入窗口 fast-fail（全量替换 nodes，窗口写入会被覆盖或阻塞）。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, registerRequestMaxBytes)
	var req models.ClusterRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 与同 handler 其余失败面同源留痕（system 身份 + 来源地址）：绑定
		// 失败此前零审计，畸形/探测请求在操作审计页不可回溯。详情不含请求体。
		// 超限体积走既有 DoS 契约——拒绝但不写审计（否则大 body 泛洪可刷满
		// 审计库，见 TestRegisterClusterNode_rejects_oversized_body）。
		if !isRequestBodyTooLarge(err) {
			services.RecordAuditLog("system", "注册失败", "集群节点", services.AuditRawDetail("注册请求格式错误") /* audit-detail raw */, c.ClientIP())
		}
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.registerRequestMalformed", err))
		return
	}
	// access_url 的信任锚=服务端观测到的连接来源地址（路由器
	// SetTrustedProxies(nil)，c.ClientIP() 即直连对端，不采信转发头）——请求体
	// 自述 ip_address 只用于展示/连通性，不参与该判定。
	registration, err := h.clusterService.RegisterNode(c.Request.Context(), req, c.ClientIP(), time.Now())
	if err != nil {
		if errors.Is(err, services.ErrInvalidRegisterToken) {
			// 无效令牌路径不携带攻击者输入，详情与响应均用通用文案
			services.RecordAuditLog("system", "注册失败", "集群节点", services.AuditRawDetail("注册令牌无效") /* audit-detail raw */, c.ClientIP())
			c.JSON(http.StatusUnauthorized, clusterErrorKeyedResponse(http.StatusUnauthorized, "cluster.registrationTokenInvalid", err))
			return
		}
		if errors.Is(err, services.ErrNotMasterNode) {
			// SQL 级角色条件命中 0 行（降级竞态）→ 403，与
			// requireMaster 同文案同头形状，不折叠成 500。
			clusterMasterForbidden(c, err)
			return
		}
		if errors.Is(err, models.ErrInvalidClusterNodeName) {
			// 归一后为空的节点名属客户端可修正输入，映射 400。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(services.AuditRawPart(registerAuditField(req.Name)), services.AuditRawPart(registerAuditField(req.IPAddress)), services.AuditRawPart(err.Error())), c.ClientIP())
			clusterError(c, http.StatusBadRequest, err.Error(), err)
			return
		}
		if errors.Is(err, models.ErrMissingClusterNodeIP) {
			// 自述地址缺失且来源地址不可用：客户端需显式配置访问地址后重试。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(services.AuditRawPart(registerAuditField(req.Name)), services.AuditRawPart(err.Error())), c.ClientIP())
			clusterError(c, http.StatusBadRequest, err.Error(), err)
			return
		}
		if errors.Is(err, models.ErrInvalidClusterNodeIP) {
			// 非空自述地址非 IP 字面量（服务层直调/旧客户端绕过 binding）：
			// 与 HTTP 入口 binding ip 同判，映射 400。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(services.AuditRawPart(registerAuditField(req.Name)), services.AuditRawPart(registerAuditField(req.IPAddress)), services.AuditRawPart(err.Error())), c.ClientIP())
			clusterError(c, http.StatusBadRequest, err.Error(), err)
			return
		}
		if errors.Is(err, models.ErrInvalidClusterAccessURL) {
			// 非法访问地址同属客户端可修正输入：落 500 会让从端 SetClusterMode
			// 把它包成「向目标主节点注册失败」的 502，运维误判主节点故障。
			// 与同族入口（UpdateClusterNodeAccessURL/SetClusterMode/v2 导入）的
			// 400 口径一致；此处此前缺分支，与同文件注释矛盾。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(services.AuditRawPart(registerAuditField(req.Name)), services.AuditRawPart(registerAuditField(req.IPAddress)), services.AuditRawPart(err.Error())), c.ClientIP())
			c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.accessUrlInvalid", err))
			return
		}
		services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(services.AuditRawPart(registerAuditField(req.Name)), services.AuditRawPart(registerAuditField(req.IPAddress)), services.AuditRawPart(err.Error())), c.ClientIP())
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.nodeRegisterFailed", err))
		return
	}
	// 重复 ip:port 命中已批准节点时，upsert 会重置审批与令牌——响应与
	// 审计点名被覆盖节点，避免运营方把覆盖误认为新节点加入。
	messageKey := "cluster.registrationAccepted"
	var messageArgs []any
	// 审计名与落库值同源（同款归一函数）；失败路径保留原始值供取证。
	auditParts := []services.AuditPart{services.AuditRawPart(fmt.Sprintf("节点 %d", registration.RegistrationID)), services.AuditRawPart(registerAuditField(models.NormalizeClusterNodeName(req.Name))), services.AuditRawPart(registerAuditField(req.IPAddress)), services.AuditRawPart("等待审批")}
	if registration.OverwrittenNodeID > 0 {
		overwritten := fmt.Sprintf("已覆盖节点 #%d（%s）", registration.OverwrittenNodeID, registerAuditField(registration.OverwrittenNodeName))
		auditParts = append(auditParts, services.AuditRawPart(overwritten))
		messageKey = "cluster.registrationAcceptedOverwritten"
		messageArgs = []any{registration.OverwrittenNodeID, registerAuditField(registration.OverwrittenNodeName)}
	}
	// 自述访问地址与来源 IP 不一致时已忽略（不落库），此处显性
	// 告知——该值决定能力票据投递地址，只能由管理员显式配置。
	if registration.AccessURLIgnored {
		auditParts = append(auditParts, services.AuditRawPart("自述访问地址与来源 IP 不一致，已忽略"))
		if messageKey == "cluster.registrationAcceptedOverwritten" {
			messageKey = "cluster.registrationAcceptedOverwrittenAccessUrlIgnored"
		} else {
			messageKey = "cluster.registrationAcceptedAccessUrlIgnored"
		}
	}
	services.RecordAuditLog("system", "注册", "集群节点", services.FormatAuditDetail(auditParts...), c.ClientIP())
	c.JSON(http.StatusOK, apimsg.Envelope(0, messageKey, messageArgs...).WithData(registration))
}

func (h *Handlers) GetClusterRegistrationStatus(c *gin.Context) {
	// 参数校验先于角色门：非法 ID 恒 400，不因节点角色变化。
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.registrationIdInvalid", err))
		return
	}
	// 导入窗口 fast-fail：本端点会写 nodes（交付集群令牌，条件 UPDATE），
	// 与同族「GET 写 nodes」的 GetClusterSnapshot 及其余写端点同口径——
	// 窗口内写入会撞导入事务的全量替换，阻塞至 busy_timeout 后落 500「查询
	// 注册状态失败」（语义应为 409），或被覆盖丢失。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	// 同族机器端点（register/confirm/snapshot/waf-files/report）均有
	// 主节点门，仅本端点缺失——降级后的主节点按保留 nodes 行，残留
	// 注册行仍可被应答 approved 并重发集群令牌。权限面不扩大（令牌由 secret
	// 确定性派生），但角色门必须一致收敛。
	if !h.requireMaster(c) {
		return
	}
	status, err := h.clusterService.RegistrationStatus(c.Request.Context(), id, c.GetString("registration_secret"), time.Now())
	if err != nil {
		if errors.Is(err, services.ErrNotMasterNode) {
			clusterMasterForbidden(c, err)
			return
		}
		// 仅凭证类哨兵 401——DB 故障误映射 401 会驱使从节点走
		// 五连败轨道耗尽注册配额。
		if errors.Is(err, services.ErrNodeNotFound) || errors.Is(err, services.ErrInvalidClusterAuth) {
			// 凭证拒绝留痕（与同族机器端点 registrationAuth/confirm 同口径）：
			// 中间件验密后事务内复核仍可能拒（密钥轮换/到期），零审计会让
			// 残留凭证的枚举尝试在取证面无痕。一分钟去重由 middleware 单源承担。
			if registrationStatusRejectionRecorder != nil {
				registrationStatusRejectionRecorder(c)
			}
			c.JSON(http.StatusUnauthorized, clusterErrorKeyedResponse(http.StatusUnauthorized, "cluster.registrationCredentialInvalid", err))
			return
		}
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.registrationStatusQueryFailed", err))
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T("cluster.registrationStatusQueried"), MessageKey: "cluster.registrationStatusQueried", Data: status})
}

func (h *Handlers) ConfirmClusterRegistration(c *gin.Context) {
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	nodeName, err := h.clusterService.ConfirmRegistration(c.Request.Context(), authenticatedClusterToken(c))
	if err != nil {
		if errors.Is(err, services.ErrNotMasterNode) {
			clusterMasterForbidden(c, err)
			return
		}
		// 同 RegistrationStatus 分判。失败也留痕（与 register 一致）：注册
		// 密钥被拒/重放尝试在审计面无记录时无法回溯。
		// ConfirmRegistration 只产出 ErrNotMasterNode（已单独处理）、
		// ErrInvalidClusterAuth 与包装后的 DB 错误——ErrNodeNotFound/
		// ErrInvalidRegisterToken 两臂不可达，删除以免误导后续维护者以为
		// 服务层会产这两个哨兵。
		if errors.Is(err, services.ErrInvalidClusterAuth) {
			services.RecordAuditLog("system", "确认失败", "集群节点", services.FormatAuditDetail(services.AuditResultPart("failure")) /* audit-detail raw */, c.ClientIP())
			c.JSON(http.StatusUnauthorized, clusterErrorKeyedResponse(http.StatusUnauthorized, "cluster.registrationConfirmFailed", err))
			return
		}
		services.RecordAuditLog("system", "确认失败", "集群节点", services.FormatAuditDetail(services.AuditResultPart("failure"), services.AuditRawPart(err.Error())), c.ClientIP())
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.registrationConfirmFailed", err))
		return
	}
	services.RecordAuditLog("system", "确认", "集群节点", services.FormatAuditDetail(services.AuditTextPart("audit.nodeNamed", nodeName), services.AuditTextPart("audit.registrationSecretInvalid"), services.AuditResultPart("success")), c.ClientIP())
	c.JSON(http.StatusOK, apimsg.Envelope(0, "cluster.registrationConfirmed"))
}

func (h *Handlers) ApproveClusterNode(c *gin.Context) {
	h.clusterNodeAction(c, "审批", func(id int) error { return h.clusterService.ApproveNode(c.Request.Context(), id, time.Now()) })
}

func (h *Handlers) RejectClusterNode(c *gin.Context) {
	h.clusterNodeAction(c, "拒绝", func(id int) error { return h.clusterService.DeleteNode(c.Request.Context(), id) })
}

func (h *Handlers) DeleteClusterNode(c *gin.Context) {
	h.clusterNodeAction(c, "删除", func(id int) error { return h.clusterService.DeleteNode(c.Request.Context(), id) })
}

func (h *Handlers) UpdateClusterNodeSiteCoordinates(c *gin.Context) {
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	// 失败留痕单源：与 clusterNodeAction 同构——审计中间件对 explicit 路由
	// 无条件早退（含 4xx/5xx），本 handler 的每条失败面都必须自行补记，
	// 否则坐标保存失败（前端旧缓存提交越界坐标、节点离线、DB 故障）在操作
	// 审计页无痕，只剩 stdout。
	auditFailure := func(nodePart services.AuditPart, code string, reason services.AuditPart) {
		recordAudit(c, "更新", "集群节点", services.FormatAuditDetail(nodePart, reason, services.AuditResultPart(code)))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		// 编号未解析成功：nodeLabel 槽按「节点 <原始值>」留痕（与访问地址端点
		// 同形），失败原因槽只放结论——旧写法把整句塞进 nodeLabel 槽，
		// reason 槽重复同一句，段落错位。
		auditFailure(services.AuditTextPart("audit.nodeField", registerAuditField(c.Param("id"))), "invalid_request", services.AuditTextPart("audit.nodeIdInvalidSentence"))
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.nodeIdInvalid", err))
		return
	}
	nodeLabel := fmt.Sprintf("节点 %d", id)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, registerRequestMaxBytes)
	var req models.ClusterNodeSiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		auditFailure(services.AuditRawPart(nodeLabel), "invalid_request", services.AuditRawPart("站点坐标格式错误"))
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.siteCoordinatesMalformed", err))
		return
	}
	if req.ServerMapLat == nil || req.ServerMapLon == nil {
		auditFailure(services.AuditRawPart(nodeLabel), "invalid_request", services.AuditRawPart("必须同时提交站点纬度和经度"))
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.siteCoordinatesBothRequired", nil))
		return
	}
	if err := validateServerMapCoordinates(req.ServerMapLat, req.ServerMapLon); err != nil {
		auditFailure(services.AuditTextPart("audit.nodeNumber", id), "invalid_request", services.AuditRawPart(err.Error()))
		clusterError(c, http.StatusBadRequest, err.Error(), err)
		return
	}
	if err := h.clusterService.UpdateNodeSiteCoordinates(c.Request.Context(), id, *req.ServerMapLat, *req.ServerMapLon); err != nil {
		// 服务层降级竞态 403 与 requireMaster 门同源带头。
		if errors.Is(err, services.ErrNotMasterNode) {
			auditFailure(services.AuditRawPart(nodeLabel), "blocked", services.AuditTextPart("audit.nodeRoleDemoted"))
			clusterMasterForbidden(c, err)
			return
		}
		if errors.Is(err, services.ErrNodeNotFound) {
			auditFailure(services.AuditRawPart(nodeLabel), "failed", services.AuditRawPart("节点不存在"))
			c.JSON(http.StatusNotFound, clusterErrorKeyedResponse(http.StatusNotFound, "cluster.siteCoordinatesUpdateFailed", err))
			return
		}
		auditFailure(services.AuditTextPart("audit.nodeNumber", id), "failed", services.AuditRawPart(err.Error()))
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.siteCoordinatesUpdateFailed", err))
		return
	}
	recordAudit(c, "更新", "集群节点", services.FormatAuditDetail(
		services.AuditTextPart("audit.nodeNumber", id),
		services.AuditTextPart("audit.siteCoordinates", *req.ServerMapLat, *req.ServerMapLon),
		services.AuditResultPart("success")))
	notify.Publish(notify.Event{Type: notify.EvtClusterNodeSettings, Fields: map[string]string{
		"1": c.GetString("username"),
		"2": "更新了节点站点坐标",
		"3": fmt.Sprintf("节点 %d（纬度 %.4f，经度 %.4f）", id, *req.ServerMapLat, *req.ServerMapLon),
	}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T("cluster.nodeSiteCoordinatesSaved"), MessageKey: "cluster.nodeSiteCoordinatesSaved", Data: gin.H{
		"server_map_lat": *req.ServerMapLat,
		"server_map_lon": *req.ServerMapLon,
	}})
}

func (h *Handlers) UpdateClusterNodeAccessURL(c *gin.Context) {
	// 门控前置：导入窗口 409 / 主节点 403 必须先于请求体解析——
	// 先 bind 会让窗口内/从端请求拿到 400 解析错误而非真实门控语义。两道门
	// 幂等无副作用，clusterNodeAction 内重复执行安全。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterMachineBodyLimitBytes)
	var req models.ClusterNodeAccessURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 审计中间件对 explicit 路由无条件早退（含 4xx），绑定失败在此补记
		// ——与同族站点坐标端点同构。编号尚未解析，按路径参数留痕。
		recordAudit(c, "更新地址", "集群节点", services.FormatAuditDetail(
			services.AuditTextPart("audit.nodeNamed", registerAuditField(c.Param("id"))), services.AuditTextPart("audit.accessUrlInvalid"), services.AuditResultPart("invalid_request")))
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.accessUrlMalformed", err))
		return
	}
	h.clusterNodeAction(c, "更新地址", func(id int) error {
		return h.clusterService.UpdateNodeAccessURL(c.Request.Context(), id, req.AccessURL)
	})
	// 成功才发通知事件（clusterNodeAction 内已写响应；失败分支各自 return）。
	if c.Writer.Status() == http.StatusOK {
		notify.Publish(notify.Event{Type: notify.EvtClusterNodeSettings, Fields: map[string]string{
			"1": c.GetString("username"),
			"2": "更新了节点访问地址",
			"3": "节点 " + registerAuditField(c.Param("id")),
		}})
	}
}

func (h *Handlers) clusterNodeAction(c *gin.Context, action string, operation func(int) error) {
	// 审批/拒绝/删除共用的写端点收口——导入窗口 409 fast-fail。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	// 失败留痕单源：审批/拒绝/删除/更新地址的每条失败面都必须进操作审计
	// （与 ControlClusterNodeService 的 auditFailure 同构）。审计中间件对
	// explicit 路由无条件早退（含 5xx），handler 不补记即取证缺口。
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		recordAudit(c, action, "集群节点", services.FormatAuditDetail(services.AuditTextPart("audit.nodeIdInvalid", registerAuditField(c.Param("id"))), services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.nodeIdInvalid", err))
		return
	}
	auditFailure := func(code string, reason services.AuditPart) {
		recordAudit(c, action, "集群节点", services.FormatAuditDetail(services.AuditTextPart("audit.nodeNumber", id), reason, services.AuditResultPart(code)))
	}
	if err := operation(id); err != nil {
		// 服务层降级竞态 403 与 requireMaster 门同源带头。
		if errors.Is(err, services.ErrNotMasterNode) {
			auditFailure("blocked", services.AuditTextPart("audit.nodeRoleDemoted"))
			clusterMasterForbidden(c, err)
			return
		}
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, services.ErrNodeNotPending) {
			// 重复审批/已处理节点 409,与「不存在」404 分判。
			status = http.StatusConflict
		}
		// 非法访问地址是客户端可修正的输入问题，
		// 此前落默认 500「更新地址节点失败」，用户以为服务端故障且拿不到规则
		// 说明（同族入口 RegisterClusterNode/SetClusterMode/v2 导入均已 400）。
		if errors.Is(err, models.ErrInvalidClusterAccessURL) {
			auditFailure("invalid_request", services.AuditTextPart("audit.accessUrlNotValid"))
			c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.accessUrlInvalid", err))
			return
		}
		auditFailure("failed", services.AuditRawPart(err.Error()))
		c.JSON(status, clusterErrorKeyedResponse(status, "cluster.nodeActionFailed", err, action))
		return
	}
	recordAudit(c, action, "集群节点", services.FormatAuditDetail(services.AuditTextPart("audit.nodeNumber", id), services.AuditResultPart("success")))
	// 成功消息的动词插值按请求语言取词条（审计动作词保持 zh 字面量）——
	// 此前中文动词直达 en 模板呈「审批 node succeeded」中英混杂。
	verbKeys := map[string]string{"审批": "cluster.nodeActionApprove", "拒绝": "cluster.nodeActionReject", "删除": "cluster.nodeActionDelete", "更新地址": "cluster.nodeActionUpdateAccessUrl"}
	verb := action
	if key, ok := verbKeys[action]; ok {
		verb = apimsg.T(key)
	}
	c.JSON(http.StatusOK, apimsg.Envelope(0, "cluster.nodeActionSucceeded", verb))
}
