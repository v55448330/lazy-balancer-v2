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

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// registerRequestMaxBytes 限制注册请求体大小：注册端点为公开机器接口
// （无 JWT/API Key 认证），超大体可撑爆审计库。
const registerRequestMaxBytes = 16 << 10

// registerAuditField 限制写入审计详情的节点字段：截断至 128B（回退合法 UTF-8
// 边界）并去除控制字符，防未认证请求注入超长内容或伪造日志换行。
func registerAuditField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
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
		recordAudit(c, "生成", "注册令牌", services.FormatAuditDetail(services.AuditResultPart("failure"), err.Error()))
		clusterError(c, http.StatusInternalServerError, "生成注册令牌失败", err)
		return
	}
	recordAudit(c, "生成", "注册令牌", services.FormatAuditDetail(fmt.Sprintf("有效期至：%s", expiresAt.UTC().Format("2006-01-02 15:04:05 UTC")), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "注册令牌已生成，仅显示一次", Data: gin.H{"token": token, "expires_at": expiresAt.UTC().Format(time.RFC3339)}})
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
			services.RecordAuditLog("system", "注册失败", "集群节点", "注册请求格式错误", c.ClientIP())
		}
		clusterError(c, http.StatusBadRequest, "注册请求格式错误", err)
		return
	}
	// access_url 的信任锚=服务端观测到的连接来源地址（路由器
	// SetTrustedProxies(nil)，c.ClientIP() 即直连对端，不采信转发头）——请求体
	// 自述 ip_address 只用于展示/连通性，不参与该判定。
	registration, err := h.clusterService.RegisterNode(c.Request.Context(), req, c.ClientIP(), time.Now())
	if err != nil {
		if errors.Is(err, services.ErrInvalidRegisterToken) {
			// 无效令牌路径不携带攻击者输入，详情与响应均用通用文案
			services.RecordAuditLog("system", "注册失败", "集群节点", "注册令牌无效", c.ClientIP())
			clusterError(c, http.StatusUnauthorized, "注册令牌无效或已过期", err)
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
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(registerAuditField(req.Name), registerAuditField(req.IPAddress), err.Error()), c.ClientIP())
			clusterError(c, http.StatusBadRequest, err.Error(), err)
			return
		}
		if errors.Is(err, models.ErrMissingClusterNodeIP) {
			// 自述地址缺失且来源地址不可用：客户端需显式配置访问地址后重试。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(registerAuditField(req.Name), err.Error()), c.ClientIP())
			clusterError(c, http.StatusBadRequest, err.Error(), err)
			return
		}
		if errors.Is(err, models.ErrInvalidClusterNodeIP) {
			// 非空自述地址非 IP 字面量（服务层直调/旧客户端绕过 binding）：
			// 与 HTTP 入口 binding ip 同判，映射 400。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(registerAuditField(req.Name), registerAuditField(req.IPAddress), err.Error()), c.ClientIP())
			clusterError(c, http.StatusBadRequest, err.Error(), err)
			return
		}
		if errors.Is(err, models.ErrInvalidClusterAccessURL) {
			// 非法访问地址同属客户端可修正输入：落 500 会让从端 SetClusterMode
			// 把它包成「向目标主节点注册失败」的 502，运维误判主节点故障。
			// 与同族入口（UpdateClusterNodeAccessURL/SetClusterMode/v2 导入）的
			// 400 口径一致；此处此前缺分支，与同文件注释矛盾。
			services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(registerAuditField(req.Name), registerAuditField(req.IPAddress), err.Error()), c.ClientIP())
			clusterError(c, http.StatusBadRequest, "访问地址无效", err)
			return
		}
		services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(registerAuditField(req.Name), registerAuditField(req.IPAddress), err.Error()), c.ClientIP())
		clusterError(c, http.StatusInternalServerError, "节点注册失败", err)
		return
	}
	// 重复 ip:port 命中已批准节点时，upsert 会重置审批与令牌——响应与
	// 审计点名被覆盖节点，避免运营方把覆盖误认为新节点加入。
	message := "注册成功，等待主节点审批"
	auditParts := []string{fmt.Sprintf("节点 %d", registration.RegistrationID), registerAuditField(req.Name), registerAuditField(req.IPAddress), "等待审批"}
	if registration.OverwrittenNodeID > 0 {
		overwritten := fmt.Sprintf("已覆盖节点 #%d（%s）", registration.OverwrittenNodeID, registerAuditField(registration.OverwrittenNodeName))
		auditParts = append(auditParts, overwritten)
		message = "注册成功，" + overwritten + "，等待主节点审批"
	}
	// 自述访问地址与来源 IP 不一致时已忽略（不落库），此处显性
	// 告知——该值决定能力票据投递地址，只能由管理员显式配置。
	if registration.AccessURLIgnored {
		auditParts = append(auditParts, "自述访问地址与来源 IP 不一致，已忽略")
		message += "；自述访问地址与来源 IP 不一致，已忽略，请在节点设置中显式配置访问地址"
	}
	services.RecordAuditLog("system", "注册", "集群节点", services.FormatAuditDetail(auditParts...), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: registration})
}

func (h *Handlers) GetClusterRegistrationStatus(c *gin.Context) {
	// 参数校验先于角色门：非法 ID 恒 400，不因节点角色变化。
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		clusterError(c, http.StatusBadRequest, "注册编号无效", err)
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
			clusterError(c, http.StatusUnauthorized, "注册凭证无效", err)
			return
		}
		clusterError(c, http.StatusInternalServerError, "查询注册状态失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "注册状态查询成功", Data: status})
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
			services.RecordAuditLog("system", "确认失败", "集群节点", services.AuditResultPart("failure"), c.ClientIP())
			clusterError(c, http.StatusUnauthorized, "确认集群注册失败", err)
			return
		}
		services.RecordAuditLog("system", "确认失败", "集群节点", services.FormatAuditDetail(services.AuditResultPart("failure"), err.Error()), c.ClientIP())
		clusterError(c, http.StatusInternalServerError, "确认集群注册失败", err)
		return
	}
	services.RecordAuditLog("system", "确认", "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %s", nodeName), "注册密钥已失效", services.AuditResultPart("success")), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "集群注册已确认"})
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
	auditFailure := func(nodeLabel, code, reason string) {
		recordAudit(c, "更新", "集群节点", services.FormatAuditDetail(nodeLabel, reason, services.AuditResultPart(code)))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		auditFailure("节点编号无效（"+registerAuditField(c.Param("id"))+"）", "invalid_request", "节点编号无效")
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	nodeLabel := fmt.Sprintf("节点 %d", id)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, registerRequestMaxBytes)
	var req models.ClusterNodeSiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		auditFailure(nodeLabel, "invalid_request", "站点坐标格式错误")
		clusterError(c, http.StatusBadRequest, "站点坐标格式错误", err)
		return
	}
	if req.ServerMapLat == nil || req.ServerMapLon == nil {
		auditFailure(nodeLabel, "invalid_request", "必须同时提交站点纬度和经度")
		clusterError(c, http.StatusBadRequest, "必须同时提交站点纬度和经度", nil)
		return
	}
	if err := validateServerMapCoordinates(req.ServerMapLat, req.ServerMapLon); err != nil {
		auditFailure(nodeLabel, "invalid_request", err.Error())
		clusterError(c, http.StatusBadRequest, err.Error(), err)
		return
	}
	if err := h.clusterService.UpdateNodeSiteCoordinates(c.Request.Context(), id, *req.ServerMapLat, *req.ServerMapLon); err != nil {
		// 服务层降级竞态 403 与 requireMaster 门同源带头。
		if errors.Is(err, services.ErrNotMasterNode) {
			auditFailure(nodeLabel, "blocked", "节点角色已降级")
			clusterMasterForbidden(c, err)
			return
		}
		if errors.Is(err, services.ErrNodeNotFound) {
			auditFailure(nodeLabel, "failed", "节点不存在")
			clusterError(c, http.StatusNotFound, "更新节点站点坐标失败", err)
			return
		}
		auditFailure(nodeLabel, "failed", err.Error())
		clusterError(c, http.StatusInternalServerError, "更新节点站点坐标失败", err)
		return
	}
	recordAudit(c, "更新", "集群节点", services.FormatAuditDetail(
		fmt.Sprintf("节点 %d", id),
		fmt.Sprintf("站点坐标：纬度 %.4f，经度 %.4f", *req.ServerMapLat, *req.ServerMapLon),
		services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点站点坐标已保存", Data: gin.H{
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req models.ClusterNodeAccessURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 审计中间件对 explicit 路由无条件早退（含 4xx），绑定失败在此补记
		// ——与同族站点坐标端点同构。编号尚未解析，按路径参数留痕。
		recordAudit(c, "更新地址", "集群节点", services.FormatAuditDetail(
			"节点 "+registerAuditField(c.Param("id")), "访问地址格式错误", services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, "访问地址格式错误", err)
		return
	}
	h.clusterNodeAction(c, "更新地址", func(id int) error {
		return h.clusterService.UpdateNodeAccessURL(c.Request.Context(), id, req.AccessURL)
	})
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
		recordAudit(c, action, "集群节点", services.FormatAuditDetail("节点编号无效（"+registerAuditField(c.Param("id"))+"）", services.AuditResultPart("failure")))
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	auditFailure := func(code, reason string) {
		recordAudit(c, action, "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", id), reason, services.AuditResultPart(code)))
	}
	if err := operation(id); err != nil {
		// 服务层降级竞态 403 与 requireMaster 门同源带头。
		if errors.Is(err, services.ErrNotMasterNode) {
			auditFailure("blocked", "节点角色已降级")
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
			auditFailure("invalid_request", "访问地址无效")
			clusterError(c, http.StatusBadRequest, "访问地址无效", err)
			return
		}
		auditFailure("failed", err.Error())
		clusterError(c, status, action+"节点失败", err)
		return
	}
	recordAudit(c, action, "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", id), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: action + "节点成功"})
}
