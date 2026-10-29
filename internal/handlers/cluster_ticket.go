package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GenerateClusterLoginTicket(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	// v2.1.8 决策4：集群「登录从节点」需当前 admin 已启用 MFA——未启用直接引导
	// 先去安全设置绑定；写验证开关开启时还要求 10 分钟内验证过（428 → 前端
	// 全局 step-up 弹窗验码后自动重试），票据本身即含 MFA 事实。
	// DB 读错误必须 fail-closed（无法证明已启用=拒绝），此前
	// err != nil 时条件不成立直接放行发票。
	// v2.3.0 用户裁定:OIDC 用户与本地 MFA 体系完全解耦(IdP 侧已验证二因子),
	// 两道 MFA 门仅对本地用户生效——OIDC 会话直接放行发票。
	if c.GetString("auth_method") != "oidc" {
		mfaEnabled, err := services.MFAUserEnabled(int(contextUserID(c)))
		if err != nil {
			// 失败留痕单源：审计中间件对 explicit 路由无条件早退（含 5xx），
			// 本 handler 的每条失败面必须自行补记——票据签发失败（MFA 未启用/
			// step-up 缺失/节点离线/DB 故障）此前只剩 stdout clusterError 日志。
			recordAudit(c, "生成失败", "登录票据", "读取 MFA 状态失败")
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "读取 MFA 状态失败"})
			return
		}
		if !mfaEnabled {
			recordAudit(c, "生成失败", "登录票据", "当前账号未启用 MFA，拒绝登录从节点")
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "登录从节点需先启用 MFA（在「系统设置 → 用户管理」中对自己的账号绑定）"})
			return
		}
	}
	// （用户裁决）：登录从节点每次点击都要求 MFA 验证——不再复用登录后
	// 的 10 分钟写操作宽限窗（用户实测窗口内直接跳转登录成功，与「点击登录时
	// 需要验证」的决策语义不符）。保留 60 秒宽限仅供 428 → 前端弹码 →
	// verify-step → 自动重试这一次链路闭环（重试发生在验证后的数秒内）。
	// API Key（机器身份/MCP 工具）无 mfa_ts 概念，豁免该窗口检查——MFA 是
	// 人类交互式登录的第二因子，API Key 已有自身的密钥管理边界。
	if c.GetString("auth_type") == "jwt" && c.GetString("auth_method") != "oidc" {
		mfaTs, _ := c.Get("mfa_ts")
		if ts, ok := mfaTs.(float64); !ok || time.Since(time.Unix(int64(ts), 0)) >= 60*time.Second {
			recordAudit(c, "生成失败", "登录票据", "缺少有效的 MFA 验证（step-up 未完成）")
			c.AbortWithStatusJSON(http.StatusPreconditionRequired, gin.H{"code": 428, "message": "MFA_STEP_UP_REQUIRED", "detail": "登录从节点需要 MFA 验证"})
			return
		}
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		recordAudit(c, "生成失败", "登录票据", services.FormatAuditDetail("节点编号无效（"+registerAuditField(c.Param("id"))+"）", services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	response, err := h.clusterService.GenerateLoginTicket(c.Request.Context(), models.ClusterLoginTicketClaims{
		UserID: int(contextUserID(c)), Username: c.GetString("username"), AuthMethod: c.GetString("auth_method"), NodeID: nodeID,
	}, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		message := "生成登录票据失败"
		auditCode := "failed"
		auditReason := err.Error()
		if errors.Is(err, services.ErrNotMasterNode) {
			c.Header("X-LB-Error-Code", masterRequiredErrorCode)
			status = http.StatusForbidden
			message = err.Error()
			auditCode = "blocked"
			auditReason = "节点角色已降级"
		}
		if errors.Is(err, services.ErrNodeNotFound) {
			// 节点不存在属客户端寻址错误,与同族端点
			// (cluster_registration.go:151、cluster_service.go:71、
			// cluster_sync.go:135)的 ErrNodeNotFound→404 口径对齐。
			status = http.StatusNotFound
		}
		if errors.Is(err, services.ErrNodeOffline) {
			// 已批准但未上报/已离线是「现在不可达」而非
			// 「不存在」——409 + 可行动文案，运营方据此检查从节点进程/网络。
			status = http.StatusConflict
			message = "目标从节点尚未上报或已离线，请确认从节点在线后重试"
		}
		if errors.Is(err, services.ErrNodeTokenPending) {
			// 已批准但集群令牌尚未交付（从节点还没轮询注册状态）：节点存在、
			// 只是暂不可签发——409 + 单源文案，不得落成 404「节点不存在」把
			// 排障引向「是否被删除」。
			status = http.StatusConflict
			message = err.Error()
		}
		recordAudit(c, "生成失败", "登录票据", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), auditReason, services.AuditResultPart(auditCode)))
		clusterError(c, status, message, err)
		return
	}
	// 审计带节点名(与服务控制事件同格式「节点 %d（%s）」,:ID 必留,
	// nodes.name 无 UNIQUE,仅名无法定位行)。
	recordAudit(c, "生成", "登录票据", services.FormatAuditDetail(fmt.Sprintf("节点 %d（%s）", nodeID, response.NodeName), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, response)
}

func (h *Handlers) TicketLogin(c *gin.Context) {
	var req models.ClusterLoginTicketRequest
	if !guardAuthJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		recordTicketLoginFailure(c, "", "invalid_request")
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 装配缺失 fail-closed 必须晚于体积/格式门：公开端点的 413 预检是请求
	// 语义的前置契约（先拦超大体积，再判服务可用性），与 login 端点同序。
	if !h.requireClusterService(c) {
		return
	}
	claims, user, passwordVersion, err := h.clusterService.ValidateLoginTicket(c.Request.Context(), req.Ticket, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		reason := "database_error"
		if errors.Is(err, services.ErrInvalidLoginTicket) {
			status = http.StatusUnauthorized
			reason = "invalid_ticket"
			switch {
			case errors.Is(err, services.ErrLoginTicketSignature):
				reason = "invalid_signature"
			case errors.Is(err, services.ErrLoginTicketExpired):
				reason = "expired"
			case errors.Is(err, services.ErrLoginTicketReplay):
				reason = "replay"
			case errors.Is(err, services.ErrLoginTicketUserUnavailable):
				reason = "user_unavailable"
			}
		}
		recordTicketLoginFailure(c, claims.Username, reason)
		message := "登录票据无效或已过期"
		if status == http.StatusInternalServerError {
			// DB/内部故障（审计侧已归因 database_error）
			// 不得复用凭证文案——否则运维误判为票据问题并反复重取票据。
			message = "登录票据校验失败，请稍后重试"
		}
		c.JSON(status, models.APIResponse{Code: status, Message: message})
		return
	}
	h.respondLoginWithMFA(c, user, passwordVersion, 0, true, claims.AuthMethod)
}

func recordTicketLoginFailure(c *gin.Context, username, reason string) {
	services.RecordAuditLog(username, "登录失败", "登录票据", services.AuditResultPart(reason), c.ClientIP())
}
