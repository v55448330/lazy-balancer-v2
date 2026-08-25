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
	// R72 C-I-4：DB 读错误必须 fail-closed（无法证明已启用=拒绝），此前
	// err != nil 时条件不成立直接放行发票。
	mfaEnabled, err := services.MFAUserEnabled(currentUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "读取 MFA 状态失败"})
		return
	}
	if !mfaEnabled {
		c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "登录从节点需先启用 MFA（在「系统设置 → 用户管理」中对自己的账号绑定）"})
		return
	}
	// R72 三次（用户裁决）：登录从节点每次点击都要求 MFA 验证——不再复用登录后
	// 的 10 分钟写操作宽限窗（用户实测窗口内直接跳转登录成功，与「点击登录时
	// 需要验证」的决策语义不符）。保留 60 秒宽限仅供 428 → 前端弹码 →
	// verify-step → 自动重试这一次链路闭环（重试发生在验证后的数秒内）。
	// API Key（机器身份/MCP 工具）无 mfa_ts 概念，豁免该窗口检查——MFA 是
	// 人类交互式登录的第二因子，API Key 已有自身的密钥管理边界。
	if c.GetString("auth_type") == "jwt" {
		mfaTs, _ := c.Get("mfa_ts")
		if ts, ok := mfaTs.(float64); !ok || time.Since(time.Unix(int64(ts), 0)) >= 60*time.Second {
			c.AbortWithStatusJSON(http.StatusPreconditionRequired, gin.H{"code": 428, "message": "MFA_STEP_UP_REQUIRED", "detail": "登录从节点需要 MFA 验证"})
			return
		}
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	response, err := h.clusterService.GenerateLoginTicket(c.Request.Context(), models.ClusterLoginTicketClaims{
		UserID: currentUserID(c), Username: c.GetString("username"), NodeID: nodeID,
	}, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrNodeNotFound) {
			status = http.StatusConflict
		}
		clusterError(c, status, "生成登录票据失败", err)
		return
	}
	recordAudit(c, "生成", "登录票据", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), services.AuditResultPart("success")))
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
		c.JSON(status, models.APIResponse{Code: status, Message: "登录票据无效或已过期"})
		return
	}
	h.respondLogin(c, user, passwordVersion)
}

func recordTicketLoginFailure(c *gin.Context, username, reason string) {
	services.RecordAuditLog(username, "登录失败", "登录票据", services.AuditResultPart(reason), c.ClientIP())
}
