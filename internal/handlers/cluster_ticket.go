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
	if mfaEnabled, err := services.MFAUserEnabled(currentUserID(c)); err == nil && !mfaEnabled {
		c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "登录从节点需先启用 MFA（在安全设置中绑定）"})
		return
	}
	if services.MFAWriteGuardEnabled() {
		mfaTs, _ := c.Get("mfa_ts")
		if ts, ok := mfaTs.(float64); !ok || time.Since(time.Unix(int64(ts), 0)) >= 10*time.Minute {
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
