package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GenerateClusterLoginTicket(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	response, err := h.clusterService.GenerateLoginTicket(c.Request.Context(), models.ClusterLoginTicketClaims{
		UserID: currentUserID(c), Username: c.GetString("username"), Role: c.GetString("role"), NodeID: nodeID,
	}, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrNodeNotFound) {
			status = http.StatusConflict
		}
		clusterError(c, status, "生成登录票据失败", err)
		return
	}
	recordAudit(c, "生成", "从节点登录票据", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, response)
}

func (h *Handlers) TicketLogin(c *gin.Context) {
	var req models.ClusterLoginTicketRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	claims, err := h.clusterService.ValidateLoginTicket(c.Request.Context(), req.Ticket, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrInvalidLoginTicket) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, models.APIResponse{Code: status, Message: "登录票据无效或已过期"})
		return
	}
	var user models.User
	var passwordVersion int64
	err = db.DB.QueryRow(`SELECT id,username,role,display_name,is_enabled,created_at,last_login,password_version FROM users WHERE id=?`, claims.UserID).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &passwordVersion)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!user.IsEnabled || user.Username != claims.Username) {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不存在或已禁用"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	h.respondLogin(c, user, passwordVersion)
}
