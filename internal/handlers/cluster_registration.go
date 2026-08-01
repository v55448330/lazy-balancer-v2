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

func (h *Handlers) GenerateClusterRegisterToken(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	token, expiresAt, err := h.clusterService.GenerateRegisterToken(c.Request.Context(), currentUserID(c), time.Now())
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "生成注册令牌失败", err)
		return
	}
	recordAudit(c, "生成", "集群注册令牌", services.FormatAuditDetail("有效期：30 分钟", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "注册令牌已生成，仅显示一次", Data: gin.H{"token": token, "expires_at": expiresAt.UTC().Format(time.RFC3339)}})
}

func (h *Handlers) RegisterClusterNode(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	var req models.ClusterRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "注册请求格式错误", err)
		return
	}
	registration, err := h.clusterService.RegisterNode(c.Request.Context(), req, time.Now())
	if err != nil {
		services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(req.Name, req.IPAddress, err.Error()), c.ClientIP())
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrInvalidRegisterToken) {
			status = http.StatusUnauthorized
		}
		clusterError(c, status, err.Error(), err)
		return
	}
	services.RecordAuditLog("system", "注册", "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", registration.RegistrationID), req.Name, req.IPAddress, "等待审批"), c.ClientIP())
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "注册成功，等待主节点审批", Data: registration})
}

func (h *Handlers) GetClusterRegistrationStatus(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		clusterError(c, http.StatusBadRequest, "注册编号无效", err)
		return
	}
	status, err := h.clusterService.RegistrationStatus(c.Request.Context(), id, c.GetString("registration_secret"))
	if err != nil {
		clusterError(c, http.StatusUnauthorized, "注册凭证无效", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "注册状态查询成功", Data: status})
}

func (h *Handlers) ConfirmClusterRegistration(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	if err := h.clusterService.ConfirmRegistration(c.Request.Context(), authenticatedClusterToken(c)); err != nil {
		clusterError(c, http.StatusUnauthorized, "确认集群注册失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "集群注册已确认"})
}

func (h *Handlers) ApproveClusterNode(c *gin.Context) {
	h.clusterNodeAction(c, "审批", func(id int) error { return h.clusterService.ApproveNode(c.Request.Context(), id) })
}

func (h *Handlers) RejectClusterNode(c *gin.Context) {
	h.clusterNodeAction(c, "拒绝", func(id int) error { return h.clusterService.DeleteNode(c.Request.Context(), id) })
}

func (h *Handlers) DeleteClusterNode(c *gin.Context) {
	h.clusterNodeAction(c, "删除", func(id int) error { return h.clusterService.DeleteNode(c.Request.Context(), id) })
}

func (h *Handlers) UpdateClusterNodeAccessURL(c *gin.Context) {
	var req models.ClusterNodeAccessURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "访问地址格式错误", err)
		return
	}
	h.clusterNodeAction(c, "更新访问地址", func(id int) error {
		return h.clusterService.UpdateNodeAccessURL(c.Request.Context(), id, req.AccessURL)
	})
}

func (h *Handlers) clusterNodeAction(c *gin.Context, action string, operation func(int) error) {
	if !h.requireMaster(c) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	if err := operation(id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		clusterError(c, status, action+"节点失败", err)
		return
	}
	recordAudit(c, action, "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", id), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: action + "节点成功"})
}
