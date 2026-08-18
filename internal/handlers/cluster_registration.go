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
// （无 JWT/API Key 认证），超大体可撑爆审计库（R35-6）。
const registerRequestMaxBytes = 16 << 10

// registerAuditField 限制写入审计详情的节点字段：截断至 128B（回退合法 UTF-8
// 边界）并去除控制字符，防未认证请求注入超长内容或伪造日志换行（R35-6）。
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
	if !h.requireMaster(c) {
		return
	}
	token, expiresAt, err := h.clusterService.GenerateRegisterToken(c.Request.Context(), currentUserID(c), time.Now())
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "生成注册令牌失败", err)
		return
	}
	recordAudit(c, "生成", "集群注册令牌", services.FormatAuditDetail(fmt.Sprintf("有效期至：%s", expiresAt.UTC().Format("2006-01-02 15:04:05 UTC")), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "注册令牌已生成，仅显示一次", Data: gin.H{"token": token, "expires_at": expiresAt.UTC().Format(time.RFC3339)}})
}

func (h *Handlers) RegisterClusterNode(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, registerRequestMaxBytes)
	var req models.ClusterRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "注册请求格式错误", err)
		return
	}
	registration, err := h.clusterService.RegisterNode(c.Request.Context(), req, time.Now())
	if err != nil {
		if errors.Is(err, services.ErrInvalidRegisterToken) {
			// 无效令牌路径不携带攻击者输入，详情与响应均用通用文案（R35-6/8）
			services.RecordAuditLog("system", "注册失败", "集群节点", "注册令牌无效", c.ClientIP())
			clusterError(c, http.StatusUnauthorized, "注册令牌无效或已过期", err)
			return
		}
		services.RecordAuditLog("system", "注册失败", "集群节点", services.FormatAuditDetail(registerAuditField(req.Name), registerAuditField(req.IPAddress), err.Error()), c.ClientIP())
		clusterError(c, http.StatusInternalServerError, "节点注册失败", err)
		return
	}
	services.RecordAuditLog("system", "注册", "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", registration.RegistrationID), registerAuditField(req.Name), registerAuditField(req.IPAddress), "等待审批"), c.ClientIP())
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
