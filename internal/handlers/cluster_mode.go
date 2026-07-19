package handlers

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) SetClusterMode(c *gin.Context) {
	var req models.ClusterModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "集群模式参数无效", err)
		return
	}
	if req.Mode == "master" {
		clusterError(c, http.StatusBadRequest, "请使用提升接口切换为主节点", nil)
		return
	}
	if req.MasterURL == "" || req.RegisterToken == "" {
		clusterError(c, http.StatusBadRequest, "主节点地址和注册令牌不能为空", nil)
		return
	}
	name := req.NodeName
	if name == "" {
		name = h.cfg.NodeName
	}
	registration, err := h.syncService.RegisterWithMaster(c.Request.Context(), req.MasterURL, models.ClusterRegisterRequest{
		Token: req.RegisterToken, Name: name, IPAddress: localOutboundIP(), Port: h.cfg.Port,
	})
	if err != nil {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", err.Error()))
		clusterError(c, http.StatusBadGateway, "向目标主节点注册失败: "+err.Error(), err)
		return
	}
	if err := h.clusterService.BecomeSlave(c.Request.Context(), strings.TrimRight(req.MasterURL, "/"), registration); err != nil {
		clusterError(c, http.StatusInternalServerError, "保存从节点模式失败", err)
		return
	}
	recordAudit(c, "切换", "集群模式", services.FormatAuditDetail("主节点 → 从节点", req.MasterURL, "等待审批"))
	message := "已切换为从节点，等待主节点审批"
	if strings.HasPrefix(strings.ToLower(req.MasterURL), "http://") {
		message += "；警告：证书私钥将经明文 HTTP 传输，建议使用 HTTPS"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

func (h *Handlers) PromoteClusterNode(c *gin.Context) {
	if err := h.clusterService.Promote(c.Request.Context()); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrAlreadyMaster) {
			status = http.StatusBadRequest
		}
		clusterError(c, status, "提升为主节点失败: "+err.Error(), err)
		return
	}
	recordAudit(c, "提升", "集群模式", services.FormatAuditDetail("从节点 → 主节点", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已提升为主节点"})
}

func (h *Handlers) UpdateClusterSettings(c *gin.Context) {
	var req models.ClusterSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "集群设置参数无效", err)
		return
	}
	if err := h.clusterService.UpdateSettings(c.Request.Context(), req); err != nil {
		clusterError(c, http.StatusForbidden, err.Error(), err)
		return
	}
	recordAudit(c, "更新", "集群设置", services.AuditResultPart("success"))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "集群设置已更新"})
}

func localOutboundIP() string {
	connection, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer connection.Close()
	address, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "127.0.0.1"
	}
	return address.IP.String()
}
