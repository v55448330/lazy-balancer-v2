package handlers

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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
	parsedMasterURL, parseErr := url.Parse(req.MasterURL)
	masterAuditURL := "主节点地址无效"
	if parseErr == nil && parsedMasterURL.Scheme != "" && parsedMasterURL.Host != "" {
		masterAuditURL = parsedMasterURL.Scheme + "://" + parsedMasterURL.Host
	}
	if err := models.ValidateClusterAccessURL(req.MasterURL); err != nil {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标："+masterAuditURL, err.Error()))
		clusterError(c, http.StatusBadRequest, err.Error(), err)
		return
	}
	name := req.NodeName
	if name == "" {
		name = h.cfg.NodeName
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.MasterURL)), "http://") {
		recordAudit(c, "警告", "集群模式", services.FormatAuditDetail("目标：从节点", "使用明文 HTTP 注册，证书私钥将明文传输，建议改用 HTTPS"))
	}
	registration, err := h.syncService.RegisterWithMaster(c.Request.Context(), req.MasterURL, models.ClusterRegisterRequest{
		Token: req.RegisterToken, Name: name, IPAddress: localOutboundIP(), Port: h.cfg.Port, Protocol: requestProtocol(c),
	})
	if err != nil {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", err.Error()))
		clusterError(c, http.StatusBadGateway, "向目标主节点注册失败: "+err.Error(), err)
		return
	}
	if err := h.clusterService.BecomeSlave(c.Request.Context(), strings.TrimRight(req.MasterURL, "/"), registration); err != nil {
		log.Printf("cluster registration %d requires manual cleanup after local mode transition failed: %v", registration.RegistrationID, err)
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", fmt.Sprintf("registration_id：%d", registration.RegistrationID), err.Error()))
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "保存从节点模式失败；远端注册已创建，请管理员清理后重试",
			Data:    gin.H{"registration_id": registration.RegistrationID},
		})
		return
	}
	// R64 A-N4：令牌撤销/schema 不匹配会把同步循环置为 Halted 终态，而 BecomeSlave
	// 只调 StartSync()→Start()——Start 对 Halted 态是 no-op（cluster_sync.go startLocked
	// 门控），重新注册后循环永不重启、注册轮询不可达，从节点静默永久脱同步（唯一
	// 出口 Resume 此前只有手动同步一处调用，且重新注册后 token='' 使 Pull 在 Resume
	// 之前就失败早退）。Resume 对非 Halted 态是 no-op，幂等安全；此时 run 循环已
	// 终止（done 已关），Resume 立即拉起新循环进入注册轮询。
	h.syncService.Resume()
	recordAudit(c, "切换", "集群模式", services.FormatAuditDetail("主节点 → 从节点", masterAuditURL, "等待审批"))
	message := "已切换为从节点，等待主节点审批"
	if strings.HasPrefix(strings.ToLower(req.MasterURL), "http://") {
		message += "；警告：证书私钥将经明文 HTTP 传输，建议使用 HTTPS"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

func requestProtocol(c *gin.Context) string {
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}

func (h *Handlers) PromoteClusterNode(c *gin.Context) {
	if err := h.clusterService.Promote(c.Request.Context()); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrAlreadyMaster) {
			status = http.StatusBadRequest
		}
		recordAudit(c, "提升失败", "集群模式", err.Error())
		clusterError(c, status, "提升为主节点失败: "+err.Error(), err)
		return
	}
	// R67 A-N2：提升成功后清空内存 TOFU pin 缓存——Promote 的 cleanupClusterPin
	// 只删 pin 文件，内存 verifiedPins 残留旧主节点指纹会让记录与钉扎状态错位
	//（M13① 后 do() 不再以内存指纹回写，此处清空保持内存/磁盘 TOFU 生命周期
	// 对齐）。与 R64 A-N4 的 Resume() 同点位：角色切换的完整收尾。
	h.syncService.ForgetClusterPins()
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
		status := http.StatusForbidden
		if errors.Is(err, services.ErrInvalidSyncInterval) {
			status = http.StatusBadRequest
		}
		clusterError(c, status, err.Error(), err)
		return
	}
	recordAudit(c, "更新", "集群设置", services.FormatAuditDetail(clusterSettingsChangeDetail(req), services.AuditResultPart("success")))
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

func clusterSettingsChangeDetail(req models.ClusterSettingsRequest) string {
	labels := map[string]string{
		"sync_global_config": "全局配置", "sync_users": "系统数据", "sync_rules": "负载规则",
		"sync_waf_files": "规则库数据库", "sync_security": "安全策略规则",
	}
	var parts []string
	toggles := []struct {
		key string
		val *bool
	}{
		{"sync_global_config", req.SyncGlobalConfig}, {"sync_users", req.SyncUsers},
		{"sync_rules", req.SyncRules}, {"sync_waf_files", req.SyncWafFiles},
		{"sync_security", req.SyncSecurity},
	}
	for _, t := range toggles {
		if t.val == nil {
			continue
		}
		state := "关闭"
		if *t.val {
			state = "开启"
		}
		parts = append(parts, labels[t.key]+"："+state)
	}
	if req.SyncInterval != nil {
		parts = append(parts, fmt.Sprintf("同步间隔：%d 秒", *req.SyncInterval))
	}
	return strings.Join(parts, "；")
}
