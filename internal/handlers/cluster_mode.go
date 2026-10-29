package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) SetClusterMode(c *gin.Context) {
	// 导入事务全量替换 global_config，
	// 窗口内切换角色会在远端留下无法本地回滚的注册（BecomeSlave 之后被导入
	// 覆盖 → 远端孤儿注册 + 本地仍为主节点）。必须先于任何网络副作用 fast-fail。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireClusterService(c) {
		// explicit 路由中间件对 5xx 不代记（与本函数其余拒绝面同口径），
		// 装配缺失的 503 也由 handler 留痕。
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("集群服务未初始化", services.AuditResultPart("service_unavailable")))
		return
	}
	if h.syncService == nil {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("同步服务未初始化", services.AuditResultPart("service_unavailable")))
		clusterError(c, http.StatusServiceUnavailable, "同步服务未初始化", nil)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req models.ClusterModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", "集群模式参数无效", services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, "集群模式参数无效", err)
		return
	}
	if req.Mode == "master" {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：主节点", "请使用提升接口切换为主节点", services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, "请使用提升接口切换为主节点", nil)
		return
	}
	if req.MasterURL == "" || req.RegisterToken == "" {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", "主节点地址和注册令牌不能为空", services.AuditResultPart("invalid_request")))
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
	// 与主节点落库侧同一归一（去空白/控制字符/截断 100 rune），
	// 避免主节点拒绝或把脏名字写入集群。
	name = models.NormalizeClusterNodeName(name)
	if name == "" {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", models.ErrInvalidClusterNodeName.Error(), services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, models.ErrInvalidClusterNodeName.Error(), models.ErrInvalidClusterNodeName)
		return
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.MasterURL)), "http://") {
		recordAudit(c, "警告", "集群模式", services.FormatAuditDetail("目标：从节点", "使用明文 HTTP 注册，证书私钥将明文传输，建议改用 HTTPS"))
	}
	outboundIP, outboundIPOK := dialOutboundIP()
	// 探测失败时不得把回环地址当机器地址上报：多台无默认路由的从节点会命中
	// 主节点 UNIQUE(ip_address,port) 互相覆盖（后注册者重置前者的审批与令牌）。
	// 上报空串，由主节点按注册来源地址落库（同 getOutboundIP 的口径）。
	registrationIP := outboundIP
	if !outboundIPOK {
		registrationIP = ""
	}
	if outboundIPOK && models.ClusterAccessURLTargetsNode(req.MasterURL, outboundIP, h.cfg.Port) {
		const message = "不能将本节点注册为自己的从节点，请填写另一主节点的地址，或使用提升接口保持主节点角色"
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标："+masterAuditURL, message))
		clusterError(c, http.StatusBadRequest, message, nil)
		return
	}
	registration, err := h.syncService.RegisterWithMaster(c.Request.Context(), req.MasterURL, models.ClusterRegisterRequest{
		Token: req.RegisterToken, Name: name, IPAddress: registrationIP, Port: h.cfg.Port, Protocol: requestProtocol(c),
	})
	if err != nil {
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", err.Error()))
		clusterError(c, http.StatusBadGateway, "向目标主节点注册失败: "+err.Error(), err)
		return
	}
	if err := h.clusterService.BecomeSlave(c.Request.Context(), strings.TrimRight(req.MasterURL, "/"), registration); err != nil {
		services.Logf("error", "cluster registration %d requires manual cleanup after local mode transition failed: %v", registration.RegistrationID, err)
		recordAudit(c, "切换失败", "集群模式", services.FormatAuditDetail("目标：从节点", fmt.Sprintf("registration_id：%d", registration.RegistrationID), err.Error()))
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: "保存从节点模式失败；远端注册已创建，请管理员清理后重试",
			Data:    gin.H{"registration_id": registration.RegistrationID},
		})
		return
	}
	// 令牌撤销/schema 不匹配会把同步循环置为 Halted 终态，而角色翻转
	// 由引擎 SetRole 唯一驱动（cluster-sync daemon 换代重启；BecomeSlave 侧仅
	// SetRole + 恢复调度开关，不再有旧 StartSync 生命周期旁路）——Start() 对
	// Halted 态是 no-op（cluster_sync.go startLocked 门控），重新注册后循环永不
	// 重启、注册轮询不可达，从节点静默永久脱同步（唯一出口 Resume 此前只有手动
	// 同步一处调用，且重新注册后 token='' 使 Pull 在 Resume 之前就失败早退）。
	// Resume 对非 Halted 态是 no-op，幂等安全；此时 run 循环已终止（done 已关），
	// Resume 立即拉起新循环进入注册轮询。
	h.syncService.Resume()
	recordAudit(c, "切换", "集群模式", switchToSlaveAuditDetail(masterAuditURL, outboundIPOK))
	message := "已切换为从节点，等待主节点审批"
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(req.MasterURL)), "http://") {
		message += "；警告：证书私钥将经明文 HTTP 传输，建议使用 HTTPS"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

// requestProtocol 返回本节点自述访问协议，注册时上报主节点（用于拼接该
// 节点的访问地址与面板展示）。X-Forwarded-Proto 无条件采信——自述协议，
// 可信度以部署边界为界：伪造该头的可达前提是已通过认证的 admin 管理面，
// 污染面仅限自家节点的注册地址。保守维持
// 现状，不加受信门。
func requestProtocol(c *gin.Context) string {
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}

func (h *Handlers) PromoteClusterNode(c *gin.Context) {
	// 导入窗口写 global_config 会被全量替换覆盖——
	// 与节点写端点同族 fast-fail（先于任何状态读取/生效）。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireClusterService(c) {
		recordAudit(c, "提升失败", "集群模式", services.FormatAuditDetail("集群服务未初始化", services.AuditResultPart("service_unavailable")))
		return
	}
	// syncService 缺失判定前置——此前 Promote 已生效才报
	// 503,调用方见到失败但角色已提升,重试撞 ErrAlreadyMaster。
	if h.syncService == nil {
		recordAudit(c, "提升失败", "集群模式", services.FormatAuditDetail("同步服务未初始化", services.AuditResultPart("service_unavailable")))
		clusterError(c, http.StatusServiceUnavailable, "同步服务未初始化", nil)
		return
	}
	if err := h.clusterService.Promote(c.Request.Context()); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrAlreadyMaster) {
			status = http.StatusBadRequest
		}
		recordAudit(c, "提升失败", "集群模式", err.Error())
		clusterError(c, status, "提升为主节点失败: "+err.Error(), err)
		return
	}
	// 提升成功后清空内存 TOFU pin 缓存——Promote 的 cleanupClusterPin
	// 只删 pin 文件，内存 verifiedPins 残留旧主节点指纹会让记录与钉扎状态错位
	//不再以内存指纹回写，此处清空保持内存/磁盘 TOFU 生命周期
	// 对齐）。与 Resume() 同点位：角色切换的完整收尾。
	h.syncService.ForgetClusterPins()
	// 生命周期由任务引擎统一驱动（Promote → SetRole → daemon hook/角色门），
	// handler 不再直调管理器或旧调度器。
	recordAudit(c, "提升", "集群模式", services.FormatAuditDetail("从节点 → 主节点", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已提升为主节点"})
}

func (h *Handlers) UpdateClusterSettings(c *gin.Context) {
	// 同步开关与间隔写 global_config，导入窗口内的写入
	// 会被全量替换覆盖（静默丢失）——与节点写端点同族 fast-fail。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireClusterService(c) {
		// explicit 路由中间件对 5xx 不代记（与本函数其余失败面同口径），
		// 装配缺失的 503 也由 handler 留痕。
		recordAudit(c, "更新失败", "集群设置", services.FormatAuditDetail("集群服务未初始化", services.AuditResultPart("service_unavailable")))
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req models.ClusterSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		recordAudit(c, "更新失败", "集群设置", services.FormatAuditDetail("集群设置参数无效", services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, "集群设置参数无效", err)
		return
	}
	if err := h.clusterService.UpdateSettings(c.Request.Context(), req); err != nil {
		// 分判——角色/权限语义(403)/客户端参数(400)/其余 DB 与
		// 内部故障(500,此前误 403 误导排障)。
		status := http.StatusInternalServerError
		msg := "更新集群设置失败"
		// UpdateSettings 不产出 ErrAlreadyMaster(仅 Promote 产出,
		// Promote 路径 :93 映射保留),原 case 为死分支已删除。
		switch {
		case errors.Is(err, services.ErrInvalidSyncInterval) || errors.Is(err, services.ErrSyncUsersLocked):
			status = http.StatusBadRequest
			msg = err.Error()
		default:
			if errors.Is(err, services.ErrSlaveReadOnly) {
				status = http.StatusForbidden
				msg = err.Error()
				c.Header("X-LB-Error-Code", masterRequiredErrorCode)
			}
		}
		// explicit 路由的 4xx/5xx 中间件不代记——拒绝面（含从节点越权/误操作
		// 与内部故障）必须由 handler 留痕，与成功面同端点同口径。
		detail := msg
		if err.Error() != msg {
			detail = services.FormatAuditDetail(msg, err.Error())
		}
		recordAudit(c, "更新失败", "集群设置", detail)
		clusterError(c, status, msg, err)
		return
	}
	// 空 body = 幂等空保存，parts 为空时审计详情曾落空串
	// （无法区分「无修改」与记录缺陷）——复用同域既有「无修改」文案
	// （caproviders/certificates 同口径）。
	detail := clusterSettingsChangeDetail(req)
	if detail == "" {
		detail = "无修改"
	}
	recordAudit(c, "更新", "集群设置", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "集群设置已更新"})
}

// switchToSlaveAuditDetail 构建切换从节点的审计详情;出口 IP 探测失败
// 时追加点名——上报地址为空、由主节点按注册来源地址落库，运维可见。
func switchToSlaveAuditDetail(masterURL string, outboundIPOK bool) string {
	parts := []string{"主节点 → 从节点", masterURL, "等待审批"}
	if !outboundIPOK {
		parts = append(parts, "出口 IP 探测失败，已按注册来源地址登记，请稍后在节点设置中确认访问地址")
	}
	return services.FormatAuditDetail(parts...)
}

func clusterSettingsChangeDetail(req models.ClusterSettingsRequest) string {
	labels := map[string]string{
		// sync_rules 标签与集群设置卡/新版 hover
		// 统一为「负载均衡规则」(备份分类标签「负载规则」不在此口径)。
		"sync_users": "系统数据", "sync_rules": "负载均衡规则",
		"sync_security": "安全防护",
	}
	var parts []string
	toggles := []struct {
		key string
		val *bool
	}{
		{"sync_users", req.SyncUsers},
		{"sync_rules", req.SyncRules},
		{"sync_security", req.SyncSecurity},
	}
	for _, t := range toggles {
		if t.val == nil {
			continue
		}
		parts = append(parts, labels[t.key]+"："+enabledStateLabel(*t.val))
	}
	if req.SyncInterval != nil {
		parts = append(parts, fmt.Sprintf("同步间隔：%d 秒", *req.SyncInterval))
	}
	return strings.Join(parts, "；")
}
