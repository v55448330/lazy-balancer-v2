package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GetClusterSnapshot(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	// 快照生成会内联写 nodes（注册令牌交付清空，见
	// services/cluster_snapshot.go），与配置导入的 nodes 全量替换同表——
	// 导入窗口内下发会让令牌交付与导入事务交错（被覆盖或阻塞至 busy_timeout）。
	// 与节点写端点同口径 409 fast-fail；从节点下一同步周期自动重试。
	if rejectWriteDuringImport(c, "下发集群快照（含节点令牌交付）") {
		return
	}
	sinceVersion, _ := strconv.Atoi(c.Query("since_version"))
	snapshot, changed, err := h.clusterService.Snapshot(c.Request.Context(), sinceVersion, c.Query("fingerprint"), authenticatedClusterToken(c))
	if err != nil {
		if errors.Is(err, services.ErrNotMasterNode) {
			// 降级竞态（requireMaster 门通过后角色翻转）：与服务层节点写族
			// 同口径 403 + X-LB-Error-Code，从端 Pull 按「目标降级」分类重试。
			clusterMasterForbidden(c, err)
			return
		}
		clusterError(c, http.StatusInternalServerError, "生成集群快照失败", err)
		return
	}
	if !changed {
		// 304「配置无变化」只在从节点侧留痕；主节点每个同步周期都会被
		// 轮询命中，记录只会制造噪音，无需在此审计。
		c.Status(http.StatusNotModified)
		return
	}
	if nodeIDValue, exists := c.Get("cluster_node_id"); exists {
		if nodeID, ok := nodeIDValue.(int); ok {
			// 节点名查询失败/为空(节点已删除等)回退
			// 「节点 #<id>」,不再落尾部空名的「节点 」。
			// 查询走 h.clusterService 的库句柄（与本次快照读取同一库），
			// 不得直读全局 db.DB——句柄不一致时审计会错标到另一库的同 ID 节点。
			nodeLabel := fmt.Sprintf("节点 #%d", nodeID)
			if name, nameErr := h.clusterService.NodeName(c.Request.Context(), nodeID); nameErr == nil && name != "" {
				nodeLabel = fmt.Sprintf("节点 %s", name)
			}
			services.RecordAuditLog("system", "同步下发", "集群节点", services.FormatAuditDetail(nodeLabel, fmt.Sprintf("下发版本：%d", snapshot.Version)), c.ClientIP())
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_e2134b03"), MessageKey: "k_e2134b03", Data: snapshot})
}

// authenticatedClusterToken 读取集群令牌。两处调用方
// 均挂 clusterTokenAuth 之后,该中间件成功时恒 Set("cluster_token")——
// 头部回退分支不可达且 TrimPrefix 语义与中间件 bearerToken 分叉,收敛为
// 只读 ctx 值(空串=未认证,唯一生产行为)。
func authenticatedClusterToken(c *gin.Context) string {
	return c.GetString("cluster_token")
}

func (h *Handlers) PullClusterSnapshot(c *gin.Context) {
	// 主节点无同步对象：入口直接拒绝，不调 Pull——否则「主节点不能从其他
	// 节点同步」会经 recordSyncError 写入 last_sync_error 且无自动清除路径，
	// 节点页面持续显示假错误。前端按钮只对从节点渲染，此为后端防御。
	// 角色读取走 h.clusterService 句柄（与 GetClusterSnapshot/ForgetClusterPins
	// 同口径，不直读全局 db.DB——多库注入时读错库会误判角色）；
	// 装配缺失 503、角色查询失败 500（与 ForgetClusterPins 的 fail-closed
	// 口径一致：瞬时 DB 故障不得伪装成「主节点」400 误导排障）。
	if h.clusterService == nil {
		clusterError(c, http.StatusServiceUnavailable, "集群服务未初始化", nil)
		return
	}
	isMaster, roleErr := h.clusterService.IsMaster(c.Request.Context())
	if roleErr != nil {
		clusterError(c, http.StatusInternalServerError, "节点角色查询失败", roleErr)
		return
	}
	if isMaster {
		clusterError(c, http.StatusBadRequest, "主节点无需手动同步", nil)
		return
	}
	// 与 SetClusterMode/Promote/
	// ForgetClusterPins 同口径——装配缺失时 503，不得 nil 指针 panic 落成
	// Gin recovery 的 500 空体。
	if h.syncService == nil {
		clusterError(c, http.StatusServiceUnavailable, "同步服务未初始化", nil)
		return
	}
	// 手动同步会写 global_config/lb_rules 等导入全量替代表，导入会话
	// 的排空阶段不覆盖 Daemon/手动 Pull（coordinator 明确 Daemon 不在范围）——
	// 窗口内提交要么被导入覆盖，要么阻塞在 SQLite 写锁上至 busy_timeout 后 500。
	// 与节点写族同口径 409；后台 daemon 仍按「主节点为准」保留。
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: apimsg.T(c, "k_86db0e60"), MessageKey: "k_86db0e60"})
		return
	}
	result, err := h.syncService.Pull(c.Request.Context())
	if err != nil {
		recordAudit(c, "同步失败", "集群同步", err.Error())
		clusterError(c, http.StatusInternalServerError, "同步失败: "+err.Error(), err)
		return
	}
	if result.Changed {
		recordAudit(c, "手动同步", "集群同步", services.FormatAuditDetail("应用版本："+strconv.Itoa(result.AppliedVersion), services.AuditResultPart("success")))
	} else {
		recordAudit(c, "手动同步", "集群同步", services.FormatAuditDetail("配置无变化", services.AuditResultPart("success")))
	}
	h.syncService.Resume()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_91110f22"), MessageKey: "k_91110f22", Data: result})
}

// ForgetClusterPins 是从节点管理员的 PinMismatch 补救端点：主节点更换
// 管理面板证书后从节点同步持续指纹不匹配，运维确认新证书合法后清空全部 TOFU
// 指纹钉（内存缓存+磁盘 pin 文件），下一同步 tick 按新证书重新钉扎。仅 admin
// 路由组可达（readOnlyGuard 的 /cluster/* 白名单保证从节点可用），操作留审计。
func (h *Handlers) ForgetClusterPins(c *gin.Context) {
	// 复审裁定 4：本端点语义=清除「本机作为从节点」对主节点证书的钉扎；主节点
	// 的 pin 目录存的是各从节点钉（服务控制 TOFU 消费），误调会整体重置从节点
	// 钉扎——主节点直接拒绝。
	if h.syncService == nil {
		clusterError(c, http.StatusServiceUnavailable, "同步服务未初始化", nil)
		return
	}
	// 主节点守卫不得随装配缺失 ——h.clusterService 为 nil
	// 时此前直接放行清除本机全部 TOFU 钉（主节点误清从节点钉的风险路径）。
	// 与 PullClusterSnapshot「装配缺失 → 503」及本文件其余口径
	// 一致：无法确认角色即拒绝。
	if h.clusterService == nil {
		clusterError(c, http.StatusServiceUnavailable, "集群服务未初始化，已拒绝清除（fail-closed）", nil)
		return
	}
	{
		// 门控 ——查询失败按主节点语义拒绝
		// (与 PullClusterSnapshot 的降级口径一致),防瞬时 DB 读错绕过
		// 守卫误清从节点钉扎。
		isMaster, err := h.clusterService.IsMaster(c.Request.Context())
		if err != nil {
			clusterError(c, http.StatusInternalServerError, "无法确认节点角色，已拒绝清除（fail-closed）", err)
			return
		}
		if isMaster {
			recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail("主节点调用被拒绝：主节点 pin 目录存各从节点钉", services.AuditResultPart("failure")))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_14d8a178"), MessageKey: "k_14d8a178"})
			return
		}
	}
	removed, err := h.syncService.ForgetPins()
	if err != nil {
		recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail(err.Error(), services.AuditResultPart("failure")))
		clusterError(c, http.StatusInternalServerError, "清除主节点证书指纹失败: "+err.Error(), err)
		return
	}
	recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
		fmt.Sprintf("已清除 %d 个主节点证书指纹，下次同步将重新验证并钉扎", removed),
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_d94bc52e"), MessageKey: "k_d94bc52e"})
}

// ForgetClusterNodePin 是主节点侧「单节点 TOFU 指纹钉」重置端点（与从节点
// 侧 ForgetClusterPins 对称）：从节点更换管理面板证书后，主节点对其服务控制持续
// PinMismatch；本端点按节点（access_url 优先，回退 protocol://ip:port）定位并
// 删除对应 pin 文件（内存缓存一并失效），下次服务控制按从节点当前证书重新钉扎。
// 仅主节点管理员可达（requireMaster + admin 路由组），操作留审计。
func (h *Handlers) ForgetClusterNodePin(c *gin.Context) {
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		// 编号非法属客户端可修正输入，但 explicit 路由的审计中间件对 4xx
		// 无条件早退——本分支必须自行留痕（与同文件其余失败面同口径）。
		recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail(
			"节点编号无效（"+registerAuditField(c.Param("id"))+"）", services.AuditResultPart("invalid_request")))
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	host, err := h.clusterService.ForgetNodePin(c.Request.Context(), nodeID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, services.ErrNotMasterNode):
			// 降级竞态 403 与 requireMaster 门同源带头（保留失败审计）。
			c.Header("X-LB-Error-Code", masterRequiredErrorCode)
			status = http.StatusForbidden
		case errors.Is(err, services.ErrNodeNotFound):
			status = http.StatusNotFound
		case errors.Is(err, services.ErrNoClusterPin):
			// 幂等：无钉可删（http 地址/从未服务控制过）按成功语义回应，
			// 不阻断运维排障流程。
			recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
				fmt.Sprintf("节点 %d", nodeID), "该节点没有已钉扎的证书指纹，无需清除"))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_ec34e103"), MessageKey: "k_ec34e103"})
			return
		}
		recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), err.Error()))
		clusterError(c, status, "清除节点证书指纹失败", err)
		return
	}
	if h.syncService != nil {
		h.syncService.ForgetNodePinCache(host)
	}
	recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
		fmt.Sprintf("节点 %d（%s）", nodeID, host), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_bcd41466"), MessageKey: "k_bcd41466"})
}

// GetClusterWafFiles serves the full CRS/IP2Region file bundle on demand to
// slaves whose snapshot-carried hash reference differs from their local files.
// 响应体按引用指纹缓存（一次 base64/JSON 编码），不再每请求
// 全树打包 + 重新序列化；限流由 clusterMachineRateLimit 在路由层预占。
func (h *Handlers) GetClusterWafFiles(c *gin.Context) {
	// 导入窗口 fast-fail：本端点打包时取 WafFileLock，而导入排空阶段即预持该锁
	// 至会话结束——不接门会让请求阻塞到导入完成（14MB 级打包后客户端易超时
	// 截断），与导出端点同口径 409。
	if rejectWriteDuringImport(c, "下发规则库文件") {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	body := services.BuildWafFileBundleResponse()
	if body == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_cf2eac23"), MessageKey: "k_cf2eac23"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}
