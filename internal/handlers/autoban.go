package handlers

// 自动封禁（F73-A）端面：配置读写（六项+校验；保存联动调度启停）、
// 运行状态（状态卡数据源：运行态/今日封禁/名单条数/引用状态/观察建议）。
// 预置名单的条目管理例外（删 400/条目可改）在 securityiplists.go。
// 「立即执行」端点已废除（2026-10-14 裁定：调度唯一前提=业务启用）。

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// GetAutobanConfig GET /security/autoban：六项配置（全员可读，business 组）。
func (h *Handlers) GetAutobanConfig(c *gin.Context) {
	c.JSON(http.StatusOK, services.GetAutobanConfig())
}

// UpdateAutobanConfig PUT /security/autoban：六项配置写侧（校验：阈值 1-10000、
// 窗口 1-60 分钟、时长/口径枚举）。窗口/口径变更由 services 层重置计数器
// （口径语义变化后旧计数不可混算）。保存联动调度启停（2026-10-14 裁定：
// 本任务调度唯一前提=业务启用——enabled=true 开 autoban 循环调度、false 停；
// 任务列表手动开调度未启用时由 Run 体业务门拦停）。配置只影响本节点调度与
// 计数——主节点门（从节点写会被快照覆盖，与 UpdateThreatAutoUpdate 同口径）。
func (h *Handlers) UpdateAutobanConfig(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	var req services.AutobanConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if !requireMasterNode(c) {
		return
	}
	if err := services.SetAutobanConfig(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	recordAudit(c, "更新", "自动封禁", fmt.Sprintf("启用：%s；调度：%s；阈值：%d 次/%d 分钟；时长：%s；口径：%s；模式：%s",
		boolOnOff(req.Enabled), map[bool]string{true: "已开启", false: "已停止"}[req.Enabled], req.Threshold, req.WindowMinutes,
		services.AutobanDurationLabel(req.Duration), autobanScopeText(req.Scope),
		map[bool]string{true: "观察", false: "正式"}[req.DryRun]))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "自动封禁配置已更新", Data: services.GetAutobanConfig()})
}

func boolOnOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

func autobanScopeText(scope string) string {
	switch scope {
	case "blocked":
		return "仅拦截"
	case "logged":
		return "仅检测"
	default:
		return "全部"
	}
}

// GetAutobanStatus GET /security/autoban/status：状态卡数据源（business 组全员
// 可读）。running/last_run 取任务引擎实态；list_referenced=启用中的安全策略
// （ip_acl_list_refs ∪ ip_whitelist_refs，JSON 精确解析）是否引用预置名单——
// 未引用时前端黄条提示「名单未生效」；suggestions=上一轮观察建议（dry-run）。
// is_master/role=调度面节点角色（F75C-2，第 75 轮：从端卡片按角色门控写按钮，
// 引擎未装配时保守判从）；list_entries 与渲染生效面同口径（AB-4：剔除已到期
// 未清理条目）。
func (h *Handlers) GetAutobanStatus(c *gin.Context) {
	cfg := services.GetAutobanConfig()
	entries, _, err := services.AutobanListEntries()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自动封禁名单失败: " + err.Error()})
		return
	}
	isMaster := services.AutobanIsMaster()
	suggestions := services.AutobanSuggestions()
	for i := range suggestions {
		// 归属地富化与安全事件列表同源（enrichIPLocation 单源：保留地址前置
		// 拦截、无 xdb 降级空串、永不报错）。
		suggestions[i].Location = enrichIPLocation(suggestions[i].IP)
	}
	resp := gin.H{
		"enabled":         cfg.Enabled,
		"dry_run":         cfg.DryRun,
		"threshold":       cfg.Threshold,
		"window_minutes":  cfg.WindowMinutes,
		"duration":        cfg.Duration,
		"scope":           cfg.Scope,
		"banned_today":    services.AutobanBannedToday(),
		"list_entries":    len(services.AutobanActiveEntries(entries)),
		"list_referenced": h.autobanListReferenced(),
		"tracked_ips":     services.AutobanTrackedIPs(),
		"suggestions":     suggestions,
		"is_master":       isMaster,
		"role":            map[bool]string{true: "master", false: "slave"}[isMaster],
		"running":         false,
		"last_run":        "",
		"last_status":     "",
	}
	if te := services.TaskEngine(); te != nil {
		if m, ok := te.Lookup(services.AutobanTaskID); ok {
			resp["running"] = m.Running
			resp["loop_on"] = m.LoopOn
		}
		if last := te.LatestRun(services.AutobanTaskID); last != nil {
			resp["last_run"] = last.StartedAt
			resp["last_status"] = last.Status
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// autobanListReferenced 启用中的策略是否引用预置名单（黄条判据）。引用面判定
// 单源 services.IPListsReferencedByEnabledPolicy（HP77-8，第 77 轮：原第二份
// 窄引用实现只查 ip_acl_list_refs/ip_whitelist_refs，与热路径资格门 SEC-2
// 补全后的四面口径分叉——仅被受信代理网段/CRS 排除 scope=ip/list ListRefs
// 引用的名单会被黄条误报「名单未生效」；错误日志沿用单源通用前缀「IP 名单
// 写路径」）。查询失败 fail-closed（按已引用处理——不弹黄条，避免误报「未
// 生效」），与单源内部口径一致。
func (h *Handlers) autobanListReferenced() bool {
	var listID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, services.AutobanPresetListName).Scan(&listID); err != nil {
		return true
	}
	return services.IPListsReferencedByEnabledPolicy([]int{int(listID)})
}
