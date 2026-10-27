package handlers

// 自动封禁端面：配置读写（六项+校验；保存联动调度启停）、
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
	cfg, err := services.GetAutobanConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取自动封禁配置失败", err)})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// UpdateAutobanConfig PUT /security/autoban：六项配置写侧（校验：阈值 1-10000、
// 窗口 1-60 分钟、时长/口径枚举）。窗口/口径变更由 services 层重置计数器
// （口径语义变化后旧计数不可混算）。保存联动调度启停（2026-10-14 裁定：
// 本任务调度唯一前提=业务启用——enabled=true 开 autoban 循环调度、false 停；
// 任务列表手动开调度未启用时由 Run 体业务门拦停）。配置只影响本节点调度与
// 计数——主节点门（从节点写会被快照覆盖，与 UpdateThreatAutoUpdate 同口径）。
func (h *Handlers) UpdateAutobanConfig(c *gin.Context) {
	// 自动封禁用例配置写 global_config，导入全量替换——窗口内提交会被静默
	// 覆盖（用户以为已改配置）或撞写锁 500，与同族写端点同口径 409。
	if rejectWriteDuringImport(c, "修改自动封禁配置（配置导入进行中）") {
		return
	}
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
	// 校验与持久化分出口：SetAutobanConfig 的 400 判定只覆盖纯校验（阈值/
	// 窗口/枚举），DB 写失败（写锁冲突/IO 故障）必须 500 + 泛化文案——与同域
	// 其它写端点同口径。旧实现把两者压成 400 并回传存储层原文，真实故障被
	// 报成「请求参数无效」，调用方停止重试且响应泄露表/列名。
	if err := services.ValidateAutobanConfig(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := services.SetAutobanConfig(req); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存自动封禁配置失败", err)})
		return
	}
	recordAudit(c, "更新", "自动封禁", fmt.Sprintf("启用：%s；调度：%s；阈值：%d 次/%d 分钟；时长：%s；口径：%s；模式：%s",
		boolOnOff(req.Enabled), enabledStateLabel(req.Enabled), req.Threshold, req.WindowMinutes,
		services.AutobanDurationLabel(req.Duration), autobanScopeText(req.Scope),
		map[bool]string{true: "观察", false: "正式"}[req.DryRun]))
	updated, err := services.GetAutobanConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("回读自动封禁配置失败", err)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "自动封禁配置已更新", Data: updated})
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
// is_master/role=调度面节点角色（从端卡片按角色门控写按钮，
// 引擎未装配时保守判从）；list_entries 与渲染生效面同口径（剔除已到期
// 未清理条目）。
func (h *Handlers) GetAutobanStatus(c *gin.Context) {
	cfg, err := services.GetAutobanConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取自动封禁配置失败", err)})
		return
	}
	entries, listID, err := services.AutobanListEntries()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取自动封禁名单失败", err)})
		return
	}
	preset := autobanPresetListState{id: listID, entries: entries}
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
		"list_referenced": h.autobanListReferenced(preset),
		// 黄条真正需要的是「封禁是否生效」——名单被 deny + IP 访问
		// 控制启用的策略引用且名单非空才生效；list_referenced 复用热路径资格门
		// 的四面引用集（含白名单/受信代理/CRS 排除），不能区分「引用」与「拦截
		// 生效」，曾抑制唯一的不生效告警。
		"ban_effective": h.autobanBanEffective(preset),
		"tracked_ips":   services.AutobanTrackedIPs(),
		"suggestions":   suggestions,
		"is_master":     isMaster,
		"role":          map[bool]string{true: "master", false: "slave"}[isMaster],
		"running":       false,
		"last_run":      "",
		"last_status":   "",
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
	// 喂入源（安全事件采集）健康——数据源停摆时自动封禁
	// 静默失效（计数恒 0、轮次仍 success）。状态卡据此显示降级原因，不自动
	// 拉起用户显式停止的任务。
	feedDegraded, feedReason := services.AutobanFeedHealth()
	resp["feed_degraded"] = feedDegraded
	resp["feed_degraded_reason"] = feedReason
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// autobanPresetListState 是一次请求内预置名单的单一读取结果：id 与条目快照
// 一并传入两个黄条判据，避免同一状态端点三次查同一行。读取故障在
// GetAutobanStatus 已 500 返回（见上方 AutobanListEntries 错误分支），故本结构
// 不携带 err；id<=0 仅为构造不变量的 fail-closed 兜底（两判据均按 true）。
type autobanPresetListState struct {
	id      int64
	entries []models.IPListEntry
}

// autobanListReferenced 启用中的策略是否引用预置名单（黄条判据）。引用面判定
// 单源 services.IPListsReferencedByEnabledPolicy（原第二份
// 窄引用实现只查 ip_acl_list_refs/ip_whitelist_refs，与热路径资格门
// 补全后的四面口径分叉——仅被受信代理网段/CRS 排除 scope=ip/list ListRefs
// 引用的名单会被黄条误报「名单未生效」；错误日志沿用单源通用前缀「IP 名单
// 写路径」）。查询失败 fail-closed（按已引用处理——不弹黄条，避免误报「未
// 生效」），与单源内部口径一致。
func (h *Handlers) autobanListReferenced(preset autobanPresetListState) bool {
	if preset.id <= 0 {
		return true
	}
	return services.IPListsReferencedByEnabledPolicy([]int{int(preset.id)})
}

// autobanBanEffective 封禁是否真正生效：预置名单存在且
// 含未到期条目，并被至少一个「启用 + IP 访问控制启用 + deny 模式」的策略在
// ip_acl_list_refs 中引用，且该策略已绑定到「启用 + 至少一个启用上游」的
// HTTP 规则（渲染层对零启用上游的规则整条跳过——见
// services/caddy.go 全量渲染的 enabledUpstreamCount 门——此前判据只看到规则
// 启用，名单实际不拦截却抑制黄条）。白名单/受信代理/CRS 排除引用不构成拦截
// 生效。
// 已知边界：TLS 规则在证书待签发窗口同样被渲染层整条跳过（availableCerts
// 门），本判据不覆盖该窗口——证书可用集在渲染器内部计算（含 ACME 签发态与
// 文件就绪探测），在此复制判据会形成第二份实现；签发起步通常以分钟计，且
// 证书就绪后自动重载，黄条在窗口内可能短暂假阴性。
// 查询失败 fail-closed（返回 true，不弹误导性黄条——与 list_referenced 同口径）。
func (h *Handlers) autobanBanEffective(preset autobanPresetListState) bool {
	if preset.id <= 0 {
		return true
	}
	entries := preset.entries
	if len(services.AutobanActiveEntries(entries)) == 0 {
		return false // 空名单：即便被 deny 策略引用也不拦截任何 IP
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies p
		WHERE COALESCE(p.enabled,0)=1 AND COALESCE(p.ip_acl_enabled,0)=1 AND COALESCE(p.ip_acl_mode,'')='deny'
		  AND json_valid(COALESCE(p.ip_acl_list_refs,'[]'))
		  AND EXISTS (SELECT 1 FROM json_each(COALESCE(p.ip_acl_list_refs,'[]')) je WHERE je.value=?)
		  AND EXISTS (SELECT 1 FROM security_policy_bindings b
		              JOIN lb_rules r ON r.caddy_id=b.rule_caddy_id
		              WHERE b.policy_id=p.id AND r.protocol='http' AND COALESCE(r.enabled,0)=1
		                AND EXISTS (SELECT 1 FROM upstreams u
		                            WHERE u.rule_id=r.caddy_id AND `+services.UpstreamEnabledSQLPredicate+`))`,
		preset.id).Scan(&count); err != nil {
		return true
	}
	return count > 0
}
