package handlers

// 自动封禁端面：配置读写（十项+校验；保存联动调度启停）、
// 运行状态（状态卡数据源：运行态/今日封禁/名单条数/引用状态/观察建议）。
// 预置名单的条目管理例外（删 400/条目可改）在 securityiplists.go。
// 「立即执行」端点已废除（2026-10-14 裁定：调度唯一前提=业务启用）。

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// GetAutobanConfig GET /security/autoban：十项配置（全员可读，business 组）。
func (h *Handlers) GetAutobanConfig(c *gin.Context) {
	cfg, err := services.GetAutobanConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取自动封禁配置失败", err)})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// UpdateAutobanConfig PUT /security/autoban：十项配置写侧（校验：阈值 1-10000、
// 窗口 1-60 分钟、时长/口径/升级枚举）。窗口/口径变更由 services 层重置计数器
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_868de64b"), MessageKey: "k_868de64b"})
		return
	}
	// 缺省归一（旧客户端未携带新字段）与 SetAutobanConfig 同单源。
	req.Escalation = services.AutobanEscalationOrOff(req.Escalation)
	req.CountingMode = services.AutobanCountingModeOrClassic(req.CountingMode)
	req.SuspicionMultiplier = services.AutobanSuspicionMultiplierOrDefault(req.SuspicionMultiplier)
	req.ConfirmFloorRatio = services.AutobanConfirmFloorRatioOrDefault(req.ConfirmFloorRatio)
	if !requireMasterNode(c) {
		return
	}
	// 校验与持久化分出口：SetAutobanConfig 的 400 判定只覆盖纯校验（阈值/
	// 窗口/枚举），DB 写失败（写锁冲突/IO 故障）必须 500 + 泛化文案——与同域
	// 其它写端点同口径。旧实现把两者压成 400 并回传存储层原文，真实故障被
	// 报成「请求参数无效」，调用方停止重试且响应泄露表/列名。
	if err := services.ValidateAutobanConfig(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.ErrMsg(c, err)})
		return
	}
	if err := services.SetAutobanConfig(req); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存自动封禁配置失败", err)})
		return
	}
	// 启用与调度是同一字段的两面（保存即联动调度启停），只产出一个状态位并
	// 括注联动关系——旧文案「启用：开；调度：开启」两个同义布尔易被误读为
	// 独立状态。
	recordAudit(c, "更新", "自动封禁", fmt.Sprintf("启用：%s（调度随之启停）；阈值：%d 次/%d 分钟；时长：%s；口径：%s；模式：%s；计数：%s",
		boolOnOff(req.Enabled), req.Threshold, req.WindowMinutes,
		services.AutobanDurationLabel(req.Duration), autobanScopeText(req.Scope),
		map[bool]string{true: "观察", false: "正式"}[req.DryRun],
		autobanCountingModeText(req)))
	updated, err := services.GetAutobanConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("回读自动封禁配置失败", err)})
		return
	}
	notify.Publish(notify.Event{Type: notify.EvtAutobanCfgChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "更新了自动封禁配置"}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_7c026b1f"), MessageKey: "k_7c026b1f", Data: updated})
}

func boolOnOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

func autobanScopeText(scope string) string {
	return services.AutobanScopeLabel(scope)
}

// autobanCountingModeText 计数模式审计文案：classic=等权；evidence 披露
// 倍率/打底（配置变更留痕需可还原判定参数）。
func autobanCountingModeText(cfg services.AutobanConfig) string {
	if cfg.CountingMode == services.AutobanCountingEvidence {
		return fmt.Sprintf("证据分层（嫌疑倍率 %d，确证打底 %s）", cfg.SuspicionMultiplier, cfg.ConfirmFloorRatio)
	}
	return "等权"
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
	active := services.AutobanActiveEntries(entries)
	preset := autobanPresetListState{id: listID, activeCount: len(active)}
	isMaster := services.AutobanIsMaster()
	suggestions := services.AutobanSuggestions()
	for i := range suggestions {
		// 归属地富化与安全事件列表同源（enrichIPLocation 单源：保留地址前置
		// 拦截、无 xdb 降级空串、永不报错）。
		suggestions[i].Location = enrichIPLocation(suggestions[i].IP)
	}
	// 封禁生效判定（ban_effective=IP 名单引用通道）+ 缺失环节细分（用户裁定
	// 2026-11-21：binding 缺失时提示关联规则，不得引导去创建策略）。
	ipEffective := h.autobanBanEffectiveIP(preset)
	banMissing := ""
	if !ipEffective {
		banMissing = h.autobanMissingLink(preset)
	}
	resp := gin.H{
		"enabled":              cfg.Enabled,
		"dry_run":              cfg.DryRun,
		"threshold":            cfg.Threshold,
		"window_minutes":       cfg.WindowMinutes,
		"duration":             cfg.Duration,
		"scope":                cfg.Scope,
		"escalation":           cfg.Escalation,
		"counting_mode":        cfg.CountingMode,
		"suspicion_multiplier": cfg.SuspicionMultiplier,
		"confirm_floor_ratio":  cfg.ConfirmFloorRatio,
		"list_id":              listID,
		"escalated_count":      services.AutobanEscalatedCount(),
		"banned_today":         services.AutobanBannedToday(),
		"list_entries":         preset.activeCount,
		"list_referenced":      h.autobanListReferenced(preset),
		// 黄条真正需要的是「封禁是否生效」——IP 级=名单被 deny + IP 访问
		// 控制启用的策略引用且名单非空。list_referenced 复用热路径资格门的
		// 四面引用集（含白名单/受信代理/CRS 排除），不能区分「引用」与
		// 「拦截生效」，曾抑制唯一的不生效告警。
		"ban_effective":    ipEffective,
		"ban_missing":      banMissing,
		"ban_effective_ip": ipEffective,
		"tracked_ips":      services.AutobanTrackedIPs(),
		"suggestions":      suggestions,
		"is_master":        isMaster,
		"role":             map[bool]string{true: "master", false: "slave"}[isMaster],
		"running":          false,
		// loop_on 预置 false：响应键集不随任务引擎装配状态漂移（引擎未装配/
		// Lookup 未命中时此前整键缺失，apidocs 示例与前端类型按恒有键消费）。
		"loop_on":     false,
		"last_run":    "",
		"last_status": "",
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

// GetAutobanRecidivism GET /security/autoban/recidivism：累犯历史筛选分页
// （business 组全员可读）——面板「累犯升级」统计的下钻弹框数据源。
// query：hide_permanent（默认 true，隐藏 escalated_duration=permanent 行；
// false/0 显示全部）、ip（identity 子串匹配）、page/page_size（默认 1/20，
// parsePaginationParam 统一口径）。offense_count 降序、identity 升序；
// 空结果 records=[]（数组契约）；响应 {records,total,page,page_size}。
// 逐行 ip_location 富化与安全事件列表同源（enrichIPLocation 单源：保留地址
// 前置拦截、无 xdb 降级空串、永不报错）；ban_status/ban_expires_at 与
// hits_24h/last_event_at 由服务层富化（名单生效条目 join + metrics 近 24h
// 按身份键聚合，展示位容错）。
func (h *Handlers) GetAutobanRecidivism(c *gin.Context) {
	page, ok := parsePaginationParam(c, "page", 1, 1000)
	if !ok {
		return
	}
	pageSize, ok := parsePaginationParam(c, "page_size", 20, 100)
	if !ok {
		return
	}
	hidePermanent := true
	switch strings.TrimSpace(c.Query("hide_permanent")) {
	case "false", "0":
		hidePermanent = false
	}
	ipFilter := strings.TrimSpace(c.Query("ip"))
	records, total, err := services.ListAutobanRecidivism(hidePermanent, ipFilter, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取自动封禁累犯记录失败", err)})
		return
	}
	for i := range records {
		records[i].IPLocation = enrichIPLocation(records[i].Identity)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"records": records, "total": total, "page": page, "page_size": pageSize}})
}

// DeleteAutobanRecidivism DELETE /security/autoban/recidivism/:identity：
// 单条移除累犯身份（删除该 identity 行 + 清计数桶/观察建议——打断累犯
// 流程，与加名单中断同口径；下次达阈值按首次档起算）。identity 经
// services.AutobanEntryIdentity 归一（大写/完整形态 IPv6 与记账键同形，
// 审计记归一值）。封禁中的身份（名单生效条目命中，限时/永久）拒绝移除
// （400）——须先从 IP 快捷弹框取消封禁，避免「移除前科但封禁仍在」的处置
// 语义分裂；守卫读与删除同一 BEGIN IMMEDIATE 事务（并发 merge 不得在
// 两者之间落封禁条目）。幂等（identity 不存在也返回成功）；只清历史记账，
// 不动名单条目。主节点门+导入窗口门同全量重置。
func (h *Handlers) DeleteAutobanRecidivism(c *gin.Context) {
	if rejectWriteDuringImport(c, "删除自动封禁累犯记录（配置导入进行中）") {
		return
	}
	if !requireMasterNode(c) {
		return
	}
	identity := services.AutobanEntryIdentity(c.Param("identity"))
	identity, err := services.DeleteAutobanRecidivismGuarded(caddyWriteCtx(c), identity)
	if errors.Is(err, services.ErrAutobanIdentityBanned) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_d5ad4db8"), MessageKey: "k_d5ad4db8"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("删除自动封禁累犯记录失败", err)})
		return
	}
	// 移除=主动处置：清计数桶+观察建议（纯内存，与加名单中断同口径），
	// 否则旧计数仍在下一轮达阈值立即重封，「移除打断累犯」被撤销。
	services.AutobanForgetIPs([]string{identity})
	recordAudit(c, "删除", "累犯记录", fmt.Sprintf("移除累犯身份 %s（打断累犯流程：清计数桶与观察建议，下次达阈值按首次档起算；已生效封禁条目不受影响）", identity))
	notify.Publish(notify.Event{Type: notify.EvtAutobanCfgChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "移除了累犯前科"}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// ResetAutobanRecidivism DELETE /security/autoban/recidivism：重置全部累犯
// 历史（清空 autoban_recidivism，下次达阈值按首次档起算）。无条件清空、
// 幂等（重复调用保持空表并返回成功，与 unbind 同族）；只清历史记账，
// 已生效封禁条目保持至到期。主节点门（从端写会被快照覆盖，与
// UpdateAutobanConfig 同口径）；导入窗口拒绝写（累犯表在 security 节
// 全量替换清单内）。
func (h *Handlers) ResetAutobanRecidivism(c *gin.Context) {
	if rejectWriteDuringImport(c, "重置自动封禁累犯记录（配置导入进行中）") {
		return
	}
	if !requireMasterNode(c) {
		return
	}
	if err := services.ResetAutobanRecidivism(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("重置自动封禁累犯记录失败", err)})
		return
	}
	recordAudit(c, "重置", "累犯记录", "清空全部自动封禁累犯升级历史（下次达阈值按首次档起算；已生效封禁条目不受影响）")
	notify.Publish(notify.Event{Type: notify.EvtAutobanCfgChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "重置了累犯前科"}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// autobanPresetListState 是一次请求内预置名单的单一读取结果：id 与生效条目
// 计数一并传入黄条判据，避免重复查行与重复过滤/分配。
// GetAutobanStatus 已 500 返回（见上方 AutobanListEntries 错误分支），故本结构
// 不携带 err；id<=0 仅为构造不变量的 fail-closed 兜底（判据按 true）。
type autobanPresetListState struct {
	id          int64
	activeCount int
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

// autobanBanEffectiveIP IP 级通道封禁是否真正生效：预置名单存在且
// 含未到期条目，并被至少一个「启用 + IP 访问控制启用 + deny 模式」的策略在
// ip_acl_list_refs 中引用，且该策略已绑定到「启用 + 至少一个启用上游」的
// HTTP 规则（渲染层对零启用上游的规则整条跳过——见
// services/caddy.go 全量渲染的 enabledUpstreamCount 门——此前判据只看到规则
// 启用，名单实际不拦截却抑制黄条）。白名单/受信代理/CRS 排除引用不构成拦截
// 生效。L4 与 IP ACL 消费本通道。
// 已知边界：TLS 规则在证书待签发窗口同样被渲染层整条跳过（availableCerts
// 门），本判据不覆盖该窗口——证书可用集在渲染器内部计算（含 ACME 签发态与
// 文件就绪探测），在此复制判据会形成第二份实现；签发起步通常以分钟计，且
// 证书就绪后自动重载，黄条在窗口内可能短暂假阴性。
// 查询失败 fail-closed（返回 true，不弹误导性黄条——与 list_referenced 同口径）。
func (h *Handlers) autobanBanEffectiveIP(preset autobanPresetListState) bool {
	if preset.id <= 0 {
		return true
	}
	// 2026-11-21 用户裁定：名单为空≠功能未生效——封禁链路就绪（deny 引用+
	// 绑定+启用规则+启用上游）即生效，写入名单即拦截；空名单不弹不生效黄条。
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

// autobanMissingLink 细分封禁链路缺失环节：policy=无启用 deny 策略引用名单
// （提示创建/引用）；binding=策略就绪但未关联到启用 HTTP 规则+启用上游（提示
// 关联规则）。查询失败返回空（fail-closed，黄条侧已有 ban_effective 兜底）。
func (h *Handlers) autobanMissingLink(preset autobanPresetListState) string {
	if preset.id <= 0 {
		return ""
	}
	var policyReady int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies p
		WHERE COALESCE(p.enabled,0)=1 AND COALESCE(p.ip_acl_enabled,0)=1 AND COALESCE(p.ip_acl_mode,'')='deny'
		  AND json_valid(COALESCE(p.ip_acl_list_refs,'[]'))
		  AND EXISTS (SELECT 1 FROM json_each(COALESCE(p.ip_acl_list_refs,'[]')) je WHERE je.value=?)`,
		preset.id).Scan(&policyReady); err != nil {
		return ""
	}
	if policyReady == 0 {
		return "policy"
	}
	return "binding"
}
