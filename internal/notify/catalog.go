package notify

// 事件目录（71 类）——订阅矩阵 UI 与默认订阅的唯一事实源。
// 每项：事件 ID / 级别 / 默认是否订阅 / 标题与正文模板（中文单源，%s 参数）。
//
// 模板参数序契约（发布方必须遵守）：
//   - BodyFormat 的 %s/%d 参数按模板出现顺序编号，发布方 Event.Fields 以
//     "1","2",… 字符串键依序填充（fieldsArgs 按此序取参渲染）；多填的键
//     忽略、缺序则该参数位及之后全部丢失（fmt 宽度参数缺失告警降级为
//     %!s(MISSING)）——埋点以本文件为唯一参数序事实源。
//   - 事件级别不随发布方覆写语义（dispatch 仅在空值时回填目录级别）；
//     恢复类 warn（cfg.caddy_recovered）与伴生 critical
//     （cfg.caddy_apply_failed）默认订阅一致，保证同一受众能收到成对事实。

import "strings"

// 事件 ID 常量（发布方使用；订阅矩阵 event_type 存同一字符串）。
const (
	EvtLoginSuccess           = "auth.login_success"
	EvtLoginFailed            = "auth.login_failed"
	EvtPasswordChanged        = "auth.password_changed"
	EvtMFAChanged             = "auth.mfa_changed"
	EvtMFAVerifyFailed        = "auth.mfa_verify_failed" // MFA 验证码校验失败（安全可观测）
	EvtUserCreated            = "auth.user_created"
	EvtUserDeleted            = "auth.user_deleted"
	EvtUserStatusChanged      = "auth.user_status_changed" // 启用/禁用
	EvtPasswordReset          = "auth.password_reset"      // 管理员重置密码
	EvtAPIKeyCreated          = "auth.apikey_created"
	EvtAPIKeyDeleted          = "auth.apikey_deleted"
	EvtRuleCreated            = "cfg.rule_created"
	EvtRuleUpdated            = "cfg.rule_updated"
	EvtRuleDeleted            = "cfg.rule_deleted"
	EvtRuleToggled            = "cfg.rule_toggled"
	EvtGlobalChanged          = "cfg.global_changed"
	EvtCaddyApplyFailed       = "cfg.caddy_apply_failed"
	EvtCaddyRecovered         = "cfg.caddy_recovered" // 应用失败标记清除的配置恢复（仅失败→成功转变，warn）
	EvtImportDone             = "cfg.import_done"
	EvtImportFailed           = "cfg.import_failed"
	EvtBackupDone             = "cfg.backup_done"
	EvtBackupFailed           = "cfg.backup_failed"
	EvtRestoreDone            = "cfg.restore_done"
	EvtRestoreFailed          = "cfg.restore_failed"
	EvtBlockedAggregate       = "sec.blocked_aggregate"
	EvtChallengeSummary       = "sec.challenge_summary"
	EvtCCTriggered            = "sec.cc_triggered"
	EvtAutobanTriggered       = "sec.autoban_triggered"
	EvtAutobanSummary         = "sec.autoban_summary"
	EvtAutobanExpired         = "sec.autoban_expired"
	EvtCertIssued             = "cert.issued"
	EvtCertFailed             = "cert.failed"
	EvtCertExpiryWarning      = "cert.expiry_warning"
	EvtClusterOffline         = "cluster.offline"
	EvtClusterRoleChanged     = "cluster.role_changed"
	EvtClusterNodeJoined      = "cluster.node_joined"
	EvtClusterNodeRemoved     = "cluster.node_removed"
	EvtClusterSyncDrift       = "cluster.sync_drift"
	EvtStartupCompleted       = "sys.startup_completed"
	EvtStartupAbnormal        = "sys.startup_abnormal"
	EvtDailyReport            = "sys.daily_report"
	EvtNotifyChannelDown      = "notify.channel_down"      // 通道掉线自监控（走其它还活着的通道告警）
	EvtNotifyChannelRecovered = "notify.channel_recovered" // 通道恢复（与掉线成对）
	EvtTaskFailed             = "task.failed"              // 定时任务执行失败
	EvtAPIKeyExpiryWarning    = "apikey.expiry_warning"    // API 密钥临期预警
	// ── 2026-11-21 用户裁定「全部都做」：写操作通知事件查漏补缺（T1+T2 全量）──
	EvtCaddyLifecycle         = "cfg.caddy_lifecycle"           // Caddy 启动/停止/重启
	EvtOIDCChanged            = "cfg.oidc_changed"              // OIDC 单点登录配置（动作参数）
	EvtAutoBackupChanged      = "cfg.auto_backup_changed"       // 自动备份设置
	EvtNotificationCfgChanged = "cfg.notification_changed"      // 通知投递设置
	EvtClusterSettingsChanged = "cfg.cluster_settings_changed"  // 集群设置
	EvtCertConfigChanged      = "cert.config_changed"           // 免费证书域配置（CA/DNS/续期等）
	EvtPolicyChanged          = "sec.policy_changed"            // 安全策略 CRUD/绑定/解绑/批量/拆分/默认策略（动作参数）
	EvtIPListChanged          = "sec.ip_list_changed"           // IP 名单 CRUD/条目增删（动作参数）
	EvtCustomRuleChanged      = "sec.custom_rule_changed"       // 自定义安全规则 CRUD
	EvtBlockPageChanged       = "sec.block_page_changed"        // 拦截页 CRUD
	EvtAutobanCfgChanged      = "sec.autoban_config_changed"    // 自动封禁配置/累犯移除
	EvtMCPDisconnected        = "sec.mcp_disconnected"          // MCP 会话强制断开
	EvtLibUpdated             = "sec.lib_updated"               // 规则库更新（手动/自动，四库终态）
	EvtIngestDegraded         = "sec.ingest_degraded"           // 安全事件摄取健康降级（聚合原因）
	EvtIngestRecovered        = "sec.ingest_recovered"          // 安全事件摄取健康恢复
	EvtUserUpdated            = "auth.user_updated"             // 管理员修改用户角色/显示名
	EvtLibSettingsChanged     = "sec.lib_settings_changed"      // 安全库自动更新/定时/v6 开关
	EvtClusterServiceControl  = "cluster.service_control"       // 主节点控制从节点服务（启停 Caddy/重启面板）
	EvtClusterLoginTicket     = "cluster.login_ticket"          // 集群登录票据签发（主节点侧）
	EvtClusterNodeSettings    = "cluster.node_settings_changed" // forget-pin/注册令牌/access-url/节点站点
	EvtClusterManualSync      = "cluster.manual_sync"           // 手动配置拉取同步
	EvtAPIKeyToggled          = "auth.apikey_toggled"           // API 密钥启用/禁用
	EvtRestartRequested       = "sys.restart_requested"         // 面板重启请求
	EvtTaskManualAction       = "task.manual_action"            // 任务手动触发/启停/取消/控制
	EvtNotifyChannelChanged   = "notify.channel_changed"        // 通知通道 CRUD
	EvtNotifyRuleChanged      = "notify.rule_changed"           // 通知规则 CRUD
)

// catalogEntry 事件目录条目。
type catalogEntry struct {
	ID          string
	Level       Level
	DefaultSub  bool   // 新用户默认订阅（critical+warn=true，info=false）
	TitleFormat string // 标题模板
	BodyFormat  string // 正文模板
}

// catalog 事件目录全集（订阅 UI 分组树按 Group 渲染）。
var catalog = []catalogEntry{
	{EvtLoginSuccess, LevelInfo, false, "登录成功", "用户 %s 于 %s 登录（%s）"},
	{EvtLoginFailed, LevelWarn, true, "登录失败", "用户 %s 登录失败（%s），来源 %s"},
	{EvtPasswordChanged, LevelWarn, true, "密码已修改", "用户 %s 修改了登录密码"},
	{EvtMFAChanged, LevelWarn, true, "MFA 配置变更", "用户 %s 变更了 MFA 配置（%s）"},
	{EvtMFAVerifyFailed, LevelWarn, true, "MFA 验证失败", "用户 %s 的 MFA 验证码校验失败（%s）"},
	{EvtUserCreated, LevelWarn, true, "用户已创建", "管理员 %s 创建了用户「%s」（角色：%s）"},
	{EvtUserDeleted, LevelWarn, true, "用户已删除", "管理员 %s 删除了用户「%s」"},
	{EvtUserStatusChanged, LevelWarn, true, "用户状态变更", "管理员 %s 将用户「%s」%s"},
	{EvtUserUpdated, LevelWarn, true, "用户配置变更", "用户 %s 修改了用户「%s」（%s）"},
	{EvtPasswordReset, LevelWarn, true, "密码已重置", "管理员 %s 重置了用户「%s」的密码"},
	{EvtAPIKeyCreated, LevelInfo, false, "API 密钥已创建", "用户 %s 创建了 API 密钥「%s」"},
	{EvtAPIKeyDeleted, LevelWarn, true, "API 密钥已删除", "用户 %s 删除了 API 密钥「%s」"},
	{EvtRuleCreated, LevelInfo, false, "负载均衡规则已创建", "%s 创建了规则 %s"},
	{EvtRuleUpdated, LevelInfo, false, "负载均衡规则已修改", "%s 修改了规则 %s"},
	{EvtRuleDeleted, LevelWarn, true, "负载均衡规则已删除", "%s 删除了规则 %s"},
	{EvtRuleToggled, LevelInfo, false, "负载均衡规则已启停", "%s %s 了规则 %s"},
	{EvtGlobalChanged, LevelInfo, false, "全局配置已变更", "%s 修改了全局配置（%s）"},
	{EvtCaddyApplyFailed, LevelCritical, true, "Caddy 应用失败", "%s 的配置应用失败：%s"},
	{EvtCaddyRecovered, LevelWarn, true, "Caddy 配置恢复", "Caddy 配置应用已恢复（%s）"},
	{EvtImportDone, LevelInfo, false, "配置导入完成", "%s 完成了配置导入"},
	{EvtImportFailed, LevelCritical, true, "配置导入失败", "配置导入失败：%s"},
	{EvtBackupDone, LevelInfo, false, "自动备份完成", "自动备份完成：%s"},
	{EvtBackupFailed, LevelCritical, true, "自动备份失败", "自动备份失败：%s"},
	{EvtRestoreDone, LevelInfo, false, "还原完成", "%s 完成了配置还原"},
	{EvtRestoreFailed, LevelCritical, true, "还原失败", "配置还原失败：%s"},
	{EvtBlockedAggregate, LevelInfo, true, "拦截聚合", "%s内拦截 %s 次 / 挑战 %s 次 / 自动封禁 %s 次（TOP 规则：%s；TOP IP：%s；TOP 路径：%s）"},
	{EvtChallengeSummary, LevelWarn, false, "挑战统计", "%s内挑战 %s 次（TOP 原因：%s；TOP IP：%s）"},
	{EvtCCTriggered, LevelWarn, true, "CC 防护触发", "%s 命中 CC 异常阈值（%s）"},
	{EvtAutobanTriggered, LevelWarn, true, "自动封禁触发", "%s 被自动封禁（%s）"},
	{EvtAutobanSummary, LevelWarn, true, "封禁风暴", "%s内自动封禁 %s 个 IP（最近：%s）"},
	{EvtAutobanExpired, LevelInfo, false, "自动封禁已到期", "%s 的自动封禁已到期解封"},
	{EvtCertIssued, LevelInfo, false, "证书签发成功", "%s 签发成功（%s）"},
	{EvtCertFailed, LevelCritical, true, "证书签发失败", "%s 签发失败：%s"},
	{EvtCertExpiryWarning, LevelWarn, true, "证书临期预警", "%s 将于 %s 到期（剩余 %s 天）"},
	{EvtClusterOffline, LevelCritical, true, "集群节点失联", "节点 %s 失联（最后活动 %s）"},
	{EvtClusterRoleChanged, LevelCritical, true, "集群角色翻转", "节点 %s 角色变更为 %s"},
	{EvtClusterNodeJoined, LevelInfo, false, "集群节点加入", "节点 %s 已加入集群"},
	{EvtClusterNodeRemoved, LevelWarn, true, "集群节点移除", "节点 %s 已被移除"},
	{EvtClusterSyncDrift, LevelWarn, true, "集群同步漂移", "节点 %s 检测到配置漂移"},
	{EvtStartupCompleted, LevelInfo, false, "系统启动完成", "面板启动完成（%s）"},
	{EvtStartupAbnormal, LevelCritical, true, "系统启动异常", "启动异常：%s"},
	{EvtIngestDegraded, LevelWarn, true, "安全事件摄取降级", "安全事件摄取降级：%s"},
	{EvtIngestRecovered, LevelInfo, true, "安全事件摄取恢复", "安全事件摄取已恢复（降级原因：%s）"},
	// sys.daily_report 不进目录：日报已拆独立区块（per-user 配置+直接落投递，
	// 不走订阅矩阵事件订阅面）；事件键保留供投递记录展示。
	{EvtNotifyChannelDown, LevelWarn, true, "通知通道离线", "通知通道「%s」已离线（%s）——事件将暂存重投"},
	{EvtNotifyChannelRecovered, LevelInfo, true, "通知通道恢复", "通知通道已恢复（%s），投递正常"},
	{EvtTaskFailed, LevelWarn, true, "定时任务失败", "任务 %s 执行失败：%s"},
	{EvtAPIKeyExpiryWarning, LevelWarn, true, "API 密钥临期", "API 密钥「%s」将于 %s 到期（剩余 %s 天）"},
	// ── 2026-11-21 查漏补缺批：可用性/安全敏感 = warn+默认订阅；常规运维 = info ──
	// cfg.caddy_lifecycle 参数序：1=操作人 2=动作（启动/停止/重启）3=结果
	// ——结果为自由文本，启动/停止失败同样发本事件，失败时传「失败：<原因摘要>」
	//（发布点见 handlers/caddy.go；模板本身不区分成功/失败措辞）。
	{EvtCaddyLifecycle, LevelWarn, true, "Caddy 服务启停", "用户 %s %s Caddy 服务（%s）"},
	{EvtOIDCChanged, LevelInfo, false, "OIDC 配置变更", "用户 %s %s了 OIDC 单点登录配置"},
	{EvtAutoBackupChanged, LevelInfo, false, "自动备份设置变更", "用户 %s 更新了自动备份设置"},
	{EvtNotificationCfgChanged, LevelInfo, false, "通知设置变更", "用户 %s 更新了通知投递设置"},
	{EvtClusterSettingsChanged, LevelInfo, false, "集群设置变更", "用户 %s 更新了集群设置"},
	{EvtCertConfigChanged, LevelInfo, false, "免费证书配置变更", "用户 %s %s（%s）"},
	{EvtPolicyChanged, LevelWarn, true, "安全策略变更", "用户 %s %s（策略：%s）"},
	{EvtIPListChanged, LevelInfo, false, "IP 名单变更", "用户 %s %s（名单：%s）"},
	{EvtCustomRuleChanged, LevelInfo, false, "自定义规则变更", "用户 %s %s（规则：%s）"},
	{EvtBlockPageChanged, LevelInfo, false, "拦截页变更", "用户 %s %s（页面：%s）"},
	{EvtAutobanCfgChanged, LevelWarn, true, "自动封禁配置变更", "用户 %s %s"},
	{EvtMCPDisconnected, LevelWarn, true, "MCP 会话断开", "管理员 %s 强制断开了 MCP 会话（%s）"},
	{EvtLibUpdated, LevelInfo, false, "规则库更新", "「%s」%s更新%s（%s）"},
	{EvtLibSettingsChanged, LevelInfo, false, "安全库设置变更", "用户 %s 变更了%s（%s）"},
	{EvtClusterServiceControl, LevelWarn, true, "集群服务控制", "管理员 %s 对节点 %s 执行 %s（%s）"},
	{EvtClusterLoginTicket, LevelWarn, true, "集群登录票据签发", "管理员 %s 签发了节点 %s 的登录票据（目标用户：%s）"},
	{EvtClusterNodeSettings, LevelWarn, true, "集群节点管理操作", "管理员 %s 执行了 %s（%s）"},
	{EvtClusterManualSync, LevelWarn, true, "集群手动同步", "用户 %s 发起了从节点配置拉取同步"},
	{EvtAPIKeyToggled, LevelWarn, true, "API 密钥状态变更", "用户 %s %s了 API 密钥「%s」"},
	{EvtRestartRequested, LevelWarn, true, "面板重启请求", "用户 %s 发起了面板重启，系统即将重启"},
	{EvtTaskManualAction, LevelInfo, false, "任务手动操作", "用户 %s 对任务 %s 执行了 %s"},
	{EvtNotifyChannelChanged, LevelInfo, false, "通知通道变更", "用户 %s %s了通知通道「%s」"},
	{EvtNotifyRuleChanged, LevelInfo, false, "通知规则变更", "用户 %s %s了通知规则「%s」"},
}

// defaultSubscribedFor 新用户默认订阅集：critical+warn 全开，info 与日报默认关。
func defaultSubscribedFor(e catalogEntry) bool { return e.DefaultSub }

// CatalogLookup 外部目录查询（集群上报端点的目录门——与 Publish 同口径）。
func CatalogLookup(id string) bool {
	_, ok := catalogByID(id)
	return ok
}

// catalogByID 事件 ID → 目录条目。
// catalogIndex 目录 O(1) 查找索引（catalog 切片保留给导出行序；每事件被
// 多路调用，线性扫 ~60 条是白热路径开销）。
var catalogIndex = func() map[string]catalogEntry {
	m := make(map[string]catalogEntry, len(catalog))
	for _, e := range catalog {
		m[e.ID] = e
	}
	return m
}()

func catalogByID(id string) (catalogEntry, bool) {
	if e, ok := catalogIndex[id]; ok {
		return e, true
	}
	return catalogEntry{}, false
}

// CatalogItem 目录导出行（REST /notification/catalog 消费；订阅矩阵 UI
// 分组树数据源）。
type CatalogItem struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	Level             string `json:"level"`
	DefaultSubscribed bool   `json:"default_subscribed"`
	Group             string `json:"group"`
	Description       string `json:"description"`
}

// catalogGroup 事件 ID 前缀 → 分组名（与 REST 契约约定的八个分组对齐；
// sys.* 与 notify.*（通道自监控）归入「系统」）。
func catalogGroup(id string) string {
	switch {
	case strings.HasPrefix(id, "auth."), strings.HasPrefix(id, "apikey."):
		return "认证"
	case strings.HasPrefix(id, "cfg."):
		return "配置"
	case strings.HasPrefix(id, "sec."):
		return "安全"
	case strings.HasPrefix(id, "cert."):
		return "证书"
	case strings.HasPrefix(id, "cluster."):
		return "集群"
	case strings.HasPrefix(id, "task."):
		return "任务"
	case strings.HasPrefix(id, "notify."):
		return "通知"
	case id == EvtCaddyLifecycle:
		return "系统" // 服务生命周期，不属配置内容
	default:
		return "系统"
	}
}

// CatalogExport 事件目录全量导出（catalog 唯一事实源的只读投影）。
func CatalogExport() []CatalogItem {
	out := make([]CatalogItem, 0, len(catalog))
	for _, e := range catalog {
		out = append(out, CatalogItem{
			ID:                e.ID,
			Title:             e.TitleFormat,
			Level:             string(e.Level),
			DefaultSubscribed: e.DefaultSub,
			Group:             catalogGroup(e.ID),
			Description:       catalogDescription(e.ID),
		})
	}
	return out
}
