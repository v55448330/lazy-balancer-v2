package notify

// 事件目录（27 类）——订阅矩阵 UI 与默认订阅的唯一事实源。
// 每项：事件 ID / 级别 / 默认是否订阅 / 标题与正文模板（中文单源，%s 参数）。
//
// 模板参数序契约（发布方必须遵守）：
//   - BodyFormat 的 %s/%d 参数按模板出现顺序编号，发布方 Event.Fields 以
//     "1","2",… 字符串键依序填充（fieldsArgs 按此序取参渲染）；多填的键
//     忽略、缺序则该参数位及之后全部丢失（fmt 宽度参数缺失告警降级为
//     %!s(MISSING)）——埋点以本文件为唯一参数序事实源。
//   - 事件级别不随发布方覆写语义（dispatch 仅在空值时回填目录级别）；
//     恢复类 info（cfg.caddy_recovered）与伴生 critical
//     （cfg.caddy_apply_failed）默认订阅一致，保证同一受众能收到成对事实。

import "strings"

// 事件 ID 常量（发布方使用；订阅矩阵 event_type 存同一字符串）。
const (
	EvtLoginSuccess       = "auth.login_success"
	EvtLoginFailed        = "auth.login_failed"
	EvtPasswordChanged    = "auth.password_changed"
	EvtMFAChanged         = "auth.mfa_changed"
	EvtMFAVerifyFailed    = "auth.mfa_verify_failed" // MFA 验证码校验失败（安全可观测）
	EvtUserCreated        = "auth.user_created"
	EvtUserDeleted        = "auth.user_deleted"
	EvtUserStatusChanged  = "auth.user_status_changed" // 启用/禁用
	EvtPasswordReset      = "auth.password_reset"      // 管理员重置密码
	EvtAPIKeyCreated      = "auth.apikey_created"
	EvtAPIKeyDeleted      = "auth.apikey_deleted"
	EvtRuleCreated        = "cfg.rule_created"
	EvtRuleUpdated        = "cfg.rule_updated"
	EvtRuleDeleted        = "cfg.rule_deleted"
	EvtRuleToggled        = "cfg.rule_toggled"
	EvtGlobalChanged      = "cfg.global_changed"
	EvtCaddyApplyFailed   = "cfg.caddy_apply_failed"
	EvtCaddyRecovered     = "cfg.caddy_recovered" // 应用失败标记清除的恢复 info（与 caddy_apply_failed 同受众默认订阅）
	EvtImportDone         = "cfg.import_done"
	EvtImportFailed       = "cfg.import_failed"
	EvtBackupDone         = "cfg.backup_done"
	EvtBackupFailed       = "cfg.backup_failed"
	EvtRestoreDone        = "cfg.restore_done"
	EvtRestoreFailed      = "cfg.restore_failed"
	EvtBlockedAggregate   = "sec.blocked_aggregate"
	EvtCCTriggered        = "sec.cc_triggered"
	EvtAutobanTriggered   = "sec.autoban_triggered"
	EvtAutobanExpired     = "sec.autoban_expired"
	EvtCertIssued         = "cert.issued"
	EvtCertFailed         = "cert.failed"
	EvtCertExpiryWarning  = "cert.expiry_warning"
	EvtClusterOffline     = "cluster.offline"
	EvtClusterRoleChanged = "cluster.role_changed"
	EvtClusterNodeJoined  = "cluster.node_joined"
	EvtClusterNodeRemoved = "cluster.node_removed"
	EvtClusterSyncDrift   = "cluster.sync_drift"
	EvtStartupCompleted   = "sys.startup_completed"
	EvtStartupAbnormal    = "sys.startup_abnormal"
	EvtDailyReport        = "sys.daily_report"
	EvtNotifyChannelDown  = "notify.channel_down" // 通道掉线自监控（走其它还活着的通道告警）
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
	{EvtPasswordReset, LevelWarn, true, "密码已重置", "管理员 %s 重置了用户「%s」的密码"},
	{EvtAPIKeyCreated, LevelInfo, false, "API 密钥已创建", "用户 %s 创建了 API 密钥「%s」"},
	{EvtAPIKeyDeleted, LevelWarn, true, "API 密钥已删除", "用户 %s 删除了 API 密钥「%s」"},
	{EvtRuleCreated, LevelInfo, false, "负载均衡规则已创建", "%s 创建了规则 %s"},
	{EvtRuleUpdated, LevelInfo, false, "负载均衡规则已修改", "%s 修改了规则 %s"},
	{EvtRuleDeleted, LevelWarn, true, "负载均衡规则已删除", "%s 删除了规则 %s"},
	{EvtRuleToggled, LevelInfo, false, "负载均衡规则已启停", "%s %s 了规则 %s"},
	{EvtGlobalChanged, LevelInfo, false, "全局配置已变更", "%s 修改了全局配置（%s）"},
	{EvtCaddyApplyFailed, LevelCritical, true, "Caddy 应用失败", "%s 的配置应用失败：%s"},
	{EvtCaddyRecovered, LevelInfo, true, "Caddy 应用恢复", "配置应用已恢复（%s）"},
	{EvtImportDone, LevelInfo, false, "配置导入完成", "%s 完成了配置导入"},
	{EvtImportFailed, LevelCritical, true, "配置导入失败", "配置导入失败：%s"},
	{EvtBackupDone, LevelInfo, false, "备份完成", "自动备份完成：%s"},
	{EvtBackupFailed, LevelCritical, true, "备份失败", "自动备份失败：%s"},
	{EvtRestoreDone, LevelInfo, false, "还原完成", "%s 完成了配置还原"},
	{EvtRestoreFailed, LevelCritical, true, "还原失败", "配置还原失败：%s"},
	{EvtBlockedAggregate, LevelInfo, true, "拦截聚合", "%d 分钟内拦截 %d 次（TOP 规则：%s）"},
	{EvtCCTriggered, LevelWarn, true, "CC 防护触发", "%s 命中 CC 异常阈值（%s）"},
	{EvtAutobanTriggered, LevelWarn, true, "自动封禁触发", "%s 被自动封禁（%s）"},
	{EvtAutobanExpired, LevelInfo, false, "自动封禁已到期", "%s 的自动封禁已到期解封"},
	{EvtCertIssued, LevelInfo, true, "证书签发成功", "%s 签发成功（%s）"},
	{EvtCertFailed, LevelCritical, true, "证书签发失败", "%s 签发失败：%s"},
	{EvtCertExpiryWarning, LevelWarn, true, "证书临期预警", "%s 将于 %s 到期（剩余 %d 天）"},
	{EvtClusterOffline, LevelCritical, true, "集群节点失联", "节点 %s 失联（最后活动 %s）"},
	{EvtClusterRoleChanged, LevelCritical, true, "集群角色翻转", "节点 %s 角色变更为 %s"},
	{EvtClusterNodeJoined, LevelInfo, false, "集群节点加入", "节点 %s 已加入集群"},
	{EvtClusterNodeRemoved, LevelWarn, true, "集群节点移除", "节点 %s 已被移除"},
	{EvtClusterSyncDrift, LevelWarn, true, "集群同步漂移", "节点 %s 检测到配置漂移"},
	{EvtStartupCompleted, LevelInfo, false, "系统启动完成", "面板启动完成（%s）"},
	{EvtStartupAbnormal, LevelCritical, true, "系统启动异常", "启动异常：%s"},
	// sys.daily_report 不进目录：日报已拆独立区块（per-user 配置+直接落投递，
	// 不走订阅矩阵事件订阅面）；事件键保留供投递记录展示。
	{EvtNotifyChannelDown, LevelWarn, true, "通知通道离线", "通知通道「%s」已离线（%s）——事件将暂存重投"},
}

// defaultSubscribedFor 新用户默认订阅集：critical+warn 全开，info 与日报默认关。
func defaultSubscribedFor(e catalogEntry) bool { return e.DefaultSub }

// catalogByID 事件 ID → 目录条目。
func catalogByID(id string) (catalogEntry, bool) {
	for _, e := range catalog {
		if e.ID == id {
			return e, true
		}
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
}

// catalogGroup 事件 ID 前缀 → 分组名（与 REST 契约约定的七个分组对齐；
// sys.* 与 notify.*（通道自监控）归入「系统」）。
func catalogGroup(id string) string {
	switch {
	case strings.HasPrefix(id, "auth."):
		return "认证"
	case strings.HasPrefix(id, "cfg."):
		return "配置"
	case strings.HasPrefix(id, "sec."):
		return "安全"
	case strings.HasPrefix(id, "cert."):
		return "证书"
	case strings.HasPrefix(id, "cluster."):
		return "集群"
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
		})
	}
	return out
}
