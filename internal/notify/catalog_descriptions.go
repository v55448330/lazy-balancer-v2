package notify

// 事件说明单源（订阅浮层 hover 用）：一句话说明「什么条件会触发」，避免用户
// 只凭标题猜测。新增事件必须在此登记（测试强制全覆盖），前端经 CatalogItem
// description 展示；未登记时回退标题（不会出现空 tooltip）。
var catalogDescriptions = map[string]string{
	"auth.login_success":            "登录面板成功时提醒，带来源 IP。",
	"auth.login_failed":             "同一账号或 IP 在 10 分钟内连续登录失败 5 次时提醒；账号被锁定或禁用时立即提醒，偶尔输错一次不提醒。",
	"auth.password_changed":         "用户修改自己的登录密码时提醒。",
	"auth.mfa_changed":              "用户开启、关闭或重新绑定 MFA 时提醒。",
	"auth.mfa_verify_failed":        "同一账号或 IP 在 10 分钟内连续输错 MFA 验证码 5 次时提醒。",
	"auth.user_created":             "管理员新建用户时提醒。",
	"auth.user_deleted":             "管理员删除用户时提醒。",
	"auth.user_status_changed":      "管理员启用或禁用用户时提醒。",
	"auth.user_updated":             "管理员修改用户角色或显示名，或用户修改自己的显示名时提醒；改角色按警告，改显示名按信息。",
	"auth.password_reset":           "管理员重置用户密码时提醒。",
	"auth.apikey_created":           "创建 API 密钥时提醒。",
	"auth.apikey_deleted":           "删除 API 密钥时提醒。",
	"auth.apikey_toggled":           "启用或禁用 API 密钥时提醒。",
	"apikey.expiry_warning":         "密钥 7 天内到期时每天提醒一次，直到续期或停用。",
	"cfg.rule_created":              "新建负载均衡规则时提醒。",
	"cfg.rule_updated":              "修改负载均衡规则时提醒。",
	"cfg.rule_deleted":              "删除负载均衡规则时提醒。",
	"cfg.rule_toggled":              "启用或停用负载均衡规则时提醒。",
	"cfg.global_changed":            "保存基础设置或全局配置时提醒；证书相关配置走免费证书配置变更。",
	"cfg.caddy_apply_failed":        "Caddy 配置加载或重载失败时提醒。",
	"cfg.caddy_recovered":           "之前 Caddy 配置加载失败，修好后第一次成功加载时提醒；正常重载不提醒。",
	"cfg.import_done":               "配置导入成功时提醒。",
	"cfg.import_failed":             "配置导入失败时提醒。",
	"cfg.backup_done":               "自动或手动备份成功时提醒。",
	"cfg.backup_failed":             "自动或手动备份失败时提醒。",
	"cfg.restore_done":              "配置还原成功时提醒。",
	"cfg.restore_failed":            "配置还原失败时提醒。",
	"cfg.caddy_lifecycle":           "通过面板启动、停止或重启 Caddy 时提醒，包含操作失败。",
	"cfg.oidc_changed":              "修改 OIDC 单点登录配置时提醒。",
	"cfg.auto_backup_changed":       "修改自动备份设置时提醒。",
	"cfg.notification_changed":      "修改通知投递设置时提醒。",
	"cfg.cluster_settings_changed":  "修改集群管理设置时提醒。",
	"cert.issued":                   "证书签发或续签成功时提醒。",
	"cert.failed":                   "证书签发或续签失败时提醒。",
	"cert.expiry_warning":           "证书进入续期窗口但还没续签成功时每天提醒一次，直到续签。",
	"cert.config_changed":           "修改免费证书的 CA、DNS、ACME 邮箱、续期天数、到期提醒或重试次数时提醒。",
	"cluster.offline":               "集群节点心跳超时、失联时提醒。",
	"cluster.role_changed":          "集群节点主从角色发生切换时提醒。",
	"cluster.node_joined":           "新节点加入集群时提醒。",
	"cluster.node_removed":          "节点从集群移除时提醒。",
	"cluster.sync_drift":            "从节点发现本地数据与主节点记录不一致时提醒，只在刚发生漂移时提醒一次。",
	"cluster.service_control":       "主节点对从节点执行启停 Caddy、重启面板等服务操作时提醒。",
	"cluster.login_ticket":          "管理员为集群节点签发登录票据时提醒。",
	"cluster.node_settings_changed": "修改集群节点设置（忘记 PIN、注册令牌、访问地址、节点站点）时提醒。",
	"cluster.manual_sync":           "手动触发从节点配置同步时提醒。",
	"sys.startup_completed":         "面板启动完成并开始监听时提醒，每次启动只提醒一次。",
	"sys.startup_abnormal":          "面板启动失败或异常退出时提醒，带失败原因。",
	"sys.restart_requested":         "通过面板请求重启、系统即将重启时提醒。",
	"sec.blocked_aggregate":         "5 分钟内拦截达到 10 次时提醒一次；达到 50/200 次分别升级为警告/严重。正文列出拦截、挑战、自动封禁次数和 TOP 规则/IP/路径；低于 10 次不提醒。",
	"sec.challenge_summary":         "5 分钟内人机挑战达到 50 次时提醒一次，正文给出 TOP 原因和 IP；默认关闭，需要时在规则里开启。",
	"sec.cc_triggered":              "CC 防护触发人机挑战时提醒；同一 IP 10 分钟内只提醒一次，已被自动封禁的 IP 不再提醒。",
	"sec.autoban_triggered":         "自动封禁实际执行时提醒，带 IP、原因和时长。",
	"sec.autoban_summary":           "5 分钟内自动封禁达到 5 个 IP 时合并提醒一次，之后不再逐个 IP 提醒。",
	"sec.autoban_expired":           "自动封禁到期解封时提醒；默认关闭。",
	"sec.policy_changed":            "安全策略新建、修改、删除、绑定或解绑时提醒。",
	"sec.ip_list_changed":           "IP 名单或名单条目新建、修改、删除时提醒。",
	"sec.custom_rule_changed":       "自定义安全规则新建、修改或删除时提醒。",
	"sec.block_page_changed":        "拦截页新建、修改或删除时提醒。",
	"sec.autoban_config_changed":    "自动封禁配置变更、累犯记录移除或重置时提醒。",
	"sec.mcp_disconnected":          "管理员强制断开 MCP 会话时提醒。",
	"sec.lib_updated":               "规则库更新结束时提醒，带成功/失败和版本或错误摘要。",
	"sec.lib_settings_changed":      "修改安全库自动更新开关、定时设置或数据源开关时提醒。",
	"sec.ingest_degraded":           "安全事件入库出现异常时提醒，可能丢失安全事件，需尽快检查审计日志。",
	"sec.ingest_recovered":          "安全事件入库从异常恢复时提醒。",
	"notify.channel_down":           "QQ、微信等通知通道断开时提醒，事件会暂存并重投。",
	"notify.channel_recovered":      "通知通道恢复、投递正常时提醒。",
	"notify.channel_changed":        "通知通道新建、修改或删除时提醒。",
	"notify.rule_changed":           "通知订阅规则新建、修改或删除时提醒。",
	"task.succeeded":                "任意类型的任务执行成功时提醒，正文带任务类型与任务名；默认关闭。",
	"task.failed":                   "任意类型的任务执行失败时提醒，正文带任务类型、任务名和错误摘要。",
	"task.manual_action":            "用户手动触发、启停或取消任务时提醒。",
}

// catalogDescription 取事件说明；未登记回退标题（测试强制全覆盖）。
func catalogDescription(id string) string {
	if d := catalogDescriptions[id]; d != "" {
		return d
	}
	if e, ok := catalogByID(id); ok {
		return e.TitleFormat
	}
	return id
}
