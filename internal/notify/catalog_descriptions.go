package notify

// 事件说明单源（订阅浮层 hover 用）：一句话说明「什么条件会触发」，避免用户
// 只凭标题猜测。新增事件必须在此登记（测试强制全覆盖），前端经 CatalogItem
// description 展示；未登记时回退标题（不会出现空 tooltip）。
var catalogDescriptions = map[string]string{
	"auth.login_success":            "用户成功登录面板（含来源 IP）。",
	"auth.login_failed":             "登录认证失败、账户锁定或禁用；同一用户/IP 10 分钟内只通知一次，锁定/禁用终态立即通知。",
	"auth.password_changed":         "用户自行修改登录密码。",
	"auth.mfa_changed":              "用户启用、关闭或重新绑定 MFA。",
	"auth.mfa_verify_failed":        "MFA 验证码校验失败；同一用户/IP 10 分钟内只通知一次。",
	"auth.user_created":             "管理员创建新用户。",
	"auth.user_deleted":             "管理员删除用户。",
	"auth.user_status_changed":      "管理员启用或禁用用户。",
	"auth.user_updated":             "管理员修改用户角色或显示名（纯粹启停走状态变更事件）。",
	"auth.password_reset":           "管理员重置用户密码。",
	"auth.apikey_created":           "用户创建 API 密钥。",
	"auth.apikey_deleted":           "用户删除 API 密钥。",
	"auth.apikey_toggled":           "用户启用或禁用 API 密钥。",
	"apikey.expiry_warning":         "启用的 API 密钥将在 7 天内到期（每个密钥每日一次）。",
	"cfg.rule_created":              "创建负载均衡规则。",
	"cfg.rule_updated":              "修改负载均衡规则。",
	"cfg.rule_deleted":              "删除负载均衡规则。",
	"cfg.rule_toggled":              "启用或停用负载均衡规则。",
	"cfg.global_changed":            "保存基础设置/全局配置（证书域配置见「免费证书配置变更」）。",
	"cfg.caddy_apply_failed":        "配置应用/重载 Caddy 失败。",
	"cfg.caddy_recovered":           "此前的 Caddy 应用失败标记在成功重载后清除（仅失败→成功转变时发一次，不是每次成功重载）。",
	"cfg.import_done":               "配置导入成功。",
	"cfg.import_failed":             "配置导入失败。",
	"cfg.backup_done":               "自动/手动备份成功。",
	"cfg.backup_failed":             "自动/手动备份失败。",
	"cfg.restore_done":              "配置还原完成。",
	"cfg.restore_failed":            "配置还原失败。",
	"cfg.caddy_lifecycle":           "通过面板启动、停止或重启 Caddy 服务（含失败结果）。",
	"cfg.oidc_changed":              "修改 OIDC 单点登录配置。",
	"cfg.auto_backup_changed":       "修改自动备份设置。",
	"cfg.notification_changed":      "修改通知投递设置（SMTP/保留期等）。",
	"cfg.cluster_settings_changed":  "修改集群管理设置。",
	"cert.issued":                   "证书签发或续签成功。",
	"cert.failed":                   "证书签发或续签失败。",
	"cert.expiry_warning":           "证书进入续期窗口且尚未续签成功；每证书每日最多一次。",
	"cert.config_changed":           "免费证书域配置变更：CA 提供商、DNS 提供商配置、ACME 邮箱、续期天数、过期提醒或重试次数。",
	"cluster.offline":               "集群节点失联（心跳超时）。",
	"cluster.role_changed":          "节点主从角色发生翻转。",
	"cluster.node_joined":           "新节点加入集群。",
	"cluster.node_removed":          "节点从集群移除。",
	"cluster.sync_drift":            "从节点检测到本地数据与主节点同步记录不一致（仅在进入漂移时通知一次）。",
	"cluster.service_control":       "主节点对从节点执行服务控制（启停 Caddy/重启面板等）。",
	"cluster.login_ticket":          "管理员为集群节点签发登录票据。",
	"cluster.node_settings_changed": "集群节点管理操作：forget-pin、注册令牌、访问地址或节点站点变更。",
	"cluster.manual_sync":           "手动触发从节点配置拉取同步。",
	"sys.startup_completed":         "面板启动完成、开始监听（每个进程一次）。",
	"sys.startup_abnormal":          "面板启动失败/异常退出（含原因摘要）。",
	"sys.restart_requested":         "通过面板请求重启，系统即将重启。",
	"sec.blocked_aggregate":         "WAF 拦截按 5 分钟窗口聚合：每级别至多一条（首发 info，跨阈值补 warn/critical），正文含拦截/挑战/自动封禁计数与 TOP 规则。",
	"sec.cc_triggered":              "CC 防护规则触发人机挑战；同 IP 10 分钟内去重，该 IP 已被自动封禁时抑制。",
	"sec.autoban_triggered":         "自动封禁实际执行（含 IP、原因与时长）。",
	"sec.autoban_expired":           "自动封禁到期解封（逐 IP，默认关闭）。",
	"sec.policy_changed":            "安全策略创建、更新、删除、绑定/解绑、批量或拆分，以及默认策略应用。",
	"sec.ip_list_changed":           "IP 名单或名单条目创建、修改、删除。",
	"sec.custom_rule_changed":       "自定义安全规则创建、更新或删除。",
	"sec.block_page_changed":        "拦截页创建、更新或删除。",
	"sec.autoban_config_changed":    "自动封禁配置变更、累犯记录移除或重置。",
	"sec.mcp_disconnected":          "管理员强制断开 MCP 会话。",
	"sec.lib_updated":               "规则库更新终态（CRS/IP2Region/威胁情报/爬虫，手动或自动；含成功/失败与版本或错误摘要）。",
	"sec.lib_settings_changed":      "安全库自动更新开关、定时设置或数据源开关变更。",
	"sec.ingest_degraded":           "安全事件摄取降级：审计日志畸形区、写侧丢弃、命中明细截断或计数不可读（可能丢失安全事件）。",
	"sec.ingest_recovered":          "安全事件摄取从降级恢复。",
	"notify.channel_down":           "通知通道离线（QQ/微信连接断开等），事件将暂存重投。",
	"notify.channel_recovered":      "通知通道恢复，投递恢复正常。",
	"notify.channel_changed":        "通知通道创建、更新或删除。",
	"notify.rule_changed":           "通知订阅规则创建、更新或删除。",
	"task.failed":                   "定时/周期任务执行失败（含任务名与错误摘要）。",
	"task.manual_action":            "用户手动触发、启停或取消任务。",
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
