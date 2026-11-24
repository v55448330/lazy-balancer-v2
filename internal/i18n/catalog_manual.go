package i18n

// 手工补充词条（非 codemod 产物）：后端响应注记键，zh 母本 + en 译文。
// catalog_gen.go 由 gencatalog 从 JSON 生成不可手改；新增后端词条在此登记，
// 键 = FNV1a(zh)（与 codemod key_of 同算法）。

func init() {
	// IPv6 地理库开关退化提交注记（200 + 重载失败详情槽）。
	Register("k_7d87740a", "已保存，但重载 Caddy 配置失败（待下次成功重载生效）: %s", "Saved, but reloading the Caddy config failed (takes effect on the next successful reload): %s")
	// IPv6 地理库开关写失败 5xx 固定文案（DB 细节由服务层 error 日志留痕）。
	Register("k_6a9699ed", "保存 IPv6 开关失败", "Failed to save the IPv6 toggle")
	// 从节点服务控制执行失败 5xx 固定文案（票据凭证端点，底层错误只进审计+日志）。
	Register("k_37dad086", "服务控制执行失败", "Service control execution failed")

	// 通知中心 REST（订阅/投递/设置）响应词条：zh 母本 + en 译文成对。
	Register("k_20b2245c", "仅管理员可管理通知设置", "Only administrators can manage notification settings")
	// API Key 接入统计（REST 采集）非管理员 403——与「通知设置」文案区分，
	// 此前误复用通知设置文案指向无关页面（回归）。
	Register("k_83dc5539", "仅管理员可查看接入统计", "Only administrators can view access statistics")
	// 审计日志深翻页 400（i18n 化；此前 fmt.Sprintf 直写中文绕过词条表）。
	Register("k_c17e3275", "结果过多（超过 %d 页），请使用时间范围/用户/动作筛选缩小范围", "Too many results (more than %d pages); narrow the range by time range, user, or action")
	// Caddy 生命周期控制（启停/重启）嵌入式装配缺 cfg 的 503 降级文案。
	Register("k_26fd2037", "服务配置未初始化", "Service configuration is not initialized")
	Register("k_74125a73", "订阅事件不在目录中: %s", "Subscription event is not in the catalog: %s")
	Register("k_3ae60346", "订阅级别必须为 info/warn/critical", "Subscription level must be info/warn/critical")
	Register("k_0d569dd0", "不支持的投递状态过滤: %s", "Unsupported delivery status filter: %s")
	Register("k_e742ee3f", "通知投递不存在", "Notification delivery does not exist")
	Register("k_e18b003b", "仅可重发自己的通知投递", "You can only resend your own notification deliveries")
	Register("k_c16c1667", "该投递已处于待发队列", "This delivery is already queued for sending")
	Register("k_07b47533", "重发已受理，等待投递", "Resend accepted, waiting for delivery")
	Register("k_75aeb7a0", "测试消息已加入投递队列，结果见投递记录", "Test message queued for delivery; see delivery log for the result")
	Register("k_165a4c01", "日报测试已加入投递队列，结果见投递记录", "Daily report test queued for delivery; see delivery log for the result")
	Register("k_d37587be", "SMTP 端口必须为 1-65535 的数字", "SMTP port must be a number between 1 and 65535")
	Register("k_04f0eea4", "拦截告警阈值需满足 0 < warn < critical", "Alert thresholds must satisfy 0 < warn < critical")
	Register("k_ce6e6687", "通知设置已保存", "Notification settings saved")
	Register("k_e0d0be34", "每日日报已触发", "Daily report triggered")
	Register("k_43ce31bf", "日报生成失败: %s", "Failed to generate the daily report: %s")

	// MCP 会话可见性与统计（通知中心）响应词条：zh 母本 + en 译文成对。
	Register("k_963a42ce", "MCP 已停用", "MCP is disabled")
	Register("k_3ef73d3f", "MCP 会话不存在", "MCP session does not exist")
	Register("k_835205fe", "读取 MCP 会话失败", "Failed to load MCP sessions")
	Register("k_1b35f304", "断开 MCP 会话失败", "Failed to disconnect the MCP session")
	Register("k_768f666d", "MCP 会话已断开", "MCP session disconnected")
	Register("k_369f2da8", "读取 MCP 统计失败", "Failed to load MCP statistics")

	// 通知通道 CRUD/测试响应词条（zh 母本 + en 译文成对）。
	Register("k_0b1f0aee", "不支持的通知通道类型", "Unsupported notification channel type")
	Register("k_6928b5b0", "仅可管理自己的通知通道", "You can only manage your own notification channels")
	Register("k_435eb4ab", "仅可测试自己的通知通道", "You can only test your own notification channels")
	Register("k_8e353bc9", "测试消息发送失败: %s", "Failed to send the test message: %s")
	Register("k_4bde3724", "测试消息已发送", "Test message sent")
	Register("k_9be13c70", "未知事件组: %s", "Unknown event group: %s")
	// 规则保存：非空通道选择经就绪门清洗后为空（全部已停用/未通过测试/微信会话待刷新）。
	Register("k_6287f2db", "选定的通知通道均不可用（已停用/未通过测试/微信会话待刷新）", "None of the selected notification channels is available (disabled, not passing the test, or the WeChat session needs to be refreshed)")
	Register("k_958958af", "无效规则 ID: %s", "Invalid rule ID: %s")
	// 规则级事件×通道模板保存门（与派发渲染口径同门：webhook=JSON 载荷、
	// 机器人/邮件=文本模板长度上限）。
	Register("k_00c1f3e8", "规则模板不是合法 JSON（占位符替换后仍需可解析）", "The rule template is not valid JSON (placeholders must still parse after substitution)")
	Register("k_0d9a61a4", "规则模板过长（机器人通道 ≤2000 字节，邮件 ≤4000 字节）", "The rule template is too long (≤2000 bytes for bots, ≤4000 bytes for email)")
	// 任务监控：不可取消任务的取消拒绝（409）。与「任务未在运行中或不支持取消」
	// 拆分——运行中的不可取消任务不得报「未在运行」（与监控页显示自相矛盾）。
	Register("k_44b8c98f", "该任务不支持手动取消", "This task cannot be cancelled manually")
}
