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
	// 此前误复用通知设置文案指向无关页面。
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
	// 任务监控：畸形 cert-job ID 的 400（此前硬编码英文 "Invalid job ID"，
	// message_key 缺失导致双语界面切换对该提示无效）。
	Register("k_688f8e91", "无效的任务 ID", "Invalid job ID")
	// 任务监控：不可取消任务的取消拒绝（409）。与「任务未在运行中或不支持取消」
	// 拆分——运行中的不可取消任务不得报「未在运行」（与监控页显示自相矛盾）。
	Register("k_44b8c98f", "该任务不支持手动取消", "This task cannot be cancelled manually")

	// 保存基础/Caddy 全局设置的成功响应（此前中文字面量直出，en 界面显示中文）。
	// base 键区分「已应用」与「仅落库」，格式清空说明用模板键接在后面。
	Register("k_60212d99", "配置已更新并应用", "Configuration updated and applied")
	Register("k_400c411d", "配置已更新", "Configuration updated")
	Register("k_4fb4b00b", "%s（访问日志 JSON 已关闭，自定义格式已清空：该格式不生效）", "%s (access-log JSON is off, so the custom format was cleared and has no effect)")

	// 导入/还原结果的固定告警：当前账户被替换、部分成功 + 规则库数据文件缺失的
	// 固定说明。会话吊销告警按「导入/还原」动作各登记一条（见下方告警面）。
	Register("k_610d9398", "备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录", "The backup does not contain the current account — system data was replaced, so sign in with an administrator account from the backup")
	Register("k_4c105363", "配置已%s（部分完成）：证书任务恢复失败: %s", "Configuration %s (partially completed): restoring certificate tasks failed: %s")
	Register("k_672e1587", "数据库已提交，但证书任务恢复失败: %s", "The database was committed, but restoring certificate tasks failed: %s")
	Register("k_15ae2f31", "备份不含规则库数据文件——规则库版本记录已跳过（仅 lbbak 完整备份可导入该类）", "The backup has no rule-library data files — the rule-library version record was skipped (only a complete lbbak backup can carry it)")
	Register("k_a8f33c4d", "备份不含 CRS 数据文件——CRS 版本记录已跳过（仅含该文件的 lbbak 备份可导入）", "The backup has no CRS data files — the CRS version record was skipped (only an lbbak backup containing it can import it)")
	Register("k_81ef1989", "备份不含 IP2Region 数据文件——IP2Region 版本记录已跳过（仅含该文件的 lbbak 备份可导入）", "The backup has no IP2Region data files — the IP2Region version record was skipped (only an lbbak backup containing it can import it)")

	// 日志存储条的治理说明（悬浮提示）：来源（config_source）与保留口径
	// （retention_note）此前为中文直出，en 界面混入中文。
	Register("k_1c5a5dd2", "基础设置 · 日志保留（操作/运行/安全事件）", "Basic settings · log retention (operations/runtime/security events)")
	Register("k_a842fc6f", "基础设置 · 任务日志大小", "Basic settings · task log size")
	Register("k_e1eefb8b", "基础设置 · 运行日志大小", "Basic settings · runtime log size")
	Register("k_f4f4504f", "Caddy 全局配置 · 日志大小", "Caddy global settings · log size")
	Register("k_2784868e", "统一任务日志（%s）", "Unified task log (%s)")
	Register("k_916311e9", "每日清理 · 保留 %s 个月", "Cleaned daily · keep %s months")
	Register("k_7a8d7d93", "时间戳轮转，按保留期清理（份数随保留期）", "Timestamp rotation, pruned by the retention period (copy count follows it)")

	// 导入/还原告警面（预览与结果弹框的 warnings、冲突明细原因）：产出点只记
	// 事实（handlers.importWarning：键 + 参数），预览/导入/还原响应按请求语言
	// 渲染，操作审计明细恒取中文母本。带「导入/还原」动作词的整句各登记一条
	// （动作词在两种语言里的句中形态不同，不做词级拼接）。
	Register("k_959f5965", "纯 JSON 备份不携带威胁名单文件，已保留本地威胁源配置与名单", "The plain JSON backup carries no threat-list files; local threat-source settings and lists were kept")
	Register("k_64ab7fb0", "规则 %s 的域名为空，已跳过导入", "Rule %s has an empty domain and was skipped")
	Register("k_f4867f3d", "%d 条安全策略绑定随空域名规则一并跳过", "%d security policy bindings were skipped together with the empty-domain rules")
	Register("k_9777b466", "拦截页面 %s 的内容为空，已跳过导入", "Block page %s has empty content and was skipped")
	Register("k_517d0571", "%d 条版本/源记录携带「更新中」活动态，导入节点不执行该任务，已归一为 failed", "%d version/source records carried an active \"updating\" state; this node does not run that task after import, so they were normalized to failed")
	Register("k_d45c1567", "%d 条版本/源记录的 update_status 不在词表内，已归一为 idle", "%d version/source records had an update_status outside the allowed vocabulary and were normalized to idle")
	Register("k_54e8dd71", "%d 条证书任务引用的 CA 提供商不存在或已禁用，已归一为跟随默认提供商（原引用会导致任务首次入队即失败）", "%d certificate jobs referenced a CA provider that is missing or disabled; they were normalized to follow the default provider (the original reference would make the job fail on its first enqueue)")
	Register("k_56860680", "%d 个证书任务的 CA 提供商已禁用——续签将失败（任务转 failed 终态），请补齐 CA 提供商或在证书页手工重试", "%d certificate jobs use a disabled CA provider, so renewal will fail (the job ends in the failed state); fix the CA provider or retry manually on the certificates page")
	Register("k_464e8105", "%d 个证书任务引用的 CA 提供商已不存在——续签时将回落首个启用提供商（自愈），如需保持原提供商请补齐", "%d certificate jobs reference a CA provider that no longer exists; renewal falls back to the first enabled provider (self-healing), so add the provider back if the original one must be kept")
	Register("k_5c8dbec2", "证书任务 CA 提供商悬挂统计未完成（读取失败）：%s", "The dangling check for certificate-job CA providers did not complete (read failed): %s")
	Register("k_a941d605", "证书任务 CA 提供商悬挂统计未完成（读取失败，导入本身不受影响）：%s", "The dangling check for certificate-job CA providers did not complete (read failed; the import itself is unaffected): %s")
	Register("k_c321af37", "ACME 引用悬挂统计未完成（读取失败，导入本身不受影响）：%s", "The dangling check for ACME references did not complete (read failed; the import itself is unaffected): %s")
	Register("k_f5db32dd", "备份未记录导出产品版本，当前运行版本为 %s——跨版本还原前请确认兼容性", "The backup does not record the product version it was exported from, while the current running version is %s. Confirm compatibility before restoring across versions")
	Register("k_264dfeb4", "备份导出产品版本为 %s，当前运行版本为 %s——跨版本还原可能存在兼容性差异，请确认后继续", "The backup was exported by product version %s, while the current running version is %s. Restoring across versions may cause compatibility differences, so confirm before continuing")
	Register("k_1c71d3a4", "备份不含完整性校验和（史前版本导出），已按结构性校验导入——文件内容未经摘要校验，建议尽快用当前版本重新导出备份", "The backup has no integrity checksum (exported by an early version) and was imported after structural validation only; its contents were not verified by digest. Re-export the backup with the current version as soon as possible")
	Register("k_fff391ed", "备份同时替换 CRS 规则树：安全策略中的 CRS 组号/规则 ID 未按当前规则库做存在性校验（落地基准以备份内规则树为准）——导入后请在安全策略页复核选组，避免空 Include 静默失效", "The backup also replaces the CRS rule tree: CRS group/rule IDs in security policies were not checked against the current rule library (the backup's rule tree is the baseline after landing). Review the selected groups on the security policy page after import, so that an empty Include does not fail silently")
	Register("k_acbc4130", "备份不包含当前操作账户——若导入时勾选“系统数据”，导入后请使用备份内的管理员账户登录", "The backup does not contain the current account; if \"System data\" is selected on import, sign in afterwards with an administrator account from the backup")
	Register("k_3f3a9de7", "lbbak 完整备份（含规则库数据文件，完整性已校验）——规则库数据库分类将随导入落盘", "Complete lbbak backup (rule-library data files included, integrity verified); the rule-library database category will be written to disk on import")
	Register("k_23ca6349", "lbbak 含威胁库名单文件（完整性已校验）——导入「安全防护」将落盘名单文件；本包不含 CRS/IP2Region 数据文件", "The lbbak contains threat-list files (integrity verified); importing \"Security protection\" will write the list files to disk, and this package has no CRS/IP2Region data files")
	Register("k_d5ab8a60", "lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验，已按原样落盘；建议核实来源后重新导出备份", "The lbbak contains threat-library entries not registered in the manifest (%s); their contents were not integrity-verified and were written to disk as is. Verify the source and re-export the backup")
	Register("k_b46f2ff0", "lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验；本次分类未选择安全防护数据，条目未导入、未落盘", "The lbbak contains threat-library entries not registered in the manifest (%s); their contents were not integrity-verified, and the Security protection category was not selected, so the entries were not imported or written to disk")
	Register("k_922ae27b", "品牌配置文件还原失败: %s", "Failed to restore the branding configuration file: %s")
	Register("k_f42c573c", "品牌镜像刷新失败: %s", "Failed to refresh the branding mirror: %s")
	Register("k_d201bf89", "%d 个节点的备份令牌与本地不一致，已保留本地令牌与审批状态（备份仅恢复拓扑属性，从节点无需重新审批）", "%d nodes had backup tokens that differ from the local ones; the local tokens and approval states were kept (the backup only restores topology attributes, so slaves need no re-approval)")
	Register("k_653168b7", "%d 条记录的归属用户未随备份包含或已被替换，作者显示可能为空或错配（导入未改写归属字段）", "%d records have an owner that was not included in the backup or was replaced, so the author may show as empty or mismatched (the import did not rewrite ownership fields)")
	Register("k_e59272f4", "已按导入后的规则与策略视图清理 %d 条悬挂安全策略绑定", "%d dangling security policy bindings were cleaned up according to the post-import rule and policy view")
	Register("k_8f24dccc", "%d 个 WAF 模式为 off 且挂启用自定义规则的策略已按旧语义归一为 custom_only（自定义规则开始生效）", "%d policies with WAF mode off and enabled custom rules were normalized to custom_only under the legacy semantics (the custom rules start to take effect)")
	Register("k_3bcda218", "已解除 %d 条 TCP 规则的安全策略绑定（TCP 不参与策略渲染）", "%d security policy bindings on TCP rules were removed (TCP does not take part in policy rendering)")
	Register("k_ae6c81db", "备份未携带 OIDC 配置——现有 OIDC 配置已随备份收敛清空（用户数据按备份替换，避免「OIDC 启用但零用户」不一致状态）", "The backup carries no OIDC configuration, so the existing OIDC configuration was cleared to converge with the backup (user data is replaced by the backup, avoiding an inconsistent state with OIDC enabled but zero users)")
	Register("k_893f9b1b", "爬虫运行快照重建失败（重启或下次更新后重试）: %s", "Failed to rebuild the crawler runtime snapshot (retry after a restart or the next update): %s")
	Register("k_54eed4be", "管理面板 HTTPS 配置已导入，需重启后生效（当前进程继续使用启动时的证书）", "The admin panel HTTPS configuration was imported; a restart is required for it to take effect (the current process keeps using the certificate loaded at startup)")
	Register("k_725cf35e", "管理面板 HTTPS 配置已还原，需重启后生效（当前进程继续使用启动时的证书）", "The admin panel HTTPS configuration was restored; a restart is required for it to take effect (the current process keeps using the certificate loaded at startup)")
	Register("k_dffc3f29", "系统数据已导入：全部登录会话已吊销，请重新登录", "System data was imported: all login sessions were revoked, please sign in again")
	Register("k_23e13305", "系统数据已还原：全部登录会话已吊销，请重新登录", "System data was restored: all login sessions were revoked, please sign in again")
	Register("k_5a6b172f", "导入后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐", "After import, %d enabled rules have dangling DNS provider configuration (the reference did not come with the backup and is missing or disabled in the current configuration), so the next issuance/renewal will fail; fix it promptly")
	Register("k_6518c08b", "还原后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐", "After restore, %d enabled rules have dangling DNS provider configuration (the reference did not come with the backup and is missing or disabled in the current configuration), so the next issuance/renewal will fail; fix it promptly")
	Register("k_8a06e6ae", "导入后 %d 条启用规则的 DNS 提供商配置悬挂（引用不在导入数据中）——下一次签发/续签将失败，请及时补齐", "After import, %d enabled rules have dangling DNS provider configuration (the reference is not in the imported data), so the next issuance/renewal will fail; fix it promptly")
	Register("k_0f2464ba", "还原后 %d 条启用规则的 DNS 提供商配置悬挂（引用不在导入数据中）——下一次签发/续签将失败，请及时补齐", "After restore, %d enabled rules have dangling DNS provider configuration (the reference is not in the restored data), so the next issuance/renewal will fail; fix it promptly")
	Register("k_39df510b", "证书签发队列已恢复运行，但导入后的任务恢复未完成：%s——请检查证书任务列表，必要时手动重试", "The certificate issuance queue is running again, but the post-import task recovery did not complete: %s. Check the certificate job list and retry manually if needed")
	Register("k_7f690b4a", "证书签发任务保持停止，且导入后的任务恢复未完成：%s——请检查证书任务列表，恢复该任务后才会继续推进", "The certificate issuance task remains stopped and the post-import task recovery did not complete: %s. Check the certificate job list; progress resumes only after the task is resumed")
	Register("k_854c7ae0", "证书签发任务已停止：导入的非终态证书任务本窗口未重排（数量统计失败，请检查任务列表）——恢复该任务后才会继续推进", "The certificate issuance task is stopped: non-terminal certificate jobs from the import were not rescheduled in this window (the count failed, so check the job list). Progress resumes only after the task is resumed")
	Register("k_96e1e1a8", "%d 个非终态证书任务因证书签发任务已停止而未重排——恢复该任务后才会继续推进", "%d non-terminal certificate jobs were not rescheduled because the certificate issuance task is stopped. Progress resumes only after the task is resumed")
	Register("k_550e4adc", "规则 %s（%s）：%s", "Rule %s (%s): %s")
	Register("k_328102ef", "规则 %s：%s", "Rule %s: %s")
	Register("k_64f5881f", "证书链可能不完整，部分客户端将握手失败", "The certificate chain may be incomplete, so some clients will fail the handshake")
	Register("k_f24a01f7", "证书域名与规则域名不匹配", "The certificate domain does not match the rule domain")
	Register("k_233440d6", "证书已过期 (过期时间: %s)", "Certificate expired (expired on: %s)")
	Register("k_4167ea7d", "证书尚未生效 (生效时间: %s)", "Certificate not yet valid (valid from: %s)")

	// 自动封禁运行期收敛说明（services.AutobanConfigReplaceEffectNote，分句与
	// 列举项的连接符随语言）、导入钳制说明、冲突明细原因。
	Register("k_f51fda25", "统计窗口由 %d 分钟改为 %d 分钟", "statistics window changed from %d to %d minutes")
	Register("k_a5957fda", "统计口径由 %s 改为 %s", "statistics scope changed from %s to %s")
	Register("k_bc07f397", "计数方式由 %s 改为 %s", "counting mode changed from %s to %s")
	Register("k_e652808f", "嫌疑累计倍率由 %d 改为 %d", "suspicion accumulation multiplier changed from %d to %d")
	Register("k_5036bfda", "确证打底比例由 %s 改为 %s", "confirmation floor ratio changed from %s to %s")
	Register("k_7fccba3a", "证据分层计数参数变更（%s）", "evidence-tiered counting parameters changed (%s)")
	Register("k_ca3c3bab", "，已清空自动封禁统计计数（旧计数不适用于新口径）", ", so the auto-ban statistics counters were cleared (old counts do not fit the new criteria)")
	Register("k_e5903e21", "封禁阈值由 %d 改为 %d，已按新阈值重算统计达标标记", "ban threshold changed from %d to %d, and the statistics reached-marks were recomputed under the new threshold")
	Register("k_922a8854", "自动封禁已停用，已执行禁用收尾（到期条目解封、统计计数清空）", "auto-ban is now disabled and disable finalization was run (expired entries unbanned, statistics counters cleared)")
	Register("k_dd8099ce", "自动封禁处于停用态，已清理到期条目并清空统计计数", "auto-ban is disabled; expired entries were cleaned up and the statistics counters were cleared")
	Register("k_27b4fed8", "自动封禁已启用，调度已按新配置开启", "auto-ban is now enabled and scheduling was started under the new configuration")
	Register("k_1f352d1a", "自动封禁配置变更：", "Auto-ban configuration changed: ")
	Register("k_5452edb3", "autoban_threshold 越界（%d），已钳位为 %d", "autoban_threshold out of range (%d), clamped to %d")
	Register("k_f5cd955a", "autoban_threshold 非整数形态，已归一为 %d", "autoban_threshold was not an integer, normalized to %d")
	Register("k_933e7850", "autoban_window_minutes 越界（%d），已钳位为 %d", "autoban_window_minutes out of range (%d), clamped to %d")
	Register("k_f37da833", "autoban_window_minutes 非整数形态，已归一为 %d", "autoban_window_minutes was not an integer, normalized to %d")
	Register("k_ff362aae", "autoban_scope 空值，已归一为默认全选", "autoban_scope was empty, normalized to the default (all selected)")
	Register("k_979ef9c1", "autoban_scope 旧单值口径（%s）已迁移为多选集合（%s）", "autoban_scope legacy single value (%s) was migrated to the multi-select set (%s)")
	Register("k_f59c70bf", "autoban_suspicion_multiplier 越界（%d），已钳位为 %d", "autoban_suspicion_multiplier out of range (%d), clamped to %d")
	Register("k_6277ad5e", "autoban_suspicion_multiplier 非整数形态，已归一为 %d", "autoban_suspicion_multiplier was not an integer, normalized to %d")
	Register("k_75473069", "%s 空值，已归一为 %s", "%s was empty, normalized to %s")
	Register("k_8da541b9", "request_body_max_size_mb 非法形态（%v），已归一为 %d", "request_body_max_size_mb has an invalid form (%v), normalized to %d")
	Register("k_3acfb6ae", "request_body_max_size_mb 越界（%d），已钳位为 %d", "request_body_max_size_mb out of range (%d), clamped to %d")
	Register("k_be9391c5", "%s 非法形态，已重置为 %d", "%s has an invalid form, reset to %d")
	Register("k_0906bec1", "%s 非法（须为正整数），已归默认 %d", "%s is invalid (must be a positive integer), reset to the default %d")
	Register("k_fa5433f6", "%s 越界，已重置为 %d", "%s out of range, reset to %d")
	Register("k_ab5ac3ed", "%s 越界（%d），已钳位为 %d", "%s out of range (%d), clamped to %d")
	Register("k_4047995d", "端口 %d 的 TLS 与明文规则不能混布（该端口监听器将整体切换为 TLS，明文规则不可达）", "TLS and plain-text rules cannot share port %d (the listener on this port switches to TLS as a whole, making the plain-text rules unreachable)")
	Register("k_06f94a25", "HTTP 域名 %s 重复", "HTTP domain %s is duplicated")
	Register("k_6cab3806", "HTTP 域名 %s 被 HTTPS 跳转遮蔽", "HTTP domain %s is shadowed by the HTTPS redirect")
	Register("k_99a31c82", "TCP 监听端口 %d 重复", "TCP listen port %d is duplicated")
	Register("k_e25b3624", "TCP 与 HTTP 监听端口 %d 冲突", "TCP and HTTP conflict on listen port %d")

	// v1（nginx）导入的转换/跳过/归一说明与三条固定说明。
	Register("k_601d3128", "规则 %s 的负载策略 %s 无法映射，已使用 weighted_round_robin", "Rule %s: load-balancing strategy %s cannot be mapped; weighted_round_robin was used")
	Register("k_edbaf122", "规则 %s 的域名 %s 无效，已跳过导入: %s", "Rule %s: domain %s is invalid and was skipped: %s")
	Register("k_2d634eaf", "规则 #%d（%s）：%v", "Rule #%d (%s): %v")
	Register("k_36a641a5", "规则 #%d（%s）：协议无效", "Rule #%d (%s): invalid protocol")
	Register("k_3112f593", "规则 #%d（%s）：域名 %s 无效", "Rule #%d (%s): invalid domain %s")
	Register("k_735a8f5e", "规则 #%d（%s）上游 #%d：HTTP 规则上游协议 %s 已按 %s 导入", "Rule #%d (%s) upstream #%d: upstream protocol %s on an HTTP rule was imported as %s")
	Register("k_dcf9c45f", "规则 #%d（%s）上游 #%d：TCP 规则上游协议 %s 已按 %s 导入", "Rule #%d (%s) upstream #%d: upstream protocol %s on a TCP rule was imported as %s")
	Register("k_32e30624", "规则 #%d（%s）上游 #%d：上游协议 %s 无效（支持 http/https/tcp/tls）", "Rule #%d (%s) upstream #%d: invalid upstream protocol %s (supported: http/https/tcp/tls)")
	Register("k_6b0cc379", "规则 #%d（%s）：v1 健康检查间隔过短，已提为 %d 秒（须大于健康检查超时 %d 秒）", "Rule #%d (%s): the v1 health-check interval was too short and was raised to %d seconds (it must exceed the health-check timeout of %d seconds)")
	Register("k_61e13486", "规则 #%d（%s）：TCP 规则不支持入站 TLS，已按关闭 TLS 导入", "Rule #%d (%s): TCP rules do not support inbound TLS, so the rule was imported with TLS turned off")
	Register("k_8ea54163", "规则 #%d（%s）：启用 TLS 但证书或私钥为空，已跳过导入", "Rule #%d (%s): TLS is enabled but the certificate or private key is empty; skipped")
	Register("k_4ed6710d", "规则 #%d（%s）：规则为禁用状态且证书/私钥为空，已按关闭 TLS 导入（证书可后续补齐再启用）", "Rule #%d (%s): the rule is disabled and its certificate/private key is empty, so it was imported with TLS turned off (add the certificate later before enabling it)")
	Register("k_29089ac2", "仅导入负载规则（用户、全局配置不导入；旧规则的证书任务、证书材料与日志将随规则替换一并清理）", "Only load-balancing rules are imported (users and global settings are not; certificate jobs, certificate material and logs of old rules are cleaned up along with the rule replacement)")
	Register("k_d4627f56", "v1 不支持 ACME，HTTPS 规则的证书与私钥将以手动方式随规则导入", "v1 does not support ACME; certificates and private keys of HTTPS rules are imported with the rules as manual certificates")
	Register("k_b60538b6", "nginx 特有配置（custom_config、日志路径等）已忽略", "nginx-specific settings (custom_config, log paths, etc.) were ignored")
	Register("k_f3564383", "已解除 %d 条安全策略绑定；v1 备份不恢复策略绑定，导入后规则不再应用原 WAF/安全防护策略，请按需重新绑定", "%d security policy bindings were removed; a v1 backup does not restore policy bindings, so rules no longer apply their original WAF/security policies after import. Rebind as needed")

	// lbbak 规则库/威胁库文件落盘、收敛与回退结论，提交不确定态的产物清理去向。
	Register("k_47e2e72c", "IP2Region 数据文件无法装载（%s）——已拒绝该文件并保留本地文件；IP2Region 版本记录已丢弃（记录与文件须同批）", "The IP2Region data file cannot be loaded (%s), so the file was rejected and the local file kept; the IP2Region version record was dropped (records and files must land together)")
	Register("k_ea4ef9eb", "威胁库 %s 未落盘：同步包校验被拒（拒绝整包）——该源保留本地文件与记录", "Threat source %s was not written to disk because the sync bundle was rejected (whole bundle rejected); the local file and record of this source were kept")
	Register("k_b2e292cf", "CRS 规则库文件落盘失败: %s——CRS 版本记录已丢弃（记录与文件须同批）", "Failed to write the CRS rule-library file: %s; the CRS version record was dropped (records and files must land together)")
	Register("k_d5b34aac", "IP2Region 数据文件未成功应用: %s——IP2Region 版本记录已丢弃（记录与文件须同批）", "The IP2Region data file was not applied: %s; the IP2Region version record was dropped (records and files must land together)")
	Register("k_c8bcaf95", "CRS 规则库文件已落盘并保留版本记录；仅 IP2Region 应用失败", "The CRS rule-library file was written and its version record kept; only the IP2Region application failed")
	Register("k_91f9bc9e", "威胁库 %s %s: %s——该源保留本地文件与记录", "Threat source %s %s: %s; the local file and record of this source were kept")
	Register("k_455b8d5b", "mkdir 失败", "mkdir failed")
	Register("k_5f40e901", "落盘/编译失败", "write/compile failed")
	Register("k_76f8b3d3", "IP2Region 内存缓存热换失败（重启后生效）: %s", "Failed to hot-swap the IP2Region in-memory cache (takes effect after a restart): %s")
	Register("k_1eb7387c", "删除威胁库 %s 本地文件失败: %s", "Failed to delete the local file of threat source %s: %s")
	Register("k_256f8be1", "威胁库 %s 在备份中为空（上次下载成功但无条目），已删除本地旧名单文件（记录按备份）", "Threat source %s is empty in the backup (the last download succeeded but produced no entries), so the old local list file was deleted (the record follows the backup)")
	Register("k_04f9fe39", "威胁库 %s 备份未携带该源文件（导出节点尚未成功下载），已删除本地旧名单文件——如该源需继续生效，请启用更新后手动触发一次威胁库更新", "Threat source %s: the backup carries no file for this source (the exporting node has not downloaded it successfully yet), so the old local list file was deleted. If this source must stay in effect, enable updates and trigger a threat-library update manually")
	Register("k_ff1557d5", "扫描威胁库目录失败: %s", "Failed to scan the threat-library directory: %s")
	Register("k_8e68a642", "导入前 IP2Region 数据文件路径不是普通文件，未纳入回退（该路径的写入本身会失败）", "The pre-import IP2Region data file path is not a regular file and was not included in the rollback (writes to this path fail anyway)")
	Register("k_4d13e681", "导入前 IP2Region 版本标记路径不是普通文件，未纳入回退", "The pre-import IP2Region version marker path is not a regular file and was not included in the rollback")
	Register("k_fe7c270c", "威胁名单目录路径不是目录，威胁名单未纳入回退（该路径下的写入本身会失败）", "The threat-list directory path is not a directory, so threat lists were not included in the rollback (writes under this path fail anyway)")
	Register("k_b88e56a6", "IP2Region 数据文件已回退为导入前的不存在状态——运行时内存缓存无法卸载导入的数据库，重启后与磁盘收敛", "The IP2Region data file was rolled back to its pre-import absent state; the runtime in-memory cache cannot unload the imported database and converges with disk after a restart")
	Register("k_23bf2e66", "规则库文件已按备份落盘且保持导入后状态（未回退）——数据库提交结果不确定：若提交实际成功则文件与数据库一致，若实际未提交则文件与版本记录分叉，请核对规则库页版本后重新导入或触发规则库更新收敛", "Rule-library files were written from the backup and kept in their post-import state (not rolled back) because the database commit result is uncertain: if the commit actually succeeded the files match the database; if it did not, the files diverge from the version records. Check the version on the rule-library page, then re-import or trigger a rule-library update to converge")
	Register("k_47a1262e", "规则库文件已按备份落盘，数据库已回滚，但规则库文件回退失败: %s——文件与版本记录可能分裂，请重新导入或触发规则库更新以收敛", "Rule-library files were written from the backup and the database was rolled back, but rolling back the rule-library files failed: %s. The files may diverge from the version records; re-import or trigger a rule-library update to converge")
	Register("k_594803a8", "规则库文件已按备份落盘，数据库已回滚——规则库文件已回退到导入前状态（文件与版本记录一致）", "Rule-library files were written from the backup and the database was rolled back; the rule-library files were restored to their pre-import state (files and version records are consistent)")
	Register("k_bbed968a", "规则库文件已按备份落盘，但数据库已回滚——文件与版本记录可能分裂，请重新导入或触发规则库更新以收敛", "Rule-library files were written from the backup, but the database was rolled back; the files may diverge from the version records. Re-import or trigger a rule-library update to converge")
	Register("k_437730e3", "数据库提交结果不确定：无材料规则的残留证书文件清理将按已提交视图复核后执行（实际回滚时自动跳过）", "The database commit result is uncertain: cleanup of leftover certificate files for rules without material will run after being checked against the committed view (skipped automatically on an actual rollback)")
	Register("k_a4725e7f", "数据库提交结果不确定：本次导入移除规则的证书文件/指标/日志清理未能核对已提交视图（%v）——请人工核对 certs/ 与各日志目录", "The database commit result is uncertain: cleanup of certificate files/metrics/logs for the rules removed by this import could not be checked against the committed view (%v). Manually check certs/ and the log directories")
	Register("k_d6d521a6", "数据库提交结果不确定：已提交视图仍包含本次导入替换的规则（提交实际未落地），无需清理产物", "The database commit result is uncertain: the committed view still contains the rules replaced by this import (the commit did not land), so no artifacts need cleaning up")
	Register("k_a71e068e", "数据库提交结果不确定：已按已提交视图确认本次导入移除的 %d 条规则，其证书文件/指标/日志将在导入收尾后清理（实际回滚时自动跳过）", "The database commit result is uncertain: %d rules removed by this import were confirmed against the committed view, and their certificate files/metrics/logs will be cleaned up after the import finishes (skipped automatically on an actual rollback)")

	// 日志存储条的安全事件行保留提示（天数 + 行帽 + 体积上限同句表达）。
	Register("k_7229ce33", "每日清理 · 保留 %d 天 / 上限 %d 行（按行计，单行最大约 %s，理论体积上限约 %s）", "Cleaned daily · keep %d days / cap %d rows (counted by row; up to about %s per row, theoretical size ceiling about %s)")
}
