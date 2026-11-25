package i18n

// 词条目录（后增部分）。键是语义键（域名.驼峰名）：描述"是哪条消息"、不含措辞，是
// 前后端之间的稳定契约。新增后端词条在此登记，zh 母本 + en 译文成对。

func init() {
	// IPv6 地理库开关退化提交注记（200 + 重载失败详情槽）。
	Register("security.savedButCaddyReloadFailed", "已保存，但重载 Caddy 配置失败（待下次成功重载生效）: %s")
	// IPv6 地理库开关写失败 5xx 固定文案（DB 细节由服务层 error 日志留痕）。
	Register("security.ipv6ToggleSaveFailed", "保存 IPv6 开关失败")
	// 从节点服务控制执行失败 5xx 固定文案（票据凭证端点，底层错误只进审计+日志）。
	Register("cluster.serviceControlFailed", "服务控制执行失败")

	// 通知中心 REST（订阅/投递/设置）响应词条：zh 母本 + en 译文成对。
	Register("notify.settingsAdminOnly", "仅管理员可管理通知设置")
	// API Key 接入统计（REST 采集）非管理员 403——与「通知设置」文案区分，
	// 此前误复用通知设置文案指向无关页面。
	Register("apikey.accessStatsAdminOnly", "仅管理员可查看接入统计")
	// 审计日志深翻页 400（i18n 化；此前 fmt.Sprintf 直写中文绕过词条表）。
	Register("audit.deepPageLimitExceeded", "结果过多（超过 %d 页），请使用时间范围/用户/动作筛选缩小范围")
	// Caddy 生命周期控制（启停/重启）嵌入式装配缺 cfg 的 503 降级文案。
	Register("caddy.serviceConfigNotInitialized", "服务配置未初始化")
	Register("notify.subscriptionEventNotInCatalog", "订阅事件不在目录中: %s")
	Register("notify.invalidSubscriptionLevel", "订阅级别必须为 info/warn/critical")
	Register("notify.unsupportedDeliveryStatusFilter", "不支持的投递状态过滤: %s")
	Register("notify.deliveryNotFound", "通知投递不存在")
	Register("notify.canOnlyResendOwnDelivery", "仅可重发自己的通知投递")
	Register("notify.deliveryAlreadyQueued", "该投递已处于待发队列")
	Register("notify.resendAccepted", "重发已受理，等待投递")
	Register("notify.testMessageQueued", "测试消息已加入投递队列，结果见投递记录")
	Register("notify.dailyReportTestQueued", "日报测试已加入投递队列，结果见投递记录")
	Register("notify.smtpPortInvalid", "SMTP 端口必须为 1-65535 的数字")
	Register("notify.attackThresholdsInvalid", "拦截告警阈值需满足 0 < warn < critical")
	Register("notify.settingsSaved", "通知设置已保存")

	// MCP 会话可见性与统计（通知中心）响应词条：zh 母本 + en 译文成对。
	Register("apikey.mcpDisabled", "MCP 已停用")
	Register("apikey.mcpSessionNotFound", "MCP 会话不存在")
	Register("apikey.mcpSessionsLoadFailed", "读取 MCP 会话失败")
	Register("apikey.mcpSessionDisconnectFailed", "断开 MCP 会话失败")
	Register("apikey.mcpSessionDisconnected", "MCP 会话已断开")
	Register("apikey.mcpStatsLoadFailed", "读取 MCP 统计失败")

	// 通知通道 CRUD/测试响应词条（zh 母本 + en 译文成对）。
	Register("notify.unsupportedChannelType", "不支持的通知通道类型")
	Register("notify.canOnlyManageOwnChannel", "仅可管理自己的通知通道")
	Register("notify.canOnlyTestOwnChannel", "仅可测试自己的通知通道")
	Register("notify.testMessageSendFailed", "测试消息发送失败: %s")
	Register("notify.testMessageSent", "测试消息已发送")
	Register("notify.eventGroupNotFound", "未知事件组: %s")
	// 日报配置校验、日报手动触发的管理员门、QQ 扫码绑定与微信扫码登录的 5xx。
	// 这 7 条自引入起只在 handlers/notification_messages.go 定义了键、从未登记——
	// 未登记的键被 T 原样返回，用户看到的是 k_xxx 这样的原始键（2026-11-25 实测后补）。
	Register("notify.dailySendTimeInvalid", "日报发送时间无效（格式应为 HH:MM）")
	Register("notify.dailyItemUnknown", "未知的日报项目: %s")
	Register("notify.dailyTriggerForbidden", "仅管理员可手动触发日报")
	Register("notify.qqBindTaskCreateFailed", "创建 QQ 扫码绑定任务失败: %s")
	Register("notify.qqBindPollFailed", "查询 QQ 扫码绑定状态失败: %s")
	Register("notify.wxLoginStartFailed", "发起微信扫码登录失败: %s")
	Register("notify.wxLoginPollFailed", "查询微信扫码状态失败: %s")
	// 规则保存：非空通道选择经就绪门清洗后为空（全部已停用/未通过测试/微信会话待刷新）。
	Register("notify.selectedChannelsAllUnavailable", "选定的通知通道均不可用（已停用/未通过测试/微信会话待刷新）")
	Register("notify.invalidRuleId", "无效规则 ID: %s")
	// 规则级事件×通道模板保存门（与派发渲染口径同门：webhook=JSON 载荷、
	// 机器人/邮件=文本模板长度上限）。
	Register("notify.ruleTemplateInvalidJson", "规则模板不是合法 JSON（占位符替换后仍需可解析）")
	Register("notify.ruleTemplateTooLong", "规则模板过长（机器人通道 ≤2000 字节，邮件 ≤4000 字节）")
	// 任务监控：畸形 cert-job ID 的 400（此前硬编码英文 "Invalid job ID"，
	// message_key 缺失导致双语界面切换对该提示无效）。
	Register("system.taskIdInvalid", "无效的任务 ID")
	// 任务监控：不可取消任务的取消拒绝（409）。与「任务未在运行中或不支持取消」
	// 拆分——运行中的不可取消任务不得报「未在运行」（与监控页显示自相矛盾）。
	Register("system.taskCancelNotSupported", "该任务不支持手动取消")

	// 保存基础/Caddy 全局设置的成功响应（此前中文字面量直出，en 界面显示中文）。
	// base 键区分「已应用」与「仅落库」，格式清空说明用模板键接在后面。
	Register("caddy.configUpdatedAndApplied", "配置已更新并应用")
	Register("caddy.configUpdated", "配置已更新")
	Register("caddy.accessLogJsonOffFormatCleared", "%s（访问日志 JSON 已关闭，自定义格式已清空：该格式不生效）")

	// 导入/还原结果的固定告警：当前账户被替换、部分成功 + 规则库数据文件缺失的
	// 固定说明。会话吊销告警按「导入/还原」动作各登记一条（见下方告警面）。
	Register("backup.importOperatorAccountNotInBackup", "备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录")
	Register("backup.importCommittedCertJobRecoveryFailed", "数据库已提交，但证书任务恢复失败: %s")
	Register("backup.importRuleLibraryVersionRecordsSkippedNoDataFile", "备份不含规则库数据文件——规则库版本记录已跳过（仅 lbbak 完整备份可导入该类）")
	Register("backup.importCrsVersionRecordSkippedNoDataFile", "备份不含 CRS 数据文件——CRS 版本记录已跳过（仅含该文件的 lbbak 备份可导入）")
	Register("backup.importIp2RegionVersionRecordSkippedNoDataFile", "备份不含 IP2Region 数据文件——IP2Region 版本记录已跳过（仅含该文件的 lbbak 备份可导入）")

	// 日志存储条的治理说明（悬浮提示）：来源（config_source）与保留口径
	// （retention_note）此前为中文直出，en 界面混入中文。
	Register("system.logRetentionConfigSourceBasicSettings", "基础设置 · 日志保留（操作/运行/安全事件）")
	Register("system.logSizeConfigSourceBasicTaskLog", "基础设置 · 任务日志大小")
	Register("system.logSizeConfigSourceBasicRuntime", "基础设置 · 运行日志大小")
	Register("system.logSizeConfigSourceCaddyGlobal", "Caddy 全局配置 · 日志大小")
	Register("system.logConfigSourceUnifiedTaskLog", "统一任务日志（%s）")
	Register("system.auditLogRetentionNote", "每日清理 · 保留 %s 个月")
	Register("system.runtimeLogRetentionNote", "时间戳轮转，按保留期清理（份数随保留期）")

	// 导入/还原告警面（预览与结果弹框的 warnings、冲突明细原因）：产出点只记
	// 事实（handlers.importWarning：键 + 参数），预览/导入/还原响应按请求语言
	// 渲染，操作审计明细恒取中文母本。带「导入/还原」动作词的整句各登记一条
	// （动作词在两种语言里的句中形态不同，不做词级拼接）。
	Register("backup.importPlainJsonThreatSourcesKeptLocal", "纯 JSON 备份不携带威胁名单文件，已保留本地威胁源配置与名单")
	Register("backup.importRuleEmptyDomainSkipped", "规则 %s 的域名为空，已跳过导入")
	Register("backup.importEmptyDomainRulePolicyBindingsSkipped", "%d 条安全策略绑定随空域名规则一并跳过")
	Register("backup.importBlockPageEmptyContentSkipped", "拦截页面 %s 的内容为空，已跳过导入")
	Register("backup.importVersionSourceActiveUpdateNormalizedToFailed", "%d 条版本/源记录携带「更新中」活动态，导入节点不执行该任务，已归一为 failed")
	Register("backup.importVersionSourceUnknownUpdateStatusNormalizedToIdle", "%d 条版本/源记录的 update_status 不在词表内，已归一为 idle")
	Register("backup.importCertJobCaProviderDanglingNormalizedToDefault", "%d 条证书任务引用的 CA 提供商不存在或已禁用，已归一为跟随默认提供商（原引用会导致任务首次入队即失败）")
	Register("backup.importCertJobCaProviderDisabled", "%d 个证书任务的 CA 提供商已禁用——续签将失败（任务转 failed 终态），请补齐 CA 提供商或在证书页手工重试")
	Register("backup.importCertJobCaProviderMissing", "%d 个证书任务引用的 CA 提供商已不存在——续签时将回落首个启用提供商（自愈），如需保持原提供商请补齐")
	Register("backup.validateCertJobDanglingCheckNotCompleted", "证书任务 CA 提供商悬挂统计未完成（读取失败）：%s")
	Register("backup.importCertJobDanglingCheckNotCompleted", "证书任务 CA 提供商悬挂统计未完成（读取失败，导入本身不受影响）：%s")
	Register("backup.importAcmeRefDanglingCheckNotCompleted", "ACME 引用悬挂统计未完成（读取失败，导入本身不受影响）：%s")
	Register("backup.importExportedProductVersionMissing", "备份未记录导出产品版本，当前运行版本为 %s——跨版本还原前请确认兼容性")
	Register("backup.importExportedProductVersionDiffers", "备份导出产品版本为 %s，当前运行版本为 %s——跨版本还原可能存在兼容性差异，请确认后继续")
	Register("backup.importNoIntegrityChecksumOnlyStructurallyValidated", "备份不含完整性校验和（史前版本导出），已按结构性校验导入——文件内容未经摘要校验，建议尽快用当前版本重新导出备份")
	Register("backup.importCrsTreeReplacedPolicyRefsUnverified", "备份同时替换 CRS 规则树：安全策略中的 CRS 组号/规则 ID 未按当前规则库做存在性校验（落地基准以备份内规则树为准）——导入后请在安全策略页复核选组，避免空 Include 静默失效")
	Register("backup.validateOperatorAccountNotInBackup", "备份不包含当前操作账户——若导入时勾选“系统数据”，导入后请使用备份内的管理员账户登录")
	Register("backup.importLbbakCompleteWithRuleLibraryFiles", "lbbak 完整备份（含规则库数据文件，完整性已校验）——规则库数据库分类将随导入落盘")
	Register("backup.importLbbakHasOnlyThreatListFiles", "lbbak 含威胁库名单文件（完整性已校验）——导入「安全防护」将落盘名单文件；本包不含 CRS/IP2Region 数据文件")
	Register("backup.importThreatEntryUnregisteredLandedUnverified", "lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验，已按原样落盘；建议核实来源后重新导出备份")
	Register("backup.importThreatEntryUnregisteredNotImported", "lbbak 含 manifest 未登记的威胁库条目（%s）——内容未经完整性校验；本次分类未选择安全防护数据，条目未导入、未落盘")
	Register("backup.importBrandingFileRestoreFailed", "品牌配置文件还原失败: %s")
	Register("backup.importBrandingMirrorRefreshFailed", "品牌镜像刷新失败: %s")
	Register("backup.importNodeTokenMismatchLocalKept", "%d 个节点的备份令牌与本地不一致，已保留本地令牌与审批状态（备份仅恢复拓扑属性，从节点无需重新审批）")
	Register("backup.importRecordOwnerMismatchNotRewritten", "%d 条记录的归属用户未随备份包含或已被替换，作者显示可能为空或错配（导入未改写归属字段）")
	Register("backup.importDanglingPolicyBindingsPruned", "已按导入后的规则与策略视图清理 %d 条悬挂安全策略绑定")
	Register("backup.importWafOffPolicyNormalizedToCustomOnly", "%d 个 WAF 模式为 off 且挂启用自定义规则的策略已按旧语义归一为 custom_only（自定义规则开始生效）")
	Register("backup.importTcpRulePolicyBindingsRemoved", "已解除 %d 条 TCP 规则的安全策略绑定（TCP 不参与策略渲染）")
	Register("backup.importOidcConfigClearedToMatchBackup", "备份未携带 OIDC 配置——现有 OIDC 配置已随备份收敛清空（用户数据按备份替换，避免「OIDC 启用但零用户」不一致状态）")
	Register("backup.importCrawlerRuntimeSnapshotRebuildFailed", "爬虫运行快照重建失败（重启或下次更新后重试）: %s")
	Register("backup.importAdminTlsRestartRequired", "管理面板 HTTPS 配置已导入，需重启后生效（当前进程继续使用启动时的证书）")
	Register("backup.restoreAdminTlsRestartRequired", "管理面板 HTTPS 配置已还原，需重启后生效（当前进程继续使用启动时的证书）")
	Register("backup.importSystemDataSessionsRevoked", "系统数据已导入：全部登录会话已吊销，请重新登录")
	Register("backup.restoreSystemDataSessionsRevoked", "系统数据已还原：全部登录会话已吊销，请重新登录")
	Register("backup.importBackupRulesDnsProviderDangling", "导入后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐")
	Register("backup.restoreBackupRulesDnsProviderDangling", "还原后 %d 条启用规则的 DNS 提供商配置悬挂（引用未随备份导入，且现有配置中不存在或已禁用）——下一次签发/续签将失败，请及时补齐")
	Register("backup.importLocalRulesDnsProviderDangling", "导入后 %d 条启用规则的 DNS 提供商配置悬挂（引用不在导入数据中）——下一次签发/续签将失败，请及时补齐")
	Register("backup.restoreLocalRulesDnsProviderDangling", "还原后 %d 条启用规则的 DNS 提供商配置悬挂（引用不在导入数据中）——下一次签发/续签将失败，请及时补齐")
	Register("backup.importCertJobRequeueFailedQueueResumed", "证书签发队列已恢复运行，但导入后的任务恢复未完成：%s——请检查证书任务列表，必要时手动重试")
	Register("backup.importCertJobRequeueFailedQueueStillStopped", "证书签发任务保持停止，且导入后的任务恢复未完成：%s——请检查证书任务列表，恢复该任务后才会继续推进")
	Register("backup.importCertJobsNotRequeuedQueueStoppedCountUnknown", "证书签发任务已停止：导入的非终态证书任务本窗口未重排（数量统计失败，请检查任务列表）——恢复该任务后才会继续推进")
	Register("backup.importCertJobsNotRequeuedQueueStopped", "%d 个非终态证书任务因证书签发任务已停止而未重排——恢复该任务后才会继续推进")
	Register("backup.importRuleCertificateWarning", "规则 %s（%s）：%s")
	Register("backup.validateRuleCertificateWarning", "规则 %s：%s")
	Register("cert.certChainPossiblyIncomplete", "证书链可能不完整，部分客户端将握手失败")
	Register("cert.certDoesNotCoverRuleDomain", "证书域名与规则域名不匹配")
	Register("cert.certExpired", "证书已过期 (过期时间: %s)")
	Register("cert.certNotYetValid", "证书尚未生效 (生效时间: %s)")

	// 自动封禁运行期收敛说明（services.AutobanConfigReplaceEffectNote，分句与
	// 列举项的连接符随语言）、导入钳制说明、冲突明细原因。
	Register("security.autoBanStatsWindowChanged", "统计窗口由 %d 分钟改为 %d 分钟")
	Register("security.autoBanStatsScopeChanged", "统计口径由 %s 改为 %s")
	Register("security.autoBanCountingModeChanged", "计数方式由 %s 改为 %s")
	Register("security.autoBanSuspicionMultiplierChanged", "嫌疑累计倍率由 %d 改为 %d")
	Register("security.autoBanConfirmFloorRatioChanged", "确证打底比例由 %s 改为 %s")
	Register("security.autoBanEvidenceTierParamsChanged", "证据分层计数参数变更（%s）")
	Register("security.autoBanStatsCountersCleared", "，已清空自动封禁统计计数（旧计数不适用于新口径）")
	Register("security.autoBanThresholdChangedReachedRecomputed", "封禁阈值由 %d 改为 %d，已按新阈值重算统计达标标记")
	Register("security.autoBanDisabledFinalizationDone", "自动封禁已停用，已执行禁用收尾（到期条目解封、统计计数清空）")
	Register("security.autoBanRemainsDisabledCleanupDone", "自动封禁处于停用态，已清理到期条目并清空统计计数")
	Register("security.autoBanEnabledSchedulerStarted", "自动封禁已启用，调度已按新配置开启")
	Register("security.autoBanConfigChanged", "自动封禁配置变更：")
	Register("backup.importAutobanThresholdClamped", "autoban_threshold 越界（%d），已钳位为 %d")
	Register("backup.importAutobanThresholdNotIntegerNormalized", "autoban_threshold 非整数形态，已归一为 %d")
	Register("backup.importAutobanWindowMinutesClamped", "autoban_window_minutes 越界（%d），已钳位为 %d")
	Register("backup.importAutobanWindowMinutesNotIntegerNormalized", "autoban_window_minutes 非整数形态，已归一为 %d")
	Register("backup.importAutobanScopeEmptyNormalizedToDefault", "autoban_scope 空值，已归一为默认全选")
	Register("backup.importAutobanScopeLegacySingleValueMigrated", "autoban_scope 旧单值口径（%s）已迁移为多选集合（%s）")
	Register("backup.importAutobanSuspicionMultiplierClamped", "autoban_suspicion_multiplier 越界（%d），已钳位为 %d")
	Register("backup.importAutobanSuspicionMultiplierNotIntegerNormalized", "autoban_suspicion_multiplier 非整数形态，已归一为 %d")
	Register("backup.importAutobanFieldEmptyNormalizedToDefault", "%s 空值，已归一为 %s")
	Register("backup.importRequestBodyMaxSizeInvalidShapeNormalized", "request_body_max_size_mb 非法形态（%v），已归一为 %d")
	Register("backup.importRequestBodyMaxSizeOutOfRangeNormalized", "request_body_max_size_mb 越界（%d），已钳位为 %d")
	Register("backup.importConfigFieldInvalidShapeResetToDefault", "%s 非法形态，已重置为 %d")
	Register("backup.importConfigFieldNotPositiveIntegerResetToDefault", "%s 非法（须为正整数），已归默认 %d")
	Register("backup.importConfigFieldOutOfRangeResetToDefault", "%s 越界，已重置为 %d")
	Register("backup.importConfigFieldOutOfRangeClamped", "%s 越界（%d），已钳位为 %d")
	Register("backup.importConflictTlsAndPlainSamePort", "端口 %d 的 TLS 与明文规则不能混布（该端口监听器将整体切换为 TLS，明文规则不可达）")
	Register("backup.importConflictHttpDomainDuplicated", "HTTP 域名 %s 重复")
	Register("backup.importConflictHttpDomainShadowedByRedirect", "HTTP 域名 %s 被 HTTPS 跳转遮蔽")
	Register("backup.importConflictTcpPortDuplicated", "TCP 监听端口 %d 重复")
	Register("backup.importConflictTcpAndHttpSamePort", "TCP 与 HTTP 监听端口 %d 冲突")

	// v1（nginx）导入的转换/跳过/归一说明与三条固定说明。
	Register("backup.importV1StrategyUnmappableDefaulted", "规则 %s 的负载策略 %s 无法映射，已使用 weighted_round_robin")
	Register("backup.importV1RuleDomainInvalidSkipped", "规则 %s 的域名 %s 无效，已跳过导入: %s")
	Register("backup.importV1RuleInvalidSkipped", "规则 #%d（%s）：%v")
	Register("backup.importV1RuleProtocolInvalid", "规则 #%d（%s）：协议无效")
	Register("backup.importV1RuleDomainInvalid", "规则 #%d（%s）：域名 %s 无效")
	Register("backup.importV1HttpRuleUpstreamProtocolNormalized", "规则 #%d（%s）上游 #%d：HTTP 规则上游协议 %s 已按 %s 导入")
	Register("backup.importV1TcpRuleUpstreamProtocolNormalized", "规则 #%d（%s）上游 #%d：TCP 规则上游协议 %s 已按 %s 导入")
	Register("backup.importV1UpstreamProtocolInvalid", "规则 #%d（%s）上游 #%d：上游协议 %s 无效（支持 http/https/tcp/tls）")
	Register("backup.importV1HealthCheckIntervalRaised", "规则 #%d（%s）：v1 健康检查间隔过短，已提为 %d 秒（须大于健康检查超时 %d 秒）")
	Register("backup.importV1TcpRuleTlsTurnedOff", "规则 #%d（%s）：TCP 规则不支持入站 TLS，已按关闭 TLS 导入")
	Register("backup.importV1RuleTlsWithoutCertSkipped", "规则 #%d（%s）：启用 TLS 但证书或私钥为空，已跳过导入")
	Register("backup.importV1DisabledRuleTlsTurnedOff", "规则 #%d（%s）：规则为禁用状态且证书/私钥为空，已按关闭 TLS 导入（证书可后续补齐再启用）")
	Register("backup.importV1RulesOnly", "仅导入负载规则（用户、全局配置不导入；旧规则的证书任务、证书材料与日志将随规则替换一并清理）")
	Register("backup.importV1CertificatesImportedAsManual", "v1 不支持 ACME，HTTPS 规则的证书与私钥将以手动方式随规则导入")
	Register("backup.importV1NginxSpecificConfigIgnored", "nginx 特有配置（custom_config、日志路径等）已忽略")
	Register("backup.importV1PolicyBindingsCleared", "已解除 %d 条安全策略绑定；v1 备份不恢复策略绑定，导入后规则不再应用原 WAF/安全防护策略，请按需重新绑定")

	// lbbak 规则库/威胁库文件落盘、收敛与回退结论，提交不确定态的产物清理去向。
	Register("backup.importIp2RegionUnloadableFileRejected", "IP2Region 数据文件无法装载（%s）——已拒绝该文件并保留本地文件；IP2Region 版本记录已丢弃（记录与文件须同批）")
	Register("backup.importThreatSourceNotWrittenBundleRejected", "威胁库 %s 未落盘：同步包校验被拒（拒绝整包）——该源保留本地文件与记录")
	Register("backup.importCrsApplyFailedVersionRecordDropped", "CRS 规则库文件落盘失败: %s——CRS 版本记录已丢弃（记录与文件须同批）")
	Register("backup.importIp2RegionApplyFailedVersionRecordDropped", "IP2Region 数据文件未成功应用: %s——IP2Region 版本记录已丢弃（记录与文件须同批）")
	Register("backup.importCrsAppliedOnlyIp2RegionFailed", "CRS 规则库文件已落盘并保留版本记录；仅 IP2Region 应用失败")
	Register("backup.importThreatSourceApplyFailedLocalKept", "威胁库 %s %s: %s——该源保留本地文件与记录")
	Register("backup.importThreatSourceMkdirFailed", "mkdir 失败")
	Register("backup.importThreatSourceWriteCompileFailed", "落盘/编译失败")
	Register("backup.importIp2RegionCacheHotSwapFailed", "IP2Region 内存缓存热换失败（重启后生效）: %s")
	Register("backup.importThreatSourceLocalFileDeleteFailed", "删除威胁库 %s 本地文件失败: %s")
	Register("backup.importThreatSourceEmptyInBackupLocalFileRemoved", "威胁库 %s 在备份中为空（上次下载成功但无条目），已删除本地旧名单文件（记录按备份）")
	Register("backup.importThreatSourceFileNotInBackupLocalFileRemoved", "威胁库 %s 备份未携带该源文件（导出节点尚未成功下载），已删除本地旧名单文件——如该源需继续生效，请启用更新后手动触发一次威胁库更新")
	Register("backup.importThreatDirScanFailed", "扫描威胁库目录失败: %s")
	Register("backup.importIp2RegionFileNotRegularRollbackSkipped", "导入前 IP2Region 数据文件路径不是普通文件，未纳入回退（该路径的写入本身会失败）")
	Register("backup.importIp2RegionVersionMarkerNotRegularRollbackSkipped", "导入前 IP2Region 版本标记路径不是普通文件，未纳入回退")
	Register("backup.importThreatListDirNotDirectoryRollbackSkipped", "威胁名单目录路径不是目录，威胁名单未纳入回退（该路径下的写入本身会失败）")
	Register("backup.rollbackIp2RegionFileAbsentCacheNeedsRestart", "IP2Region 数据文件已回退为导入前的不存在状态——运行时内存缓存无法卸载导入的数据库，重启后与磁盘收敛")
	Register("backup.importCommitIndeterminateRuleLibraryFilesKept", "规则库文件已按备份落盘且保持导入后状态（未回退）——数据库提交结果不确定：若提交实际成功则文件与数据库一致，若实际未提交则文件与版本记录分叉，请核对规则库页版本后重新导入或触发规则库更新收敛")
	Register("backup.importDbRolledBackRuleLibraryFilesRestoreFailed", "规则库文件已按备份落盘，数据库已回滚，但规则库文件回退失败: %s——文件与版本记录可能分裂，请重新导入或触发规则库更新以收敛")
	Register("backup.importDbRolledBackRuleLibraryFilesRestored", "规则库文件已按备份落盘，数据库已回滚——规则库文件已回退到导入前状态（文件与版本记录一致）")
	Register("backup.importDbRolledBackRuleLibraryFilesKept", "规则库文件已按备份落盘，但数据库已回滚——文件与版本记录可能分裂，请重新导入或触发规则库更新以收敛")
	Register("backup.importCommitIndeterminateLeftoverCertCleanupRechecked", "数据库提交结果不确定：无材料规则的残留证书文件清理将按已提交视图复核后执行（实际回滚时自动跳过）")
	Register("backup.importCommitIndeterminateRuleCleanupRecheckFailed", "数据库提交结果不确定：本次导入移除规则的证书文件/指标/日志清理未能核对已提交视图（%v）——请人工核对 certs/ 与各日志目录")
	Register("backup.importCommitIndeterminateRulesStillPresentNoCleanup", "数据库提交结果不确定：已提交视图仍包含本次导入替换的规则（提交实际未落地），无需清理产物")
	Register("backup.importCommitIndeterminateRulesRemovedCleanupPending", "数据库提交结果不确定：已按已提交视图确认本次导入移除的 %d 条规则，其证书文件/指标/日志将在导入收尾后清理（实际回滚时自动跳过）")

	// 日志存储条的安全事件行保留提示（天数 + 行帽 + 体积上限同句表达）。
	Register("security.eventsRetentionPolicySummary", "每日清理 · 保留 %d 天 / 上限 %d 行（按行计，单行最大约 %s，理论体积上限约 %s）")
}
