// 审计日志 Action/Resource 枚举词条单源（audit-i18n 方案 C · 第 1 步）。
//
// 键=audit_log 库值（后端 zh 枚举原样入库，见 internal/db/audit.go 写点侧口径），
// 值=词条后缀（en 母本在 locales/en/common.ts 的 app.auditActions / app.auditResources；
// zh 母本与库值同文——zh 原样展示，词条仅承载 en 翻译）。
//
// 渲染契约（AuditLog.vue 消费）：
//   - 表内命中 → tSafe 解析词条；键缺失/未解析 → 回落库值原文（混存期旧行 zh 原样，
//     新值兜底不裸键）；
//   - 表外值（未来新增动作/存量历史词）→ 原样回落，永不裸键、永不显示函数源码
//     （读取点全部过 hasOwn，见 vocabularyProtoKeys 全仓扫描）。
//
// 枚举集完整性由 tests/auditVocabularyPairs.spec.ts 钉住：全仓扫描 Go 写点
// （recordAudit / RecordAuditLog / recordSystemAudit(Once) 字面量 + 已核清动态
// 装配族取值），任一动作/对象未入表即红——新增写点漏词条在门禁层暴露。
import { tSafe } from '../i18n/tSafe.ts'
import { hasOwn } from './hasOwn.ts'

// ── 动作（Action）枚举：113 词 + 语义族分组 ───────────────────────────
export const AUDIT_ACTION_KEYS: Record<string, string> = {
  // 会话/认证
  '登录成功': 'signedIn',
  '登录失败': 'signInFailed',
  '登出': 'signedOut',
  '认证拒绝': 'authDenied',
  '重置': 'reset',
  '重置密码': 'passwordReset',
  '重新绑定': 'rebound',
  '生成': 'generated',
  '生成失败': 'generationFailed',
  '确认': 'confirmed',
  '确认失败': 'confirmFailed',
  // CRUD
  '创建': 'create',
  '创建失败': 'createFailed',
  '更新': 'update',
  '更新失败': 'updateFailed',
  '删除': 'delete',
  '删除失败': 'deleteFailed',
  '写入': 'write',
  '写入失败': 'writeFailed',
  '修改状态': 'statusChange',
  '复制': 'duplicate',
  '复制失败': 'duplicateFailed',
  '导入': 'import',
  '导入失败': 'importFailed',
  '导入警告': 'importWarning',
  '导入归一': 'importNormalized',
  '还原': 'restore',
  '还原警告': 'restoreWarning',
  '导出': 'export',
  '取消': 'cancel',
  // 启用/禁用
  '启用': 'enable',
  '启用失败': 'enableFailed',
  '禁用': 'disable',
  '禁用失败': 'disableFailed',
  // 服务控制
  '启动': 'start',
  '停止': 'stop',
  '重启': 'restart',
  '重启失败': 'restartFailed',
  '重载': 'reload',
  '重载失败': 'reloadFailed',
  '服务控制': 'serviceControl',
  '载入': 'loaded',
  '启动警告': 'startupWarning',
  // 证书生命周期
  '签发成功': 'issued',
  '签发失败': 'issuanceFailed',
  '签发限流': 'issueRateLimited',
  '续签': 'renewed',
  '续签排队': 'renewalQueued',
  '重试排队': 'retryQueued',
  '恢复排队': 'recoveryQueued',
  '重新排队': 'requeued',
  '重新签发': 'reissued',
  '触发签发': 'issueTriggered',
  '部署失败': 'deployFailed',
  '恢复': 'recovered',
  '恢复失败': 'recoveryFailed',
  '重建': 'rebuilt',
  '重试': 'retried',
  '重试失败': 'retryFailed',
  // 配置备份
  '自动备份': 'autoBackup',
  '手动备份': 'manualBackup',
  '备份设置': 'backupSettings',
  '备份失败': 'backupFailed',
  '备份下载': 'backupDownloaded',
  '备份删除': 'backupDeleted',
  '还原失败': 'restoreFailed',
  '部分失败': 'partialFailure',
  '清理': 'cleanup',
  '清理失败': 'cleanupFailed',
  '清除': 'cleared',
  '清除失败': 'clearFailed',
  // 集群
  '注册': 'registered',
  '注册失败': 'registrationFailed',
  '审批': 'approved',
  '拒绝': 'rejected',
  '脱离': 'detached',
  '提升': 'promote',
  '提升失败': 'promoteFailed',
  '提升完成': 'promoted',
  '更新地址': 'addressUpdated',
  '切换': 'switched',
  '切换失败': 'switchFailed',
  '同步': 'synced',
  '同步下发': 'snapshotPushed',
  '同步停止': 'syncPaused',
  '同步失败': 'syncFailed',
  '同步应用': 'syncApplied',
  '同步自愈': 'selfHealed',
  '同步警告': 'syncWarning',
  '同步跳过': 'syncSkipped',
  '手动同步': 'manualSync',
  // 完整性/配置安全
  '下载校验': 'downloadVerified',
  '校验阻断': 'downloadBlocked',
  '校验失败': 'validationFailed',
  '校验成功': 'validationPassed',
  '应用失败': 'applyFailed',
  '应用降级': 'applyDegraded',
  '补偿失败': 'compensationFailed',
  '配置恢复': 'configRecovered',
  '配置漂移': 'configDrift',
  '渲染跳过': 'renderSkipped',
  '容量收敛': 'capacityTrimmed',
  '自动封禁': 'autoBanned',
  '自动解封': 'autoUnbanned',
  '跳过': 'skipped',
  '警告': 'warning',
  '触发': 'triggered',
  '触发失败': 'triggerFailed',
  '库自愈': 'dbSelfHealed',
  '启动迁移': 'startupMigration',
  '下载失败': 'downloadFailed',
  '上报失败': 'reportFailed',
  '保存失败': 'saveFailed',
  '更新信息': 'profileUpdated',
  '测试成功': 'testPassed',
  '测试失败': 'testFailed',
}

// ── 对象（Resource）枚举：60 词 ──────────────────────────────────────
export const AUDIT_RESOURCE_KEYS: Record<string, string> = {
  'ACME配置': 'acmeSettings',
  'API密钥': 'apiKey',
  'CA提供商': 'caProvider',
  'CRS规则库': 'crsRuleset',
  'Caddy服务': 'caddyService',
  'Caddy配置': 'caddyConfig',
  'DNS配置': 'dnsConfig',
  'IP 地址列表': 'ipAddressList',
  'IP数据库': 'ipDatabase',
  'OIDC 配置': 'oidcSettings',
  // 任务引擎触发审计的 resource=Family id（task_trigger.go），en 以 Task · 前缀呈现
  'backup': 'taskBackup',
  'cert-job': 'taskCertJob',
  'certificates': 'taskCertificates',
  'cluster': 'taskCluster',
  'security': 'taskSecurity',
  'startup': 'taskStartup',
  'system': 'taskSystem',
  '任务监控': 'taskMonitor',
  '全局配置': 'globalConfig',
  '品牌配置': 'branding',
  '基础设置': 'basicSettings',
  '威胁情报库': 'threatIntelLibrary',
  '安全数据': 'securityData',
  '安全策略': 'securityPolicy',
  '安全事件': 'securityEvent',
  '完整性记录': 'integrityRecord',
  '恢复码': 'recoveryCodes',
  '拦截页面': 'blockPage',
  '注册令牌': 'registrationToken',
  '爬虫地址库': 'crawlerLibrary',
  '用户': 'user',
  '用户认证': 'userAuth',
  '登录票据': 'loginTicket',
  '系统': 'system',
  '系统配置': 'systemConfig',
  '自动封禁': 'autoBan',
  '自定义规则': 'customRule',
  '节点服务': 'nodeServices',
  '规则库': 'ruleStore',
  '规则指标': 'ruleMetrics',
  '规则日志': 'ruleLogs',
  '证书': 'certificate',
  '证书产物': 'certificateArtifacts',
  '证书任务': 'certificateJobs',
  '证书指纹': 'certificateFingerprint',
  '证书文件': 'certificateFiles',
  '证书日志': 'certificateLogs',
  '负载规则': 'lbRule',
  '配置备份': 'configBackup',
  '集群同步': 'clusterSync',
  '集群快照': 'clusterSnapshot',
  '集群模式': 'clusterMode',
  '集群管理': 'clusterManagement',
  '集群节点': 'clusterNode',
  '集群设置': 'clusterSettings',
  '操作日志': 'auditLog',
  'IP 名单': 'ipList',
  '威胁源': 'threatSources',
  '证书配置': 'certificateConfig',
  '指标库': 'metricsDb',
  // 存量词：当前写点已不产出（词表归一迁到 用户认证），仅历史行展示用；
  // 若扫描器再次发现写点产出此值，钉测会以「存量词复活」报红。
  '安全审计': 'securityAuditLegacy',
}

// 词条解析：键缺失/未解析（tSafe 返回键路径）→ 回落库值原文。
// 混存期契约：zh 母本与库值同文 ⇒ zh 展示恒为原样；en 母本承载翻译。
const resolveLabel = (prefix: string, suffix: string, raw: string): string => {
  const key = `${prefix}.${suffix}`
  const v = tSafe(key)
  return v === key ? raw : v
}

/** 动作枚举 → 当前语言标签；表外值/null 原样回落（空串保持空串）。 */
export const auditActionLabel = (raw: string | null | undefined): string =>
  raw != null && hasOwn(AUDIT_ACTION_KEYS, raw) ? resolveLabel('common.app.auditActions', AUDIT_ACTION_KEYS[raw], raw) : raw ?? ''

/** 对象枚举 → 当前语言标签；表外值/null 原样回落（空串保持空串）。 */
export const auditResourceLabel = (raw: string | null | undefined): string =>
  raw != null && hasOwn(AUDIT_RESOURCE_KEYS, raw) ? resolveLabel('common.app.auditResources', AUDIT_RESOURCE_KEYS[raw], raw) : raw ?? ''
