// 日志统计条显示名单源：后端 /system/logs/storage 每行下发稳定 key + 中文
// name（internal/handlers/logstats.go 的 infos 清单）。name 是后端母本文案，
// 英文界面直出即中文混入——显示名按稳定 key 查词条，未登记 key（含
// task:<id> 逐任务动态行）回落后端 name；调用方可用组件 label 覆盖成已本地化
// 的名字（任务监控弹框：taskDisplayName + taskLogName 后缀词条）。
//
// 固定行 key 与 logstats.go 的 infos 清单同集：后端新增行时前端漏译会回落
// 中文 name（可见但未本地化），跨栈清单一致性由 tests/taskMonitorAndAuditLogUi
// .spec.ts 对账。
import { tSafe } from '../i18n/tSafe.ts'
import { hasOwn } from './hasOwn.ts'

/** 后端固定行 key → 词条后缀（common.app.views.logStorage.names.<key>）。 */
export const LOG_STORAGE_NAME_KEYS: Record<string, string> = {
  audit: 'audit',
  security_events: 'securityEvents',
  certjob: 'certjob',
  crs_update: 'crsUpdate',
  ip2region_update: 'ip2regionUpdate',
  threat_update: 'threatUpdate',
  crawlerbot_update: 'crawlerbotUpdate',
  runtime: 'runtime',
  caddy: 'caddy',
  caddy_runtime: 'caddyRuntime',
  caddy_tls: 'caddyTls',
  caddy_server: 'caddyServer',
  caddy_proxy: 'caddyProxy',
  rule_access: 'ruleAccess',
}

/** 该 key 的显示名词条键；非固定行（task:<id> 等）返回 null。 */
export const logStorageNameKey = (logKey: string): string | null =>
  hasOwn(LOG_STORAGE_NAME_KEYS, logKey) ? `common.app.views.logStorage.names.${LOG_STORAGE_NAME_KEYS[logKey]}` : null

/**
 * 统计条显示名：固定 key 走词条；带 caddy_id 的查询（certjob/rule_access）
 * 后端把行名改写为「<基名> #<ruleId>」，本地化基名后必须保留该后缀，否则同一
 * 条统计在切换规则前后出现两种名字口径。
 */
export const logStorageDisplayName = (logKey: string, backendName: string): string => {
  const key = logStorageNameKey(logKey)
  if (!key) return backendName
  const localized = tSafe(key)
  // 词条缺失（tSafe 回裸键）=未登记译名，回落后端 name（不裸键、不丢后缀）。
  if (localized === key) return backendName
  const suffixAt = backendName.indexOf(' #')
  return suffixAt >= 0 ? localized + backendName.slice(suffixAt) : localized
}
