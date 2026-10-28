// 自动封禁名单条目的到期展示口径单源：名单编辑弹框（SecurityRules）与 IP
// 处置快捷弹框（IPLocationAction）共用，原为 SecurityRules 内的组件局部函数。
//
// expires_at 是库内 UTC 墙钟串（"YYYY-MM-DD HH:mm:ss"，空=永久条目）。到期
// 判定/剩余时长以浏览器侧解析与本机时钟对比——展示层近似（分钟粒度），封禁
// 真值以后端投影过滤为准。

// 与 utils/date.ts 的 parseDbTimeMs 同一内核（其规范化+解析实现即
// timeZoneFormat.parseDbDateMs，本模块零依赖以便 node --test 直接求值）。
import { parseDbDateMs } from './timeZoneFormat.ts'

/** 是否已过到期时刻。空值/不可解析（永久或脏数据）一律不算到期。 */
export const autobanEntryExpired = (expiresAt: string): boolean => {
  const ms = parseDbDateMs(expiresAt)
  return ms !== null && ms <= Date.now()
}

/** 剩余时长可读文案（分钟/小时分钟/天时三档）；不可解析返回 `—`，已到期为 `0 分钟`。 */
export const autobanEntryRemaining = (expiresAt: string): string => {
  const ms = parseDbDateMs(expiresAt)
  if (ms === null) return '—'
  const minutes = Math.floor((ms - Date.now()) / 60000)
  if (minutes < 60) return `${Math.max(minutes, 0)} 分钟`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时 ${minutes % 60} 分`
  return `${Math.floor(hours / 24)} 天 ${hours % 24} 时`
}
