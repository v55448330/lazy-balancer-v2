// 规则日志统计的键上限容器：每个统计桶维护自有键计数，使上限判定为 O(1)——
// Object.keys(map).length 在每次新增键时都要遍历整表（500 键上限下全量摄入
// 会重复分配数百次）。
//
// 容器必须原型安全：统计键来自请求日志（攻击者可控）。普通对象上写入
// __proto__ 会命中原型 setter——键静默不落、keyCounts 已自增（幽灵键吃满
// 容量），constructor/toString 只能靠 own-property 守卫侥幸正确；无原型容器让
// 任意字符串都是普通自有键，不依赖守卫细节。
//
// 独立纯模块而非留在视图 SFC 内：上限/回落语义可由 node --test 直接求值，
// 不依赖「函数文本里出现某常量」的源码钉。

import { hasOwn } from './hasOwn.ts'

export const MAX_LOG_STAT_KEYS = 500
export const OTHER_LOG_STAT_KEY = '其他'

type LogStatBucket = 'ip' | 'ua' | 'uri'

export interface LogStatBuckets {
  ip: Record<string, number>
  ua: Record<string, number>
  uri: Record<string, number>
  total: number
  keyCounts: Record<LogStatBucket, number>
}

export const createLogStatBuckets = (): LogStatBuckets => ({
  ip: Object.create(null) as Record<string, number>,
  ua: Object.create(null) as Record<string, number>,
  uri: Object.create(null) as Record<string, number>,
  total: 0,
  keyCounts: { ip: 0, ua: 0, uri: 0 },
})

/**
 * 单桶计数：已有键自增；新键在容量内落库并计入 keyCounts；满表后全部归入
 * 「其他」桶——计数不丢弃，键集合不再增长（MAX-1 个自有键 + 「其他」）。
 */
export const incrementCappedStat = (buckets: LogStatBuckets, bucket: LogStatBucket, key: string): void => {
  const map = buckets[bucket]
  if (hasOwn(map, key)) {
    map[key] += 1
    return
  }
  if (buckets.keyCounts[bucket] < MAX_LOG_STAT_KEYS - 1) {
    map[key] = 1
    buckets.keyCounts[bucket] += 1
    return
  }
  map[OTHER_LOG_STAT_KEY] = (map[OTHER_LOG_STAT_KEY] || 0) + 1
}

/**
 * 摄入一条已解析的访问日志：total 自增一次、三桶各计一次键。
 *
 * total 与桶计数的一致性由本函数单点维护——此前 total++ 由调用方手写，与三桶
 * 的推进拆在两处，任何一侧改口径（漏计/重复计）都无从钉住。展示侧恒可假设
 * total === 三桶各自计数之和（每条日志在三桶中各恰好落一个槽位，满表回落
 * 「其他」也是计数）。
 */
export const recordLogStatEntry = (
  buckets: LogStatBuckets,
  entry: { readonly ip: string; readonly uri: string; readonly ua: string },
): void => {
  buckets.total += 1
  incrementCappedStat(buckets, 'ip', entry.ip)
  incrementCappedStat(buckets, 'uri', entry.uri)
  incrementCappedStat(buckets, 'ua', entry.ua)
}
