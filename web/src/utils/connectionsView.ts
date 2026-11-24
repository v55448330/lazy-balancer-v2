// 连接监控弹框的视图口径单源（请求视图 vs 连接视图）。
//
// 后端 /metrics/connections/list 同时下发两套明细：
//   - requests[]（lb_reqmon 逐请求）：category 是**窗口区间**语义
//     （active≤1min / closing≤10min / closed≤1h），另有 status 状态码；
//   - connections[]（netstat socket）：category 是**socket 状态族**
//     （established/time_wait/closed）。
// 两套分类的筛选键同形（active/closing/closed），但用户可读文案完全不同：
// 请求视图必须说「1 分钟内 / 1–10 分钟 / 10 分钟–1 小时」，连接视图才是
// 「活跃 / 待关闭 / 已关闭」。把连接态词条贴到请求窗口分类上，等于把时间窗
// 说成 socket 状态。
//
// 另一个口径：requests 只下发窗口内最新 500 条（后端 requests_truncated=true
// 时触达上限），此时总数与分类计数都是封顶值——必须写「500+」并由调用方
// 补充「仅统计最新 500 条」的口径说明，不能把 500 当窗口总请求数。
//
// 纯函数承载全部差异，node --test 直接覆盖行为（不靠源码文本钉）。

import { connectionFilterCategory } from './connectionCategories.ts'

/** 请求明细展示上限（与后端 connectionsListMaxRows 同值：500）。 */
export const REQUEST_VIEW_MAX_ROWS = 500

interface FilterCategory {
  readonly key: string
  readonly label: string
}

/** 请求视图筛选键：窗口区间语义 + 5xx（状态码维度只存在于请求明细）。 */
export const requestFilterCategories = (t: (key: string) => string): FilterCategory[] => [
  { key: 'active', label: t('app.dashboard.connCatReqActive') },
  { key: 'closing', label: t('app.dashboard.connCatReqClosing') },
  { key: 'closed', label: t('app.dashboard.connCatReqClosed') },
  { key: '5xx', label: t('app.dashboard.connFilter5xx') },
  { key: 'all', label: t('app.dashboard.connCatAll') },
]

/** 连接视图筛选键：socket 状态族语义（established/time_wait/closed）。 */
export const connectionFilterCategories = (t: (key: string) => string): FilterCategory[] => [
  { key: 'active', label: t('app.dashboard.connCatEstablished') },
  { key: 'closing', label: t('app.dashboard.connCatTimeWait') },
  { key: 'closed', label: t('app.dashboard.connCatClosed') },
  { key: 'all', label: t('app.dashboard.connCatAll') },
]

/**
 * 行分类 → 筛选键（连接视图 socket 状态族映射；请求视图 category 已是
 * active/closing/closed，映射幂等）。徽标文案与筛选比较必须共用本函数，
 * 否则默认 active 视图下 socket 行恒被过滤掉。
 */
export const filterKeyOf = (category: string): string => connectionFilterCategory(category)

/**
 * 按筛选键取行：all=全量；5xx=状态码 ≥500（仅请求明细有状态码）；
 * 其余按 filterKeyOf 映射后的分类比较。
 */
export const filterRows = <T extends { category?: string; status?: number }>(
  rows: readonly T[],
  category: string,
): readonly T[] => {
  if (category === 'all') return rows
  if (category === '5xx') return rows.filter((row) => (row.status ?? 0) >= 500)
  return rows.filter((row) => filterKeyOf(row.category ?? '') === category)
}

/** 总请求卡文案：触达展示上限写「500+」（真实窗口总数未知）。 */
export const totalRequestsText = (total: number, truncated: boolean, cap = REQUEST_VIEW_MAX_ROWS): string =>
  truncated ? `${cap}+` : String(total)
