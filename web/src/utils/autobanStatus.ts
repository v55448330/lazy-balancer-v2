// 自动封禁「未生效黄条」判据单源
// ban_effective 为生效面单一判据（名单非空且被启用 + deny 的策略引用）；
// list_referenced（四面引用集，含仅被白名单/受信代理引用的误判面）仅保留为
// 后端内部字段，不得驱动 UI。
interface AutobanEffectivenessView {
  readonly enabled: boolean
  readonly ban_effective?: boolean
}

/** 是否展示「已启用但未生效」黄条：仅显式 ban_effective === false 时提示。 */
export const isAutobanIneffective = (status: AutobanEffectivenessView): boolean =>
  status.enabled && status.ban_effective === false

export type SuggestionBand = 'high' | 'mid' | 'low'

/**
 * 状态条数值的未知态口径：`GET /security/autoban/status` 失败时，数值一律渲染
 * 「—」而不是前端初值（未启用 / 阈值 100 / 今日封禁 0）——否则读者会把本机默认
 * 值当成真实配置与真实封禁量。
 */
export const autobanStatValue = (error: boolean, value: string | number, unit = ''): string =>
  error ? '—' : `${value}${unit}`

/** 状态标签文案：读取失败=「状态未知」，不得沿用「未启用」这一确定结论。 */
export const autobanStateLabel = (error: boolean, enabled: boolean, dryRun: boolean): string => {
  if (error) return '状态未知'
  if (!enabled) return '未启用'
  return dryRun ? '观察模式' : '运行中'
}

/**
 * 建议行命中次数分档：≥4×阈值 高、≥2×阈值 中、其余低（阈值缺省按 1）。
 * 命中次数色深与阈值倍数进度条配色是同一判据的两种呈现——档位在此单源，
 * 各视图只做「档位 → 样式/颜色」映射，改档不再需要双改。
 */
export const suggestionBand = (count: number, threshold: number): SuggestionBand => {
  const t = threshold || 1
  if (count >= t * 4) return 'high'
  if (count >= t * 2) return 'mid'
  return 'low'
}
