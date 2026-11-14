// 自动封禁「未生效黄条」判据单源
// ban_effective 为生效面单一判据（IP 名单通道：名单非空且被启用中的
// IP 访问控制 deny 策略引用）。list_referenced（四面引用集，含仅被
// 白名单/受信代理引用的误判面）仅保留为后端内部字段，不得驱动 UI。

// 展示文案走 i18n（批次 D autoban 域）：键形与 zh 母本原文由 autobanStatus.spec 双钉。
import { tSafe as t } from '../i18n/tSafe.ts'

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
  if (error) return t('common.app.views.autoban.stateUnknown')
  if (!enabled) return t('common.app.views.autoban.stateNotEnabled')
  return dryRun ? t('common.app.views.autoban.stateDryRun') : t('common.app.views.autoban.stateRunning')
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

// ---- 建议行累犯档（状态级配置口径）----

/**
 * 累犯档短文案键（建议表列用，状态级配置口径——/status 建议行不携带逐身份
 * offense_count，不得虚构逐行档位）：off=固定时长；standard/aggressive=升级档。
 * 非法/缺省按 off（与后端 AutobanEscalationOrOff 同口径）。
 */
export const autobanEscalationShortKey = (escalation: string | undefined): string => {
  switch (escalation) {
    case 'standard': return 'app.security.overview.autoban.escalationStandardShort'
    case 'aggressive': return 'app.security.overview.autoban.escalationAggressiveShort'
    default: return 'app.security.overview.autoban.escalationOffShort'
  }
}

/**
 * 建议时长披露键（观察建议为 dry-run 候选，尚未产生逐身份累犯记账——
 * 不虚构逐行档位）：一律按配置时长呈现，升级档开启时由消费侧附
 * 「按累犯档升级」tooltip（durationEscalatesTip）。
 */
export const autobanSuggestedDurationKey = (duration: string): string =>
  `app.security.events.${autobanDurationKey(duration)}`

/** IP 时长库值 → events.duration* 词条键段（未知值原样回显，与事件页同口径）。 */
const autobanDurationKey = (duration: string): string => {
  switch (duration) {
    case '10m': return 'duration10m'
    case '30m': return 'duration30m'
    case '1h': return 'duration1h'
    case '6h': return 'duration6h'
    case '12h': return 'duration12h'
    case '24h': return 'duration24h'
    case 'permanent': return 'durationPermanent'
    default: return duration
  }
}

