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

/** IP 时长库值 → events.duration* 词条键段。 */
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

/**
 * 时长库值 → 展示文案（events.duration* 词条；未知值原样回显，空值占位「—」）。
 * 总览/事件两页时长展示与累犯弹框「上次执法/下次封禁」列共用本单源。
 */
export const autobanDurationLabel = (duration: string): string => {
  switch (duration) {
    case '10m': case '30m': case '1h': case '6h': case '12h': case '24h': case 'permanent':
      return t(`app.security.events.${autobanDurationKey(duration)}`)
    default: return duration || '—'
  }
}

// ---- 累犯弹框「下次封禁」预期时长 ----

/**
 * 下次封禁预期时长（按当前 escalation 档位 + 累计次数推算下一档，与后端
 * autobanEscalatedDuration 档位映射同口径，autobanStatus.spec 跨栈对表）：
 * - 首封即永久 / off / 非法档位 → 固定配置时长（永久时长下升级无意义，
 *   消费侧按 off 兜底，预期不得虚构「下次更重」）；
 * - standard：第 2 次 24h、第 3 次起永久；aggressive：第 2 次起永久。
 * 衰减近似：距上次封禁超过 30 天无再犯则历史清零、按首次档重新起算——
 * 后端衰减窗口可配（测试缝），面板按默认 30 天近似；last_ban_at 缺失/不可
 * 解析时不做衰减推算（与后端 parse 失败不衰减同口径）。
 */
export const autobanNextBanDuration = (
  cfg: { duration: string; escalation?: string },
  row: { offense_count: number; last_ban_at: string },
  nowMs: number,
  lastBanMs: number | null,
): string => {
  if (cfg.duration === 'permanent') return cfg.duration
  const tier = cfg.escalation === 'standard' || cfg.escalation === 'aggressive' ? cfg.escalation : 'off'
  if (tier === 'off') return cfg.duration
  const decayed = lastBanMs !== null && nowMs - lastBanMs > 30 * 24 * 60 * 60 * 1000
  const nextOffense = (decayed ? 0 : row.offense_count) + 1
  if (tier === 'standard') {
    if (nextOffense <= 1) return cfg.duration
    if (nextOffense === 2) return '24h'
    return 'permanent'
  }
  return nextOffense <= 1 ? cfg.duration : 'permanent'
}

/**
 * 累犯身份展示形态：IPv6 /64 网络地址（后端身份键 = /64 归一后的网络地址，
 * 低 64 位恒零）展示为 CIDR，与封禁条目形态同口径；IPv4/不可解析串原样。
 * 不做二次掩码（身份已是网络地址）——与后端 autobanBanValue 同判据。
 */
export const autobanIdentityDisplay = (identity: string): string => {
  if (!identity.includes(':')) return identity
  // :: 压缩尾缀（后端归一键恒把全零低 64 位压成 ::）即 /64 网络地址
  if (identity.endsWith('::')) return `${identity}/64`
  const groups = identity.split(':')
  // 完整 8 组无压缩：低 4 组全零才是 /64 网络地址
  if (groups.length === 8 && groups.slice(4).every((g) => /^0+$/.test(g))) return `${identity}/64`
  return identity
}

