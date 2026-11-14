// 自动封禁「未生效黄条」判据单源
// ban_effective 为生效面单一判据（双通道析取：IP 名单通道 ∨ 会话通道），
// 总判据与黄条展示口径不变；分通道判据供状态卡分裂黄条与执法层披露。
// list_referenced（四面引用集，含仅被白名单/受信代理引用的误判面）仅保留为
// 后端内部字段，不得驱动 UI。

// 展示文案走 i18n（批次 D autoban 域）：键形与 zh 母本原文由 autobanStatus.spec 双钉。
import { tSafe as t } from '../i18n/tSafe.ts'

interface AutobanEffectivenessView {
  readonly enabled: boolean
  readonly ban_effective?: boolean
  readonly ban_effective_ip?: boolean
  readonly ban_effective_session?: boolean
  readonly nat_detection?: boolean
  readonly session_bans?: number
}

/** 是否展示「已启用但未生效」黄条：仅显式 ban_effective === false 时提示。 */
export const isAutobanIneffective = (status: AutobanEffectivenessView): boolean =>
  status.enabled && status.ban_effective === false

/**
 * IP 名单通道未生效黄条（总判据分裂）：已启用且后端显式下发
 * ban_effective_ip === false（名单为空，或未被「启用 + IP ACL + deny」策略
 * 引用）。旧后端缺分通道键时不提示（fail-closed，与总判据同口径）。
 */
export const isAutobanIpIneffective = (status: AutobanEffectivenessView): boolean =>
  status.enabled && status.ban_effective_ip === false

/**
 * 会话通道未装配黄条（仅 NAT 态）：NAT 精修已启用且存在会话封禁，但挑战链
 * 未装配（无启用的人机验证策略绑定启用的 HTTP 规则）——会话封禁无执法点。
 * 键缺失（旧后端）/无会话封禁时不提示。
 */
export const isAutobanSessionIneffective = (status: AutobanEffectivenessView): boolean =>
  status.enabled && status.nat_detection === true && (status.session_bans ?? 0) > 0 &&
  status.ban_effective_session === false

/** NAT 精修运行态徽标判据：NAT 检测启用且存在生效会话封禁（仅已启用时）。 */
export const isAutobanNatActive = (status: AutobanEffectivenessView): boolean =>
  status.enabled && status.nat_detection === true && (status.session_bans ?? 0) > 0

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

// ---- 建议行身份/执法层/累犯档（A+C 双通道）----

/**
 * 建议身份键拆解（与后端 autobanIdentityKey / autobanCompositeKeyParts 同形）：
 * 复合键「归一 IP|指纹」（首个 | 为边界，指纹非空）= NAT 会话身份；否则 IP 身份。
 * 建议行 ip 字段承载身份键——复合键不得直接当 IP 展示/处置。
 */
export const splitAutobanIdentity = (key: string): { ip: string; fingerprint: string; composite: boolean } => {
  const i = key.indexOf('|')
  if (i <= 0 || i === key.length - 1) return { ip: key, fingerprint: '', composite: false }
  return { ip: key.slice(0, i), fingerprint: key.slice(i + 1), composite: true }
}

/**
 * 建议行执法层判据：复合身份 → 会话挑战（挑战链内拒绝，不落 IP 名单）；
 * IP 身份 → IP 封禁（名单通道）。与后端 merge 跳过复合候选的口径一致。
 */
export const autobanEnforcementLayer = (identity: string): 'ip' | 'session' =>
  splitAutobanIdentity(identity).composite ? 'session' : 'ip'

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
 * 不虚构逐行档位）：会话身份=会话通道短时长（10 分钟，词条 durationSession
 * 与后端 autobanSessionBanTTL 双锚，改一侧必须同步另一侧）；IP 身份=配置
 * 时长，升级档开启时附「按累犯档升级」提示键（tooltip）。
 */
export const autobanSuggestedDurationKey = (identity: string, duration: string): string =>
  splitAutobanIdentity(identity).composite
    ? 'app.security.overview.autoban.durationSession'
    : `app.security.events.${autobanDurationKey(duration)}`

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

