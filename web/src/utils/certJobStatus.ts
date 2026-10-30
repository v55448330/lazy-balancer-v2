// 状态联合类型的唯一事实源在 types/index.ts（证书任务视图类型族同源处）；
// 此处 re-export 保持既有 `@/utils/certJobStatus` 导入面不变。
import type { CertJobStatus } from '../types/index.ts'
import { hasOwn } from './hasOwn.ts'
export type { CertJobStatus }

/**
 * 状态 → 中文标签全表。`satisfies Record<CertJobStatus, string>` 是**编译期穷尽性**
 * 约束：后端 db.certJobStatuses 新增一态后，此处不补文案即 tsc 报错（原先 switch
 * 缺 case 只会静默落 unknown 分支，标签显示原始 token）。
 */
const CERT_JOB_STATUS_LABELS = {
  issued: '已签发',
  failed: '失败',
  disabled: '已禁用',
  queued: '排队中',
  waiting_ca: '限流中',
  pending: '待处理',
  processing: '处理中',
  creating_account: '创建账户',
  creating_order: '创建订单',
  order_created: '建单完成',
  waiting_order_ready: '等待就绪',
  order_ready: '订单就绪',
  cleanup_dns: '清理中',
  cleanup_warning: '清理警告',
  presenting_dns: '配置解析',
  waiting_propagation: '等待传播',
  dns_propagated: '已传播',
  accepting_challenge: '提交验证',
  waiting_order_valid: '等待验证',
  order_valid: '验证完成',
  validating: '验证中',
  validated: '验证通过',
  finalizing: '最终化',
  finalized: '订单完成',
  downloading: '下载证书',
  downloaded: '下载完成',
} satisfies Record<CertJobStatus, string>

export const certJobStatusLabel = (status: CertJobStatus): string => {
  // 空值/undefined 静默回退（存量行 status 空列的瞬时形态，非异常——
  // 控制台噪音「Unknown cert job status: undefined」治理，2026-10-11）；
  // 非空未知值仍 warn 暴露真实状态机漂移。
  if (!status) return '未知'
  // 状态表是普通对象：原型键（constructor/toString 等）直接下标会返回函数并
  // 被下方真值判断当成命中，必须走自有属性守卫（缺失即落 warn 分支）。
  const label = hasOwn(CERT_JOB_STATUS_LABELS, status) ? CERT_JOB_STATUS_LABELS[status] : undefined
  if (label) return label
  console.warn('Unknown cert job status:', status)
  return String(status)
}

/** 证书任务状态色调（与 certJobStatusLabel 同一状态机）。 */
type CertJobStatusTone = 'success' | 'danger' | 'warning' | 'info'

/** 状态 → Element tag 色调全表（同样受 `satisfies Record<CertJobStatus, …>` 穷尽性约束）。 */
const CERT_JOB_STATUS_TONES = {
  issued: 'success',
  failed: 'danger',
  disabled: 'info',
  queued: 'info',
  waiting_ca: 'warning',
  pending: 'warning',
  processing: 'warning',
  creating_account: 'warning',
  creating_order: 'warning',
  order_created: 'warning',
  waiting_order_ready: 'warning',
  order_ready: 'warning',
  cleanup_dns: 'warning',
  cleanup_warning: 'warning',
  presenting_dns: 'warning',
  waiting_propagation: 'warning',
  dns_propagated: 'warning',
  accepting_challenge: 'warning',
  waiting_order_valid: 'warning',
  order_valid: 'warning',
  validating: 'warning',
  validated: 'warning',
  finalizing: 'warning',
  finalized: 'warning',
  downloading: 'warning',
  downloaded: 'warning',
} satisfies Record<CertJobStatus, CertJobStatusTone>

export const certJobStatusTone = (status: CertJobStatus): CertJobStatusTone => {
  if (!status) return 'info'
  const tone = hasOwn(CERT_JOB_STATUS_TONES, status) ? CERT_JOB_STATUS_TONES[status] : undefined
  if (tone) return tone
  console.warn('Unknown cert job status:', status)
  return 'info'
}

/**
 * 证书任务是否已过后端下发的重试冷却。冷却值唯一由 API 决定，且语义是
 * 「此刻剩余秒数」——后端已按 updated_at 扣减流逝部分（证书任务列表与任务监控
 * 证书行同源同口径），所以判据只有「≤0 即就绪」，不得再按 updated_at 二次
 * 扣减（那会让冷却过半即显示可点，点击后被服务端 429 拒绝）。
 * null 表示该状态永久不可重试（disabled），不是「无冷却」。
 * 轮询（证书任务页 5s / 任务监控 10s）刷新剩余值，无需本地 ticker。
 */
export const certJobRetryReady = (cooldownSeconds: number | null | undefined): boolean => {
  if (cooldownSeconds === null || cooldownSeconds === undefined) return false
  const seconds = Number(cooldownSeconds)
  if (!Number.isFinite(seconds)) return false
  return seconds <= 0
}

// ── 续签语境状态口径（2026-10-30 裁定）───────────────────────────────
// failed 细分为 失败（首次签发失败）/ 续签失败（旧证书在场，续签失败）/
// 需人工（自动重试达上限），全部标签 ≤4 字；状态 hover 走派生口径，CA 原文
// （message）只在「日志」对话框呈现。

import { certJobEffectiveNotAfter } from './certJobExpiry.ts'

/** 细分口径消费的行字段（CertJobListItem 的按需子集，宽松可选便于单测）。 */
interface CertJobRenewalViewFields {
  status: CertJobStatus
  renewal_attempts?: number
  ca_available_after?: string | null
  updated_at?: string | null
  days_remaining?: number
  expires_at?: string | null
  not_after?: string | null
}

/** 续签重试上限兜底值（= db.DefaultCertRenewalAttempts）：/config 未就绪/读取失败时使用。 */
export const CERT_JOB_RENEWAL_ATTEMPTS_FALLBACK = 5

/**
 * 需人工判定：终态失败且已无 CA 冷却且失败次数达上限。后端契约：达上限的行
 * 必为 failed 且 ca_available_after 已清空（markJobWaitingCA 上限分支与扫描侧
 * 上限迁移同字段集），故「有冷却值」的行仍在自动重试节奏内，不算需人工。
 */
export const certJobManualNeeded = (job: CertJobRenewalViewFields, capAttempts: number): boolean =>
  job.status === 'failed' && !job.ca_available_after && (job.renewal_attempts ?? 0) >= capAttempts

/** 旧证书在场 = 到期派生非空（重排队续签保留 expires_at/cert_pem；首次签发行两者皆空）。 */
const certJobHasOldCert = (job: CertJobRenewalViewFields): boolean => certJobEffectiveNotAfter(job) !== ''

/**
 * 状态列展示标签：failed 按续签语境细分（需人工 > 续签失败 > 失败），其余状态
 * 沿用全表（certJobStatusLabel）。全表与细分标签都满足「≤4 字」列宽约束。
 */
export const certJobRowStatusLabel = (job: CertJobRenewalViewFields, capAttempts: number): string => {
  if (job.status !== 'failed') return certJobStatusLabel(job.status)
  if (certJobManualNeeded(job, capAttempts)) return '需人工'
  if (certJobHasOldCert(job)) return '续签失败'
  return '失败'
}

/** 冷却档位（小时）——与后端 computeBackoff 阶梯同规则：1→1h、2→2h、≥3→3h。 */
export const certJobCooldownTierHours = (attempts: number): number =>
  attempts <= 1 ? 1 : attempts === 2 ? 2 : 3

/** 冷却实际间隔（分钟粒度）紧凑文案：47m / 1h30m / 2h；非正值返回空串。 */
export const certJobCooldownSpan = (ms: number): string => {
  if (!Number.isFinite(ms) || ms <= 0) return ''
  const minutes = Math.ceil(ms / 60_000)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest === 0 ? `${hours}h` : `${hours}h${String(rest).padStart(2, '0')}m`
}

/** clock 注入：ISO → 配置时区 HH:mm（由调用方提供，单源 utils/date；测试注入固定实现）。 */
type CertJobClockFormatter = (iso: string) => string

/**
 * 冷却时间列（终态失败行）：「档位 · 时刻」形态（如 1h · 01:13）。429 的
 * ca_available_after − updated_at 实际间隔可能短于档位，此时显示实际间隔
 * （如 43m · 01:13）。waiting_ca 仍由页面倒计时文案承载，其余状态空串（-）。
 */
export const certJobCooldownCell = (
  job: CertJobRenewalViewFields,
  clock: CertJobClockFormatter,
): string => {
  if (job.status !== 'failed' || !job.ca_available_after) return ''
  const end = Date.parse(job.ca_available_after)
  if (!Number.isFinite(end)) return ''
  const start = Date.parse(job.updated_at ?? '')
  const tierHours = certJobCooldownTierHours(job.renewal_attempts ?? 0)
  const actual = Number.isFinite(start) ? end - start : Number.NaN
  const label = Number.isFinite(actual) && actual > 0 && actual < tierHours * 3_600_000
    ? certJobCooldownSpan(actual)
    : `${tierHours}h`
  const at = clock(job.ca_available_after)
  return at ? `${label} · ${at}` : label
}

/** 下次自动重试段：下次自动重试 HH:MM（剩 N 分钟）；无冷却时刻/畸形时间省略，冷却已过不给倒计时。 */
const certJobNextRetryPart = (job: CertJobRenewalViewFields, now: number, clock: CertJobClockFormatter): string => {
  if (!job.ca_available_after) return ''
  const at = Date.parse(job.ca_available_after)
  if (!Number.isFinite(at)) return ''
  const time = clock(job.ca_available_after)
  if (!time) return ''
  const remainMinutes = Math.ceil((at - now) / 60_000)
  return remainMinutes > 0 ? `下次自动重试 ${time}（剩 ${remainMinutes} 分钟）` : `下次自动重试 ${time}`
}

/**
 * hover 段落拼接：常规分隔「 · 」，全角闭括号后省前导空格（「（上限 M）· 下次」
 * 的中文排版口径，与裁定文案逐字一致）。
 */
const joinHoverParts = (parts: string[]): string =>
  parts.reduce((acc, part) => (acc ? acc + (/）$/.test(acc) ? '' : ' ') + '· ' + part : part), '')

/**
 * 状态标签 hover（派生口径，挂状态标签）：
 * - 续签失败：旧证书剩 N 天 · 已失败 N 次（上限 M）· 下次自动重试 …
 * - 失败：同上去掉旧证书段
 * - 需人工：自动重试已停止 · 查看日志 / 检查 DNS 或凭据 / 手动重签
 * - 限流中：已失败 N 次（上限 M）· 下次自动重试 …
 * 其余状态返回空串（调用方回落在途说明）。message（CA 原文）永不进入本口径
 * ——只在「日志」对话框呈现。
 */
export const certJobStatusHover = (
  job: CertJobRenewalViewFields,
  capAttempts: number,
  now: number,
  clock: CertJobClockFormatter,
): string => {
  if (job.status === 'failed') {
    if (certJobManualNeeded(job, capAttempts)) {
      return '自动重试已停止 · 查看日志 / 检查 DNS 或凭据 / 手动重签'
    }
    const parts: string[] = []
    if (certJobHasOldCert(job) && typeof job.days_remaining === 'number' && Number.isFinite(job.days_remaining)) {
      // 旧证书过期不渲染裸负数（与有效期列「已过期 N 天」同口径）
      parts.push(job.days_remaining >= 0
        ? `旧证书剩 ${job.days_remaining} 天`
        : `旧证书已过期 ${Math.abs(job.days_remaining)} 天`)
    }
    parts.push(`已失败 ${job.renewal_attempts ?? 0} 次（上限 ${capAttempts}）`)
    const retry = certJobNextRetryPart(job, now, clock)
    if (retry) parts.push(retry)
    return joinHoverParts(parts)
  }
  if (job.status === 'waiting_ca') {
    const parts = [`已失败 ${job.renewal_attempts ?? 0} 次（上限 ${capAttempts}）`]
    const retry = certJobNextRetryPart(job, now, clock)
    if (retry) parts.push(retry)
    return joinHoverParts(parts)
  }
  return ''
}

// ── 需人工横幅（可关闭）：按「行 id + updated_at」指纹记 localStorage ──

/** 需人工行指纹：新增/变化的行（updated_at 变）产生新指纹 → 横幅重现。 */
export const certManualBannerFingerprint = (job: { id: number; updated_at?: string | null }): string =>
  `${job.id}:${job.updated_at ?? ''}`

const CERT_MANUAL_BANNER_STORAGE_KEY = 'cert-jobs-manual-banner-dismissed'
// 指纹集上限：只影响「已关闭不再弹」的记忆深度，最旧行先遗忘（横幅会重现，无信息丢失风险）。
const CERT_MANUAL_BANNER_STORAGE_LIMIT = 200

/** 读取已关闭指纹集；localStorage 不可用（隐私模式/测试宿主缺失）返回空集。 */
export const loadCertManualBannerDismissed = (): Set<string> => {
  try {
    const raw = localStorage.getItem(CERT_MANUAL_BANNER_STORAGE_KEY)
    if (!raw) return new Set()
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return new Set()
    return new Set(parsed.filter((item): item is string => typeof item === 'string'))
  } catch {
    return new Set()
  }
}

/** 持久化已关闭指纹集（最旧先淘汰，上限 200）。写前重读 localStorage 合并：
 *  双标签页各持内存副本，后保存方若直接整写会覆盖先保存方已落库的 dismiss
 *  （另一标签的横幅因此重现）——合并=先存量后本次（Set 保序），再按上限淘汰
 *  最旧。写失败静默（下次横幅重现，无害）。 */
export const saveCertManualBannerDismissed = (fingerprints: Iterable<string>): void => {
  try {
    const merged = new Set([...loadCertManualBannerDismissed(), ...fingerprints])
    const items = [...merged].slice(-CERT_MANUAL_BANNER_STORAGE_LIMIT)
    localStorage.setItem(CERT_MANUAL_BANNER_STORAGE_KEY, JSON.stringify(items))
  } catch {
    // 隐私模式/配额失败：不阻塞页面，横幅下次照常出现
  }
}
