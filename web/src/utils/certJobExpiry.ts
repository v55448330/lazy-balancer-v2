// 证书任务的到期派生口径：任务页「证书有效期」与「自动重签时间」两列共用，
// 也供后续消费方（批量视图/导出）复用，避免各自判 expires_at 出现跨页分叉。
//
// 后端 /certificates/jobs 同时下发：
//   - expires_at：库列原值，导入/旧备份/集群回插可能为 null（契约不变）；
//   - not_after：真实到期时刻的派生值（expires_at 缺失时按 PEM 解析）。
// UI 必须以 not_after 为准，否则后端已算出的 days_remaining/certificate_status
// 在 expires_at 为 null 的行上没有任何消费方，页面显示「-」而规则页显示
// 「剩 N 天」，运维会误判为未签发并重复触发签发。

interface CertJobExpiryFields {
  rule_id?: string | number
  expires_at?: string | null
  not_after?: string | null
}

/** 证书真实到期时刻（ISO 串）；两列都缺失/为旧版响应时返回空串。 */
export const certJobEffectiveNotAfter = (job: CertJobExpiryFields): string =>
  job.not_after || job.expires_at || ''

/**
 * 续签保护窗口（天）：剩余有效期跌到该值即续签，同时是两次自动续签之间的
 * 最小节奏。与后端 certificates.go 的 certRenewalGuaranteedGrace 同值。
 */
const CERT_RENEWAL_GRACE_DAYS = 7

/**
 * ACME 证书的规划寿命（天）：与后端 certinfo.go 的 CertRenewalLifetimeDays
 * 同值，用作续签窗口上限的基准。
 */
const CERT_RENEWAL_LIFETIME_DAYS = 90

/**
 * 实际生效的续签窗口（天）：镜像后端 certRenewalWindowForLifetime 的收敛——
 * 窗口大于「寿命 − 最小节奏」时按窗口入队会让相邻两次续签挤在一起（CA 重复
 * 证书限流），故收敛到保护区（到期前 7 天）。库值不改写，收敛只作用于渲染。
 *
 * 后端以真实证书寿命收敛，前端只有规划寿命（90 天）：配置 84–88 天时两边
 * 一致收敛为保护区；自定义 CA 签发更短寿命的证书时后端会收敛得更多，前端按
 * 规划寿命显示可能偏大——该差额由后端未来下发 renewal_at 消除。
 */
export const certRenewalWindowDays = (days: number): number => {
  if (!Number.isFinite(days) || days <= 0) return days
  const headroom = CERT_RENEWAL_LIFETIME_DAYS - CERT_RENEWAL_GRACE_DAYS
  if (days <= headroom) return days
  // 走到这里必有 days > headroom(83) > 保护区(7)：恒返回保护区窗口。
  // 动态收敛（按真实寿命）由后端执行，前端不再有一段可达的「二者取小」分支。
  return CERT_RENEWAL_GRACE_DAYS
}

/** 续签窗口是否被寿命收敛（UI 据此提示实际节奏与配置不同）。 */
export const certRenewalWindowConverged = (days: number): boolean =>
  certRenewalWindowDays(days) !== days

/**
 * 自动重签时间 = 到期时刻前「实际生效窗口」天再按规则抖动提前 0–6h，返回 ISO
 * 原值（列内紧凑格式与 tooltip 完整格式各自取用，不在 helper 里预先格式化）。
 *
 * 窗口必须经 certRenewalWindowDays 收敛：配置侧允许 84–88 天（上限按 90 天
 * 寿命留两天余量），而这已超过后端可执行窗口——按库值直算会把「自动重签
 * 时间」显示成签发后 2–6 天（已经过去的日期），与扫描实际行为相反。
 *
 * 抖动（2026-10-30 裁定）：jitter = FNV-1a32(rule_id) % 21600（0–6h，确定性），
 * 后端续签扫描按 expires_at − 窗口 − jitter 判到期（internal/services/certjitter.go
 * 标准库 hash/fnv 同算法），本列必须显示同一时刻——固定向量表两侧各持一份
 * （certJobExpiry.spec.ts / certjitter_test.go）。rule_id 缺失（旧响应/无主键
 * 消费方）退化为 0 抖动（原口径）。
 *
 * 畸形时间/非法天数一律返回空串——`new Date(NaN).toISOString()` 会抛
 * RangeError 并中断整行渲染。
 */
export const certJobRenewalAt = (job: CertJobExpiryFields, renewalDays: number): string => {
  const expiryValue = certJobEffectiveNotAfter(job)
  if (!expiryValue) return ''
  const expiry = new Date(expiryValue)
  if (Number.isNaN(expiry.getTime())) return ''
  if (!Number.isFinite(renewalDays)) return ''
  const jitterMs = certRenewalJitterSeconds(job.rule_id) * 1000
  return new Date(expiry.getTime() - certRenewalWindowDays(renewalDays) * 24 * 60 * 60 * 1000 - jitterMs).toISOString()
}

/**
 * 续签抖动（秒）：FNV-1a 32-bit(rule_id) % 21600（0–6h）。与后端
 * internal/services/certjitter.go（标准库 hash/fnv）同算法同模数；Math.imul
 * 做 32 位乘法、>>> 0 归一 uint32，TextEncoder 保证非 ASCII rule_id 按同一
 * UTF-8 字节序列参与散列。null/undefined（字段缺失的退化形态）返回 0。
 */
export const certRenewalJitterSeconds = (ruleId: string | number | null | undefined): number => {
  if (ruleId === null || ruleId === undefined) return 0
  const bytes = new TextEncoder().encode(String(ruleId))
  // FNV-1a 32 位偏移基与素数（0x811c9dc5 / 0x01000193）
  let hash = 0x811c9dc5
  for (const byte of bytes) {
    hash ^= byte
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash % 21600
}
