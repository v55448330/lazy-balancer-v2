// 批量写操作的「退化 200」呈现单源。
//
// 后端成功响应（code:0）的 message 可携带「Caddy 配置应用失败」后缀：DB 已提交
// 但运行配置应用失败——该提示必须常驻，不能被后续成功覆盖。批量端点按分片提交
// （每片 ≤100）时，原实现把每片响应赋给同一个变量，只有末片进入 showSaveResult：
// 早先分片的退化后缀被覆盖丢失，用户只看到成功提示。
//
// 本模块只做纯合并（无依赖），供 showSaveResult 的判定与各分片提交点共用。

import { tSafe as t } from '../i18n/tSafe.ts'

/** 后端退化 200 的稳定语义键（后端 message_key，语言无关）：DB 已提交、Caddy
 *  应用失败。判定首选此键——message 按 Accept-Language 翻译，en 模板不含 zh 标记。
 *
 *  两个键语义同为「已提交但 Caddy 未生效」，只是后端端点族不同：
 *    security.savedButCaddyApplyFailed=「已保存；但 Caddy 配置应用失败」（通用写端点）
 *    security.savedButCaddyReloadFailed=「已保存，但重载 Caddy 配置失败」（安全策略/默认策略 apply 端点，
 *               如 POST /security/policies/apply-defaults；待下次成功重载生效）
 *  只登记其一 = 另一族端点的失败对 UI 不可见（apply-defaults 曾把重载失败当成功）。 */
const CADDY_APPLY_FAILED_MESSAGE_KEY = 'security.savedButCaddyApplyFailed'
const CADDY_APPLY_FAILED_MESSAGE_KEYS = [CADDY_APPLY_FAILED_MESSAGE_KEY, 'security.savedButCaddyReloadFailed'] as const

/** 后端退化 200 的 zh message 标记（DB 已提交、Caddy 应用失败）。仅作无键旧响应
 *  的兜底判据（分类语义同 utils/mfaErrors 的白名单）；不得作为唯一判据。 */
export const CADDY_APPLY_FAILED_MARKER = 'Caddy 配置应用失败'

interface BulkResponseLike {
  message?: string
  /** 后端 message_key 透传（camelCase，与 utils/apiFailure 同形）。 */
  messageKey?: string
}

/** 退化 200 判定单源：稳定键优先，zh 标记兜底（无键旧响应）。 */
export const isCaddyApplyDegraded = (res: BulkResponseLike | undefined | null): boolean =>
  !!res && ((CADDY_APPLY_FAILED_MESSAGE_KEYS as readonly string[]).includes(res.messageKey ?? '') || (res.message ?? '').includes(CADDY_APPLY_FAILED_MARKER))

/**
 * 汇总批量分片响应：任一分片带退化后缀即合成一条警告文案（后缀去重；多片
 * 失败时标注片数），否则返回末片（成功文案单源保持不变）。
 */
export const mergeBulkResults = (
  results: ReadonlyArray<BulkResponseLike | undefined | null>,
): BulkResponseLike | undefined => {
  const defined = results.filter((r): r is BulkResponseLike => !!r)
  if (defined.length === 0) return undefined
  const degraded: string[] = []
  for (const r of defined) {
    const message = r.message ?? ''
    if (isCaddyApplyDegraded(r) && !degraded.includes(message)) degraded.push(message)
  }
  if (degraded.length === 0) return defined[defined.length - 1]
  if (degraded.length === 1) return { message: degraded[0], messageKey: CADDY_APPLY_FAILED_MESSAGE_KEY }
  return { message: t('common.app.views.impexp.bulkDegradedMore', { message: degraded[0], count: degraded.length - 1 }), messageKey: CADDY_APPLY_FAILED_MESSAGE_KEY }
}
