/**
 * 导入/还原失败响应的展示行。
 *
 * 后端失败分支把事实披露放在响应体的 data.warnings（规则库文件面三态判决、
 * 提交结果不确定的人工核对指引、软跳过/归一化清单），message 只承载「阶段 +
 * 真实错误」。axios 拦截器把失败响应转成 ApiRequestError 时若不回传响应体，
 * 这些事实就只剩审计可见——运维按「已回滚、无需动作」处理，而 WAF 执行面可能
 * 已与库分裂。
 *
 * 本模块把错误对象变成可渲染的文本行，供导入与还原的失败弹框共用（与成功
 * 路径的结果弹框同布局）；纯函数，便于 node 测试直接断言渲染结果。
 */

import { tSafe as t } from '../i18n/tSafe.ts'

/** 失败处置的展示内容。 */
interface ImportFailureReport {
  /** 主文案：后端 message（缺省时用调用方兜底文案）。 */
  readonly message: string
  /** 后端 data.warnings，按原顺序（已滤掉空串/非字符串）。 */
  readonly warnings: readonly string[]
  /** 后端 data.disabled_conflicts 条数（失败响应携带的是「导入成功会禁用哪些」预演清单）。 */
  readonly conflictCount: number
}

/**
 * error → 展示内容。
 *
 * 响应体形态 = models.APIResponse：`{ code, message, data: { warnings, disabled_conflicts, summary } }`；
 * 它挂在 ApiRequestError.data 上（拦截器从 error.response.data 透传）。
 * `fallbackMessage` 用于网络层失败/非后端错误（没有 message 可取）。
 */
export const importFailureReport = (error: unknown, fallbackMessage: string): ImportFailureReport => {
  const envelope = typeof error === 'object' && error !== null && 'data' in error ? error.data : undefined
  const payload = typeof envelope === 'object' && envelope !== null && 'data' in envelope ? envelope.data : undefined
  const backendMessage = typeof error === 'object' && error !== null && 'message' in error ? error.message : undefined
  const rawWarnings = typeof payload === 'object' && payload !== null && 'warnings' in payload ? payload.warnings : undefined
  const rawConflicts =
    typeof payload === 'object' && payload !== null && 'disabled_conflicts' in payload ? payload.disabled_conflicts : undefined
  return {
    message: typeof backendMessage === 'string' && backendMessage.trim() !== '' ? backendMessage : fallbackMessage,
    warnings: Array.isArray(rawWarnings)
      ? rawWarnings.filter((item): item is string => typeof item === 'string' && item.trim() !== '')
      : [],
    conflictCount: Array.isArray(rawConflicts) ? rawConflicts.length : 0,
  }
}

/** 展示行：主文案 + 冲突预演 + 后端 warnings（逐条独立成行）。
 *
 * 冲突行必须写成「预演」：失败响应里的 disabled_conflicts 是链内算出的
 * 「若导入成功会禁用哪些规则」，此时事务已回滚、一条规则都没被禁用（提交结果
 * 不确定时则以实际库态为准）。用成功路径的既成事实句会让管理员以为规则已被
 * 禁用而去核对，或反过来不再检查冲突。
 */
export const importFailureLines = (report: ImportFailureReport): string[] => [
  report.message,
  ...(report.conflictCount > 0
    ? [t('common.app.importFailure.conflictDisableNote', { count: report.conflictCount })]
    : []),
  ...report.warnings,
]
