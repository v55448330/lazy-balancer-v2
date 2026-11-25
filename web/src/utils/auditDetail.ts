// 审计明细按键渲染（方案 C 第 2/3 步，2026-11-25 用户批准）。
//
// 后端只下发稳定键与结构参数：detail_key 是段键以 "|" 连接的串，detail_params
// 是与段一一对应的槽位数组；槽位可以是字符串、嵌套段 {"k":键,"a":[…]},
// 或嵌套段数组。中文母本另存 detail 列（历史行只读展示 + 检索兜底）。
//
// 未知段键 fail-visible：原样显示键本身并 console.warn（不静默吞掉），便于发现
// 漏登记；无 detail_key 的历史行回落到 detail 原文。
import { API_MESSAGE_EN, API_MESSAGE_ZH } from '../i18n/apiMessages.ts'
import { formatApiMessage } from './apiMessage.ts'

type AuditDetailLocale = 'zh-CN' | 'en'

/** 明细行里与键化渲染有关的字段。 */
interface AuditDetailFields {
  readonly detail?: string | null
  readonly detail_key?: string | null
  readonly detail_params?: unknown
}

const SEPARATOR = '|'
const MAX_DEPTH = 8
const warned = new Set<string>()

const templateOf = (key: string, locale: AuditDetailLocale): string | undefined => {
  const table = locale === 'en' ? API_MESSAGE_EN : API_MESSAGE_ZH
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined
}

const warnOnce = (key: string): void => {
  if (warned.has(key)) return
  warned.add(key)
  console.warn(`[audit-detail] 未登记的词条键（按原样显示）: ${key}`)
}

const joinTexts = (texts: readonly string[], locale: AuditDetailLocale): string =>
  texts.filter((text) => text !== '').join(locale === 'en' ? '; ' : '；')

const renderParam = (param: unknown, locale: AuditDetailLocale, depth: number): string => {
  if (typeof param === 'string') return param
  if (Array.isArray(param)) {
    return joinTexts(param.map((item) => renderParam(item, locale, depth + 1)), locale)
  }
  if (param !== null && typeof param === 'object' && depth < MAX_DEPTH) {
    const nested = param as { k?: unknown; a?: unknown }
    if (typeof nested.k === 'string') {
      const args = Array.isArray(nested.a) ? nested.a : []
      return renderSegment(nested.k, args, locale, depth + 1)
    }
  }
  return ''
}

const renderSegment = (key: string, params: readonly unknown[], locale: AuditDetailLocale, depth: number): string => {
  const template = templateOf(key, locale)
  if (template === undefined) {
    warnOnce(key)
    return key
  }
  const rendered = params.map((param) => renderParam(param, locale, depth + 1))
  return formatApiMessage(template, rendered)
}

/**
 * 明细 → 当前语言的展示文本。
 * 有键按段渲染；无键（历史行）或参数形态不可解析时回落 detail 原文。
 */
export const auditDetailText = (row: AuditDetailFields, locale: AuditDetailLocale): string => {
  const key = typeof row.detail_key === 'string' ? row.detail_key : ''
  const fallback = typeof row.detail === 'string' ? row.detail : ''
  if (!key) return fallback
  if (!Array.isArray(row.detail_params)) return fallback
  const keys = key.split(SEPARATOR)
  const params = row.detail_params as unknown[]
  if (keys.length !== params.length) return fallback
  const segments = keys.map((segment, index) => {
    const slots = params[index]
    return renderSegment(segment, Array.isArray(slots) ? slots : [slots], locale, 0)
  })
  return joinTexts(segments, locale) || fallback
}
