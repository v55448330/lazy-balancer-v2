// 响应消息按键渲染（web/DESIGN_SPEC.md §25-8）。
//
// 后端响应信封带 message_key（语义键）时，前端用自己的词条按当前语言渲染提示文字；
// 后端 message 整句只在渲染不出时作回落。apiMessageText 是响应拦截器取「要显示的
// 文字」的唯一入口（utils/api.ts 的两条失败路径），零 Vue/Element 依赖，node --test
// 可直接求值。
//
// 渲染只实现后端 fmt.Sprintf 的一部分：占位符 %s、%d、%v、%q 与字面 %%。遇到这之外
// 的任何形态（其它动词、宽度/精度/标志、孤立百分号），或参数与占位符对不上，一律
// 返回 null——放弃渲染、回落原文，比拼出一句错话安全。tests/apiMessage.spec.ts 的
// 覆盖面用例钉住「后端目录里实际出现的占位符都在实现范围内」。

import { API_MESSAGE_EN, API_MESSAGE_ZH } from '../i18n/apiMessages.ts'

/** zh-CN 取中文母本，en 取英文译文（与 i18n 的 Locale 同值域）。 */
export type ApiMessageLocale = 'zh-CN' | 'en'

/** 响应信封里与提示文字有关的字段；未知形态一律按缺失处理。 */
interface ApiMessageEnvelope {
  readonly message?: unknown
  readonly message_key?: unknown
  readonly message_params?: unknown
}

// 模板按占位符切开：偶数下标是字面文本，奇数下标是占位符（%s / %d / %v / %q / %%）。
const VERB_SPLIT = /(%[sdvq%])/

/** 模板切分后占参数的占位符个数（%% 是字面百分号，不占参数）。 */
const argumentCount = (parts: readonly string[]): number => parts.filter((part, index) => index % 2 === 1 && part !== '%%').length

/** 模板里占参数的占位符动词，按出现顺序（%% 不计）。 */
export const templateVerbs = (template: string): string[] => {
  const parts = template.split(VERB_SPLIT)
  return parts.flatMap((part, index) => (index % 2 === 1 && part !== '%%' ? [part[1] as string] : []))
}

/**
 * 按模板与参数渲染（对应后端 fmt 对 %s / %d / %v / %q / %% 的语义）。
 * 参数必须与占位符一一对应：个数不等、%d 收到非整数、%q 收到非字符串，都返回
 * null——由调用方回落原文。
 */
export const formatApiMessage = (template: string, params: readonly unknown[]): string | null => {
  const parts = template.split(VERB_SPLIT)
  if (argumentCount(parts) !== params.length) return null
  let out = ''
  let next = 0 // 下一个待消费的参数下标
  for (let index = 0; index < parts.length; index++) {
    const part = parts[index] as string
    if (index % 2 === 0) {
      // 字面文本里不得再有百分号：那是没实现的动词（%f、%.2f、孤立 %）。
      if (part.includes('%')) return null
      out += part
      continue
    }
    if (part === '%%') {
      out += '%'
      continue
    }
    const value = params[next]
    next++
    if (part === '%s' || part === '%v') {
      out += value === null || value === undefined ? '<nil>' : typeof value === 'object' ? JSON.stringify(value) : String(value)
    } else if (part === '%d') {
      if (typeof value !== 'number' || !Number.isInteger(value)) return null
      out += String(value)
    } else {
      if (typeof value !== 'string') return null
      out += JSON.stringify(value)
    }
  }
  return out
}

/**
 * 响应信封 → 当前语言的提示文字。
 * 有键、词条里有、参数齐 → 渲染结果；其余一律 null（调用方回落后端 message）。
 */
export const apiMessageText = (envelope: unknown, locale: ApiMessageLocale): string | null => {
  // 接受任意输入（axios 的 response.data 是 unknown）：不是对象就按无键处理。
  if (envelope === null || typeof envelope !== 'object') return null
  const { message_key: key, message_params: params } = envelope as ApiMessageEnvelope
  if (typeof key !== 'string' || !key) return null
  // 键来自后端，是外部字符串：读取必须过 hasOwn——'constructor' 这类原型属性名不是词条。
  const template = locale === 'en'
    ? (Object.prototype.hasOwnProperty.call(API_MESSAGE_EN, key) ? API_MESSAGE_EN[key] : undefined)
    : (Object.prototype.hasOwnProperty.call(API_MESSAGE_ZH, key) ? API_MESSAGE_ZH[key] : undefined)
  if (template === undefined) return null
  if (params !== undefined && !Array.isArray(params)) return null
  return formatApiMessage(template, (params ?? []) as readonly unknown[])
}