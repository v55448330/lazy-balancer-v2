// 响应消息按键渲染（web/DESIGN_SPEC.md §25-8）。
//
// 后端响应信封带 message_key（语义键）与 message_params（模板参数，按占位符顺序、
// 一律是字符串——就是后端填进 message 的那段文本）时，前端用自己的词条按当前语言
// 渲染提示文字；后端 message 整句只在渲染不出时作回落。apiMessageText 是响应拦截器
// 取「要显示的文字」的唯一入口（utils/api.ts），零 Vue/Element 依赖，node --test
// 可直接求值。
//
// 渲染逐字复现后端 apimsg.Tf 的槽位规则（不是标准 fmt）：%s/%d/%v/%q 各消费一个
// 参数、原样填入，%q 在两侧加引号；%% 输出一个 %；槽以外的写法原样保留、不消费
// 参数；参数用完后占位符原样留下，多出的参数忽略。这样切换文案来源时用户看到的
// 文字不变。拿不准的输入（参数缺失、不是字符串数组）一律回落后端原文——比拼出
// 一句错话安全。tests/apiMessagesParity.spec.ts 与 Go 侧共享夹具钉住两侧逐字相同。

import { API_MESSAGE_EN, API_MESSAGE_ZH } from '../i18n/apiMessages.ts'

/** zh-CN 取中文母本，en 取英文译文（与 i18n 的 Locale 同值域）。 */
export type ApiMessageLocale = 'zh-CN' | 'en'

/** 响应信封里与提示文字有关的字段；未知形态一律按缺失处理。 */
interface ApiMessageEnvelope {
  readonly message?: unknown
  readonly message_key?: unknown
  readonly message_params?: unknown
}

// 模板里的占位符（与后端 Tf 同集合）：%s / %d / %v / %q 各占一槽，%% 是字面百分号。
const VERB = /%[sdvq%]/g

/** 模板里占参数的占位符动词，按出现顺序（%% 不计）。 */
export const templateVerbs = (template: string): string[] =>
  [...template.matchAll(VERB)].map((match) => match[0]).filter((verb) => verb !== '%%').map((verb) => verb[1] as string)

/**
 * 按模板与参数渲染（逐字复现后端 apimsg.Tf）。
 * params 是后端渲染进 message 的那段文本，按占位符顺序排列。
 */
export const formatApiMessage = (template: string, params: readonly string[]): string => {
  let out = ''
  let next = 0
  for (let i = 0; i < template.length; i++) {
    const ch = template[i] as string
    if (ch !== '%') {
      out += ch
      continue
    }
    const code = template[i + 1]
    if (code === '%') {
      out += '%'
      i++
      continue
    }
    if (code === 's' || code === 'd' || code === 'v' || code === 'q') {
      const text = params[next]
      if (text === undefined) {
        out += ch + code // 参数用完了：占位符原样留下（与 Tf 同口径）
      } else {
        out += code === 'q' ? `"${text}"` : text
        next++
      }
      i++
      continue
    }
    out += ch // 槽以外的写法原样保留，不消费参数
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
  if (params === undefined) {
    // 没有参数：模板必须不带占位符，否则会渲染出字面 %s——回落后端原文。
    return templateVerbs(template).length === 0 ? template : null
  }
  if (!Array.isArray(params) || !params.every((param) => typeof param === 'string')) return null
  return formatApiMessage(template, params as string[])
}
