// 通道 style_config 读写单源（通道卡编辑 + 日报每通道模板保存共用）。
//
// PUT /notification/channels 的 style_config 是全量覆盖语义：任何表单重建都必须
// 把表单不认识的既有键（daily_mode、未来新增键）原样带回，否则保存一次就把
// 别的功能写进去的键抹掉——日报渲染模式会静默回退，用户配置看似「自己变了」。
//
// 同一模块承载日报模板保存的计划函数：多 tab 全量保存时逐通道算差异，只提交
// 真正变化的通道；与任一语言预置相同的草稿不落库（预置升级继续生效）。

interface ChannelStyleForm {
  payload_template: string
  subject_template: string
  body_template: string
  content_template: string
  body_format: string
  daily_format: string
  method: string
}

export const emptyChannelStyleForm = (): ChannelStyleForm => ({
  payload_template: '', subject_template: '', body_template: '', content_template: '',
  body_format: 'text', daily_format: '', method: 'POST',
})

// 表单可编辑键 + 由通道类型/协议派生写入的键（headers 由请求头行重建，
// msg_type 由 QQ 协议固定为 markdown）——这些键不属于「未知键」保留面。
const FORM_KEYS: readonly string[] = [
  'payload_template', 'subject_template', 'body_template', 'content_template',
  'body_format', 'daily_format', 'method', 'msg_type', 'headers',
]

export const parseStyleConfig = (raw: string | undefined): Record<string, unknown> => {
  if (!raw) return {}
  try {
    const parsed: unknown = JSON.parse(raw)
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {}
  } catch {
    return {} // 坏 JSON 按空配置（默认形态）
  }
}

// 既有 style_config 中表单不认识、保存时必须原样带回的键。
export const channelStyleExtras = (raw: string | undefined): Record<string, unknown> => {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(parseStyleConfig(raw))) {
    if (!FORM_KEYS.includes(k)) out[k] = v
  }
  return out
}

// 既有 style_config → 表单初值（缺省键=默认形态；非字符串值按默认形态）。
export const channelStyleFormFrom = (raw: string | undefined): ChannelStyleForm => {
  const form = emptyChannelStyleForm()
  const parsed = parseStyleConfig(raw)
  for (const k of Object.keys(form) as (keyof ChannelStyleForm)[]) {
    const v = parsed[k]
    if (typeof v === 'string') form[k] = v
  }
  return form
}

// 表单 → style_config（全量覆盖体）：先铺未知键，再按通道类型写表单已知键；
// 留空的已知键不写入=移除该键（清空模板回退默认链）。
export const buildChannelStyleConfig = (
  typ: string,
  form: ChannelStyleForm,
  headers: Record<string, string>,
  extras: Record<string, unknown> = {},
): Record<string, unknown> => {
  const out: Record<string, unknown> = { ...extras }
  if (typ === 'webhook') {
    if (form.payload_template.trim()) out.payload_template = form.payload_template
    if (form.method === 'GET') out.method = 'GET'
    if (Object.keys(headers).length) out.headers = headers
  } else if (typ === 'email') {
    if (form.subject_template.trim()) out.subject_template = form.subject_template
    if (form.body_template.trim()) out.body_template = form.body_template
    if (form.body_format === 'html') out.body_format = 'html'
  } else {
    // 机器人协议固定：QQ=markdown、微信 iLink 仅纯文本（无 msg_type 键）
    if (form.content_template.trim()) out.content_template = form.content_template
    if (typ === 'qq') out.msg_type = 'markdown'
  }
  if (form.daily_format) out.daily_format = form.daily_format
  return out
}

// 渲染模式（与后端 DailyModuleModeEffective 同口径：显式值优先，缺省按存量
// 正文模板键推断——有模板=模板模式）。
export type DailyRenderMode = 'modules' | 'template'

export const channelBodyTplKey = (typ: string): string =>
  typ === 'webhook' ? 'payload_template' : typ === 'email' ? 'body_template' : 'content_template'

export const effectiveDailyMode = (raw: string | undefined, typ: string): DailyRenderMode => {
  const style = parseStyleConfig(raw)
  const explicit = style.daily_mode
  if (explicit === 'modules' || explicit === 'template') return explicit
  const tpl = style[channelBodyTplKey(typ)]
  return typeof tpl === 'string' && tpl.trim() !== '' ? 'template' : 'modules'
}

const canonical = (v: unknown): unknown => {
  if (Array.isArray(v)) return v.map(canonical)
  if (v !== null && typeof v === 'object') {
    const src = v as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(src).sort()) out[k] = canonical(src[k])
    return out
  }
  return v
}

// style 语义相等（键序无关）：全量覆盖写库前的差异判定。
export const stylesEqual = (a: Record<string, unknown>, b: Record<string, unknown>): boolean =>
  JSON.stringify(canonical(a)) === JSON.stringify(canonical(b))

interface DailyStylePlanInput {
  raw: string | undefined
  type: string
  draft: string
  presets: readonly string[]
  mode: DailyRenderMode
}

interface DailyStylePlan {
  style: Record<string, unknown>
  changed: boolean
}

// 单通道日报模板保存计划：正文草稿（trim）与任一语言预置相同/为空 → 移除
// 模板键（沿用默认链，预置升级继续生效）；渲染模式与存量生效值不同才写
// daily_mode；返回是否与存量有差异（无差异不写库）。
export const planDailyChannelStyle = ({ raw, type, draft, presets, mode }: DailyStylePlanInput): DailyStylePlan => {
  const original = parseStyleConfig(raw)
  const style: Record<string, unknown> = { ...original }
  const key = channelBodyTplKey(type)
  const body = draft.trim()
  if (body === '' || presets.some(p => body === p.trim())) delete style[key]
  else style[key] = body
  if (mode !== effectiveDailyMode(raw, type)) style.daily_mode = mode
  return { style, changed: !stylesEqual(style, original) }
}
