// 通道 style_config 读写单源（通道卡编辑 + 日报每通道模板保存共用）。
//
// PUT /notification/channels 的 style_config 是全量覆盖语义：任何表单重建都必须
// 把表单不认识的既有键（daily_mode、未来新增键）原样带回，否则保存一次就把
// 别的功能写进去的键抹掉——日报渲染模式会静默回退，用户配置看似「自己变了」。
//
// 同一模块承载日报模板保存的计划函数：多 tab 全量保存时逐通道算差异，只提交
// 真正变化的通道。日报模板写 daily_* 键（与事件正文模板键分离）：自定义模板
// 模式所见即所得（预置也落库）；内置模板模式下与预置相同的草稿不落库。
//
// 存量行（日报卡曾把模板写进事件键）的归一只在后端做：列表接口直接输出新
// 布局、保存入口按同一判据落库。本模块不做存量识别，按键名各管各的。

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
// 日报模板键推断——有日报模板=模板模式）。
export type DailyRenderMode = 'modules' | 'template'

// 日报正文模板键（日报卡「编辑模板」的读写面）。事件正文模板
// （payload_template/body_template/content_template）只作用于事件消息，日报
// 模板只作用于日报——两套作用域不得共用一个键（此前日报卡写事件键：事件
// 通知被日报模板改写，日报模板又因「等于预置即删键」不生效）。
export const dailyBodyTplKey = (typ: string): string =>
  typ === 'webhook' ? 'daily_payload_template' : typ === 'email' ? 'daily_body_template' : 'daily_content_template'

const DAILY_TEMPLATE_KEYS: readonly string[] = ['daily_payload_template', 'daily_body_template', 'daily_content_template']

export const effectiveDailyMode = (raw: string | undefined, _typ: string): DailyRenderMode => {
  const style = parseStyleConfig(raw)
  const explicit = style.daily_mode
  if (explicit === 'modules' || explicit === 'template') return explicit
  // 与后端 DailyModuleModeEffective 同口径：不 trim——空白模板也算已配置
  // （后端判据 Key == ""；前端曾按类型单键 + trim，跨类型/空白形态判定分叉）。
  const hasDailyTpl = DAILY_TEMPLATE_KEYS.some((k) => {
    const tpl = style[k]
    return typeof tpl === 'string' && tpl !== ''
  })
  return hasDailyTpl ? 'template' : 'modules'
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

// 单通道日报模板保存计划：正文写入日报键（daily_*）。清空草稿 → 移除日报键；
// 内置模板模式下与任一语言预置相同的草稿不落库（已存模板保留但不生效，预置
// 副本无意义）；自定义模板模式所见即所得——预置也原样落库（后端默认链并不
// 等于 webhook/邮件/英文预置，删键会让实际投递与编辑器预览不一致）。渲染模式
// 与存量生效值不同才写 daily_mode；返回是否与存量有差异（无差异不写库）。
// 事件正文模板键不属于日报卡：原样保留，不读不删。
export const planDailyChannelStyle = ({ raw, type, draft, presets, mode }: DailyStylePlanInput): DailyStylePlan => {
  const original = parseStyleConfig(raw)
  const style: Record<string, unknown> = { ...parseStyleConfig(raw) }
  const key = dailyBodyTplKey(type)
  const body = draft.trim()
  if (body === '' || (mode !== 'template' && presets.some(p => body === p.trim()))) delete style[key]
  else style[key] = body
  if (mode !== effectiveDailyMode(raw, type)) style.daily_mode = mode
  return { style, changed: !stylesEqual(style, original) }
}
