/**
 * 内置拦截页的显示名/描述多语言单源。
 *
 * 后端的稳定身份=固定 id 播种行；列表接口为内置行下发 name_key（显示名稳定码
 * `block_page.<后缀>`，清单见 internal/models/security.go 的
 * BuiltinBlockPageIdentities）。界面文案由前端词条按码渲染——码去掉
 * `block_page.` 前缀即 app.security.blockPages.builtin.<后缀> 的 name/desc。
 *
 * 库内 name/description 列保留中文库存名（播种/自愈的身份判据、审计明细母本），
 * 不作展示依据；自定义页 name_key 为空，显示用户填写的名称与描述。
 *
 * 未知码 fail-visible：原样显示码本身并 console.warn（后端新增内置页而前端
 * 词条未跟上时，界面直接暴露缺词条的码，便于定位），不做静默回落。
 */
export interface BlockPageLike {
  id: number
  name: string
  description?: string
  /** 内置页显示名稳定码（后端下发；自定义页为空/缺省）。 */
  name_key?: string
}

const BUILTIN_BLOCK_PAGE_PREFIX = 'block_page.'

/**
 * 内置页显示名/描述：`t` 由调用方注入（vue-i18n 组合式 t），按 name_key 查
 * 词条返回译文；非内置页/无 name_key 返回库内原文。
 */
export const builtinBlockPageLabel = (
  page: BlockPageLike,
  field: 'name' | 'desc',
  t: (key: string) => string,
): string => {
  const fallback = field === 'name' ? page.name : (page.description ?? '')
  const code = page.name_key ?? ''
  if (!code) return fallback
  if (!code.startsWith(BUILTIN_BLOCK_PAGE_PREFIX)) {
    console.warn(`[blockPage] name_key 不是稳定码（期望 ${BUILTIN_BLOCK_PAGE_PREFIX}*）：${code}`)
    return code
  }
  const path = `app.security.blockPages.builtin.${code.slice(BUILTIN_BLOCK_PAGE_PREFIX.length)}.${field}`
  const translated = t(path)
  if (translated === path) {
    console.warn(`[blockPage] 内置页稳定码缺少词条：${code}`)
    return code
  }
  return translated
}
