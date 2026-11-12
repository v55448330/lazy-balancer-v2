/**
 * 内置拦截页的显示名/描述多语言单源（2026-11-12 用户裁定，2026-11-13 扩充）：
 * 内置页在库内以固定 id 播种、名称/描述存中文库存名（身份判据=播种与自愈按
 * 库存名归位）。展示层按 id 翻译，词条缺失时回退库内原文——切语言不改写库，
 * 也不动身份判据。
 *
 * id 1=默认拦截页（is_default）；9001=限流；9002=维护；
 * 9005=滑块人机验证页面（{{human_verify_widget}}）；9006=JS 人机验证页面
 * （{{human_js_widget}}）——两个内置人机页是策略可选的真实挑战页载体，
 * 占位符由 lb_human 按验证方式替换为真实组件。
 * 自定义页（无对应词条）恒显示用户填写的名称与描述。
 */
const BUILTIN_BLOCK_PAGE_KEYS: Record<number, 'default' | 'ratelimit' | 'maintenance' | 'human' | 'humanJs'> = {
  1: 'default',
  9001: 'ratelimit',
  9002: 'maintenance',
  9005: 'human',
  9006: 'humanJs',
}

export interface BlockPageLike {
  id: number
  name: string
  description?: string
}

/** 内置页 id → 词条后缀；非内置返回 null。 */
const builtinBlockPageKey = (id: number): string | null => BUILTIN_BLOCK_PAGE_KEYS[id] ?? null

/**
 * 内置页显示名/描述：`t` 由调用方注入（vue-i18n 组合式 t），返回译文；
 * 非内置页或词条缺失（t 原样回传键名）时回退库内原文。
 */
export const builtinBlockPageLabel = (
  page: BlockPageLike,
  field: 'name' | 'desc',
  t: (key: string) => string,
): string => {
  const fallback = field === 'name' ? page.name : (page.description ?? '')
  const key = builtinBlockPageKey(page.id)
  if (!key) return fallback
  const path = `app.security.blockPages.builtin.${key}.${field}`
  const translated = t(path)
  return translated === path ? fallback : translated
}
