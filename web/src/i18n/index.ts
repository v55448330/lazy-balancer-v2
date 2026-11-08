// i18n 入口:locale 持久化(localStorage)+ 首访跟随浏览器;仅 zh-CN/en。
// 词条按域拆分于 src/locales/{zh,en}/*.json,经 index 聚合。
import { createI18n } from 'vue-i18n'
import zhCommon from '@/locales/zh/common'
import enCommon from '@/locales/en/common'

export type Locale = 'zh-CN' | 'en'

const STORAGE_KEY = 'lb_locale'

export function detectLocale(): Locale {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'zh-CN' || saved === 'en') return saved
  // 首访跟随浏览器;无法识别回落中文
  const nav = typeof navigator !== 'undefined' ? navigator.language || '' : ''
  return /^en\b/i.test(nav) ? 'en' : 'zh-CN'
}

export function setLocale(l: Locale): void {
  localStorage.setItem(STORAGE_KEY, l)
  window.location.reload()
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': { common: zhCommon },
    en: { common: enCommon },
  },
  missingWarn: false,
  fallbackWarn: false,
})
