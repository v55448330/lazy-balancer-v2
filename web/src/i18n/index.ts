// i18n 入口:locale 持久化(localStorage)+ 首访跟随浏览器;仅 zh-CN/en。
// 词条按域拆分于 src/locales/{zh,en}/*.json,经 index 聚合。
import { createI18n } from 'vue-i18n'
import zhCommon from '@/locales/zh/common'
import enCommon from '@/locales/en/common'
import zhRules from '@/locales/zh/rules'
import enRules from '@/locales/en/rules'
import zhSecurity from '@/locales/zh/security'
import enSecurity from '@/locales/en/security'
import zhMisc from '@/locales/zh/misc'
import enMisc from '@/locales/en/misc'

// 域词条合并:每份文件 export { app: { <子域> } },app 下子域互斥,浅合并即可。
const appOf = (m: { app?: Record<string, unknown> }) => m.app ?? {}
const zhApp = { ...appOf(zhRules), ...appOf(zhSecurity), ...appOf(zhMisc) }
const enApp = { ...appOf(enRules), ...appOf(enSecurity), ...appOf(enMisc) }

export type Locale = 'zh-CN' | 'en'

const STORAGE_KEY = 'lb_locale'

export function detectLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'zh-CN' || saved === 'en') return saved
  } catch {
    return 'zh-CN' // 非 DOM 环境(测试进程)安全回落
  }
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
    'zh-CN': { common: zhCommon, app: zhApp },
    en: { common: enCommon, app: enApp },
  },
  missingWarn: false,
  fallbackWarn: false,
})
