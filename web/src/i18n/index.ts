// i18n 入口:locale 持久化(localStorage)+ 首访跟随浏览器;仅 zh-CN/en。
// 词条按域拆分于 src/locales/{zh,en}/*.ts,经本文件归一聚合。
import { createI18n } from 'vue-i18n'
import zhCommon from '../locales/zh/common.ts'
import enCommon from '../locales/en/common.ts'
import zhRules from '../locales/zh/rules.ts'
import enRules from '../locales/en/rules.ts'
import zhSecurity from '../locales/zh/security.ts'
import enSecurity from '../locales/en/security.ts'
import zhMisc from '../locales/zh/misc.ts'
import enMisc from '../locales/en/misc.ts'
import zhSettings from '../locales/zh/settings.ts'
import enSettings from '../locales/en/settings.ts'
import zhViews from '../locales/zh/views.ts'
import enViews from '../locales/en/views.ts'

type Tree = Record<string, unknown>

function isPlainObject(v: unknown): v is Tree {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function deepMerge(base: Tree, ...sources: Tree[]): Tree {
  const out: Tree = { ...base }
  for (const src of sources) {
    for (const k of Object.keys(src)) {
      const b = out[k]
      const s = src[k]
      out[k] = isPlainObject(b) && isPlainObject(s) ? deepMerge(b, s) : s
    }
  }
  return out
}

// 各批次文件包装形态不一(有的 {app:{子域}},有的裸 {rules}/{settings}/{appShell});
// 深合并成一棵树 T,双路径暴露:
//   t('app.x.*')(C/F 形态)        → messages.app = T
//   t('common.app.x.*')(A/B/E/D) → messages.common.app = T.app ∪ T 根级散域键
// 同树双路径加倍词条体积(P5 优化项:统一调用前缀后收敛),运行期语义一致。
const zhTree = deepMerge({}, zhCommon, zhRules, zhSecurity, zhMisc, zhSettings, zhViews as Tree)
const enTree = deepMerge({}, enCommon, enRules, enSecurity, enMisc, enSettings, enViews as Tree)

function commonApp(tree: Tree): Tree {
  const app = isPlainObject(tree.app) ? { ...tree.app } : {}
  for (const k of Object.keys(tree)) {
    if (k !== 'app' && isPlainObject(tree[k])) app[k] = tree[k]
  }
  return app
}
const zhCommonApp = commonApp(zhTree)
const enCommonApp = commonApp(enTree)

export type Locale = 'zh-CN' | 'en'

const STORAGE_KEY = 'lb_locale'

export function detectLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'zh-CN' || saved === 'zh' || saved === 'en') return saved === 'zh' ? 'zh-CN' : saved
  } catch {
    return 'zh-CN' // 非 DOM 环境(测试进程)安全回落
  }
  // 首访跟随浏览器;无法识别回落中文
  const nav = typeof navigator !== 'undefined' ? navigator.language || '' : ''
  return /^en\b/i.test(nav) ? 'en' : 'zh-CN'
}

export function setLocale(l: Locale): void {
  // audit137-U2-F3:storage 禁用环境(嵌入式 webview)裸 setItem 抛错会跳过
  // reload——用户困在旧语言页面。静默降级(偏好不持久化,本次会话仍生效)。
  try {
    localStorage.setItem(STORAGE_KEY, l)
  } catch {
    /* storage 禁用:忽略 */
  }
  window.location.reload()
}

// 语言标记到 html(供 CSS 按语言覆盖布局:英文 label auto、中文固定宽)
if (typeof document !== 'undefined' && document.documentElement) {
  document.documentElement.dataset.locale = detectLocale()
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'zh-CN',
  // app 与 common.app 同一棵合并树(双前缀形态并存;appShell 等根级散键入 common.app)
  messages: {
    'zh-CN': { common: { app: zhCommonApp }, app: zhCommonApp },
    en: { common: { app: enCommonApp }, app: enCommonApp },
  },
  missingWarn: false,
  fallbackWarn: false,
})
