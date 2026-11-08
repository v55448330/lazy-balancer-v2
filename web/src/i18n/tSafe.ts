// 批次 E(utils/composables)抽词的词条安全 t():内建仅挂本批次 misc 子树的
// 轻量 vue-i18n 实例,不依赖 i18n/index 的注册接线(main 在全部批次完成后
// 统一接线)——接线前后 zh/en 都能直出译文,node --test 无别名钩子也能原生
// 解析整条 import 链;locale 读同一 lb_locale 存储键,setLocale 整页重载,
// 与 app 实例无跨帧不一致。行为测试进程无 localStorage,安全回落 zh-CN,
// 与既有字面钉逐字等价(同 i18n/index.detectLocale 口径)。
import { createI18n } from 'vue-i18n'
import zhMisc from '../locales/zh/misc.ts'
import enMisc from '../locales/en/misc.ts'
import zhViews from '../locales/zh/views.ts'
import enViews from '../locales/en/views.ts'

const batchELocale = (): 'zh-CN' | 'en' => {
  try {
    return localStorage.getItem('lb_locale') === 'en' ? 'en' : 'zh-CN'
  } catch {
    return 'zh-CN' // 非 DOM 环境(测试进程)安全回落
  }
}

// 域子树浅合并(app 下互斥,批次 E misc + 批次 D views;批次 F settings 由其批次追加)
const appOf = (m: { app?: Record<string, unknown> }) => m.app ?? {}
const zhApp = { ...appOf(zhMisc), ...appOf(zhViews) }
const enApp = { ...appOf(enMisc), ...appOf(enViews) }

const i18n = createI18n({
  legacy: false,
  locale: batchELocale(),
  fallbackLocale: 'zh-CN',
  missingWarn: false,
  fallbackWarn: false,
  messages: {
    'zh-CN': { common: { app: zhApp } },
    en: { common: { app: enApp } },
  },
})

export const tSafe = (key: string, params?: Record<string, unknown>): string => i18n.global.t(key, params ?? {})
