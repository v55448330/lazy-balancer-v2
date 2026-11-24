import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { i18n } from './i18n/index'
import { loadBranding } from './utils/branding'
import { reportGlobalError } from './utils/globalError'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'
import './styles/main.css'

const app = createApp(App)
const pinia = createPinia()

// 全局渲染错误兜底：未捕获异常/Promise 拒绝不得静默吞掉（面板表现是
// 「点了没反应」且无任何留痕）。此处只留痕不恢复——局部错误边界仍由
// AsyncPageError（异步页面加载）与各调用点自己的 try/catch 承担。
// 错误对象原样透传（保留 stack），info 单独成参——拼成一行字符串会丢掉
// 组件栈/调用栈，两条入口（渲染/rejection）的诊断能力必须一致。
app.config.errorHandler = (err, _instance, info) => reportGlobalError('render', err, info)
window.addEventListener('unhandledrejection', (event) => reportGlobalError('unhandledrejection', event.reason))

app.use(pinia)
app.use(i18n)
app.config.globalProperties.$flw = (zhWidth: string): string => {
  // 表单 label 宽度语言感知:zh=设计固定宽;en=设计宽×1.3(下限 120px)——
  // 英文文案较中文长 30-80%,适度加宽消除临界误折(Custom routes 等),
  // 超长 label 仍按裁定整词换行两行(非单行化/非 auto 拉宽)。
  // 语言取 i18n 实例的当前 locale(首访跟随浏览器时存储里没有偏好,读存储键
  // 会把英文界面判成中文,英文标签按中文窄宽度排版)。
  if (i18n.global.locale.value !== 'en') return zhWidth
  const n = parseInt(zhWidth)
  return `${Math.max(Math.round(n * 1.3), 120)}px`
}
// 首屏优先：branding 是装饰性请求（含 30s 全局超时），
// 原 `void loadBranding().finally(() => app.mount('#app'))` 让后端抖动/超时
// 时白屏最长 30s。现先挂载（品牌名/版本到达后由响应式状态自然刷新）。
app.mount('#app')
void loadBranding()
