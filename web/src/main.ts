import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { loadBranding } from './utils/branding'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'
import './styles/main.css'

const app = createApp(App)
const pinia = createPinia()

// 全局渲染错误兜底：未捕获异常/Promise 拒绝不得静默吞掉（面板表现是
// 「点了没反应」且无任何留痕）。此处只留痕不恢复——局部错误边界仍由
// AsyncPageError（异步页面加载）与各调用点自己的 try/catch 承担。
const reportGlobalError = (kind: string, error: unknown): void => {
  console.error(`[global:${kind}]`, error)
}
app.config.errorHandler = (err, _instance, info) => reportGlobalError('render', `${info}: ${String(err)}`)
window.addEventListener('unhandledrejection', (event) => reportGlobalError('unhandledrejection', event.reason))

app.use(pinia)
// 首屏优先：branding 是装饰性请求（含 30s 全局超时），
// 原 `void loadBranding().finally(() => app.mount('#app'))` 让后端抖动/超时
// 时白屏最长 30s。现先挂载（品牌名/版本到达后由响应式状态自然刷新）。
app.mount('#app')
void loadBranding()
