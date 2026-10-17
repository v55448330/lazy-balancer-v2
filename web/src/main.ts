import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { loadBranding } from './utils/branding'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'
import './styles/main.css'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
// 首屏优先（第 78 轮 U15-F09）：branding 是装饰性请求（含 30s 全局超时），
// 原 `void loadBranding().finally(() => app.mount('#app'))` 让后端抖动/超时
// 时白屏最长 30s。现先挂载（品牌名/版本到达后由响应式状态自然刷新）。
app.mount('#app')
void loadBranding()
