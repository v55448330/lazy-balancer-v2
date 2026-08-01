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
void loadBranding().finally(() => app.mount('#app'))
