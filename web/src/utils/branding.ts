import { ref, computed } from 'vue'
import { request } from '@/utils/api'
import { escapeHtml } from '@/utils/escape'

interface BrandingResponse {
  data?: {
    app_name?: string
    footer_text?: string
    version?: string
    footer_uses_default?: boolean
  }
}

export const appName = ref('Lazy Balancer')
const footerText = ref('Lazy Balancer V2 · Copyright © 2026 XiaoBao')
// R72 二十九次：发版检查单——发版时需同步 bump 此回退版本。
export const appVersion = ref('v2.3.5')
const footerUsesDefault = ref(true)

export const footerHtml = computed(() => {
  if (!footerUsesDefault.value) {
    return escapeHtml(footerText.value)
  }
  return (
    escapeHtml(footerText.value) +
    ' · <a href="https://github.com/v55448330/lazy-balancer-v2" target="_blank" rel="noopener noreferrer" class="footer-link">GitHub</a>'
  )
})

export async function loadBranding(): Promise<void> {
  try {
    const res = await request.get<BrandingResponse>('/branding', { silent: true }) // 第 59 轮 R59-P5：装饰性预取失败不弹全局错误 toast
    if (res.data?.app_name) appName.value = res.data.app_name
    if (res.data?.version) appVersion.value = res.data.version
    footerUsesDefault.value = res.data?.footer_uses_default !== false
    if (res.data?.footer_text) footerText.value = res.data.footer_text
  } catch {
    // 使用默认文案
  }
  // V2 为产品线版本徽章（不可随 app_name 品牌定制消失），2026-09-06 用户裁定固化；
  // app_name 仅定制产品名部分（侧栏/登录页 v2-badge 徽章同此口径）。
  document.title = `${appName.value} V2`
}
