import { ref, computed } from 'vue'
import { request } from '@/utils/api'

interface BrandingResponse {
  data?: {
    app_name?: string
    footer_text?: string
    version?: string
    footer_uses_default?: boolean
  }
}

export const appName = ref('Lazy Balancer')
export const footerText = ref('Lazy Balancer V2 · Copyright © 2026 XiaoBao')
export const appVersion = ref('v2.1.7')
const footerUsesDefault = ref(true)

const escapeHtml = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

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
    const res = await request.get<BrandingResponse>('/branding')
    if (res.data?.app_name) appName.value = res.data.app_name
    if (res.data?.version) appVersion.value = res.data.version
    footerUsesDefault.value = res.data?.footer_uses_default !== false
    if (res.data?.footer_text) footerText.value = res.data.footer_text
  } catch {
    // 使用默认文案
  }
  document.title = `${appName.value} V2`
}
