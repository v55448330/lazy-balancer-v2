import { ref, computed } from 'vue'
import { request } from '@/utils/api'

interface BrandingResponse {
  data?: {
    app_name?: string
    footer_text?: string
    version?: string
  }
}

export const appName = ref('Lazy Balancer')
export const footerText = ref('Copyright © 2026 XiaoBao. All rights reserved. · https://github.com/v55448330/lazy-balancer-v2')
export const appVersion = ref('v2.1.1')

const escapeHtml = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

export const footerHtml = computed(() =>
  escapeHtml(footerText.value).replace(
    /(https?:\/\/[^\s"'&]+)/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer" class="footer-link">$1</a>',
  ),
)

export async function loadBranding(): Promise<void> {
  try {
    const res = await request.get<BrandingResponse>('/branding')
    if (res.data?.app_name) appName.value = res.data.app_name
    if (res.data?.footer_text) footerText.value = res.data.footer_text
    if (res.data?.version) appVersion.value = res.data.version
  } catch {
    // 使用默认文案
  }
  document.title = `${appName.value} V2`
}
