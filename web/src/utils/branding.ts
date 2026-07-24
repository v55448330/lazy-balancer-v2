import { ref } from 'vue'
import { request } from '@/utils/api'

interface BrandingResponse {
  data?: {
    app_name?: string
    footer_text?: string
    version?: string
  }
}

export const appName = ref('Lazy Balancer')
export const footerText = ref('Copyright © 2026 XiaoBao. All rights reserved.')
export const appVersion = ref('2.0.5')

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
