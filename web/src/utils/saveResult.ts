import { ElMessage } from 'element-plus'
import { wasRecentMfaGrace } from '@/utils/api'

interface SaveResultLike {
  message?: string
}

// 后端成功响应（code:0）的 message 可能携带 Caddy 配置应用失败后缀，
// 必须以持续警告形式呈现给用户，否则失败对 UI 不可见。
export function showSaveResult(res: SaveResultLike | undefined | void, fallback: string): void {
  const message = res?.message || fallback
  if (message.includes('Caddy 配置应用失败')) {
    ElMessage({ type: 'warning', message, duration: 0, showClose: true })
    return
  }
  // R72 十三次→十七次（用户裁决）：宽限窗内放行（用户不知情）时前缀明确说明
  // 原因——「MFA 在验证窗口期」；弹码后重试（用户刚验证）不加缀——单一 toast。
  ElMessage.success(wasRecentMfaGrace() ? `MFA 在验证窗口期，本次操作免验证，${message}` : message)
}
