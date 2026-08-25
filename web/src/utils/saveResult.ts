import { ElMessage } from 'element-plus'
import { mfaAwareSuccess } from '@/utils/api'

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
  // R72 十三次→十八次：统一走 mfaAwareSuccess（全站写事件同口径）。
  mfaAwareSuccess(message)
}
