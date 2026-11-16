import { ElMessage } from 'element-plus'
import { mfaAwareSuccess } from '@/utils/api'
import { isCaddyApplyDegraded } from '@/utils/bulkApplyResult'

interface SaveResultLike {
  message?: string
  /** 后端 message_key 透传（稳定语义键，语言无关）；退化 200 恒为 k_de8cc6aa。 */
  messageKey?: string
}

/** PUT /config 无变化成功响应的稳定语义键（后端 k_f724d3c8）：DB/运行配置均未
 *  变更。message 按 Accept-Language 翻译（zh「配置无变化」/ en「No configuration
 *  changes」），字面量比较在 en 下必然失配——三张设置卡统一走本判据。 */
const CONFIG_UNCHANGED_MESSAGE_KEY = 'k_f724d3c8'

/** 「配置无变化」判定单源：语言无关语义键。无键旧响应按未变化=未知处理（false，
 *  回落「保存成功」是历史行为，不臆测）。 */
export const isConfigUnchanged = (res: SaveResultLike | undefined | void): boolean =>
  !!res && res.messageKey === CONFIG_UNCHANGED_MESSAGE_KEY

// 后端成功响应（code:0）可能是退化 200：DB 已提交但 Caddy 配置应用失败。
// 判定首选 messageKey（语言无关）——message 按 Accept-Language 翻译，en 模板
// 不含 zh 标记；zh 标记仅作无键旧响应兜底（bulkApplyResult 单源）。
// 退化必须以持续警告呈现给用户，否则失败对 UI 不可见。
export function showSaveResult(res: SaveResultLike | undefined | void, fallback: string): void {
  const message = res?.message || fallback
  if (isCaddyApplyDegraded(res ? { message, messageKey: res.messageKey } : undefined)) {
    ElMessage({ type: 'warning', message, duration: 0, showClose: true })
    return
  }
  // →十八次：统一走 mfaAwareSuccess（全站写事件同口径）。
  mfaAwareSuccess(message)
}
