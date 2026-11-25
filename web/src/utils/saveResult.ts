import { ElMessage } from 'element-plus'
import { mfaAwareSuccess } from '@/utils/api'
import { isCaddyApplyDegraded } from '@/utils/bulkApplyResult'

interface SaveResultLike {
  message?: string
  /** 后端 message_key 透传（稳定语义键，语言无关）。退化 200 是双键集：
   *  security.savedButCaddyApplyFailed=通用写端点；security.savedButCaddyReloadFailed=安全策略/默认策略 apply（重载失败）。
   *  判定单源在 utils/bulkApplyResult.isCaddyApplyDegraded，勿按单键硬编码。 */
  messageKey?: string
}

/** PUT /config 无变化成功响应的稳定语义键（后端 caddy.configUnchanged）：DB/运行配置均未
 *  变更。后端不再按请求语言翻译，message 恒为中文母本（「配置无变化」）——但字面量比较
 *  仍属脆弱写法，三张设置卡统一走本语言无关判据。 */
const CONFIG_UNCHANGED_MESSAGE_KEY = 'caddy.configUnchanged'

/** 「配置无变化」判定单源：语言无关语义键。无键旧响应按未变化=未知处理（false，
 *  回落「保存成功」是历史行为，不臆测）。 */
export const isConfigUnchanged = (res: SaveResultLike | undefined | void): boolean =>
  !!res && res.messageKey === CONFIG_UNCHANGED_MESSAGE_KEY

// 后端成功响应（code:0）可能是退化 200：DB 已提交但 Caddy 配置应用失败。
// 判定首选 messageKey（语言无关）——message 是中文母本、且易随文案漂移；
// zh 标记仅作无键旧响应兜底（bulkApplyResult 单源）。
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
