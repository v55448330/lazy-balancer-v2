import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { tSafe as t } from '../i18n/tSafe.ts'
import { showSaveResult } from '@/utils/saveResult'
import type { APIResponse } from '@/types'

/** 地址列表选项行（GET /security/ip-lists）——事件弹框 / IP 悬浮弹层等下拉共用形态 */
export interface IpListOption {
  id: number
  name: string
  entry_count: number
  /** system=内置威胁名单（只读，更新任务独占写）——「加入/存入」下永不列出 */
  system?: boolean
}

// 全仓零外部消费（仅本模块参数类型）——去掉 export
interface AddIpToListOptions {
  /** 动作词（默认「加入」）：确认框标题/文案与成功反馈共用 */
  verb?: string
  /** 成功反馈文案覆盖（默认「已{verb}地址列表「{list.name}」」） */
  successText?: string
}

/**
 * 「把 IP 加入地址列表」共享实现（消费方：useTrustAssociation——IPLocationAction
 * 悬浮弹层黑/白/信任三侧名单动作的同一条链路）：
 * 确认框（含列表名）→ 幂等 POST /security/ip-lists/:id/ips → added 短成功 /
 * 已存在 info；非 silent——错误提示与 MFA 428 step-up 走全局拦截器链。
 * 返回是否完成写入（true 时调用方据此刷新列表选项 / entry_count）。
 */
export const useIpListAdd = () => {
  const adding = ref(false)

  const addIpToList = async (ip: string, list: IpListOption, options: AddIpToListOptions = {}): Promise<boolean> => {
    if (adding.value) return false
    const verb = options.verb ?? t('common.app.views.ipAdd.verbAdd')
    // 确认框弹出前即占位——双击不再叠两个确认框、两次 POST（与
    // useTrustAssociation 同型）；取消分支统一由 finally 复位。
    adding.value = true
    try {
      try {
        await ElMessageBox.confirm(
          t('common.app.views.ipAdd.confirmMessage', { ip, verb, list: list.name }),
          t('common.app.views.ipAdd.confirmTitle', { verb }),
          { confirmButtonText: t('common.app.views.ipAdd.confirmOk'), cancelButtonText: t('common.app.views.ipAdd.cancel'), type: 'info' },
        )
      } catch { return false }
      // 非 silent：错误走全局拦截器提示，428 时全局 MFA step-up 弹码链完整生效
      const res = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${list.id}/ips`, { value: ip })
      if (res.data?.added) {
        // 2026-09-07 裁定 L1：经 showSaveResult 呈现——退化 200+后缀（Caddy 应用
        // 失败但 DB 已提交）时弹持续警告而非成功 toast，安全处置操作不可静默。
        showSaveResult(res as unknown as { message?: string }, options.successText ?? t('common.app.views.ipAdd.successDefault', { verb, list: list.name }))
      } else ElMessage.info(t('common.app.views.ipAdd.alreadyInList', { list: list.name }))
      return true
    } catch {
      // 失败提示由全局拦截器弹出，这里只需终止流程
      return false
    } finally {
      adding.value = false
    }
  }

  return { adding, addIpToList }
}
