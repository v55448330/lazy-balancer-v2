import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import type { APIResponse } from '@/types'

/** 地址列表选项行（GET /security/ip-lists）——事件弹框 / IP 悬浮弹层等下拉共用形态 */
export interface IpListOption {
  id: number
  name: string
  entry_count: number
}

/** 地址列表下拉选项 label（列表名 + 条数）——两处消费统一格式 */
export const ipListOptionLabel = (list: IpListOption): string => `${list.name}（${list.entry_count} 条）`

/**
 * 拉取地址列表选项（失败原样抛错，静默与否由调用方决定；
 * 悬空选择清理由调用方结合自身会话守卫处理）
 */
export const fetchIpListOptions = async (): Promise<IpListOption[]> => {
  const res = await request.get<APIResponse<IpListOption[]>>('/security/ip-lists')
  return res.data || []
}

export interface AddIpToListOptions {
  /** 动作词（默认「加入」）：确认框标题/文案与成功反馈共用 */
  verb?: string
  /** 成功反馈文案覆盖（默认「已{verb}地址列表「{list.name}」」） */
  successText?: string
}

/**
 * 「把 IP 加入地址列表」共享实现（消费方：IPLocationAction 悬浮弹层「存入」、
 * SecurityEvents 事件弹框「加入」）：
 * 确认框（含列表名）→ 幂等 POST /security/ip-lists/:id/ips → added 短成功 /
 * 已存在 info；非 silent——错误提示与 MFA 428 step-up 走全局拦截器链。
 * 返回是否完成写入（true 时调用方据此刷新列表选项 / entry_count）。
 */
export const useIpListAdd = () => {
  const adding = ref(false)

  const addIpToList = async (ip: string, list: IpListOption, options: AddIpToListOptions = {}): Promise<boolean> => {
    if (adding.value) return false
    const verb = options.verb ?? '加入'
    try {
      await ElMessageBox.confirm(
        `将把 ${ip} ${verb}地址列表「${list.name}」（幂等，已存在时不会重复添加）。是否继续？`,
        `${verb}地址列表`,
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
      )
    } catch { return false }
    adding.value = true
    try {
      // 非 silent：错误走全局拦截器提示，428 时全局 MFA step-up 弹码链完整生效
      const res = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${list.id}/ips`, { value: ip })
      if (res.data?.added) mfaAwareSuccess(options.successText ?? `已${verb}地址列表「${list.name}」`)
      else ElMessage.info(`该 IP 已在列表「${list.name}」中`)
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
