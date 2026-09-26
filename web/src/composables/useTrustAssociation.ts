import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { parseRefIds } from '@/utils/securityStages'
import { useIpListAdd, type IpListOption } from '@/composables/useIpListAdd'
import type { APIResponse } from '@/types'

// 第 58 轮（用户裁定）：信任名单直接动作的共享实现——快捷弹框与触发详情弹框
// 共用。语义：
//   1) 策略已关联非系统信任地址列表 → 直接把 IP 加入该列表（确认+幂等+反馈
//      复用 useIpListAdd，与事件处置入口同一链路）；
//   2) 策略尚无信任用途列表 → 自动创建「{策略名}-信任」（category=custom、空
//      条目）→ 关联到策略 ip_whitelist_refs → 加入 IP，一步完成「创建并加入」；
//   3) 移除 = 从引用列表 remove-ip（关联保留，仅移除条目）。
// 信任名单未启用（ip_whitelist_enabled=false）时不阻断操作，仅提示「暂不生效」。
export interface TrustPolicyLike {
  id: number
  name: string
  ip_whitelist?: string
  ip_whitelist_refs?: string
  ip_whitelist_enabled?: boolean
}

export interface TrustListRef {
  id: number
  name: string
  /** system=内置威胁名单（只读）——两种组件来源的类型宽窄不一，故此处放宽 */
  system?: number | boolean
}

export const useTrustAssociation = (options: {
  /** 组件当前的地址列表选项（用于把 refs 解析为名单对象） */
  getList: () => TrustListRef[]
  /** 动作成功后的组件侧刷新（重拉策略/条目缓存等） */
  onChanged?: () => void | Promise<void>
}) => {
  const { adding, addIpToList } = useIpListAdd()
  const creating = ref(false)

  /** 策略既有信任用途列表：ip_whitelist_refs 中第一个非系统列表 */
  const resolveTrustList = (policy: TrustPolicyLike): TrustListRef | null => {
    const refs = parseRefIds(policy.ip_whitelist_refs)
    return options.getList().find((l) => refs.includes(l.id) && !l.system) ?? null
  }

  const joinTrust = async (policy: TrustPolicyLike, ip: string): Promise<void> => {
    const trust = resolveTrustList(policy)
    if (trust) {
      const opt: IpListOption = { id: trust.id, name: trust.name, entry_count: 0 }
      const done = await addIpToList(ip, opt, { verb: '加入信任', successText: `已加入信任列表「${trust.name}」` })
      if (done) await options.onChanged?.()
      return
    }
    const tip = policy.ip_whitelist_enabled === false ? '（注意：该策略信任名单当前未启用，加入后暂不生效）' : ''
    try {
      await ElMessageBox.confirm(
        `策略「${policy.name}」尚未关联信任地址列表，将创建「${policy.name}-信任」并把 ${ip} 加入${tip}。是否继续？`,
        '创建信任列表并加入',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
      )
    } catch {
      return
    }
    creating.value = true
    try {
      const created = await request.post<APIResponse<{ id: number }>>('/security/ip-lists', {
        name: `${policy.name}-信任`,
        category: 'custom',
        entries: '[]',
      } as never)
      const newId = created.data?.id
      if (!newId) return
      const refs = parseRefIds(policy.ip_whitelist_refs)
      if (!refs.includes(newId)) {
        await request.put(`/security/policies/${policy.id}`, { ip_whitelist_refs: JSON.stringify([...refs, newId]) })
      }
      const added = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${newId}/ips`, { value: ip })
      showSaveResult(added as unknown as { message?: string }, `已创建「${policy.name}-信任」并加入 ${ip}`)
      await options.onChanged?.()
    } catch {
      // 失败提示由全局拦截器弹出
    } finally {
      creating.value = false
    }
  }

  /** 从信任引用列表移除 IP（关联保留） */
  const removeFromTrustRef = async (list: TrustListRef, ip: string): Promise<void> => {
    try {
      await ElMessageBox.confirm(
        `将从信任地址列表「${list.name}」移除 ${ip}。是否继续？`,
        '从信任列表移除',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
      )
    } catch {
      return
    }
    creating.value = true
    try {
      await request.post(`/security/ip-lists/${list.id}/remove-ip`, { value: ip })
      ElMessage.success(`已从「${list.name}」移除`)
      await options.onChanged?.()
    } catch {
      // 全局拦截器已提示
    } finally {
      creating.value = false
    }
  }

  return { busyTrust: adding, creating, resolveTrustList, joinTrust, removeFromTrustRef }
}
