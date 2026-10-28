import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { mfaAwareSuccess, request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { CADDY_APPLY_FAILED_MARKER } from '@/utils/bulkApplyResult'
import { parseRefIds } from '@/utils/securityStages'
import { useIpListAdd, type IpListOption } from '@/composables/useIpListAdd'
import type { APIResponse } from '@/types'

// 历史（用户裁定）：名单直接动作的共享实现——IP 快捷弹框黑/白/信任三侧
// 单击动作共用。语义：
//   1) 策略已关联同侧非系统地址列表 → 直接把 IP 加入该列表（确认+幂等+反馈
//      复用 useIpListAdd，与事件处置入口同一链路）；
//   2) 策略无同侧非系统列表（未关联，或仅关联系统内置名单——历史裁定
//      系统名单在快捷处置中零暴露、不作为动作目标）→ 自动创建
//      「{策略名}{后缀}」（category=custom，建单即带该 IP 条目）→ 关联到策略
//      对应 refs 字段，两步完成「创建并加入」——中途失败不会留下已被策略引用
//      的空名单；同名（ASCII 大小写折叠）且未被其它引用面引用的既有名单
//      优先复用，被占用时以「{策略名}{后缀}#{策略 id}」新建；历史起 deny/allow/
//      trust 三侧全部接线此出口；
//   3) 移除 = 从引用列表 remove-ip（关联保留，仅移除条目）。
// 信任侧未启用（ip_whitelist_enabled=false）时不阻断操作，仅提示「暂不生效」。
type ListSide = 'deny' | 'allow' | 'trust'

const SIDE_CONFIG: Record<ListSide, {
  refField: 'ip_acl_list_refs' | 'ip_whitelist_refs'
  suffix: string
  verb: string
}> = {
  deny: { refField: 'ip_acl_list_refs', suffix: '-黑名单', verb: '拦截' },
  allow: { refField: 'ip_acl_list_refs', suffix: '-白名单', verb: '放行' },
  trust: { refField: 'ip_whitelist_refs', suffix: '-信任', verb: '信任' },
}

// 后端 IP 名单名上限（securityiplists.go ipListMaxNameLength=50 rune）。
// 自动名 = 策略名（上限 100 rune）+ 后缀 → 长名策略拼出必然 400。
const IP_LIST_NAME_MAX_RUNES = 50

/** 自动名单名按 50 rune 预算：超限截断策略名部分、保留后缀。 */
export const fitAutoListName = (policyName: string, suffix: string): { name: string; truncated: boolean } => {
  const chars = Array.from(policyName)
  const room = IP_LIST_NAME_MAX_RUNES - Array.from(suffix).length
  if (chars.length <= room) return { name: policyName + suffix, truncated: false }
  return { name: chars.slice(0, Math.max(0, room)).join('') + suffix, truncated: true }
}

// 名单名唯一性判据与后端同口径：创建时按 SQLite
// `LOWER(name)=LOWER(?)` 去重（ASCII 大小写折叠），命中即 409。前端复用既有
// 名单的查找如果按大小写敏感比较，`Web-白名单` 已存在时会错过、转而再次创建，
// 换来一条 409 且本次「加入 IP」不发生（弹框一次性，用户没有改用既有名单的
// 出口）。此处只折叠 ASCII（与 SQLite 内置 LOWER 一致）：非 ASCII 大小写变体
// 后端视为不同名单，前端不得提前合并。

interface TrustPolicyLike {
  id: number
  name: string
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_whitelist?: string
  ip_whitelist_refs?: string
  ip_whitelist_enabled?: boolean
}

interface TrustListRef {
  id: number
  name: string
  entry_count?: number
  /** system=内置威胁名单（只读）——两种组件来源的类型宽窄不一，故此处放宽 */
  system?: number | boolean
  /** 引用本名单的策略（GET /security/ip-lists 的 ref_policies）。 */
  ref_policies?: Array<{ id: number; name: string }>
  /** 被 Caddy 全局「受信代理网段」引用（后端已并入 ref_count 展示口径）。 */
  trusted_proxy_referenced?: boolean
}

// 名单名唯一性口径（后端 CreateIPList 的 LOWER(name)=LOWER(?)）：只折叠
// ASCII 大小写（非 ASCII 变体后端视为不同名单）。
const ipListNameKey = (name: string): string => name.replace(/[A-Z]/g, (c) => c.toLowerCase())

// 自动名单复用判据：只允许「未被其它策略、未被受信代理网段引用」的名单承接
// 本次处置——写入别人的名单会改动对方的拦截/放行面。引用视图缺失（旧载荷）
// 说明无法证明未被引用，按不可复用处理。
const isAutoListReusable = (list: TrustListRef, policyId: number): boolean => {
  if (!Array.isArray(list.ref_policies)) return false
  if (list.ref_policies.some((ref) => ref.id !== policyId)) return false
  return list.trusted_proxy_referenced !== true
}

// 自动名已被占用时换本策略限定名：名单名全局唯一（后端 LOWER(name)=LOWER(?)
// 命中即 409），而后缀策略 id 让「同名策略」与「超长截断后同前缀」的两个策略
// 各自落到不同名单；仅在与用户自建名单重名的极少数情况下继续递增。
const LIST_NAME_ATTEMPT_LIMIT = 20
const resolveScopedListName = (
  policyName: string,
  suffix: string,
  policyId: number,
  isTaken: (name: string) => boolean,
): string => {
  for (let attempt = 0; attempt < LIST_NAME_ATTEMPT_LIMIT; attempt++) {
    const scoped = attempt === 0 ? `${suffix}#${policyId}` : `${suffix}#${policyId}-${attempt + 1}`
    const candidate = fitAutoListName(policyName, scoped).name
    if (!isTaken(candidate)) return candidate
  }
  return fitAutoListName(policyName, `${suffix}#${policyId}`).name
}

// 确认后重读策略最新 refs：口径与策略读路径一致（GET /security/policies/:id
// 返回 { policy, bindings }）。读取失败返回 null——调用方必须放弃本次写入：
// 引用快照停留在弹框弹出前，确认期间其它会话（并行标签/另一管理员）新增的
// 引用会被「快照 + 目标」覆盖掉，策略静默丢掉刚加的名单。
const fetchLatestPolicyRefs = async (
  policyId: number,
  field: 'ip_acl_list_refs' | 'ip_whitelist_refs',
): Promise<number[] | null> => {
  try {
    const res = await request.get<APIResponse<{ policy?: TrustPolicyLike }>>(`/security/policies/${policyId}`, { silent: true })
    const raw = res.data?.policy?.[field]
    if (typeof raw !== 'string') return null
    return parseRefIds(raw)
  } catch {
    return null
  }
}

// 确认后重读名单引用面（GET /security/ip-lists/:id 的 ref_policies /
// trusted_proxy_referenced）：同名名单的复用判据在弹框打开时求值，确认期间另一
// 管理员/另一标签可能已把它关联到自己的策略——此时写入会静默改动对方拦截面。
// 读取失败返回 null，调用方必须放弃本次复用（快照不可证）。
const fetchLatestListRefs = async (listId: number): Promise<TrustListRef | null> => {
  try {
    const res = await request.get<APIResponse<TrustListRef>>(`/security/ip-lists/${listId}`, { silent: true })
    return res.data ?? null
  } catch {
    return null
  }
}

export const useTrustAssociation = (options: {
  /** 组件当前的地址列表选项（用于把 refs 解析为名单对象） */
  getList: () => TrustListRef[]
  /** 动作成功后的组件侧刷新（重拉策略/条目缓存等） */
  onChanged?: () => void | Promise<void>
}) => {
  const { adding, addIpToList } = useIpListAdd()
  const creating = ref(false)

  /** 同侧全部非系统列表（用户验收：多列表绑定时逐列表出按钮，不再只取第一个）*/
  const resolveSideLists = (policy: TrustPolicyLike, side: ListSide): IpListOption[] => {
    const refs = parseRefIds(policy[SIDE_CONFIG[side].refField])
    return options.getList()
      .filter((l) => refs.includes(l.id) && !l.system)
      .map((l) => ({ id: l.id, name: l.name, entry_count: l.entry_count ?? 0 }))
  }

  /** 加入指定列表（确认+幂等+反馈，历史暴露供逐列表按钮直调） */
  const joinSpecificList = async (list: IpListOption, ip: string, verb = '加入'): Promise<boolean> => {
    const done = await addIpToList(ip, list, { verb, successText: `已${verb}——已加入列表「${list.name}」` })
    if (done) await options.onChanged?.()
    return done
  }

  /** 单击动作：把 IP 加入策略指定侧的列表（自动解析/创建目标列表并关联） */
  const ensureListAndJoin = async (policy: TrustPolicyLike, ip: string, side: ListSide): Promise<void> => {
    const cfg = SIDE_CONFIG[side]
    // 单数 resolveSideList 已删（唯一内部消费点内联为 plural 首项）
    const existing = resolveSideLists(policy, side)[0] ?? null
    if (existing) {
      const opt: IpListOption = { id: existing.id, name: existing.name, entry_count: 0 }
      const done = await addIpToList(ip, opt, { verb: cfg.verb, successText: `已${cfg.verb}——已加入列表「${existing.name}」` })
      if (done) await options.onChanged?.()
      return
    }
    const tip = side === 'trust' && policy.ip_whitelist_enabled === false ? '（注意：该策略信任名单当前未启用，加入后暂不生效）' : ''
    // 历史裁定：同侧仅系统内置名单时同样走本出口——此时「尚未关联」不成立，
    // 确认文案按引用实况区分（系统名单不在快捷处置中点名/操作）。
    const lead = parseRefIds(policy[cfg.refField]).length === 0
      ? `策略「${policy.name}」尚未关联${cfg.verb}用地址列表`
      : `策略「${policy.name}」同侧仅关联系统内置名单（快捷处置不直接操作系统名单）`
    // 自动名先按后端 50 rune 上限预算（超长策略名截断并显式披露），
    // 否则确认后创建必然 400，动作无法在当前弹框内完成。
    const auto = fitAutoListName(policy.name, cfg.suffix)
    const truncatedNote = auto.truncated ? '（策略名过长，名单名已截断至 50 字符上限）' : ''
    const listNow = options.getList()
    const isNameTaken = (name: string): boolean => listNow.some((l) => ipListNameKey(l.name) === ipListNameKey(name))
    // 同名列表只在「未被其它引用面引用」时可复用（category 无关）；判据与后端
    // 唯一性口径同源（ASCII 大小写折叠）。被占用则换策略限定名走新建。
    const sameName = listNow.find((l) => !l.system && ipListNameKey(l.name) === ipListNameKey(auto.name))
    const reuseTarget = sameName && isAutoListReusable(sameName, policy.id) ? sameName : null
    const createName = isNameTaken(auto.name) ? resolveScopedListName(policy.name, cfg.suffix, policy.id, isNameTaken) : auto.name
    // 确认框弹出前即占位——双击不再叠两个确认框/重复创建
    // （原 creating 在 confirm 之后才置位）。
    if (creating.value) return
    creating.value = true
    try {
      try {
        await ElMessageBox.confirm(
          reuseTarget
            ? `将把 ${ip} 加入既有地址列表「${reuseTarget.name}」${tip}。是否继续？`
            : `${lead}，将创建「${createName}」${truncatedNote}并把 ${ip} 加入${tip}。是否继续？`,
          reuseTarget ? `加入${cfg.verb}用列表` : `创建列表并${cfg.verb}`,
          { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
        )
      } catch {
        return
      }
      // 确认后才取最新引用：快照留在弹框弹出前的策略行上，确认期间别处新增的
      // 名单引用会在「快照 + 本次目标」拼装时被覆盖掉。读取失败则整单放弃
      // （仍以快照写入比不写更危险）。
      const latestRefs = await fetchLatestPolicyRefs(policy.id, cfg.refField)
      if (latestRefs === null) {
        ElMessage.error('策略当前引用状态读取失败，本次未做任何修改；请关闭后重试')
        return
      }
      // 名单侧同样按最新状态复核：弹框打开时的复用判据只代表当时——确认期间
      // 另一管理员/另一标签把同名名单关联到别的策略（或受信代理网段）后，写入
      // 就会静默改动对方的拦截/放行面。已不可复用则改为新建策略限定名单。
      let reuse: TrustListRef | null = reuseTarget
      if (reuse) {
        const latestList = await fetchLatestListRefs(reuse.id)
        if (latestList === null) {
          ElMessage.error(`列表「${reuse.name}」当前引用状态读取失败，本次未做任何修改；请关闭后重试`)
          return
        }
        if (!isAutoListReusable(latestList, policy.id)) {
          ElMessage.warning(`列表「${reuse.name}」已被其它策略或受信代理网段引用，本次改为新建「${createName}」`)
          reuse = null
        }
      }
      if (reuse) {
        // 写序=先加 IP、再关联：反序时条目写入失败会留下「策略已引用的名单里
        // 没有该 IP」，界面仍报过关联成功，处置静默失效；反向半态（名单有条目、
        // 策略暂未引用）无损，重试只补关联。
        const added = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${reuse.id}/ips`, { value: ip })
        const alreadyLinked = latestRefs.includes(reuse.id)
        if (!alreadyLinked) {
          try {
            const assocRes = await request.put(`/security/policies/${policy.id}`, { [cfg.refField]: JSON.stringify([...latestRefs, reuse.id]) })
            // 关联中间跳的退化后缀（Caddy 应用失败但 DB 已提交）不可静默
            if (assocRes.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(assocRes, '')
          } catch {
            // 半态显性披露：条目已就绪，重试只会补关联（幂等，不重复写入）
            ElMessage.error(`已把 ${ip} 加入列表「${reuse.name}」，但策略关联失败；条目已就绪，重试不会重复添加`)
            await options.onChanged?.()
            return
          }
        }
        // 后端幂等：IP 已存在且生效中时返回 added=false 且不做任何写入
        // （securityiplists.go 该分支 rollback 后直接返回）。提示必须与事实一致——
        // 把「已存在」说成「已加入」会让用户以为刚完成一次处置。
        if (added.data?.added === true) {
          showSaveResult(
            added as unknown as { message?: string },
            alreadyLinked ? `已${cfg.verb}——已加入列表「${reuse.name}」` : `已关联既有「${reuse.name}」并加入 ${ip}`,
          )
        } else if (alreadyLinked) {
          // 条目与关联都已存在：本次零写入，只陈述事实（与 useIpListAdd 同文案）。
          ElMessage.info(`该 IP 已在列表「${reuse.name}」中`)
        } else {
          // 条目已在、本次只补了关联：按关联口径反馈，不再声称加入了条目。
          mfaAwareSuccess(`已关联既有「${reuse.name}」——该 IP 已在列表中，未重复添加`)
        }
        await options.onChanged?.()
        return
      }
      // 新建路径：建单即播种条目（后端 CreateIPListRequest.entries 支持），写序为
      // 「创建（含 IP）→ 关联 refs」。原先是 创建空名单 → 关联 → 加入 IP：加入
      // 失败时策略已引用一个空名单，用户只看到一条错误提示，且多一次往返。
      const created = await request.post<APIResponse<{ id: number }>>('/security/ip-lists', {
        name: createName,
        category: 'custom',
        entries: JSON.stringify([{ value: ip, remark: '' }]),
      })
      // 中间跳退化 200+后缀（Caddy 应用失败但 DB 已提交）也须可见——有后缀才弹
      if (created.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(created, '')
      const newId = created.data?.id
      if (!newId) {
        ElMessage.error(`列表「${createName}」创建响应异常，请重试`)
        return
      }
      const assocRes = await request.put(`/security/policies/${policy.id}`, { [cfg.refField]: JSON.stringify([...latestRefs, newId]) }).catch(() => null)
      if (!assocRes) {
        ElMessage.error(`列表「${createName}」已创建并加入 ${ip}，但策略关联失败；重试将复用该名单`)
        await options.onChanged?.()
        return
      }
      // 关联是最后一步：退化后缀弹警告，正常成功用动作口径文案（响应 message 是
      // 策略更新的通用文案，不能拿来当本次动作的反馈）。
      if (assocRes.message?.includes(CADDY_APPLY_FAILED_MARKER)) showSaveResult(assocRes, '')
      else mfaAwareSuccess(`已创建「${createName}」并加入 ${ip}`)
      await options.onChanged?.()
    } catch {
      // 失败提示由全局拦截器弹出
    } finally {
      creating.value = false
    }
  }


  /** 从引用列表移除 IP（关联保留） */
  const removeFromSideRef = async (list: TrustListRef, ip: string): Promise<void> => {
    // 确认框弹出前即占位（双击重入锁）
    if (creating.value) return
    creating.value = true
    try {
      try {
        await ElMessageBox.confirm(
          `将从地址列表「${list.name}」移除 ${ip}。是否继续？`,
          '从列表移除',
          { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
        )
      } catch {
        return
      }
      const res = await request.post<APIResponse<{ removed?: boolean }>>(`/security/ip-lists/${list.id}/remove-ip`, { value: ip })
      if (res.data?.removed !== true) {
        ElMessage.info(`列表「${list.name}」中没有 ${ip} 的精确条目；若由 CIDR 覆盖，请编辑列表处理`)
        await options.onChanged?.()
        return
      }
      // 移除是一次写事件（MFA step-up 覆盖）：与同文件「加入/创建」同口径经
      // mfaAwareSuccess 发出——宽限窗内放行时提示必须带「免验证」前缀。
      mfaAwareSuccess(`已从「${list.name}」移除`)
      await options.onChanged?.()
    } catch {
      // 全局拦截器已提示
    } finally {
      creating.value = false
    }
  }


  return { busyTrust: adding, creating, resolveSideLists, joinSpecificList, ensureListAndJoin, removeFromSideRef }
}
