// 「取消信任」处置计划单源：原逻辑内联在 IPLocationAction，
// 且残余信任判定只在「无内联精确条目」分支生效——IP 同时由内联精确条目与引用
// 列表 CIDR 信任时跳过守卫，移除后仍持续信任却弹「已取消信任/恢复拦截」。
//
// 本函数返回：
// - inlineExact：策略内联名单存在该 IP 的精确条目（可移除）
// - exactRefListIds：命中引用列表中存在精确条目且允许本弹窗移除的列表（可移除）
// - residualSources：移除后仍提供信任的来源（不可移除，须人工到策略/列表
//   编辑处理）：CIDR 覆盖条目，以及不在可移除集合中的精确条目（系统内置
//   名单由写侧门禁止新引用，仅存量策略可达）；空 = 移除后信任真正解除
// - hasRemovable：是否存在可移除条目（false = 本弹窗无可执行动作）
import { entryMatchesIp, parseIPList, parseRefIds } from './securityStages.ts'

interface TrustRemovalList {
  readonly id: number
  readonly name: string
}

interface TrustRemovalPlan {
  readonly inlineExact: boolean
  readonly exactRefListIds: readonly number[]
  readonly residualSources: readonly string[]
  readonly hasRemovable: boolean
}

export const planTrustRemoval = (input: {
  readonly ip: string
  readonly inlineWhitelist: string | undefined
  readonly whitelistRefs: string | undefined
  readonly lists: readonly TrustRemovalList[]
  readonly removableListIds: readonly number[]
  /** 名单条目读取：**必须新鲜**。本函数据此给出「移除后该 IP 是否仍被信任」的
   *  安全结论——陈旧条目会漏掉他人新增的 CIDR 覆盖（把「引擎仍信任」谎报成
   *  「已取消信任」）。调用方须在决策前强制刷新：仍在 TTL 内可复用缓存，过期
   *  必须重拉；重拉失败（条目缺失）时不得出结论。 */
  readonly listEntries: (listId: number) => readonly string[]
}): TrustRemovalPlan => {
  const ip = input.ip.trim()
  const inline = parseIPList(input.inlineWhitelist)
  const refIds = parseRefIds(input.whitelistRefs)
  const removable = new Set(input.removableListIds)

  const inlineExact = inline.includes(ip)
  const exactRefListIds = input.lists
    .filter((l) => refIds.includes(l.id) && removable.has(l.id)
      && input.listEntries(l.id).some((e) => e.trim() === ip))
    .map((l) => l.id)

  // 残余信任 = 移除后仍匹配该 IP 的条目（内联 CIDR / 引用列表 CIDR），以及
  // 不在可移除集合中的精确条目（系统内置名单：本弹窗无法移除其条目）。后者
  // 遗漏会把「已取消信任」谎报给用户——引擎仍按该精确条目豁免。
  const residualSources: string[] = []
  if (inline.some((e) => e.trim() !== ip && entryMatchesIp(e, ip))) {
    residualSources.push('策略内联 CIDR 条目')
  }
  for (const list of input.lists) {
    if (!refIds.includes(list.id)) continue
    const entries = input.listEntries(list.id)
    if (entries.some((e) => e.trim() !== ip && entryMatchesIp(e, ip))) {
      residualSources.push(`引用列表「${list.name}」的 CIDR 条目`)
      continue
    }
    if (!removable.has(list.id) && entries.some((e) => e.trim() === ip)) {
      residualSources.push(`引用列表「${list.name}」的精确条目（不可在本弹窗移除）`)
    }
  }

  return {
    inlineExact,
    exactRefListIds,
    residualSources,
    hasRemovable: inlineExact || exactRefListIds.length > 0,
  }
}

/** 写后核对三态：任何详情/名单读取缺口都是未知，绝不能拿写入前快照代替结论。 */
export const classifyTrustRemovalVerification = (input: {
  readonly detailLoaded: boolean
  readonly missingListIds: readonly number[]
  readonly residualSources: readonly string[]
}): 'unknown' | 'cleared' | 'residual' => {
  if (!input.detailLoaded || input.missingListIds.length > 0) return 'unknown'
  return input.residualSources.length > 0 ? 'residual' : 'cleared'
}
