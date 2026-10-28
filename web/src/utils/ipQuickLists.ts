import { entryMatchesIp, parseIPList, parseRefIds } from './securityStages.ts'

export type IpQuickSide = 'deny' | 'allow' | 'trust'

export interface IpQuickPolicy {
  id: number
  name: string
  policy_type?: string
  ip_acl_mode: string
  ip_acl_list: string
  ip_acl_list_refs?: string
  ip_whitelist: string
  ip_whitelist_refs?: string
}

export interface IpQuickList {
  id: number
  name: string
  entry_count: number
  system?: boolean
  ref_policies?: Array<{ id: number; name: string }>
}

export interface IpQuickSource {
  key: string
  kind: 'list' | 'inline'
  name: string
  listId?: number
  policyId?: number
  entryCount: number
  exact: boolean
  matchedEntry: string
  policies: Array<{ id: number; name: string }>
}

interface IpQuickTarget {
  key: string
  kind: 'list' | 'policy'
  name: string
  listId?: number
  policyId?: number
  entryCount: number
  policies: Array<{ id: number; name: string }>
}

const familyOf = (policy: IpQuickPolicy): string => policy.policy_type || 'mixed'

const policySupportsSide = (policy: IpQuickPolicy, side: IpQuickSide): boolean => {
  const family = familyOf(policy)
  if (side === 'trust') return family === 'stage0' || family === 'mixed'
  if (family !== 'stage1' && family !== 'mixed') return false
  return policy.ip_acl_mode === side
}

const inlineOf = (policy: IpQuickPolicy, side: IpQuickSide): string[] =>
  parseIPList(side === 'trust' ? policy.ip_whitelist : policy.ip_acl_list)

const refsOf = (policy: IpQuickPolicy, side: IpQuickSide): number[] =>
  parseRefIds(side === 'trust' ? policy.ip_whitelist_refs : policy.ip_acl_list_refs)

const uniquePolicies = (policies: Array<{ id: number; name: string }>): Array<{ id: number; name: string }> => {
  const seen = new Set<number>()
  return policies.filter((policy) => {
    if (seen.has(policy.id)) return false
    seen.add(policy.id)
    return true
  })
}

/**
 * IP 快捷弹框的唯一成员/目标模型：只描述名单成员，不计算规则上的访问结果。
 * 策略是否停用、ACL 是否启用均不影响“IP 是否在名单里”这一事实。
 */
export const buildIpQuickModel = (
  ipRaw: string,
  policies: IpQuickPolicy[],
  lists: IpQuickList[],
  entries: Record<number, string[]>,
): Record<IpQuickSide, { sources: IpQuickSource[]; targets: IpQuickTarget[] }> => {
  const ip = ipRaw.trim()
  const listById = new Map(lists.map((list) => [list.id, list]))
  const result: Record<IpQuickSide, { sources: IpQuickSource[]; targets: IpQuickTarget[] }> = {
    deny: { sources: [], targets: [] },
    allow: { sources: [], targets: [] },
    trust: { sources: [], targets: [] },
  }

  for (const side of ['deny', 'allow', 'trust'] as const) {
    const sourceMap = new Map<string, IpQuickSource>()
    const targetMap = new Map<string, IpQuickTarget>()
    for (const policy of policies) {
      if (!policySupportsSide(policy, side)) continue
      const inline = inlineOf(policy, side)
      const refs = refsOf(policy, side)
      const inlineHit = inline.find((entry) => entryMatchesIp(entry, ip))
      if (inlineHit) {
        sourceMap.set(`inline:${policy.id}`, {
          key: `inline:${policy.id}`,
          kind: 'inline',
          name: policy.name,
          policyId: policy.id,
          entryCount: inline.length,
          exact: inline.includes(ip),
          matchedEntry: inlineHit,
          policies: [{ id: policy.id, name: policy.name }],
        })
      }

      let sideHit = Boolean(inlineHit)
      let writableRefCount = 0
      for (const listId of refs) {
        const list = listById.get(listId)
        if (!list || list.system) continue
        writableRefCount += 1
        const listEntries = entries[listId] ?? []
        const matchedEntry = listEntries.find((entry) => entryMatchesIp(entry, ip))
        if (matchedEntry) {
          sideHit = true
          const key = `list:${listId}`
          const existing = sourceMap.get(key)
          if (existing) existing.policies = uniquePolicies([...existing.policies, { id: policy.id, name: policy.name }])
          else {
            sourceMap.set(key, {
              key,
              kind: 'list',
              name: list.name,
              listId,
              entryCount: list.entry_count,
              exact: listEntries.includes(ip),
              matchedEntry,
              policies: list.ref_policies?.length ? [...list.ref_policies] : [{ id: policy.id, name: policy.name }],
            })
          }
        }
        if (!matchedEntry) {
          const key = `list:${listId}`
          if (!targetMap.has(key)) {
            targetMap.set(key, {
              key,
              kind: 'list',
              name: list.name,
              listId,
              entryCount: list.entry_count,
              policies: list.ref_policies?.length ? [...list.ref_policies] : [{ id: policy.id, name: policy.name }],
            })
          }
        }
      }

      // 没有可写引用名单时，沿用现有“创建名单并关联策略”的完整实现。
      if (writableRefCount === 0 && !sideHit) {
        targetMap.set(`policy:${policy.id}`, {
          key: `policy:${policy.id}`,
          kind: 'policy',
          name: `${policy.name} · 新建名单`,
          policyId: policy.id,
          entryCount: 0,
          policies: [{ id: policy.id, name: policy.name }],
        })
      }
    }
    result[side] = {
      sources: [...sourceMap.values()].sort((a, b) => a.name.localeCompare(b.name, 'zh-CN')),
      targets: [...targetMap.values()].sort((a, b) => a.kind === b.kind ? a.name.localeCompare(b.name, 'zh-CN') : a.kind === 'list' ? -1 : 1),
    }
  }
  return result
}
