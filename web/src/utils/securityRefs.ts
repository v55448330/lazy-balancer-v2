// 安全规则页「引用」展示判定（纯函数，无 Vue/i18n 依赖；行为测试见
// tests/securityPagesRefsAndPreview.spec.ts）。自定义规则与 IP 地址列表的列表行
// 引用面同形：ref_count 含禁用策略的展示面引用；ref_count_enabled 与后端删除
// 409 门同口径——只有启用策略的引用会阻止删除。

/** 引用某个可复用安全对象（自定义规则 / IP 地址列表）的安全策略（列表行 ref_policies 元素）。 */
export interface SecurityRefPolicy {
  id: number
  name: string
  enabled: boolean
}

interface SecurityRefView {
  ref_count: number
  ref_count_enabled?: number
  ref_policies?: readonly SecurityRefPolicy[] | null
}

/** 确认框里逐条具名的上限（超出部分以「其余 N 条」收口，确认框不铺满整屏）。 */
const REF_NAMES_MAX = 10

interface RefNameScope {
  /** 条数（引导行里的数量；不小于具名条数与未具名余量之和）。 */
  count: number
  /** 可具名的策略（至多 REF_NAMES_MAX 条）。 */
  names: string[]
  /** 未能具名的条数。 */
  unnamed: number
}

interface RefDeleteDisclosure {
  /** none=无引用；blocked=被启用策略引用，服务端拒绝删除；disabledOnly=只有禁用策略引用，不阻止删除。 */
  state: 'none' | 'blocked' | 'disabledOnly'
  enabled: RefNameScope
  disabled: RefNameScope
}

const nameScope = (count: number, names: readonly string[]): RefNameScope => {
  const shown = names.slice(0, REF_NAMES_MAX)
  return { count, names: shown, unnamed: Math.max(count - shown.length, 0) }
}

/**
 * 删除确认的引用披露。启用引用数优先取行上的 ref_count_enabled（与删除 409 门同
 * 口径）；缺失时回落为 ref_policies 里的启用策略数——不得因字段缺失把「被引用」
 * 当成「无引用」。条数不小于具名条数（引用快照新于计数时以名字为准）。
 */
export const refDeleteDisclosure = (view: SecurityRefView): RefDeleteDisclosure => {
  const policies = Array.isArray(view.ref_policies) ? view.ref_policies : []
  const enabledNames = policies.filter((p) => p.enabled).map((p) => p.name)
  const disabledNames = policies.filter((p) => !p.enabled).map((p) => p.name)
  const enabledCount = Math.max(view.ref_count_enabled ?? 0, enabledNames.length)
  const disabledCount = Math.max(view.ref_count - enabledCount, disabledNames.length)
  return {
    state: enabledCount > 0 ? 'blocked' : disabledCount > 0 ? 'disabledOnly' : 'none',
    enabled: nameScope(enabledCount, enabledNames),
    disabled: nameScope(disabledCount, disabledNames),
  }
}
