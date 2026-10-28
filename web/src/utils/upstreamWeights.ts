type WeightedItem = {
  weight: number
  enabled?: boolean
}

export const MAX_UPSTREAM_ROWS = 100

const minimumWeight = (item: WeightedItem): number => item.enabled === false ? 0 : 1
const normalizedWeight = (item: WeightedItem): number => Math.max(minimumWeight(item), Math.round(item.weight || 0))

// ⚠ 变异契约：participatingItems 及依赖它的函数（normalizeWeights /
// redistributeWeight）会**就地改写** items[].weight——仅禁用行被写 0（超出
// MAX_UPSTREAM_ROWS 的行保留原权重并继续参与分配：该常量只是编辑器新增按钮的
// 上限，后端无条数上限）。当前调用方(编辑器草稿态)依赖此行为;未来在只读场景
// 复用时须先剥离副作用。
const participatingItems = <Item extends WeightedItem>(items: Item[]): Item[] => {
  // 只清零禁用行；MAX_UPSTREAM_ROWS 仅是编辑器的「添加上游」按钮上限，
  // 后端对上游条数无上限（API/导入可写入更多）。此前把超限行权重写 0，
  // 使经 API 写入的 101+ 行规则在编辑器改任一权重后「一保存就 400」，
  // 且本地缓存权重被静默清零。超限由编辑器提示显性化，权重照常参与分配。
  items.forEach((item) => {
    if (item.enabled === false) item.weight = 0
  })
  return items.filter((item) => item.enabled !== false)
}

const distributeWeight = <Item extends WeightedItem>(items: Item[], totalWeight: number): void => {
  if (items.length === 0) return
  const minimums = items.map(minimumWeight)
  const minimumTotal = minimums.reduce((sum, weight) => sum + weight, 0)
  const availableTotal = Math.max(minimumTotal, totalWeight)
  const sourceTotal = items.reduce((sum, item) => sum + normalizedWeight(item), 0)
  let allocated = 0

  items.forEach((item, index) => {
    if (index === items.length - 1) {
      item.weight = availableTotal - allocated
      return
    }
    const remainingMinimum = minimums.slice(index + 1).reduce((sum, weight) => sum + weight, 0)
    const proportional = Math.round((normalizedWeight(item) / sourceTotal) * availableTotal)
    item.weight = Math.min(availableTotal - allocated - remainingMinimum, Math.max(minimums[index], proportional))
    allocated += item.weight
  })
}

export const normalizeWeights = <Item extends WeightedItem>(items: Item[]): void => {
  distributeWeight(participatingItems(items), 100)
}

export const redistributeWeight = <Item extends WeightedItem>(items: Item[], changedIndex: number): void => {
  const participating = participatingItems(items)
  if (participating.length === 0) return
  const changed = items[changedIndex]
  if (!changed) return
  if (changed.enabled === false || !participating.includes(changed)) {
    changed.weight = 0
    distributeWeight(participating, 100)
    return
  }
  if (participating.length === 1) {
    changed.weight = 100
    return
  }
  const otherItems = participating.filter((item) => item !== changed)
  const otherMinimum = otherItems.reduce((sum, item) => sum + minimumWeight(item), 0)
  // 预算随参与行数抬升：超过 100 行时每行仍需 ≥1（否则末位分配会压到 0，
  // 后端保存 400）；≤100 行时保持既有「合计 100」语义。
  const budget = Math.max(100, participating.reduce((sum, item) => sum + minimumWeight(item), 0))
  changed.weight = Math.min(budget - otherMinimum, normalizedWeight(changed))
  distributeWeight(otherItems, budget - changed.weight)
}

// weightPercent 权重百分比展示（已收敛——原 RuleFlowDialog/Rules 两份
// 同口径复刻）。签名:(upstreams, row)→0-100 整数;禁用行 0;总和≤0 时 0。
export const weightPercent = (
  upstreams: ReadonlyArray<{ weight?: number; enabled?: boolean }> | undefined,
  row: { weight?: number; enabled?: boolean }
): number => {
  if (!upstreams?.length) return 0
  if (row.enabled === false) return 0
  const sum = upstreams.filter((u) => u.enabled !== false).reduce((s, u) => s + (u.weight || 0), 0)
  if (sum <= 0) return 0
  return Math.round(((row.weight || 0) / sum) * 100)
}

// payloadWeight：后端已废除 0→1 静默归一（weight<1 保存/导入均
// 响亮 400）。草稿态禁用行权重被 participatingItems 写 0（上方变异契约），
// 保存载荷边界为禁用行送 1——禁用行权重无业务意义（输入框禁用、百分比列
// 恒显「禁用」），与既有库形态（禁用行历史落库均为 1）一致；启用行原样送出
// （redistribute 保证 ≥1，异常 0 由后端 400 显性拦截）。
export const payloadWeight = (item: { weight?: number; enabled?: boolean }): number =>
  item.enabled === false ? 1 : (item.weight ?? 100)
