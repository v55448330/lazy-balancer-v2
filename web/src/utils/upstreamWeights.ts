type WeightedItem = {
  weight: number
  enabled?: boolean
}

export const MAX_UPSTREAM_ROWS = 100

const minimumWeight = (item: WeightedItem): number => item.enabled === undefined ? 1 : 0
const normalizedWeight = (item: WeightedItem): number => Math.max(minimumWeight(item), Math.round(item.weight || 0))

const participatingItems = <Item extends WeightedItem>(items: Item[]): Item[] => {
  const withinLimit = items.slice(0, MAX_UPSTREAM_ROWS)
  items.slice(MAX_UPSTREAM_ROWS).forEach((item) => { item.weight = 0 })
  items.forEach((item) => {
    if (item.enabled === false) item.weight = 0
  })
  return withinLimit.filter((item) => item.enabled !== false)
}

const distributeWeight = <Item extends WeightedItem>(items: Item[], totalWeight: number): void => {
  if (items.length === 0) return
  const minimums = items.map(minimumWeight)
  const minimumTotal = minimums.reduce((sum, weight) => sum + weight, 0)
  const availableTotal = Math.max(minimumTotal, totalWeight)
  const sourceTotal = items.reduce((sum, item) => sum + normalizedWeight(item), 0)
  if (sourceTotal === 0) {
    const baseWeight = Math.floor(availableTotal / items.length)
    items.forEach((item, index) => {
      item.weight = index === 0 ? availableTotal - baseWeight * (items.length - 1) : baseWeight
    })
    return
  }
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
  const otherItems = participating.filter((item) => item !== changed)
  const otherMinimum = otherItems.reduce((sum, item) => sum + minimumWeight(item), 0)
  changed.weight = Math.min(100 - otherMinimum, normalizedWeight(changed))
  distributeWeight(otherItems, 100 - changed.weight)
}
