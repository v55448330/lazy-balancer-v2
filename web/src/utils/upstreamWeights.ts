type WeightedItem = {
  weight: number
}

const normalizedWeight = (weight: number): number => Math.max(1, Math.round(weight || 0))

export const normalizeWeights = <Item extends WeightedItem>(items: Item[]): void => {
  if (items.length === 0) return
  if (items.length === 1) {
    items[0].weight = 100
    return
  }

  const total = items.reduce((sum, item) => sum + normalizedWeight(item.weight), 0)
  let allocated = 0
  items.forEach((item, index) => {
    if (index === items.length - 1) {
      item.weight = 100 - allocated
      return
    }

    const rowsAfter = items.length - index - 1
    const available = 100 - allocated - rowsAfter
    item.weight = Math.min(available, Math.max(1, Math.round((normalizedWeight(item.weight) / total) * 100)))
    allocated += item.weight
  })
}

export const redistributeWeight = <Item extends WeightedItem>(items: Item[], changedIndex: number): void => {
  if (items.length === 0) return
  if (items.length === 1) {
    items[0].weight = 100
    return
  }

  const changed = items[changedIndex]
  if (!changed) return
  const otherItems = items.filter((_, index) => index !== changedIndex)
  changed.weight = Math.min(100 - otherItems.length, normalizedWeight(changed.weight))

  const remaining = 100 - changed.weight
  const otherTotal = otherItems.reduce((sum, item) => sum + normalizedWeight(item.weight), 0)
  let allocated = 0
  otherItems.forEach((item, index) => {
    if (index === otherItems.length - 1) {
      item.weight = remaining - allocated
      return
    }

    const rowsAfter = otherItems.length - index - 1
    const available = remaining - allocated - rowsAfter
    item.weight = Math.min(available, Math.max(1, Math.round((normalizedWeight(item.weight) / otherTotal) * remaining)))
    allocated += item.weight
  })
}
