import { computed, watch, type ComputedRef, type Ref } from 'vue'

/**
 * 页码夹紧 + 分页切片单一范式（第 52 轮 P5-3，用户裁定，取代三处并存实现——
 * Rules/SecurityRules 的 watch 夹紧、BlockPages/Policies 的 computed 内副作用
 * 赋值）：列表收缩（删除/搜索收窄）或页大小变化使当前页超出最大页时自动回夹，
 * 杜绝「删除末页末条后空页」。返回分页切片与最大页。
 */
export function useClampedPagination<T>(items: Ref<T[]> | ComputedRef<T[]>, page: Ref<number>, pageSize: Ref<number>) {
  const maxPage = computed(() => Math.max(1, Math.ceil(items.value.length / pageSize.value)))
  watch(maxPage, () => {
    if (page.value > maxPage.value) page.value = maxPage.value
  })
  const pagedItems = computed(() => {
    const start = (page.value - 1) * pageSize.value
    return items.value.slice(start, start + pageSize.value)
  })
  return { pagedItems, maxPage }
}
