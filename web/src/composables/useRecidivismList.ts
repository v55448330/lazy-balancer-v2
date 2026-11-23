import { computed, ref, watch } from 'vue'

// 累犯历史列表的服务端分页状态单源（RecidivismDialog 数据面）：
// GET /security/autoban/recidivism?hide_permanent=&ip=&page=&page_size=
// → {records,total,page,page_size}。筛选/搜索/翻页/改页大小都携参重取，
// total 取响应（筛选后总数），前端不再做切片——后端 LIMIT/OFFSET 单源。
// 页码夹紧与 useClampedPagination 同口径（[1, maxPage] 双向）：列表收缩
// （删除末页末条/重置/搜索收窄）后当前页越界自动回夹并重取，杜绝空页滞留。

/** 累犯历史行（后端投影；ip_location 为 handlers 富化字段，缺省空串；
 * ban_status/ban_expires_at=名单生效条目 join（timed/permanent/none），
 * hits_24h/last_event_at=metrics 近 24h 按身份键聚合，旧后端缺省按零值）。 */
export interface RecidivismRecord {
  identity: string
  offense_count: number
  last_ban_at: string
  escalated_duration: string
  ip_location?: string
  ban_status?: 'timed' | 'permanent' | 'none'
  ban_expires_at?: string
  hits_24h?: number
  last_event_at?: string
}

/** 取数注入面：携当前筛选/分页参数请求，返回 records+total
 *（records 恒为数组契约，空结果 []）。 */
export type RecidivismFetch = (params: {
  hidePermanent: boolean
  ip: string
  page: number
  pageSize: number
}) => Promise<{ records: RecidivismRecord[]; total: number }>

export function useRecidivismList(fetchPage: RecidivismFetch) {
  const records = ref<RecidivismRecord[]>([])
  const total = ref(0)
  const loading = ref(false)
  const loadError = ref(false)
  // 筛选默认：隐藏永久封禁（escalated_duration=permanent）、IP 子串搜索空、首页。
  const hidePermanent = ref(true)
  const ipQuery = ref('')
  const page = ref(1)
  const pageSize = ref(20)

  // 弹框会话序号：快速关开/连续翻页时旧响应不得写回新会话（与事件页同范式）。
  let seq = 0
  const fetchRecords = async (): Promise<void> => {
    const requestSeq = ++seq
    loading.value = true
    loadError.value = false
    try {
      const res = await fetchPage({
        hidePermanent: hidePermanent.value,
        ip: ipQuery.value.trim(),
        page: page.value,
        pageSize: pageSize.value,
      })
      if (requestSeq !== seq) return
      records.value = res.records
      total.value = res.total
    } catch {
      if (requestSeq !== seq) return
      records.value = []
      total.value = 0
      loadError.value = true
    } finally {
      if (requestSeq === seq) loading.value = false
    }
  }

  // 页码夹紧（total 驱动）：筛选收窄/删除末页末条使 maxPage 收缩时回夹；
  // page<=0 的脏值同样收敛到 1（只做上界夹紧会让负页码静默错页）。
  const maxPage = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
  const clampPage = (): void => {
    const next = Math.min(Math.max(1, page.value), maxPage.value)
    if (next !== page.value) page.value = next
  }
  watch([maxPage, page], clampPage, { immediate: true })

  // 打开复位：筛选回默认。取数统一交给 watcher——值有变化时 pre-flush
  // watch 合并触发一次 fetch；值未变（净筛选重开）watch 不触发，补一次
  // 显式 fetch。避免「显式 fetch + watch 再 fetch」的双发。
  // ipQuery 复位会触发防抖 watch——用 suppressIpReset 标记抑制这次冗余防抖
  // 取数（复位取数已由 [hidePermanent,page,pageSize] watch / 显式 fetch 承载）。
  // 判据只看结构筛选（hidePermanent/page）：仅搜索词变化的会话重开时结构
  // watch 不触发，必须走显式 fetch——旧判据把 ipQuery 变化也算「已由 watch
  // 承载」，叠加 suppressIpReset 后既不取数也不清旧结果（列表停留在旧行）。
  // watch 为 pre-flush 异步回调，标记由回调消费（非同步块）。
  let suppressIpReset = false
  const open = (): void => {
    const structuralChanged = hidePermanent.value !== true || page.value !== 1
    if (ipQuery.value !== '') suppressIpReset = true
    hidePermanent.value = true
    ipQuery.value = ''
    page.value = 1
    clearTimeout(ipDebounce) // 丢弃复位前在途的键击防抖
    if (!structuralChanged) void fetchRecords()
  }

  // 筛选/翻页/改页大小携参重取；筛选变化先回首页。watch 默认 pre-flush
  // 合并同一 tick 的多次写入（改页大小同时回首页只发一次请求）。
  watch([hidePermanent, page, pageSize], () => { void fetchRecords() })
  // IP 搜索防抖：键击 300ms 后才发请求（避免每键一击一发）；回首页与
  // 取数同一防抖回调，翻页/筛选不受影响。open 复位触发的变更不取数。
  let ipDebounce: NodeJS.Timeout | undefined
  watch(ipQuery, () => {
    if (suppressIpReset) { suppressIpReset = false; return }
    clearTimeout(ipDebounce)
    ipDebounce = setTimeout(() => { page.value = 1; void fetchRecords() }, 300)
  })

  // 关闭作废在途响应：快速关开时旧会话响应不得写回新会话（open 会再 ++seq）；
  // 同时落 loading——被作废的请求 finally 不再复位，留着会卡死遮罩。
  const invalidate = (): void => { seq++; loading.value = false }

  return { records, total, loading, loadError, hidePermanent, ipQuery, page, pageSize, fetchRecords, open, invalidate }
}
