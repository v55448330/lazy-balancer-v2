import { computed, nextTick, ref, type Ref } from 'vue'
import { ElMessage } from 'element-plus'
import { request, ApiRequestError } from '@/utils/api'
import type { APIResponse } from '@/types'
import { usePollingTask } from '@/composables/usePollingTask'

/**
 * 规则库更新弹框单一范式（收敛 SecurityRules 三处近逐字重复的
 * CRS / IP2Region / 威胁情报库更新弹框逻辑）：可见性 + 状态/日志双拉取 +
 * 触发更新（409=任务已在跑，吞并后直接轮询进度）+ 2s 轮询 + 日志滚底。
 *
 * 三库差异全部经 options 参数化：
 * - apiPrefix 组装 `${prefix}/update`、`${prefix}/update/status`、`${prefix}/update/logs`
 * - 状态形状与进行中/终态/成功判定（CRS/IP2Region 走 status 字段，威胁库走 running/outcome）
 * - 终态成功的联动刷新（fetchCRS+fetchRules / fetchIP2RegionInfo / fetchThreatLib）
 * - 状态/日志拉取失败的 console.error（CRS/IP2Region 有标签，威胁库侧原本静默）
 *
 * 日志滚动容器 ref 归消费方所有（模板 ref 字符串绑定），对象传入以供滚底。
 */
interface UseLibUpdateDialogOptions<TInfo> {
  readonly apiPrefix: string
  /** 日志滚动容器（模板 ref 绑定在消费方），每次日志拉取后自动滚到底部 */
  readonly logContainer: Ref<HTMLDivElement | null>
  /** 状态/日志拉取失败时 console.error 的标签；不传则完全静默 */
  readonly errorLabel?: string
  /** 更新任务是否进行中（决定「立即更新」按钮显隐与打开弹框时是否续轮询） */
  readonly isRunning: (info: TInfo | null) => boolean
  /** 是否到达终态（终态即暂停轮询） */
  readonly isFinished: (info: TInfo) => boolean
  /** 终态成功判定 */
  readonly isSuccess: (info: TInfo) => boolean
  /** 终态成功时的联动刷新 */
  readonly onSuccess?: () => void
  /** 弹框 @opened 拉取前的页面级动作（三库共用 ensureScheduleTz） */
  readonly onOpen?: () => void
}

export function useLibUpdateDialog<TInfo>(options: UseLibUpdateDialogOptions<TInfo>) {
  const visible = ref(false)
  const status = ref<TInfo | null>(null) as Ref<TInfo | null>
  const logs = ref('')
  /** 触发更新请求在途（「立即更新」按钮 loading） */
  const starting = ref(false)
  let requestSeq = 0
  // 弹框会话序号：open/onClosed/dispose 各推进一档。触发请求在途时关掉重开，
  // 旧请求的收尾不得复位新会话的 starting、也不得在新会话里驱动 refreshStatus
  //（会把上一次触发的进度当成本次结果）。
  let sessionSeq = 0

  const updating = computed(() => options.isRunning(status.value))

  // 手写 setInterval → usePollingTask(后台标签页暂停/自动清理)。
  // 弹框会话级暂停(非终态)——stop 会永久 disposed,重开弹框即失效;
  // 组件卸载的终态清理由 usePollingTask 内置 onUnmounted 兜底。
  // （409 重复轮询）：onOpened / confirmUpdate 都是先 await refreshStatus()
  // 再起轮询——若 startPolling 走 resume()（start + 立即 run），同一轮 status+logs
  // 会被立刻重复请求一次（409=任务已在跑路径每次点击都翻倍）。start() 只挂 2s
  // 定时器，下一轮交给定时器；刚拉过的状态不重复拉。
  // 轮次 signal 必须透传：关闭弹框/终态 stopPolling 后，在途的两个请求
  // （长任务下日志体不小）随 abort 取消，不再空跑完成。
  const polling = usePollingTask(async ({ signal }) => { await refreshStatus(signal) }, { interval: 2000 })
  const startPolling = () => { polling.start() }
  const stopPolling = () => { polling.pause() }

  const scrollLogToBottom = async () => {
    await nextTick()
    if (options.logContainer.value) options.logContainer.value.scrollTop = options.logContainer.value.scrollHeight
  }

  /**
   * 状态/日志双拉取。`signal` 由轮询轮次传入（关闭弹框/终态 → 在途请求取消）；
   * onOpened/confirmUpdate 的显式调用不传，保持既有语义。
   */
  const refreshStatus = async (signal?: AbortSignal) => {
    if (!visible.value) return
    const seq = ++requestSeq
    const [statusResult, logsResult] = await Promise.allSettled([
      request.get<APIResponse<TInfo>>(`${options.apiPrefix}/update/status`, { silent: true, signal }),
      request.get<APIResponse<{ content: string }>>(`${options.apiPrefix}/update/logs`, { silent: true, signal }),
    ])
    if (!visible.value || seq !== requestSeq) return
    if (statusResult.status === 'fulfilled') {
      status.value = statusResult.value.data || null
    } else if (options.errorLabel) {
      console.error(`Failed to fetch ${options.errorLabel} update status:`, statusResult.reason)
    }
    if (logsResult.status === 'fulfilled') {
      logs.value = logsResult.value.data?.content || ''
      await scrollLogToBottom()
    } else if (options.errorLabel) {
      console.error(`Failed to fetch ${options.errorLabel} update logs:`, logsResult.reason)
    }
    const info = status.value
    if (info && options.isFinished(info)) {
      stopPolling()
      if (options.isSuccess(info)) options.onSuccess?.()
    }
  }

  /** 打开弹框：作废旧会话在途响应，清空上次的任务状态与日志 */
  const open = () => {
    sessionSeq++
    requestSeq++
    // 新会话不得继承上一次触发的 loading：关闭-重开时按钮必须可用
    //（旧请求仍在途，其 finally 由会话序号拦下，不会反过来清掉本次状态）。
    starting.value = false
    status.value = null
    logs.value = ''
    visible.value = true
  }

  // 打开弹框只拉取一次当前状态与既有日志；若有任务在跑则继续实时轮询
  const onOpened = async () => {
    options.onOpen?.()
    await refreshStatus()
    if (updating.value) startPolling()
  }

  const onClosed = () => {
    sessionSeq++
    requestSeq++
    starting.value = false
    stopPolling()
    status.value = null
    logs.value = ''
  }

  // 确认触发更新：409 表示已有任务在运行，跳过触发直接轮询进度
  const confirmUpdate = async () => {
    const session = sessionSeq
    starting.value = true
    try {
      await request.post<APIResponse<{ status: string; trigger: string }>>(`${options.apiPrefix}/update`, undefined, { silent: true })
    } catch (error) {
      if (!(error instanceof ApiRequestError && error.status === 409)) {
        // 非 409 失败=触发未生效，报错后终止（原实现继续走 refreshStatus+startPolling，
        // 会把无关的既有任务进度当成本次触发结果轮询）；409 维持「已有任务在跑，直接轮询」
        ElMessage.error(error instanceof Error ? error.message : '触发更新失败')
        return
      }
    } finally {
      // 会话已换（关掉重开）：不得复位新会话的 starting，也不得驱动其轮询。
      if (session === sessionSeq) starting.value = false
    }
    if (session !== sessionSeq) return
    await refreshStatus()
    if (!visible.value) return
    // refreshStatus 在终态时已 stopPolling + onSuccess——若本次状态已是
    // 终态成功（409 且任务刚好完成 / 任务瞬时完成），无条件 startPolling 会让 2s
    // 后的下一轮再判终态、onSuccess 二次执行（重复 fetchCRS/fetchRules 等）。
    // 与 onOpened 同口径：仅「任务仍在运行」或「状态未取到」（status=null，
    // 瞬时失败需靠轮询收敛）时继续轮询；已取到终态则不再自启。
    if (updating.value || status.value === null) startPolling()
  }

  const close = () => { visible.value = false }

  /** 组件卸载：作废在途响应并暂停轮询（终态清理由 usePollingTask 内置 onUnmounted 兜底） */
  const dispose = () => {
    sessionSeq++
    requestSeq++
    starting.value = false
    stopPolling()
  }

  return {
    visible, status, logs, updating, starting,
    open, close, onOpened, onClosed,
    confirmUpdate, refreshStatus, startPolling, stopPolling, dispose,
  }
}
