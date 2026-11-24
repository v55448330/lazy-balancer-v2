// 日志尾部轮询单源：Rules（规则日志）/CertJobs/TaskMonitor/
// BasicSettings（运行日志）/CaddyGlobalSettings（Caddy 日志）原各持一份同构
// setInterval 实现，且已漂移（TaskMonitor/CaddyGlobalSettings 缺后台标签页暂停、
// 序号守卫口径不一）。本 composable 统一：
//   - 定时器生命周期（start 幂等=清旧装新+立即首拉；stop 作废在途响应）
//   - 后台标签页暂停（document.hidden 轮次跳过，恢复可见后下一 tick 补拉）
//   - loading 单飞门（在途期间重复 refresh 跳过）
//   - 会话序号守卫（stop/invalidate 后迟到的响应不得写回）
//   - 写回后 nextTick 滚底，但仅在用户贴底时（isPinnedToBottom；上翻阅读不被拉回）
// 取数与各页私有守卫（目标行切换/弹框可见/tab 分支）留在调用方 fetch/isActive
// 闭包内；fetch 返回 null 表示本轮不写回。
// 不注册 onUnmounted——四处调用方均有明确的弹框关闭/卸载收尾点（stop 由调用方
// 触发），避免 composable 与 Vue 生命周期耦合。
import { nextTick, ref, type Ref } from 'vue'

/** 贴底容差（px）：行高取整/缩放会让「已贴底」差 1–2px。 */
const LOG_TAIL_PIN_TOLERANCE = 8

/**
 * 滚动容器是否贴底（写回后是否允许自动跟随）。
 * clientHeight 不可得（旧调用方只传 scrollTop/scrollHeight、或非布局态）时
 * 视为贴底——保持「写回即滚底」的旧行为，不让缺字段静默改成不跟随。
 */
export const isPinnedToBottom = (el: { scrollTop: number; scrollHeight: number; clientHeight?: number }): boolean => {
  const clientHeight = el.clientHeight
  if (typeof clientHeight !== 'number' || !Number.isFinite(clientHeight)) return true
  return el.scrollHeight - el.scrollTop - clientHeight <= LOG_TAIL_PIN_TOLERANCE
}

interface LogTailPollingOptions {
  /** 轮询间隔（毫秒；调用方自管定时器时仅作文档值） */
  interval: number
  /** 单次取数：返回日志全文；返回 null 表示本轮不写回（守卫未过/迟到响应） */
  fetch: () => Promise<string | null>
  /** 活跃门（弹框开着且仍指向同一目标）——轮次开始与写回前各检查一次 */
  isActive: () => boolean
  /** 日志全文写入目标 */
  content: Ref<string>
  /** 滚动容器（可选）：写回后仅在用户贴底时滚到底部 */
  container?: Ref<{ scrollTop: number; scrollHeight: number; clientHeight?: number } | null>
  /** 错误分流（缺省 console.error；需 toast 节流等由调用方实现） */
  onError?: (error: unknown) => void
}

interface LogTailPolling {
  /** 单飞 loading 门（模板刷新按钮 loading 态同源） */
  readonly loading: Ref<boolean>
  /** 手动刷新一轮（受 hidden/loading/isActive 门控） */
  readonly refresh: () => Promise<void>
  /** 装定时器并立即刷新一轮（幂等：先清旧定时器并作废在途响应） */
  readonly start: () => void
  /** 停定时器、作废在途响应并复位 loading */
  readonly stop: () => void
  /** 只作废在途响应与 loading（目标切换但定时器保留时用） */
  readonly invalidate: () => void
}

export const useLogTailPolling = (options: LogTailPollingOptions): LogTailPolling => {
  const loading = ref(false)
  let timer: ReturnType<typeof setInterval> | null = null
  // 会话序号：stop/invalidate/新轮次使在途响应作废（对齐五处原实现的 seq 守卫）
  let seq = 0

  const refresh = async (): Promise<void> => {
    // 后台标签页暂停轮询：定时器空转跳过，回到可见后的下一个 tick 立即补拉；
    // node --test 无 document，视为可见。
    if (typeof document !== 'undefined' && document.hidden) return
    if (loading.value || !options.isActive()) return
    const round = ++seq
    loading.value = true
    try {
      const text = await options.fetch()
      if (round !== seq || !options.isActive()) return
      if (text === null) return
      // 贴底判定必须取「写回前」的容器度量：内容变长后浏览器不会自动跟随，
      // 写回后再量会把原本贴底的用户误判成上翻（跟随从此永久失效）。
      const before = options.container?.value
      const pinned = !before || isPinnedToBottom(before)
      options.content.value = text
      await nextTick()
      if (round !== seq) return
      const el = options.container?.value
      if (el && pinned) el.scrollTop = el.scrollHeight
    } catch (error: unknown) {
      if (round === seq && options.isActive()) (options.onError ?? console.error)(error)
    } finally {
      if (round === seq) loading.value = false
    }
  }

  const stop = (): void => {
    seq++
    if (timer) {
      clearInterval(timer)
      timer = null
    }
    loading.value = false
  }

  const start = (): void => {
    stop()
    timer = setInterval(() => { void refresh() }, options.interval)
    void refresh()
  }

  const invalidate = (): void => {
    seq++
    loading.value = false
  }

  return { loading, refresh, start, stop, invalidate }
}
