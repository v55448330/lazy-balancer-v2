import { onUnmounted } from 'vue'

export interface PollingTaskContext {
  readonly signal: AbortSignal
  readonly sequence: number
  readonly isCurrent: () => boolean
}

interface PollingTaskOptions {
  readonly interval?: number
  readonly onError?: (error: unknown) => void
}

export interface PollingTask {
  readonly signal: AbortSignal
  readonly run: () => Promise<void>
  readonly start: () => void
  readonly stop: () => void
  readonly pause: () => void
  readonly resume: () => void
  readonly isDisposed: () => boolean
}

export const usePollingTask = (
  task: (context: PollingTaskContext) => Promise<void>,
  options: PollingTaskOptions = {},
): PollingTask => {
  const controller = new AbortController()
  let disposed = false
  let sequence = 0
  let inFlight: Promise<void> | null = null
  let pending = false
  let timer: ReturnType<typeof setInterval> | null = null
  let visibilityHandler: (() => void) | null = null

  const drain = async (): Promise<void> => {
    while (!disposed && pending) {
      pending = false
      const taskSequence = ++sequence
      const isCurrent = (): boolean => !disposed && taskSequence === sequence
      try {
        await task({ signal: controller.signal, sequence: taskSequence, isCurrent })
      } catch (error: unknown) {
        // FI-14：onError 是消费方回调——若其自身抛错，异常会经 drain→run() 的
        // Promise 拒绝逃逸，而定时器/可见性处用 void run() 丢弃 Promise，成为
        // unhandled rejection。回调异常就地记录并吞掉，不中断 drain、不影响下一轮。
        if (!controller.signal.aborted) {
          try {
            options.onError?.(error)
          } catch (callbackError: unknown) {
            console.error('usePollingTask onError callback threw:', callbackError)
          }
        }
      }
    }
  }

  const run = (): Promise<void> => {
    if (disposed) return Promise.resolve()
    pending = true
    if (!inFlight) {
      const drainPromise = drain().finally(() => {
        if (inFlight === drainPromise) inFlight = null
      })
      inFlight = drainPromise
    }
    return inFlight
  }

  // 后台标签页暂停定时轮询（手动 run() 不受影响）；回到可见时恢复定时器并立即刷新补齐数据。
  const beginInterval = (): void => {
    if (disposed || timer !== null || options.interval === undefined) return
    if (typeof document !== 'undefined' && document.hidden) return
    timer = setInterval(() => void run(), options.interval)
  }

  const pauseInterval = (): void => {
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
  }

  const ensureVisibilityPause = (): void => {
    if (visibilityHandler !== null || typeof document === 'undefined') return
    visibilityHandler = (): void => {
      if (disposed) return
      if (document.hidden) {
        pauseInterval()
      } else {
        beginInterval()
        void run()
      }
    }
    document.addEventListener('visibilitychange', visibilityHandler)
  }

  const start = (): void => {
    if (disposed || options.interval === undefined) return
    ensureVisibilityPause()
    beginInterval()
  }

  const invalidate = (): void => {
    sequence += 1
    pending = false
  }

  const stop = (): void => {
    if (disposed) return
    disposed = true
    invalidate()
    controller.abort()
    pauseInterval()
    if (visibilityHandler !== null && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', visibilityHandler)
      visibilityHandler = null
    }
  }

  // F-1(第 16 轮审计):非终态暂停/恢复——stop() 永久置位 disposed,弹框级
  // stop/start 循环的消费方(SecurityRules 更新进度)首轮 stop 后轮询永久
  // 失效。pause 仅停定时器与在途任务(invalidate 使过期结果丢弃),resume
  // 可反复调用;语义与 stop 不同:不 abort controller、不解除 visibility 监听。
  const pause = (): void => {
    invalidate()
    pauseInterval()
    // SR17-1(第 17 轮):同步摘除 visibility 监听——否则暂停期间标签页
    // 可见性翻转会在 handler 里 beginInterval() 复活定时器(违反 pause
    // 契约);resume→start→ensureVisibilityPause 会重挂,前 5 个不 pause
    // 的消费方不受影响。
    if (visibilityHandler !== null && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', visibilityHandler)
      visibilityHandler = null
    }
  }

  const resume = (): void => {
    start()
  }

  onUnmounted(stop)

  return { signal: controller.signal, run, start, stop, pause, resume, isDisposed: () => disposed }
}
