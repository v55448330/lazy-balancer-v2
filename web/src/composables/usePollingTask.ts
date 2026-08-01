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
  readonly invalidate: () => void
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

  const run = async (): Promise<void> => {
    if (disposed) return
    if (inFlight) {
      pending = true
      await inFlight
      return
    }

    pending = false
    const taskSequence = ++sequence
    const isCurrent = (): boolean => !disposed && taskSequence === sequence
    inFlight = task({ signal: controller.signal, sequence: taskSequence, isCurrent })
    try {
      await inFlight
    } catch (error: unknown) {
      if (!controller.signal.aborted) options.onError?.(error)
    } finally {
      const shouldDrain = !disposed && pending
      pending = false
      inFlight = null
      if (shouldDrain) queueMicrotask(() => void run())
    }
  }

  const start = (): void => {
    if (disposed || timer || options.interval === undefined) return
    timer = setInterval(() => void run(), options.interval)
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
    if (timer) clearInterval(timer)
    timer = null
  }

  onUnmounted(stop)

  return { signal: controller.signal, run, start, stop, invalidate, isDisposed: () => disposed }
}
