// 视图异步状态原语：写操作在确认前占位；读取只让最新会话落地。

/** 在入口守卫之后复用同一写锁，覆盖确认、请求与最终回填；取消/失败同样释放。 */
export const runExclusive = async <T>(
  isLocked: () => boolean,
  setLocked: (locked: boolean) => void,
  operation: () => Promise<T>,
): Promise<T | undefined> => {
  if (isLocked()) return undefined
  setLocked(true)
  try {
    return await operation()
  } finally {
    setLocked(false)
  }
}

interface LatestReadHooks<T> {
  readonly onStart: () => void
  readonly onSuccess: (value: T) => void
  readonly onError: (error: unknown) => void
  readonly onFinally: () => void
}

/** 新读取取消旧请求并推进序号；旧成功、失败和 finally 都不能修改新会话状态。 */
export const createLatestReadSession = () => {
  let generation = 0
  let controller: AbortController | null = null

  const invalidate = (): void => {
    generation++
    controller?.abort()
    controller = null
  }

  const run = async <T>(
    load: (signal: AbortSignal) => Promise<T>,
    hooks: LatestReadHooks<T>,
  ): Promise<void> => {
    controller?.abort()
    const ownController = new AbortController()
    controller = ownController
    const ownGeneration = ++generation
    const isCurrent = (): boolean => ownGeneration === generation
    hooks.onStart()
    try {
      const value = await load(ownController.signal)
      if (!isCurrent()) return
      hooks.onSuccess(value)
    } catch (error: unknown) {
      if (isCurrent()) hooks.onError(error)
    } finally {
      if (isCurrent()) {
        controller = null
        hooks.onFinally()
      }
    }
  }

  return { run, invalidate }
}
