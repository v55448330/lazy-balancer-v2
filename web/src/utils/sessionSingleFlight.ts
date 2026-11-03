// 会话式单飞加载器：原 useCrsRuleIndex 内的模块级
// requestedSeq/loadedSeq/inflight 状态机抽出为无依赖工厂——消费方注入 load/apply，
// 测试可直接验证「并发单飞、旧会话后到丢弃、新会话链式补取、失败可重试」的
// 运行时语义，无需源码文本断言。
//
// 语义（与原实现逐条对齐）：
// - ensure(session) 在 loadedSession===session 时直接返回（同会话缓存）；
// - 在途请求复用：任何消费方在途期不重复发起；
// - 新会话先登记 requestedSession 再复用旧请求；旧请求若因此失效，settled 后
//   链式补取最新会话（不得让调用方空等且永不 loaded）；
// - 旧会话的返回/异常一律丢弃（不 apply、不清 loading），由最新会话收尾。
interface SessionSingleFlight {
  readonly ensure: (session: number) => Promise<void>
  readonly loadedSession: () => number | null
  /** 最近一次 start 登记的会话号（未发起时 null）：join 在途/失败重试同会话用
   *  （useCrsRuleDirectory 惰性取索引复用会话，避免另发新会话作废在途请求）。 */
  readonly requestedSession: () => number | null
  /** 诊断/测试用：加载态由 onLoadingChange 提供给 UI。 */
  readonly isInflight: () => boolean
}

interface SessionSingleFlightOptions<T> {
  readonly load: (session: number) => Promise<T>
  readonly apply: (value: T, session: number) => void
  readonly onError?: (error: unknown, session: number) => void
  readonly onLoadingChange?: (loading: boolean) => void
}

export const createSessionSingleFlight = <T>(options: SessionSingleFlightOptions<T>): SessionSingleFlight => {
  let loadedSession: number | null = null
  let requestedSession: number | null = null
  let inflight: Promise<void> | null = null

  const fetchSession = async (session: number): Promise<void> => {
    options.onLoadingChange?.(true)
    try {
      const value = await options.load(session)
      if (session !== requestedSession) return // 会话已切换：丢弃过期返回
      options.apply(value, session)
      loadedSession = session
    } catch (error: unknown) {
      if (session !== requestedSession) return
      options.onError?.(error, session)
      // 失败不落 loadedSession：同会话下一次 ensure 可重试
    } finally {
      if (session === requestedSession) options.onLoadingChange?.(false)
    }
  }

  const start = (session: number): Promise<void> => {
    // 新会话必须先登记：旧请求若因此失效，settled 后链式补取最新会话
    requestedSession = session
    if (inflight) {
      return inflight.then(() => {
        if (loadedSession === session || requestedSession !== session) return
        return start(session)
      })
    }
    inflight = fetchSession(session).finally(() => { inflight = null })
    return inflight
  }

  return {
    ensure: (session: number): Promise<void> =>
      loadedSession === session ? Promise.resolve() : start(session),
    loadedSession: () => loadedSession,
    requestedSession: () => requestedSession,
    isInflight: () => inflight !== null,
  }
}
