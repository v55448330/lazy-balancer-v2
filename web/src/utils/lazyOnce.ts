// 模块级「单飞 + 失败可重试」懒加载状态机（第 78 轮 U15-F18）。
// useCountryNamesCn 原用 `requested=true` 在请求前闩死：一次失败（旧后端/网络
// 抖动）就让国家中文名整会话回退英文，且永不重试。此处的语义是：
//   - 并发调用共享同一个 in-flight Promise（不重复请求）；
//   - 成功后永久命中（会话级缓存）；
//   - 失败不置加载态 → 下一次调用自然重试。

export interface LazyLoader<T> {
  /** 确保已加载（并发单飞）；失败静默返回，下次调用可重试。 */
  readonly ensure: () => Promise<void>
  readonly get: () => T | null
  readonly isLoaded: () => boolean
  /** 丢弃已加载值（测试/配置切换用；in-flight 期间为空操作）。 */
  readonly reset: () => void
}

export function createLazyLoader<T>(load: () => Promise<T>): LazyLoader<T> {
  let loaded = false
  let value: T | null = null
  let inflight: Promise<void> | null = null

  const ensure = (): Promise<void> => {
    if (loaded) return Promise.resolve()
    if (inflight) return inflight
    const run = (async () => {
      try {
        value = await load()
        loaded = true
      } catch {
        value = null
        loaded = false
      } finally {
        inflight = null
      }
    })()
    inflight = run
    return run
  }

  return {
    ensure,
    get: () => value,
    isLoaded: () => loaded,
    reset: () => {
      if (inflight) return
      loaded = false
      value = null
    },
  }
}
