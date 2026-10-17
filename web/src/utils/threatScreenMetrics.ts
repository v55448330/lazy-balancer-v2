// 威胁大屏展示指标纯函数（第 78 轮 L07-F05/L07-F07/L07-F10）：
//   - trafficDelta：正常流量计数器差分。首轮只建基线（原实现 prev=0 → 首帧
//     delta=进程累计值），QPS 按真实采样间隔计算（原恒除 1.5s），计数器回退
//     （Caddy 重载/进程重启）显式标记 reset 而不是静默负数丢弃。
//   - threatIndex：24h 全局攻击总量 → 0-100 仪表标尺。与单国热力标尺解耦
//     （原复用 log10(1..1000) 单国口径，全局总量 1 次与 999 次几乎无区分度）。

export interface TrafficBaseline {
  readonly counts: ReadonlyMap<string, number>
  /** 采样时刻（performance.now 或 Date.now，与 now 同源）。 */
  readonly at: number
}

export interface TrafficDeltaResult {
  /** 本轮只建立/重建基线（不产生流量增量）。 */
  readonly baseline: boolean
  /** 计数器回退（Caddy 重载/进程重启）——曲线应断开并重建基线。 */
  readonly reset: boolean
  readonly deltas: { name: string; count: number }[]
  readonly total: number
  /** 按真实采样间隔折算的每秒请求数。 */
  readonly qps: number
}

export function trafficDelta(
  prev: TrafficBaseline | null,
  countries: Record<string, { normal?: number }>,
  now: number,
): TrafficDeltaResult {
  const counts = new Map<string, number>()
  let reset = false
  let total = 0
  const deltas: { name: string; count: number }[] = []
  for (const [name, entry] of Object.entries(countries)) {
    const value = typeof entry?.normal === 'number' && Number.isFinite(entry.normal) ? entry.normal : 0
    counts.set(name, value)
    if (!prev) continue
    const before = prev.counts.get(name)
    // 基线中不存在的新国家不计差分：其累计值不是「本间隔内新增」
    if (before === undefined) continue
    const delta = value - before
    if (delta < 0) reset = true
    else if (delta > 0) {
      deltas.push({ name, count: delta })
      total += delta
    }
  }
  if (!prev) return { baseline: true, reset: false, deltas: [], total: 0, qps: 0 }
  if (reset) return { baseline: true, reset: true, deltas: [], total: 0, qps: 0 }
  const elapsedSec = (now - prev.at) / 1000
  const qps = elapsedSec > 0 ? total / elapsedSec : 0
  return { baseline: false, reset: false, deltas, total, qps }
}

/** 24h 全局攻击总量 → 仪表百分比（log 标尺 10 万≈满分，下限 2 避免「有攻击但显示 0」）。 */
export function threatIndex(total: number): number {
  if (!Number.isFinite(total) || total <= 0) return 0
  return Math.min(100, Math.max(2, Math.round((Math.log10(total) / 5) * 100)))
}
