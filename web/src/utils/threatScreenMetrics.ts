// 威胁大屏展示指标纯函数
//   - trafficDelta：normal/attack 双桶计数器差分。首轮只建基线（原实现
//     prev=0 → 首帧 delta=进程累计值），QPS 按真实采样间隔计算。
//     计数已是**抽样还原后**的真值（caddygeoip 生产端在
//     1/N 抽样时按 N 累加），前端不得再乘 sample_n（旧实现二次放大，N=8 时
//     QPS/光流最高高估 8 倍）。sample_n 仅用于基线重建判定（抽样比切换时
//     计数口径改变，必须重置基线避免尖峰）。
export interface TrafficBaseline {
  readonly counts: ReadonlyMap<string, { normal: number; attack: number }>
  /** 采样时刻（与 now 同源）。 */
  readonly at: number
  /** 本基线对应的 Caddy 抽样比（>1 表示 1/N 抽样）。 */
  readonly sampleN: number
}

interface TrafficDeltaResult {
  /** 本轮只建立/重建基线（不产生流量增量）。 */
  readonly baseline: boolean
  /** 计数器回退或抽样比变化——曲线应断开并重建基线。 */
  readonly reset: boolean
  /** 本轮**归一后**的计数（缺失/非数值已按 0 处理）：调用方必须用它与
   *  `at`/`sampleN` 直接组装下一轮 `TrafficBaseline`，不得再从原始响应重建
   *  （原实现两侧各自归一，原始响应缺字段时基线存 undefined → 差分恒 NaN
   * 静默丢弃该国）。*/
  readonly counts: ReadonlyMap<string, { normal: number; attack: number }>
  readonly normalDeltas: { name: string; count: number }[]
  readonly attackDeltas: { name: string; count: number }[]
  readonly normalTotal: number
  readonly attackTotal: number
  /** 按真实采样间隔折算的每秒请求数（计数已由生产端抽样还原）。 */
  readonly normalQps: number
  readonly attackQps: number
  readonly sampleN: number
}

export function trafficDelta(
  prev: TrafficBaseline | null,
  countries: Record<string, { normal?: number; attack?: number }>,
  now: number,
  sampleN = 1,
): TrafficDeltaResult {
  const safeSample = Number.isFinite(sampleN) && sampleN >= 1 ? sampleN : 1
  const counts = new Map<string, { normal: number; attack: number }>()
  let reset = false
  let normalTotal = 0
  let attackTotal = 0
  const normalDeltas: { name: string; count: number }[] = []
  const attackDeltas: { name: string; count: number }[] = []
  for (const [name, entry] of Object.entries(countries)) {
    const normal = typeof entry?.normal === 'number' && Number.isFinite(entry.normal) ? entry.normal : 0
    const attack = typeof entry?.attack === 'number' && Number.isFinite(entry.attack) ? entry.attack : 0
    counts.set(name, { normal, attack })
    if (!prev) continue
    // 基线中不存在的新国家按 0 起步：计数器快照只包含非零国家，
    // 缺失即基线时刻尚无请求；其当前累计值就是本间隔新增。旧实现 continue
    // 会丢掉每个国家/地区首次出现的请求（慢速流量统计漏计）。
    const before = prev.counts.get(name) ?? { normal: 0, attack: 0 }
    const normalDelta = normal - before.normal
    const attackDelta = attack - before.attack
    if (normalDelta < 0 || attackDelta < 0) reset = true
    else {
      if (normalDelta > 0) {
        normalDeltas.push({ name, count: normalDelta })
        normalTotal += normalDelta
      }
      if (attackDelta > 0) {
        attackDeltas.push({ name, count: attackDelta })
        attackTotal += attackDelta
      }
    }
  }
  if (!prev) return { baseline: true, reset: false, counts, normalDeltas: [], attackDeltas: [], normalTotal: 0, attackTotal: 0, normalQps: 0, attackQps: 0, sampleN: safeSample }
  if (prev.sampleN !== safeSample) reset = true
  if (reset) return { baseline: true, reset: true, counts, normalDeltas: [], attackDeltas: [], normalTotal: 0, attackTotal: 0, normalQps: 0, attackQps: 0, sampleN: safeSample }
  const elapsedSec = (now - prev.at) / 1000
  const normalQps = elapsedSec > 0 ? normalTotal / elapsedSec : 0
  const attackQps = elapsedSec > 0 ? attackTotal / elapsedSec : 0
  return { baseline: false, reset: false, counts, normalDeltas, attackDeltas, normalTotal, attackTotal, normalQps, attackQps, sampleN: safeSample }
}

/** 拦截/分钟展示：后端已是一位小数，UI 用 ×10 整数动画后还原。 */
export function formatRecentRate(raw: number): string {
  if (!Number.isFinite(raw) || raw < 0) return '0.0'
  return (Math.round(raw * 10) / 10).toFixed(1)
}

/**
 * 趋势桶 tooltip：后端槽标签已是最终展示形态（≤24h 为真实 HH:MM，>24h 为
 * MM-DD），不再补 `:00`。非法/缺失标签回退空串。
 */
export function hourlyBucketLabel(name: string): string {
  return typeof name === 'string' ? name : ''
}

/**
 * 趋势桶粒度术语（与后端分桶口径对齐）：>24h 后端按「日」桶返回（标签 MM-DD），
 * 否则按「小时」桶。概览里的「峰值时段 / 有事件小时」必须跟着窗口换词，
 * 否则 7d 视图会把「有事件的天数」读成小时密度。
 */
export function bucketTerminology(windowHours: number): {
  readonly unit: '小时' | '天'
  readonly peakLabel: string
  readonly countLabel: string
  /** 窗口长度本身的展示词（`7 天` / `24 小时`）：页头、KPI、趋势标题共用，
   *  不得再写 `{{ windowHours }} 小时`——7d 视图会渲染成「168 小时」。 */
  readonly windowLabel: string
} {
  return windowHours > 24
    ? {
      unit: '天',
      peakLabel: '峰值日期',
      countLabel: '有事件天',
      windowLabel: `${Math.round(windowHours / 24)} 天`,
    }
    : { unit: '小时', peakLabel: '峰值时段', countLabel: '有事件小时', windowLabel: `${windowHours} 小时` }
}

/**
 * TCP（L4）流量差分的消费面归一（threat-screen traffic 响应 `l4` 键）。
 *
 * 后端（A1 契约）已在服务端完成差分——`rules`/`countries` 都是本次轮询的
 * **增量值**（admin /load 或计数器重置按重置后值计，不会出负数），前端不得
 * 再做第二次差分：
 *   - `countries`：放行连接按国家差分，键为中文国家名（与同响应 `countries`
 *     键完全同口径）——只并入正常弧通道（setTraffic），因 1/16 采样、未经还原，
 *     不入 QPS/累计线。
 *   - `rules`：逐规则 `allowed`/`denied` 全量差分——调用方聚合后放行并入正常
 *     QPS/累计、拒绝并入攻击 QPS/累计（攻击披露面）。
 *
 * 防御口径：`l4` 键缺省（旧后端/available=false）/空对象 → 全零结果，调用方
 * 无 l4 数据；非法形状逐字段容忍（非数值按 0），未知字段忽略。
 */
interface L4TrafficDelta {
  /** 正常弧通道条目（中文国家名 → 放行连接差分，采样口径仅作弧线可视化） */
  readonly countryArcs: { name: string; count: number }[]
  /** 全量差分合计：放行连接数（本次轮询增量） */
  readonly allowed: number
  /** 全量差分合计：拒绝（断连）连接数（本次轮询增量） */
  readonly denied: number
}

export function l4TrafficDelta(l4: unknown): L4TrafficDelta {
  if (typeof l4 !== 'object' || l4 === null) return { countryArcs: [], allowed: 0, denied: 0 }
  const shaped = l4 as { countries?: unknown; rules?: unknown }
  const countryArcs: { name: string; count: number }[] = []
  if (typeof shaped.countries === 'object' && shaped.countries !== null) {
    for (const [name, value] of Object.entries(shaped.countries as Record<string, unknown>)) {
      if (typeof name !== 'string' || name === '') continue
      const count = typeof value === 'number' && Number.isFinite(value) ? value : 0
      if (count > 0) countryArcs.push({ name, count })
    }
  }
  let allowed = 0
  let denied = 0
  if (typeof shaped.rules === 'object' && shaped.rules !== null) {
    for (const entry of Object.values(shaped.rules as Record<string, unknown>)) {
      if (typeof entry !== 'object' || entry === null) continue
      const a = (entry as { allowed?: unknown }).allowed
      const d = (entry as { denied?: unknown }).denied
      if (typeof a === 'number' && Number.isFinite(a) && a > 0) allowed += a
      if (typeof d === 'number' && Number.isFinite(d) && d > 0) denied += d
    }
  }
  return { countryArcs, allowed, denied }
}
