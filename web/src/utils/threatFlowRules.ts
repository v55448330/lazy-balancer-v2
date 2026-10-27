// 威胁大屏光流/弹框聚合单源（纯函数，node:test 可覆盖）。
// 口径：攻击类型不区分，只按地域；中国精确到省；同一地区同一秒为一桶。
import { FLOW_AGGREGATE_THRESHOLD, type FlowArcTier } from './threatTheme.ts'
import { parseDbDateMs } from './timeZoneFormat.ts'

// DB 墙钟 → epoch 的规范化/解析内核在 timeZoneFormat（与 date.ts 同源）；
// 本函数只把「解析失败」映射为 NaN（大屏按无效时间丢弃该事件，不抛）。
// 无白名单：威胁事件时间戳只可能是 DB 墙钟或 RFC3339，不做「人读文本」区分。
/** DB datetime 无时区时按 UTC 解析（与 utils/date.ts 同一内核，失败为 NaN）。 */
export function flowTimestamp(value: string): number {
  if (!value) return NaN
  return parseDbDateMs(value) ?? NaN
}

/** 增量批次动效（流光/弹框）的实时性上限：入库延迟/轮转回填会把
 *  数小时前的事件塞进增量批次，直接绘制会表现为「正在发生」。列表仍按窗口展示。 */
const FLOW_REALTIME_MAX_AGE_MS = 5 * 60_000

/** 只保留可作为“正在发生”展示的事件；未来时钟偏差沿用既有攻击流口径放行。 */
export function freshFlowEvents<T extends { at?: number }>(events: readonly T[], now: number): T[] {
  return events.filter((event) => typeof event.at === 'number'
    && Number.isFinite(event.at)
    && now - event.at <= FLOW_REALTIME_MAX_AGE_MS)
}

/**
 * 后端采样契约：-1=自适应、0=关闭逐请求光流。全量档已退役（自适应本身从
 * 1/1 起步，低流量等价全量）；存量/外来 1 与固定 2-64 一律归一为自适应。
 */
export function normalizeTrafficSampleN(value: number | null | undefined): number {
  return value === 0 ? 0 : -1
}

/** 序号回退或采集关闭表示租约/事件缓冲区已重置；下轮必须从 0 重新追赶。 */
export function nextFlowCursor(previous: number, data: { enabled?: boolean; next_seq?: number }): number {
  if (!data.enabled) return 0
  if (typeof data.next_seq === 'number' && data.next_seq < previous) return 0
  return typeof data.next_seq === 'number' ? data.next_seq : previous
}

/** 自适应档位取值集合（1/4/8）曾是零消费导出常量，移除；
 *  档位语义由 nextAdaptiveSampleN/stepAdaptiveSample 承载。 */

/**
 * 自适应切换阈值（事件/秒，用服务端 sample_n 还原后的真实速率）：
 * 1→4 高于 180、4→1 低于 120；4→8 高于 720、8→4 低于 480。
 * 上下阈值留滞回带，避免在边界附近来回抖动。
 */
const ADAPTIVE_SAMPLE_THRESHOLDS = {
  upTo4: 180,
  downTo1: 120,
  upTo8: 720,
  downTo4: 480,
} as const

/** 连续多少次采样同向才允许换档（配合 1s 轮询）。 */
const ADAPTIVE_SAMPLE_CONFIRM_SAMPLES = 2
/** 两次换档之间的最小间隔（毫秒）。 */
const ADAPTIVE_SAMPLE_MIN_SWITCH_INTERVAL_MS = 4000

/** 用服务端回报的采样因子还原真实事件速率（events 已被按 sample_n 缩小）。 */
export function reconstructObservedRate(eventCount: number, sampleN: number, fallbackSampleN = 1): number {
  const factor = sampleN > 0 ? sampleN : fallbackSampleN > 0 ? fallbackSampleN : 1
  return eventCount * factor
}

/** 自适应目标档位（含滞回带）：仅返回 1/4/8。 */
function nextAdaptiveSampleN(current: number, observedRate: number): number {
  if (current === 8) return observedRate < ADAPTIVE_SAMPLE_THRESHOLDS.downTo4 ? 4 : 8
  if (current === 4) {
    if (observedRate > ADAPTIVE_SAMPLE_THRESHOLDS.upTo8) return 8
    if (observedRate < ADAPTIVE_SAMPLE_THRESHOLDS.downTo1) return 1
    return 4
  }
  return observedRate > ADAPTIVE_SAMPLE_THRESHOLDS.upTo4 ? 4 : 1
}

interface AdaptiveSampleState {
  /** 当前生效档位（1/4/8） */
  active: number
  /** 已连续确认的**同一目标**采样次数 */
  stable: number
  /** 上次换档时刻（ms；0=尚未换过档） */
  lastSwitch: number
  /** 正在累计确认的目标档位（0=尚未累计）。目标变化即视为方向反转，计数重来。 */
  pendingTarget?: number
}

interface AdaptiveSampleOutcome extends AdaptiveSampleState {
  changed: boolean
}

/**
 * 自适应采样单步状态机：连续 2 次采样**同向**且距上次换档 ≥4s 才换档。
 * 同向=两次采样算出的目标档位一致（`pendingTarget`）；目标改变（含高→低反转）
 * 时确认计数从 1 重新累计——只按次数累加会把「突发一次+骤停一次」误判为
 * 连续确认。目标与当前一致时清空确认计数（但保留上次换档时刻——
 * 回摆同样受 4s 门约束）。
 */
export function stepAdaptiveSample(state: AdaptiveSampleState, observedRate: number, now: number): AdaptiveSampleOutcome {
  if (state.active !== 1 && state.active !== 4 && state.active !== 8) {
    return { ...state, changed: false }
  }
  const target = nextAdaptiveSampleN(state.active, observedRate)
  if (target === state.active) {
    return { active: state.active, stable: 0, pendingTarget: 0, lastSwitch: state.lastSwitch, changed: false }
  }
  const stable = state.pendingTarget === target ? state.stable + 1 : 1
  if (stable >= ADAPTIVE_SAMPLE_CONFIRM_SAMPLES && now - state.lastSwitch >= ADAPTIVE_SAMPLE_MIN_SWITCH_INTERVAL_MS) {
    return { active: target, stable: 0, pendingTarget: 0, lastSwitch: now, changed: true }
  }
  return { active: state.active, stable, pendingTarget: target, lastSwitch: state.lastSwitch, changed: false }
}

/** 单轮最多新增光流数；正常流与攻击流共用同一预算（模块内默认值）。 */
const FLOW_MAX_ARCS_PER_FLUSH = 12

interface FlowArcPlan {
  /** 分组键（地区|时间桶）。 */
  key: string
  /** 光流起点地区（中国精确到省；洪峰坍缩为国家）。 */
  region: string
  /** 弧线 weight（采样还原量级），只用于 ×N/强度，不参与聚合判断。 */
  weight: number
  /** 显式线宽档位：thin=逐条、coarse=4-8 合并、dense=>8 合并。 */
  tier: FlowArcTier
}

interface FlowArcGroupLike {
  /** 聚合地域 key（地区+时间桶）。 */
  key: string
  /** 光流起点地区。 */
  region?: string
  /** 采样后事件条数；是否聚合只用它判断，不用 weight。 */
  count: number
  /** 还原量级（count × sample_n / sum(weight)）。 */
  weight?: number
}

/**
 * 正常/攻击共用出弧计划：
 * - 1-3 条（采样后）逐条出弧（thin）；
 * - 4-8 条合并为一条粗光流（coarse）；
 * - >8 条合并为一条更粗光流（dense）；
 * - weight 不参与是否聚合，避免 1/8 采样下 1 条事件被误判成 8 条。
 */
export function planFlowArcs(
  groups: readonly FlowArcGroupLike[],
  maxArcs = FLOW_MAX_ARCS_PER_FLUSH,
): FlowArcPlan[] {
  const ordered = [...groups].sort((a, b) => (b.weight ?? b.count) - (a.weight ?? a.count) || a.key.localeCompare(b.key))
  const plan: FlowArcPlan[] = []
  let budget = Math.max(0, maxArcs)
  for (const group of ordered) {
    if (budget <= 0) break
    const count = Math.max(0, Math.floor(group.count))
    const weight = group.weight ?? group.count
    if (count <= 0 || weight <= 0) continue
    const region = group.region ?? group.key.split('|')[0]
    if (count > FLOW_AGGREGATE_THRESHOLD) {
      plan.push({ key: group.key, region, weight, tier: count > 8 ? 'dense' : 'coarse' })
      budget--
      continue
    }
    const n = Math.min(count, budget)
    const per = weight / count
    for (let i = 0; i < n; i++) plan.push({ key: group.key, region, weight: per, tier: 'thin' })
    budget -= n
  }
  return plan
}

interface FlowEventPlanInput {
  country?: string
  province?: string
  at?: number
  weight?: number
}

const FLOW_BUCKET_MS_LEVELS = [1000, 2000, 5000] as const

function flowEventRegion(ev: FlowEventPlanInput): string {
  const country = ev.country || ''
  if (!country) return ''
  return ev.province ? `${country}·${ev.province}` : country
}

function groupFlowEventsForPlan(
  events: readonly FlowEventPlanInput[],
  bucketMs: number,
  collapseCountry: boolean,
  now: number,
): FlowArcGroupLike[] {
  const groups = new Map<string, { key: string; region: string; count: number; weight: number }>()
  for (const event of events) {
    const rawRegion = flowEventRegion(event)
    if (!rawRegion) continue
    const region = collapseCountry ? (rawRegion.split('·')[0] || '未知') : rawRegion
    const at = typeof event.at === 'number' && Number.isFinite(event.at) && event.at > 0 ? event.at : now
    const bucket = Math.floor(at / bucketMs)
    const key = `${region}|${bucket}`
    const weight = Number.isFinite(event.weight) && (event.weight ?? 0) > 0 ? Number(event.weight) : 1
    const cur = groups.get(key)
    if (cur) {
      cur.count += 1
      cur.weight += weight
    } else {
      groups.set(key, { key, region, count: 1, weight })
    }
  }
  return [...groups.values()]
}

function flowGroupArcCost(group: FlowArcGroupLike): number {
  return group.count > FLOW_AGGREGATE_THRESHOLD ? 1 : Math.max(0, Math.floor(group.count))
}

/**
 * 超预算时扩大时间桶而不是直接丢组：1s→2s→5s；最终仍超预算才按权重取前
 * maxArcs（极端多地区场景仍需有界）。
 */
export function planFlowEvents(
  events: readonly FlowEventPlanInput[],
  now = Date.now(),
  maxArcs = FLOW_MAX_ARCS_PER_FLUSH,
): FlowArcPlan[] {
  if (events.length === 0) return []
  for (const bucketMs of FLOW_BUCKET_MS_LEVELS) {
    const groups = groupFlowEventsForPlan(events, bucketMs, false, now)
    const cost = groups.reduce((sum, g) => sum + flowGroupArcCost(g), 0)
    if (cost <= maxArcs) return planFlowArcs(groups, maxArcs)
  }
  // 5s 桶仍超预算：把中国各省坍缩为国家，且强制每个组至少聚合一条
  //（不再展开 1-3 条逐条），仍超出容量上限才取权重最高组。
  const groups = groupFlowEventsForPlan(events, FLOW_BUCKET_MS_LEVELS[FLOW_BUCKET_MS_LEVELS.length - 1], true, now)
  const forced = groups.map((g) => ({ ...g, count: Math.max(FLOW_AGGREGATE_THRESHOLD + 1, g.count) }))
  return planFlowArcs(forced, maxArcs)
}
