// 光流聚合规则纯函数测试（node --test）：地域 key、秒桶、阈值、弹框/光流共用分组。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  flowTimestamp,
  nextFlowCursor,
  planFlowArcs,
  freshFlowEvents,
  planFlowEvents,
  reconstructObservedRate,
  stepAdaptiveSample,
  normalizeTrafficSampleN,
} from '../src/utils/threatFlowRules.ts'
import { flowArcTierWidth } from '../src/utils/threatTheme.ts'
import { code, section } from './_helpers.ts'

test('流量采样配置：仅保留 -1/0，全量与固定 2-64 归一为自适应', () => {
  assert.equal(normalizeTrafficSampleN(-1), -1)
  assert.equal(normalizeTrafficSampleN(0), 0)
  for (const value of [1, 2, 4, 8, 64, -2, 65, 1.5, Number.NaN, undefined, null]) {
    assert.equal(normalizeTrafficSampleN(value), -1, `值 ${String(value)} 必须归一为自适应`)
  }
})

test('自适应档位滞回阈值：1↔4 用 180/120，4↔8 用 720/480（边界值不切换）', () => {
  // 档位选择是模块内部实现：经状态机两次同向确认（4s 门已过）观察换档结果。
  const switched = (active: number, observedRate: number): number => {
    const first = stepAdaptiveSample({ active, stable: 0, lastSwitch: 0 }, observedRate, 100_000)
    return stepAdaptiveSample(first, observedRate, 101_000).active
  }
  // 1 → 4：高于 180 才升档
  assert.equal(switched(1, 180), 1)
  assert.equal(switched(1, 181), 4)
  // 4 → 1：低于 120 才降档
  assert.equal(switched(4, 120), 4)
  assert.equal(switched(4, 119), 1)
  // 4 → 8：高于 720 才升档
  assert.equal(switched(4, 720), 4)
  assert.equal(switched(4, 721), 8)
  // 8 → 4：低于 480 才降档
  assert.equal(switched(8, 480), 8)
  assert.equal(switched(8, 479), 4)
  // 8 不再升档（最高档即 1/8）
  assert.equal(switched(8, 1e9), 8)
})

test('自适应切换：连续 2 次采样同向才换档，单次尖峰不生效', () => {
  let state = { active: 1, stable: 0, lastSwitch: 0 }
  let outcome = stepAdaptiveSample(state, 500, 10_000)
  assert.deepEqual(outcome, { active: 1, stable: 1, pendingTarget: 4, lastSwitch: 0, changed: false })
  // 第二次同向 → 换到 1/4
  outcome = stepAdaptiveSample(outcome, 500, 11_000)
  assert.deepEqual(outcome, { active: 4, stable: 0, pendingTarget: 0, lastSwitch: 11_000, changed: true })
  // 单次低速后回到中间带：确认计数清零，不降档
  state = { active: 4, stable: 1, lastSwitch: 0 }
  outcome = stepAdaptiveSample(state, 200, 12_000)
  assert.deepEqual(outcome, { active: 4, stable: 0, pendingTarget: 0, lastSwitch: 0, changed: false })
})

test('自适应切换：两次换档间隔必须 ≥4000ms（回摆同样受限）', () => {
  const lastSwitch = 20_000
  // 距上次换档不足 4s：即使连续确认也不换
  let outcome = stepAdaptiveSample({ active: 4, stable: 0, lastSwitch }, 900, lastSwitch + 1000)
  assert.equal(outcome.changed, false)
  assert.equal(outcome.stable, 1)
  outcome = stepAdaptiveSample(outcome, 900, lastSwitch + 2000)
  assert.equal(outcome.changed, false, '间隔 2s 未达 4s 门')
  assert.equal(outcome.stable, 2, '连续两次同向确认')
  const almost = stepAdaptiveSample(outcome, 900, lastSwitch + 3999)
  assert.equal(almost.changed, false, '间隔 3999ms 仍不足')
  assert.equal(almost.active, 4)
  // 达到 4s 门 → 允许换到 1/8
  const switched = stepAdaptiveSample(almost, 900, lastSwitch + 4000)
  assert.deepEqual(switched, { active: 8, stable: 0, pendingTarget: 0, lastSwitch: lastSwitch + 4000, changed: true })
})

test('自适应切换：档位与目标一致时清空确认计数但保留上次换档时刻', () => {
  const matched = stepAdaptiveSample({ active: 8, stable: 1, lastSwitch: 30_000 }, 900, 31_000)
  assert.deepEqual(matched, { active: 8, stable: 0, pendingTarget: 0, lastSwitch: 30_000, changed: false })
  // 之后转低速：需重新累计 2 次确认且跨过 4s 门
  const first = stepAdaptiveSample(matched, 100, 32_000)
  assert.deepEqual(first, { active: 8, stable: 1, pendingTarget: 4, lastSwitch: 30_000, changed: false })
  const second = stepAdaptiveSample(first, 100, 33_000)
  assert.deepEqual(second, { active: 8, stable: 2, pendingTarget: 4, lastSwitch: 30_000, changed: false }, '间隔不足 4s')
  const third = stepAdaptiveSample(second, 100, 34_000)
  assert.deepEqual(third, { active: 4, stable: 0, pendingTarget: 0, lastSwitch: 34_000, changed: true })
})

test('自适应切换：方向反转不累计（突发+骤停不得直接跳档）', () => {
  // 高流量一次 → 目标 8；随后骤停一次 → 目标 1。旧实现只按次数累加，
  // 在 4s 门已过时会把这两次相反采样当作「连续 2 次同向」直接切到 1/1。
  let outcome = stepAdaptiveSample({ active: 4, stable: 0, lastSwitch: 0 }, 900, 10_000)
  assert.deepEqual(outcome, { active: 4, stable: 1, pendingTarget: 8, lastSwitch: 0, changed: false })
  outcome = stepAdaptiveSample(outcome, 100, 11_000)
  assert.equal(outcome.changed, false, '方向反转不得换档')
  assert.equal(outcome.active, 4)
  assert.equal(outcome.stable, 1, '确认计数必须从 1 重新累计')
  assert.equal(outcome.pendingTarget, 1)
  // 第二次同向（低）→ 才允许降档
  const confirmed = stepAdaptiveSample(outcome, 100, 12_000)
  assert.deepEqual(confirmed, { active: 1, stable: 0, pendingTarget: 0, lastSwitch: 12_000, changed: true })
})

test('自适应切换：非自适应档位（0=关闭）不参与换档', () => {
  const outcome = stepAdaptiveSample({ active: 0, stable: 0, lastSwitch: 0 }, 10_000, 1_000)
  assert.deepEqual(outcome, { active: 0, stable: 0, lastSwitch: 0, changed: false })
})

test('速率还原：events.length × 服务端 sample_n，sample_n 缺失时回退当前档位', () => {
  assert.equal(reconstructObservedRate(125, 8), 1000, '1/8 档 125 条 = 真实 1000 条/秒')
  assert.equal(reconstructObservedRate(125, 8, 1), 1000)
  assert.equal(reconstructObservedRate(100, 0, 4), 400, '服务端未回报时用当前档位还原')
  assert.equal(reconstructObservedRate(0, 0, 0), 0)
})

test('时间解析：无时区 DB 时间按 UTC，与 date.ts 同一内核（四形态 + 失败为 NaN）', () => {
  assert.equal(flowTimestamp('2026-10-18 00:00:00'), Date.parse('2026-10-18T00:00:00Z'))
  // 带 Z / 带偏移：直接对绝对时刻，不与被委托内核自比
  assert.equal(flowTimestamp('2026-10-18T00:00:00Z'), Date.UTC(2026, 9, 18))
  assert.equal(flowTimestamp('2026-10-18T08:00:00+08:00'), Date.UTC(2026, 9, 18))
  // 大屏对无效时间只丢弃（NaN），不抛
  assert.ok(Number.isNaN(flowTimestamp('not-a-date')))
  assert.ok(Number.isNaN(flowTimestamp('')))
})

test('采集租约重置后游标回零，正常递增与缺失值保持', () => {
  assert.equal(nextFlowCursor(500, { enabled: true, next_seq: 4 }), 0)
  assert.equal(nextFlowCursor(500, { enabled: false, next_seq: 501 }), 0)
  assert.equal(nextFlowCursor(500, { enabled: true, next_seq: 501 }), 501)
  assert.equal(nextFlowCursor(500, { enabled: true, next_seq: 500 }), 500)
  assert.equal(nextFlowCursor(500, { enabled: true }), 500)
})

test('首载与恢复可见批次：正常/攻击光流都只消费五分钟内的有限时间戳事件', () => {
  const now = Date.UTC(2026, 9, 27, 12)
  const events = [
    { id: 'old', country: '中国', province: '浙江', at: now - 6 * 60_000, weight: 8 },
    { id: 'current', country: '中国', province: '上海', at: now - 1000, weight: 8 },
    { id: 'boundary', country: '美国', at: now - 5 * 60_000, weight: 4 },
    { id: 'future', country: '日本', at: now + 1000, weight: 2 },
    { id: 'nan', country: '英国', at: Number.NaN, weight: 1 },
    { id: 'infinite', country: '法国', at: Number.POSITIVE_INFINITY, weight: 1 },
    { id: 'missing', country: '德国', weight: 1 },
  ]
  assert.deepEqual(freshFlowEvents(events, now).map((event) => event.id), ['current', 'boundary', 'future'])
  assert.deepEqual(freshFlowEvents([], now), [])

  const screen = code('src/views/security/ThreatScreen.vue')
  const attack = section(screen, 'const attackFlowTask = usePollingTask', 'const statsTask = usePollingTask')
  const normal = section(screen, 'const flowTask = usePollingTask', 'async function mountEngine')
  assert.match(attack, /freshFlowEvents\(data\.events \?\? \[\], now\)/, '攻击流必须继续消费同一新鲜度门')
  assert.match(normal, /freshFlowEvents\(events, now\)/, '正常流首载/恢复可见共用的轮询必须先过滤陈旧事件')
  assert.ok(normal.indexOf('flowSince = nextFlowCursor(flowSince, data)') > normal.indexOf('freshFlowEvents(events, now)'), '过滤陈旧事件后仍须推进游标')
})

test('实时事件窗口与站点坐标边界：脏时间丢弃，(0,0) 是合法配置', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  const feed = section(screen, 'const windowFeed = computed', 'const sevFilter')
  assert.match(feed, /Number\.isFinite\(t\) && t >= cutoff/, '解析失败的事件不得永久留在窗口')
  assert.doesNotMatch(feed, /!Number\.isFinite\(t\) \|\| t >= cutoff/)
  const load = section(screen, 'async function loadServerCentroid', 'async function retryConfigLoad')
  assert.match(load, /server_map_lat !== undefined|typeof res\.data\?\.server_map_lat === 'number'/, '站点是否配置必须看字段存在性')
  assert.doesNotMatch(load, /serverLatLon\[0\] !== 0 \|\| serverLatLon\[1\] !== 0/, '(0,0) 不得被当成未配置')
})


test('正常/攻击共用显式线宽：thin 1.2、coarse 2.8、dense 4.2', () => {
  assert.equal(flowArcTierWidth('thin'), 1.2)
  assert.equal(flowArcTierWidth('coarse'), 2.8)
  assert.equal(flowArcTierWidth('dense'), 4.2)
  assert.ok(flowArcTierWidth('thin') < flowArcTierWidth('coarse'))
  assert.ok(flowArcTierWidth('coarse') < flowArcTierWidth('dense'))
})

test('正常/攻击共用出弧计划：1-3 逐条细、4-8 合并中粗、>8 合并最粗，单轮预算一致', () => {
  const plan = planFlowArcs([
    { key: 'a|1', region: 'a', count: 20, weight: 160 },
    { key: 'b|1', region: 'b', count: 5, weight: 40 },
    { key: 'c|1', region: 'c', count: 3, weight: 3 },
  ], 4)
  assert.equal(plan.length, 4)
  assert.deepEqual(plan[0], { key: 'a|1', region: 'a', weight: 160, tier: 'dense' })
  assert.deepEqual(plan[1], { key: 'b|1', region: 'b', weight: 40, tier: 'coarse' })
  assert.deepEqual(plan.slice(2), [
    { key: 'c|1', region: 'c', weight: 1, tier: 'thin' },
    { key: 'c|1', region: 'c', weight: 1, tier: 'thin' },
  ])
  const small = planFlowArcs([{ key: 'd|1', region: 'd', count: 3, weight: 3 }], 3)
  assert.deepEqual(small, [
    { key: 'd|1', region: 'd', weight: 1, tier: 'thin' },
    { key: 'd|1', region: 'd', weight: 1, tier: 'thin' },
    { key: 'd|1', region: 'd', weight: 1, tier: 'thin' },
  ])
  // 默认单轮预算（不传 maxArcs）=12 条：20 个独立组只出 12 条
  const many = Array.from({ length: 20 }, (_, i) => ({ key: `${i}|1`, region: `r${i}`, count: 1 }))
  assert.equal(planFlowArcs(many).length, 12, '默认单轮出弧预算必须为 12')
})

test('出弧预算超限时扩大时间桶而不是直接丢组', () => {
  const at = 1792281600000
  // 13 个地区各 1 条：1s 桶预算 12 放不下；2s 桶内每组仍 1 条，仍超出。
  // 5s 桶仍超预算时，坍缩为中国国家级并强制聚合，最高权重组必须保留。
  const events = Array.from({ length: 13 }, (_, i) => ({
    country: '中国',
    province: `省${i}`,
    at,
    weight: 1,
  }))
  const plan = planFlowEvents(events, at + 100, 12)
  assert.equal(plan.length, 1, '13 个省级洪峰最终坍缩为一条中国级聚合弧')
  assert.deepEqual(plan[0], { key: '中国|358456320', region: '中国', weight: 13, tier: 'dense' })
})
