// 威胁大屏流量纯函数验收：
//   A. trafficDelta 首轮基线、normal/attack 双桶、真实间隔、
//      抽样还原计数不二次放大、计数器回退/抽样比变化、新增国家不尖峰
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { trafficDelta, formatRecentRate, hourlyBucketLabel, l4TrafficDelta, type TrafficBaseline } from '../src/utils/threatScreenMetrics.ts'

function baseline(counts: Record<string, { normal: number; attack?: number }>, at: number, sampleN = 1): TrafficBaseline {
  return {
    counts: new Map(Object.entries(counts).map(([name, v]) => [name, { normal: v.normal, attack: v.attack ?? 0 }])),
    at,
    sampleN,
  }
}

test('A1 首轮只建基线：不产生增量（原实现把进程累计值当首帧 delta）', () => {
  const first = trafficDelta(null, { 中国: { normal: 120000, attack: 30 }, 美国: { normal: 500 } }, 1000)
  assert.equal(first.baseline, true)
  assert.equal(first.normalTotal, 0)
  assert.equal(first.attackTotal, 0)
  assert.equal(first.normalQps, 0)
  assert.deepEqual(first.normalDeltas, [])
  assert.deepEqual(first.attackDeltas, [])
})

test('A2 正常增量按真实间隔折算 QPS（不再恒除 1.5s）', () => {
  const prev = baseline({ 中国: { normal: 100 }, 美国: { normal: 20 } }, 0)
  const at1_5s = trafficDelta(prev, { 中国: { normal: 400 }, 美国: { normal: 50 } }, 1500)
  assert.equal(at1_5s.baseline, false)
  assert.equal(at1_5s.normalTotal, 330)
  assert.equal(at1_5s.normalQps, 220)
  assert.deepEqual(at1_5s.normalDeltas, [{ name: '中国', count: 300 }, { name: '美国', count: 30 }])
  const at300s = trafficDelta(prev, { 中国: { normal: 400 }, 美国: { normal: 50 } }, 300_000)
  assert.equal(at300s.normalQps, 1.1)
})

test('A3 计数器回退：标记 reset 并重建基线，不静默丢负数', () => {
  const prev = baseline({ 中国: { normal: 900 } }, 0)
  const after = trafficDelta(prev, { 中国: { normal: 3 } }, 1500)
  assert.equal(after.reset, true)
  assert.equal(after.baseline, true)
  assert.equal(after.normalTotal, 0)
  assert.deepEqual(after.normalDeltas, [])
})

test('A3b attack 桶回退同样 reset', () => {
  // normal 继续增长、attack 计数器回退（Caddy 重载/租约重建）——必须断开曲线
  // 重建基线，不得把负增量当 0 静默吞掉（否则攻击速率会持续偏负/失真）。
  const prev = baseline({ 中国: { normal: 100, attack: 50 } }, 0)
  const after = trafficDelta(prev, { 中国: { normal: 160, attack: 2 } }, 1000)
  assert.equal(after.reset, true)
  assert.equal(after.baseline, true)
  assert.equal(after.normalTotal, 0, '回退轮不得落地任何半截增量')
  assert.equal(after.attackTotal, 0)
  assert.deepEqual(after.attackDeltas, [])
})

test('A3c 抽样比非法（0/负数/NaN）按 1 处理且不误触发基线重建', () => {
  // safeSample 分支此前无覆盖——sampleN=0 若参与比较会让
  // 每轮都「抽样比变化」→ 恒重置基线（大屏流量曲线永久空白）。
  for (const sampleN of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    const prev = baseline({ 中国: { normal: 100 } }, 0, 1)
    const next = trafficDelta(prev, { 中国: { normal: 120 } }, 1000, sampleN)
    assert.equal(next.sampleN, 1, `sampleN=${sampleN} 必须归一为 1`)
    assert.equal(next.reset, false, `sampleN=${sampleN} 不得触发重置`)
    assert.equal(next.baseline, false)
    assert.equal(next.normalTotal, 20)
  }
})

test('A4 新出现国家从 0 起步（首次请求必须计入慢速流量统计）', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 0)
  const next = trafficDelta(prev, { 中国: { normal: 110 }, 德国: { normal: 1 } }, 1000)
  assert.equal(next.normalTotal, 11)
  assert.deepEqual(next.normalDeltas, [{ name: '中国', count: 10 }, { name: '德国', count: 1 }])
})

test('A5 attack 桶独立差分（实时攻击速率不再被丢弃）', () => {
  const prev = baseline({ 中国: { normal: 100, attack: 10 }, 美国: { normal: 20, attack: 1 } }, 0)
  const next = trafficDelta(prev, { 中国: { normal: 160, attack: 18 }, 美国: { normal: 20, attack: 4 } }, 2000)
  assert.equal(next.normalTotal, 60)
  assert.equal(next.attackTotal, 11)
  assert.equal(next.normalQps, 30)
  assert.equal(next.attackQps, 5.5)
  assert.deepEqual(next.attackDeltas, [{ name: '中国', count: 8 }, { name: '美国', count: 3 }])
})

test('A6 抽样计数已是还原值时不得二次乘 sample_n', () => {
  // 生产端 1/N 抽样时每个请求按 N 累加：counter 增量 10 即真实 10 次。
  const prev = baseline({ 中国: { normal: 100 } }, 0, 8)
  const next = trafficDelta(prev, { 中国: { normal: 110 } }, 1000, 8)
  assert.equal(next.normalTotal, 10, '已还原计数不得再乘 8')
  assert.equal(next.normalQps, 10)
  assert.deepEqual(next.normalDeltas, [{ name: '中国', count: 10 }])
})

test('A7 抽样比变化必须重建基线，避免 1↔8 切换尖峰', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 0, 1)
  const next = trafficDelta(prev, { 中国: { normal: 110 } }, 1000, 8)
  assert.equal(next.baseline, true)
  assert.equal(next.reset, true)
  assert.equal(next.normalTotal, 0)
})

test('A8 无间隔（同一时刻重复采样）不除以零', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 500)
  const same = trafficDelta(prev, { 中国: { normal: 120 } }, 500)
  assert.equal(same.normalQps, 0)
})

test('A9 脏值按 0 处理（缺失/非数值不产生 NaN）', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 0)
  const dirty = trafficDelta(prev, { 中国: {} as { normal?: number; attack?: number } }, 1000)
  assert.equal(dirty.reset, true)
  assert.equal(Number.isNaN(dirty.normalQps), false)
  assert.equal(Number.isNaN(dirty.attackQps), false)
})

test('归一 counts 单源：调用方用返回 counts 建基线，脏值下一轮仍正常差分', () => {
  type Raw = { normal?: number; attack?: number }
  const first = trafficDelta(null, { 中国: {} as Raw, 美国: { normal: 7 } }, 0)
  assert.equal(first.baseline, true)
  // 归一结果必须对外可见：缺 normal/attack 的条目按 0 落库
  assert.deepEqual(first.counts.get('中国'), { normal: 0, attack: 0 })
  assert.deepEqual(first.counts.get('美国'), { normal: 7, attack: 0 })
  // 消费方原实现从原始响应重建基线（缺字段存 undefined）→ 下一轮 NaN 静默丢国
  const prev: TrafficBaseline = { counts: first.counts, at: 0, sampleN: first.sampleN }
  const next = trafficDelta(prev, { 中国: { normal: 30, attack: 2 }, 美国: { normal: 7 } }, 2000)
  assert.equal(next.baseline, false)
  assert.deepEqual(next.normalDeltas, [{ name: '中国', count: 30 }])
  assert.deepEqual(next.attackDeltas, [{ name: '中国', count: 2 }])
  assert.equal(next.normalTotal, 30)
  assert.equal(next.attackTotal, 2)
  assert.equal(Number.isNaN(next.normalQps), false)
})

test('C 拦截/分钟展示只还原一次 10 倍定点，不再放大', () => {
  assert.equal(formatRecentRate(12.3), '12.3')
  assert.equal(formatRecentRate(0), '0.0')
  assert.equal(formatRecentRate(-1), '0.0')
})

test('D 趋势桶 tooltip 原样展示真实槽标签（小时 HH:MM / 日 MM-DD）', () => {
  assert.equal(hourlyBucketLabel('13:34'), '13:34')
  assert.equal(hourlyBucketLabel('10-12'), '10-12')
  // 空标签不得改写后端真实格式
  assert.equal(hourlyBucketLabel(''), '')
})

// ---- E. TCP（L4）流量差分归一（后端已差分，前端只做消费面归一） ----

test('E1 l4 键缺省/空对象 = 无 l4 数据（旧后端与 admin 不可达降级无感）', () => {
  assert.deepEqual(l4TrafficDelta(undefined), { countryArcs: [], allowed: 0, denied: 0 })
  assert.deepEqual(l4TrafficDelta(null), { countryArcs: [], allowed: 0, denied: 0 })
  assert.deepEqual(l4TrafficDelta({}), { countryArcs: [], allowed: 0, denied: 0 })
  assert.deepEqual(l4TrafficDelta('bad'), { countryArcs: [], allowed: 0, denied: 0 })
})

test('E2 countries 并入正常弧通道（中文国家名，非法值按 0 丢弃），rules 全量差分聚合', () => {
  const r = l4TrafficDelta({
    rules: { 'lb-a': { allowed: 12, denied: 3 }, 'lb-b': { allowed: 5, denied: 2 }, bad: null },
    countries: { 中国: 30, 美国: 7, 俄罗斯: -1, 异常: 'x' },
    sampled: true,
  })
  // 负值（计数回退防线后的残影）与非数值丢弃；正差分保留顺序
  assert.deepEqual(r.countryArcs, [{ name: '中国', count: 30 }, { name: '美国', count: 7 }])
  assert.equal(r.allowed, 17)
  assert.equal(r.denied, 5)
})

test('E3 差分值不再二次差分：同一形状两次调用结果一致（无基线参与）', () => {
  const shape = { rules: { r: { allowed: 4, denied: 1 } }, countries: { 日本: 2 } }
  assert.deepEqual(l4TrafficDelta(shape), l4TrafficDelta(shape))
})
