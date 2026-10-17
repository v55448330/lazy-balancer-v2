// 威胁大屏流量/威胁指数纯函数验收（第 78 轮 L07-F07 / L07-F10）：
//   A. trafficDelta 首轮基线、正常增量、真实间隔、计数器回退、新增国家不尖峰
//   B. threatIndex 单调且 1/2/9/1000 有区分度、0 分不显示进度
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { trafficDelta, threatIndex, type TrafficBaseline } from '../src/utils/threatScreenMetrics.ts'

function baseline(counts: Record<string, number>, at: number): TrafficBaseline {
  return { counts: new Map(Object.entries(counts)), at }
}

test('A1 首轮只建基线：不产生增量（原实现把进程累计值当首帧 delta）', () => {
  const first = trafficDelta(null, { 中国: { normal: 120000 }, 美国: { normal: 500 } }, 1000)
  assert.equal(first.baseline, true)
  assert.equal(first.total, 0)
  assert.equal(first.qps, 0)
  assert.deepEqual(first.deltas, [])
})

test('A2 正常增量按真实间隔折算 QPS（不再恒除 1.5s）', () => {
  const prev = baseline({ 中国: 100, 美国: 20 }, 0)
  const at1_5s = trafficDelta(prev, { 中国: { normal: 400 }, 美国: { normal: 50 } }, 1500)
  assert.equal(at1_5s.baseline, false)
  assert.equal(at1_5s.total, 330)
  assert.equal(at1_5s.qps, 220) // 330 / 1.5s
  assert.deepEqual(at1_5s.deltas, [{ name: '中国', count: 300 }, { name: '美国', count: 30 }])
  // 同一批增量在 5 分钟间隔下 QPS 小得多（隐藏标签页恢复场景）
  const at300s = trafficDelta(prev, { 中国: { normal: 400 }, 美国: { normal: 50 } }, 300_000)
  assert.equal(at300s.qps, 1.1)
})

test('A3 计数器回退：标记 reset 并重建基线，不静默丢负数', () => {
  const prev = baseline({ 中国: 900 }, 0)
  const after = trafficDelta(prev, { 中国: { normal: 3 } }, 1500)
  assert.equal(after.reset, true)
  assert.equal(after.baseline, true)
  assert.equal(after.total, 0)
  assert.deepEqual(after.deltas, [])
})

test('A4 新出现国家不计差分（其累计值不是本间隔新增）', () => {
  const prev = baseline({ 中国: 100 }, 0)
  const next = trafficDelta(prev, { 中国: { normal: 110 }, 德国: { normal: 999 } }, 1000)
  assert.equal(next.total, 10)
  assert.deepEqual(next.deltas, [{ name: '中国', count: 10 }])
})

test('A5 无间隔（同一时刻重复采样）不除以零', () => {
  const prev = baseline({ 中国: 100 }, 500)
  const same = trafficDelta(prev, { 中国: { normal: 120 } }, 500)
  assert.equal(same.qps, 0)
})

test('A6 脏值按 0 处理（缺失/非数值不产生 NaN）', () => {
  const prev = baseline({ 中国: 100 }, 0)
  const dirty = trafficDelta(prev, { 中国: {} as { normal?: number } }, 1000)
  assert.equal(dirty.reset, true)
  assert.equal(Number.isNaN(dirty.qps), false)
})

test('B 威胁指数：0→0、有量下限 2、单调且 1/2/9/1000 可区分', () => {
  assert.equal(threatIndex(0), 0)
  assert.equal(threatIndex(-5), 0)
  const marks = [1, 2, 9, 100, 1000, 10000, 100000]
  const values = marks.map(threatIndex)
  for (let i = 1; i < values.length; i++) {
    assert.ok(values[i] > values[i - 1], `标尺非单调: ${marks[i - 1]}→${values[i - 1]} / ${marks[i]}→${values[i]}`)
  }
  assert.equal(threatIndex(1), 2, '有攻击不得显示 0（下限 2）')
  assert.ok(threatIndex(9) > threatIndex(2))
  assert.ok(threatIndex(1000) >= 55, '千次量级应进入中高分区')
  assert.equal(threatIndex(100000), 100)
  assert.equal(threatIndex(1_000_000), 100, '上限钳制 100')
})
