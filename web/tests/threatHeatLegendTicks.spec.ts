// 威胁大屏图例刻度动态化单源验收（heatLegendTicks）
//   A. 三档位置恒 0/50/100%，0 位显式 1（与原图例文案一致）
//   B. 刻度值与 heatIntensity 同一对数标尺：max=10200 中位≈100；max=50 中位≈6
//      （原写死 1/100/10k+ 只在万级数据集近似成立）
//   C. 大 max 数据集刻度右移：max=100 万时「100」按同一标尺落 ≈33%；
//      标签 <1000 直接数字、≥1000 用 k 缩写；空数据集回退历史静态三档
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { heatIntensity, heatLegendTicks } from '../src/utils/threatShared.ts'

test('A 三档位置恒 0/50/100%，0 位显式 1', () => {
  for (const maxHeat of [0, 1, 50, 10200, 1_000_000]) {
    const ticks = heatLegendTicks(maxHeat)
    assert.deepEqual(ticks.map((t) => t.pos), [0, 50, 100], `max=${maxHeat} 位置必须是 0/50/100`)
    assert.equal(ticks[0].label, '1', `max=${maxHeat} 首档显式 1`)
  }
})

test('B 刻度值随数据集 max 自适应（对数中位）', () => {
  // max=10200：中位 = 10^(½·log10(10201))−1 ≈ 100。
  assert.equal(heatLegendTicks(10200)[1].label, '100')
  // max=50：中位 ≈ 6——写死「100」在小火数据集严重错位。
  assert.equal(heatLegendTicks(50)[1].label, '6')
  // 顶档 = 数据集 max 本尊。
  assert.equal(heatLegendTicks(50)[2].label, '50')
})

test('C 大 max 刻度右移 + k 缩写标签 + 空集回退', () => {
  const ticks = heatLegendTicks(1_000_000)
  // 中位 = 10^(½·log10(1000001))−1 ≈ 999——「100」不再占据 50% 位。
  assert.equal(ticks[1].label, '999')
  // 「100」按同一标尺落 ≈33%：与 heatIntensity 同尺（写死刻度的错位实证）。
  assert.equal(Math.round(heatIntensity(100, 1_000_000) * 100), 33)
  // k 缩写：≥1000 除以 1000 后缀 k（一位小数按需），<1000 直接数字。
  assert.equal(heatLegendTicks(10200)[2].label, '10.2k')
  assert.equal(heatLegendTicks(1000)[2].label, '1k')
  assert.equal(heatLegendTicks(10000)[2].label, '10k')
  // 空数据集（max≤0）：回退历史静态三档，版面不塌缩。
  assert.deepEqual(heatLegendTicks(0).map((t) => t.label), ['1', '100', '10k+'])
})
