// 威胁大屏热力色阶感知重设计（v2.4.x 用户裁定「按建议处理」）：
//   A. 数量级可辨升级为 OKLab ΔE 下限——RGB 欧氏距离在暗浊带失真（旧测试盲区），
//      100/1k/10k 在大 max（10 万级）数据集下必须逐级可辨（用户实锤「几乎看不出差别」）
//   B. 低段压蓝：max=100k 数据集下 count=100 必须仍处蓝紫域（sRGB b>r），
//      不得过早进入暖色（「100 以下到以上过渡太快」的矫正语义）
//   C. 高段分离：count=1000 与数据集头部（10k/100k）颜色必须可辨
//   D. 颜色过渡动画器：数据刷新颜色 0.4s 内平滑收敛，首帧吸附、同数据幂等
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { heatCss, createHeatColorTransition } from '../src/utils/threatShared.ts'

// 独立 Oklab 实现（Björn Ottosson 标准公式）——不 import 产品代码，防同源假绿。
type Lab = { L: number; a: number; b: number }

function srgbToLinear(c: number): number {
  const v = c / 255
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
}

function parseCss(css: string): [number, number, number] {
  const m = css.match(/^rgb\((\d+),(\d+),(\d+)\)$/)
  assert.ok(m, `非法颜色 ${css}`)
  return [Number(m[1]), Number(m[2]), Number(m[3])]
}

function cssToOklab(css: string): Lab {
  const [r, g, b] = parseCss(css).map(srgbToLinear)
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
  return {
    L: 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    a: 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    b: 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  }
}

function deltaE(a: string, c: string): number {
  const A = cssToOklab(a)
  const B = cssToOklab(c)
  return Math.sqrt((A.L - B.L) ** 2 + (A.a - B.a) ** 2 + (A.b - B.b) ** 2)
}

test('A 数量级可辨（OKLab ΔE）：max=10k 数据集 1/10/100/1k/10k 逐级 ΔE≥0.05', () => {
  let prev = heatCss(1, 10000)
  for (const count of [10, 100, 1000, 10000]) {
    const cur = heatCss(count, 10000)
    const d = deltaE(prev, cur)
    assert.ok(d >= 0.05, `count=${count} 与上一数量级 OKLab ΔE=${d.toFixed(4)} < 0.05`)
    prev = cur
  }
})

test('A2 大 max 数据集（用户实锤 11 万级场景）：100/1k/10k/头部 逐级 ΔE≥0.05', () => {
  const max = 100000
  let prev = heatCss(100, max)
  for (const count of [1000, 10000, 100000]) {
    const cur = heatCss(count, max)
    const d = deltaE(prev, cur)
    assert.ok(d >= 0.05, `max=100k：count=${count} 与上一数量级 ΔE=${d.toFixed(4)} < 0.05`)
    prev = cur
  }
})

test('B 低段压蓝：max=100k 数据集 count=100 仍处蓝紫域（b>r，不得过早变暖）', () => {
  const [r, g, b] = parseCss(heatCss(100, 100000))
  assert.ok(b > r, `count=100 应为蓝紫域（rgb(${r},${g},${b}) b 必须 > r）`)
})

test('C 高段分离：1k 命中与数据集头部（max=10k）ΔE≥0.05（旧阶梯四档同红的矫正）', () => {
  const d = deltaE(heatCss(1000, 10000), heatCss(10000, 10000))
  assert.ok(d >= 0.05, `1k vs 头部 ΔE=${d.toFixed(4)} < 0.05`)
})

test('C2 近 max 对可辨：0.4 倍 max 与头部 ΔE≥0.05（用户实锤 7000 vs 17000 形态）', () => {
  for (const max of [1000, 17000, 100000]) {
    const d = deltaE(heatCss(Math.floor(max * 0.4), max), heatCss(max, max))
    assert.ok(d >= 0.05, `max=${max}：0.4 倍头部与头部 ΔE=${d.toFixed(4)} < 0.05`)
  }
})

test('D 过渡动画器：首帧吸附、变更后渐进收敛≤600ms、无变化幂等', () => {
  const tr = createHeatColorTransition()
  const a = new Map([['中国', 'rgb(44,66,96)'], ['美国', 'rgb(60,80,130)']])
  tr.setTargets(a)
  tr.advance(0)
  assert.equal(tr.cssFor('中国', 'rgb(1,2,3)'), 'rgb(44,66,96)'), '首帧必须吸附目标色（无渐入残影）'
  assert.equal(tr.cssFor('未知', 'rgb(9,9,9)'), 'rgb(9,9,9)'), '未定向的键回退 fallback'
  // 变更 → 不立即跳变，渐进收敛
  const b = new Map([['中国', 'rgb(230,70,70)'], ['美国', 'rgb(120,80,180)']])
  tr.setTargets(b)
  assert.equal(tr.cssFor('中国', ''), 'rgb(44,66,96)', '变更瞬间保持旧色（动画起点）')
  let total = 0
  let changed = true
  let last = ''
  while (changed && total < 1000) {
    changed = tr.advance(16)
    total += 16
    last = tr.cssFor('中国', '')
  }
  assert.equal(last, 'rgb(230,70,70)', '收敛终值=目标色')
  assert.ok(total <= 600, `收敛耗时 ${total}ms 必须 ≤600ms`)
  // 同数据幂等：advance 不再报变化
  assert.equal(tr.advance(16), false, '收敛后 advance 恒 false（引擎不再重绘）')
})
