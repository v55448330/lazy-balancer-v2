import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { source } from './_helpers.ts'

test('省界资源头注释与实际要素和国家地区键数一致', () => {
  const countries = Object.keys(ADMIN1_PROVINCES).length
  const mergedRows = Object.values(ADMIN1_PROVINCES).reduce((total, rows) => total + rows.length, 0)
  assert.equal(countries, 251)
  // 加载期把同国同名要素合并为一条省记录（详见文件末尾合并段）：4600 要素
  // → 4575 条；数字变化必须同步文件头，否则说明合并段被删或失效。
  assert.equal(mergedRows, 4575)
  const header = source('src/utils/admin1Provinces.ts').split('\n').slice(0, 7).join('\n')
  assert.match(header, /4600 要素\/251 个国家和地区键/)
  assert.match(header, /含特殊地区/)
  assert.match(header, /4600 → 4575/)
})

test('每个国家内省名唯一（同名要素已合并，悬浮/聚合键不再二义）', () => {
  const duplicated: string[] = []
  for (const [country, rows] of Object.entries(ADMIN1_PROVINCES)) {
    const seen = new Set<string>()
    for (const row of rows) {
      if (seen.has(row.name)) duplicated.push(`${country} · ${row.name}`)
      seen.add(row.name)
    }
  }
  assert.deepEqual(duplicated, [], `同国同名省未合并：${duplicated.slice(0, 5).join('；')}`)
})

test('合并不得丢几何：多边形与坐标点总数与原始要素一致', () => {
  const polygons = Object.values(ADMIN1_PROVINCES).reduce(
    (total, rows) => total + rows.reduce((n, row) => n + row.polys.length, 0),
    0,
  )
  const points = Object.values(ADMIN1_PROVINCES).reduce(
    (total, rows) => total + rows.reduce((n, row) => n + row.polys.reduce((m, poly) => m + poly.length, 0), 0),
    0,
  )
  // 24 组同名要素组内多边形互不重复：合并后的总量必须与合并前完全相同
  //（7291 个多边形 / 7382 个坐标点），否则说明合并把不同区域吞掉了。
  assert.equal(polygons, 7291)
  assert.equal(points, 7382)
})
