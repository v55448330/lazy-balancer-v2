import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { source } from './_helpers.ts'

test('省界资源头注释与实际要素和国家地区键数一致（文档钉）', () => {
  const countries = Object.keys(ADMIN1_PROVINCES).length
  const mergedRows = Object.values(ADMIN1_PROVINCES).reduce((total, rows) => total + rows.length, 0)
  // 运行时口径=加载期别名归一（COUNTRY_ALIAS 新增目标键）+ 同国同名省合并之后。
  assert.equal(countries, 251)
  // 4600 要素 → 别名归一 4575 条省记录；数字变化必须同步文件头。
  assert.equal(mergedRows, 4575)

  // 源表字面量口径：国家地区键与省记录条数（合并前）。两个口径都要与文件头
  // 吻合，否则注释里的「源表 N 键 / M 条」会随数据集更新悄悄失真。
  const raw = source('src/utils/admin1Provinces.ts')
  assert.equal(raw.match(/^ {2}"/gm)?.length, 240, '源表国家地区键数与注释不符')
  assert.equal(raw.match(/\{ name: "/g)?.length, 4287, '源表省记录条数与注释不符')

  const header = raw.split('\n').slice(0, 12).join('\n')
  assert.match(header, /源表 240 个国家地区键 \/ 4,287 条省记录/)
  assert.match(header, /加载期别名归一后为 251 键 \/ 4,575 条/)
  assert.match(header, /含特殊地区/)
  // 表内没有中国键：消费方以 country === '中国' 特判走 chinaProvinces 高精度表。
  assert.doesNotMatch(header, /本表 China\/中国 条目/)
  assert.equal(ADMIN1_PROVINCES['中国'], undefined)
  assert.equal(ADMIN1_PROVINCES['China'], undefined)
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
