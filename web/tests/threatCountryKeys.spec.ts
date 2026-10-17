// 威胁大屏国家键集单源验收（第 78 轮 U15-F02/U15-F12）：
//   A. THREAT_COUNTRIES 排除南极洲（地图/地球两引擎同表）
//   B. 每个威胁国家（中国走 chinaProvinces 高精度表）在 ADMIN1_PROVINCES 命中
//      ——全量键集断言，非抽查（原 11 个英文/旧名分组只能靠人工发现）
//   C. COUNTRY_ALIAS 名字面量与目标键逐一有效（防别名表自身漂移）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { WORLD_COUNTRIES, THREAT_COUNTRIES } from '../src/utils/worldBorders.ts'
import { ADMIN1_PROVINCES, COUNTRY_ALIAS } from '../src/utils/admin1Provinces.ts'
import { CHINA_PROVINCES } from '../src/utils/chinaProvinces.ts'

test('A 威胁国家表：排除南极洲且其余国家与 worldBorders 一致', () => {
  assert.equal(WORLD_COUNTRIES.length - THREAT_COUNTRIES.length, 1)
  assert.ok(!THREAT_COUNTRIES.some((c) => c.name === 'Antarctica'), '南极洲必须从威胁国家表剔除')
  assert.notEqual(THREAT_COUNTRIES as unknown, WORLD_COUNTRIES as unknown, '必须是过滤后的独立数组')
  for (const c of THREAT_COUNTRIES) {
    assert.ok(WORLD_COUNTRIES.includes(c), `${c.name} 不在 worldBorders`)
  }
})

test('B 全量键集：每个威胁国家的下钻省层数据可用（中国=高精度省表）', () => {
  const missing: string[] = []
  for (const country of THREAT_COUNTRIES) {
    if (country.name === '中国') {
      assert.ok(CHINA_PROVINCES.length >= 30, '中国高精度省表缺失')
      continue
    }
    const rows = ADMIN1_PROVINCES[country.name]
    if (!rows || rows.length === 0) missing.push(country.name)
  }
  assert.deepEqual(missing, [], `以下国家无省层数据，下钻将成空洞: ${missing.join('、')}`)
})

test('B2 省层数据非空且首项含多边形（归一后仍是真实数据）', () => {
  for (const country of THREAT_COUNTRIES) {
    if (country.name === '中国') continue
    const rows = ADMIN1_PROVINCES[country.name]
    assert.ok(Array.isArray(rows), `${country.name} 非数组`)
    assert.ok(typeof rows[0].name === 'string' && rows[0].name.length > 0, `${country.name} 首项缺省名`)
    assert.ok(Array.isArray(rows[0].polys) && rows[0].polys.length > 0, `${country.name} 首项缺多边形`)
  }
})

test('C 别名表：11 个历史英文/旧名分组全部可用且目标为中文键', () => {
  const hasRows = (key: string): boolean => Array.isArray(ADMIN1_PROVINCES[key]) && ADMIN1_PROVINCES[key].length > 0
  const expected: Record<string, string> = {
    Turkey: '土耳其',
    Vietnam: '越南',
    'East Timor': '东帝汶',
    'Ivory Coast': '科特迪瓦',
    Macedonia: '北马其顿',
    'S. Sudan': '南苏丹',
    'Guinea Bissau': '几内亚比绍',
    'The Bahamas': '巴哈马',
    Brunei: '文莱',
    Swaziland: '斯威士兰',
  }
  for (const [alias, target] of Object.entries(expected)) {
    assert.equal(COUNTRY_ALIAS[alias], target, `别名 ${alias} 目标漂移`)
    assert.ok(hasRows(alias), `别名源键 ${alias} 在 ADMIN1_PROVINCES 缺失`)
    assert.ok(hasRows(target), `别名目标键 ${target} 归一后仍缺失`)
  }
  // 巴勒斯坦：Gaza Strip + West Bank 两源归一同一目标；南极洲仅为完整性保留
  assert.equal(COUNTRY_ALIAS['Gaza Strip'], '巴勒斯坦')
  assert.equal(COUNTRY_ALIAS['West Bank'], '巴勒斯坦')
  assert.ok(hasRows('巴勒斯坦'))
  assert.equal(COUNTRY_ALIAS.Antarctica, '南极洲')
  // 每个别名目标都必须是非空省层（防「键存在但数据空」的假通过）
  for (const target of new Set(Object.values(COUNTRY_ALIAS))) {
    assert.ok(hasRows(target), `别名目标 ${target} 省层为空`)
  }
})
