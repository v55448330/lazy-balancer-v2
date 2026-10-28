// 威胁大屏国家键集单源验收
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
import { normalizeCountryName, trafficOriginForCountry } from '../src/utils/threatShared.ts'
import { COUNTRY_CENTROIDS } from '../src/utils/countryCentroids.ts'
import { code } from './_helpers.ts'

test('A 威胁国家表：排除南极洲且其余国家与 worldBorders 一致', () => {
  assert.equal(WORLD_COUNTRIES.length - THREAT_COUNTRIES.length, 1)
  assert.ok(!THREAT_COUNTRIES.some((c) => c.name === 'Antarctica'), '南极洲必须从威胁国家表剔除')
  // 原 `assert.notEqual(THREAT_COUNTRIES, WORLD_COUNTRIES)` 是
  // 同义反复（两个数组对象恒不相等）——若过滤谓词改成别的国家、或顺序/集合漂移
  // 也通过。改为与「唯一预期谓词」逐项同集同序比对（元素对象按设计共享）。
  assert.deepEqual(
    THREAT_COUNTRIES,
    WORLD_COUNTRIES.filter((c) => c.name !== 'Antarctica'),
    '威胁国家表必须是 worldBorders 去掉南极洲的逐项同序投影',
  )
})

test('B 全量键集：每个威胁国家的下钻省层数据可用（中国=高精度省表）', () => {
  const missing: string[] = []
  for (const country of THREAT_COUNTRIES) {
    // 下钻目标按 normalizeCountryName 归一（Taiwan → 中国，2026-10-18 用户裁定）
    const drill = normalizeCountryName(country.name)
    if (drill === '中国') {
      assert.ok(CHINA_PROVINCES.length >= 30, '中国高精度省表缺失')
      continue
    }
    const rows = ADMIN1_PROVINCES[drill]
    if (!rows || rows.length === 0) missing.push(drill)
  }
  assert.deepEqual(missing, [], `以下国家无省层数据，下钻将成空洞: ${missing.join('、')}`)
})

type ProvinceRows = Array<{ name: string; polys: number[][][] }>
const assertProvinceRows = (rows: ProvinceRows, label: string): void => {
  assert.ok(rows.length > 0, `${label} 省层为空`)
  for (const [rowIndex, row] of rows.entries()) {
    const at = `${label} 第 ${rowIndex + 1} 行`
    assert.ok(typeof row.name === 'string' && row.name.trim().length > 0, `${at} 缺省名`)
    assert.ok(Array.isArray(row.polys) && row.polys.length > 0, `${at} 缺多边形`)
    for (const polygon of row.polys) {
      assert.ok(polygon.length > 0, `${at} 含空 polygon`)
      for (const ring of polygon) {
        assert.ok(ring.length > 0 && ring.length % 2 === 0, `${at} ring 为空或坐标不成对`)
        assert.ok(ring.every(Number.isFinite), `${at} 含非有限坐标`)
      }
    }
  }
}

test('B2 每国每行省层数据均含有效名称与多边形（含中国高精度表）', () => {
  const checked = new Set<string>()
  for (const country of THREAT_COUNTRIES) {
    const drill = normalizeCountryName(country.name)
    if (checked.has(drill)) continue
    checked.add(drill)
    assertProvinceRows(drill === '中国' ? CHINA_PROVINCES : ADMIN1_PROVINCES[drill], drill)
  }
  assert.throws(() => assertProvinceRows([
    { name: '首行正常', polys: [[[0, 0, 1, 1]]] },
    { name: '第二行坏数据', polys: [] },
  ], '合成国'), /合成国 第 2 行 缺多边形/, '首行合法不得掩盖第二行空 polys')
})

test('C 别名表：历史英文/旧名分组 + 巴勒斯坦双源；台湾/南极洲死数据已清', () => {
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
  // 别名表 ←→ 清单双向核对：产品表新增/减少历史别名时必须同步本清单
  // （原先只断言本地 expected 的长度=10，产品数据变化无人守护）。
  assert.deepEqual(
    Object.fromEntries(Object.entries(COUNTRY_ALIAS).filter(([, target]) => target !== '巴勒斯坦')),
    expected,
    '历史英文/旧名别名必须与用例清单逐项相等（巴勒斯坦双源单列于下）',
  )
  for (const [alias, target] of Object.entries(expected)) {
    assert.equal(COUNTRY_ALIAS[alias], target, `别名 ${alias} 目标漂移`)
    assert.ok(hasRows(alias), `别名源键 ${alias} 在 ADMIN1_PROVINCES 缺失`)
    assert.ok(hasRows(target), `别名目标键 ${target} 归一后仍缺失`)
  }
  // 巴勒斯坦：Gaza Strip + West Bank 两源归一同一目标
  assert.equal(COUNTRY_ALIAS['Gaza Strip'], '巴勒斯坦')
  assert.equal(COUNTRY_ALIAS['West Bank'], '巴勒斯坦')
  assert.ok(hasRows('巴勒斯坦'))
  // 两源必须**逐省合并**——只断言目标键非空会让「后到别名被静默
  // 丢弃」（原实现仅 Gaza 条带）也通过，下钻西岸整片成空洞。
  const palestine = ADMIN1_PROVINCES['巴勒斯坦']
  const palestineNames = palestine.map((row) => row.name)
  assert.ok(palestineNames.includes('Gaza Strip'), `巴勒斯坦缺少 Gaza Strip: ${palestineNames.join('、')}`)
  assert.ok(palestineNames.includes('West Bank'), `巴勒斯坦缺少 West Bank: ${palestineNames.join('、')}`)
  assert.ok(palestine.length >= 2, `巴勒斯坦条目数应 ≥2，实际 ${palestine.length}`)
  assert.equal(new Set(palestineNames).size, palestineNames.length, '合并后省名不得重复')
  // 死数据清源：南极洲永不出现在威胁国家/归属地口径（THREAT_COUNTRIES
  // 已剔除），台湾下钻经 normalizeCountryName 归一到中国高精度省表——两键的省层
  // 与别名均为不可达数据，删除后不得回流。
  assert.equal(ADMIN1_PROVINCES['南极洲'], undefined, '南极洲省层为零消费数据')
  assert.equal(COUNTRY_ALIAS.Antarctica, undefined, '南极洲别名属于死数据')
  assert.equal(ADMIN1_PROVINCES.Taiwan, undefined, '台湾下钻走中国省表，独立 Taiwan 省层为零消费数据')
  // 每个别名目标都必须是非空省层（防「键存在但数据空」的假通过）
  for (const target of new Set(Object.values(COUNTRY_ALIAS))) {
    assert.ok(hasRows(target), `别名目标 ${target} 省层为空`)
  }
})

test('正常流光流起点：台湾/Taiwan 归一后与中国同点，两引擎共用同一查表', () => {
  assert.deepEqual(trafficOriginForCountry('台湾'), COUNTRY_CENTROIDS['中国'])
  assert.deepEqual(trafficOriginForCountry('Taiwan'), COUNTRY_CENTROIDS['中国'])
  assert.deepEqual(trafficOriginForCountry('中国'), COUNTRY_CENTROIDS['中国'])
  // 未知国家仍走兜底点（不是被归一成中国）
  assert.notDeepEqual(trafficOriginForCountry('不存在国'), COUNTRY_CENTROIDS['中国'])
  // 质心表是普通对象：原型键不得取出函数（[0]/[1] 会变 NaN 坐标）
  for (const key of ['constructor', 'toString', '__proto__']) {
    assert.deepEqual(trafficOriginForCountry(key), [160, 15], `${key} 必须走兜底质心`)
  }
  // 两引擎 setTraffic 都走共享 helper，禁止第三份查表实现
  for (const path of ['src/utils/threatScene.ts', 'src/utils/threatGlobe.ts']) {
    const text = code(path)
    assert.match(text, /trafficOriginForCountry\(item\.key\)/, `${path} setTraffic 未归一`)
    assert.doesNotMatch(text, /spawnArc\(COUNTRY_CENTROIDS\[item\.key\]/, `${path} 裸查表不得回流`)
  }
})
