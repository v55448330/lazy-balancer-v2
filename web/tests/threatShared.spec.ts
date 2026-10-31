// 威胁大屏共享纯函数验收
//   A. 热力数据指纹：相同→true；计数/长度/重复键变化→false
//   B. 弧线端点：终点恒为当前本站坐标（setServer 后新弧线随新坐标）
//   C. 危险等级化简：检测模式 12 分边界（原恒等三元 >=6 与 <6 同值）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { heatEntriesEqual, heatCss, heatIntensity, maxHeatCount, heatRampGradientCss, DOT_LAND, arcEndpoints, POINTY_TOP_HEX_VERTICES, drillCountryAllowed, arcOriginForLocation, normalizeCountryName, adminShortName, aggregateCountryCounts, hasProvinceStats, drillCommitAllowed, buildCountryCellGrid, countryGridCell } from '../src/utils/threatShared.ts'
import { FALLBACK_CENTROID } from '../src/utils/countryCentroids.ts'
import { member, repoCode, code } from './_helpers.ts'

test('六边形点阵：pointy-top 六顶点且上下尖角', () => {
  assert.equal(POINTY_TOP_HEX_VERTICES.length, 6)
  assert.deepEqual(POINTY_TOP_HEX_VERTICES[0], [0, -1])
  assert.deepEqual(POINTY_TOP_HEX_VERTICES[3], [0, 1])
  assert.ok(POINTY_TOP_HEX_VERTICES.every(([x, y]) => Math.abs(x) <= Math.sqrt(3) / 2 && Math.abs(y) <= 1))
})

test('下钻白名单：缺省不限，显式列表只放行列内国家', () => {
  assert.equal(drillCountryAllowed(undefined, '美国'), true)
  assert.equal(drillCountryAllowed(['中国'], '中国'), true)
  assert.equal(drillCountryAllowed(['中国'], '美国'), false)
  assert.equal(drillCountryAllowed([], '中国'), false)
})

test('弧线起点：中国精确到省，其他国家走质心，未知走兜底', () => {
  const gd = arcOriginForLocation('中国·广东省')
  assert.ok(Math.abs(gd[0] - 113.42) < 0.5 && Math.abs(gd[1] - 23.31) < 0.5)
  const us = arcOriginForLocation('美国')
  assert.ok(Math.abs(us[0] - -97) < 1 && Math.abs(us[1] - 38) < 2)
  const unknown = arcOriginForLocation('不存在国')
  // 钉住回退坐标字面值本身——原与 arcOriginForLocation('') 自比较，同一回退分支
  // 恒等通过；改 FALLBACK_CENTROID 值或改回退实现都必须红。
  // [160, 15] = countryCentroids.FALLBACK_CENTROID（太平洋「海外」中心点）。
  assert.deepEqual(unknown, [160, 15])
  assert.deepEqual(arcOriginForLocation(''), [160, 15])
  // 质心表是普通对象：原型键不得取出函数（后续 [0]/[1] 会变 undefined→NaN 弧线）
  for (const key of ['constructor', 'toString', '__proto__']) {
    assert.deepEqual(arcOriginForLocation(key), [160, 15], `${key} 必须走兜底质心`)
  }
  assert.deepEqual(FALLBACK_CENTROID, [160, 15], '回退坐标变更需同步本用例（契约钉）')
})

test('热力底色钉：无命中恒底色，命中 1 次严格亮于底色（长尾可辨）', () => {
  const sum = (css: string): number => css.slice(4, -1).split(',').map(Number).reduce((a, b) => a + b, 0)
  assert.equal(heatCss(0, 10000), DOT_LAND, 'count=0 与未命中点阵同色')
  assert.equal(heatCss(0, 5), DOT_LAND, '任意 max 下 count=0 恒底色')
  assert.equal(heatCss(-3, 100), DOT_LAND, '负计数同底色')
  assert.ok(sum(heatCss(1, 10000)) > sum(DOT_LAND), '命中 1 次必须严格亮于底色')
  assert.ok(sum(heatCss(1, 2)) > sum(DOT_LAND), '小数据集下命中 1 次同样亮于底色')
})

test('对数标尺公式钉：强度 = log10(1+count)/log10(1+max)，max=当前数据集（自适应）', () => {
  assert.ok(Math.abs(heatIntensity(1, 9999) - Math.log10(2) / 4) < 1e-12, 'max=9999 → 分母=log10(1e4)=4')
  assert.equal(heatIntensity(10000, 10000), 1, '数据集最大值饱和=1（不写死 1000）')
  assert.equal(heatIntensity(5000, 10000), Math.log10(5001) / Math.log10(10001))
})

test('数量级可辨：1/10/100/1k/10k 逐级严格变亮且步长可感知', () => {
  const sum = (css: string): number => css.slice(4, -1).split(',').map(Number).reduce((a, b) => a + b, 0)
  let prev = sum(heatCss(1, 10000))
  for (const count of [10, 100, 1000, 10000]) {
    const cur = sum(heatCss(count, 10000))
    assert.ok(cur > prev, `count=${count} 必须亮于上一数量级`)
    assert.ok(cur - prev >= 12, `count=${count} 与上一数量级色差必须可感知（ΔRGB和≥12）`)
    prev = cur
  }
})

test('自适应 max：头部国家不再饱和于固定 1000 绝对标尺', () => {
  const brightest = 'rgb(226,84,84)'
  assert.equal(heatCss(1000, 1000), brightest, 'max=1k 数据集的头部=最亮')
  assert.equal(heatCss(20000, 20000), brightest, 'max=20k 数据集的头部同样=最亮')
  assert.notEqual(heatCss(1000, 10000), brightest, 'max=10k 时 1k 命中不得饱和（旧绝对标尺回归即红）')
})

test('单调性与退化边界：count 增→亮度不减；max 增→同 count 变暗；max≤0 退化=命中即最热', () => {
  const sum = (css: string): number => css.slice(4, -1).split(',').map(Number).reduce((a, b) => a + b, 0)
  let prev = 0
  for (const count of [1, 3, 30, 300, 3000, 10000]) {
    const cur = sum(heatCss(count, 10000))
    assert.ok(cur >= prev, `count=${count} 亮度必须单调不减`)
    prev = cur
  }
  assert.ok(sum(heatCss(100, 1000)) >= sum(heatCss(100, 10000)), '同 count，max 越大越暗（归一化口径）')
  assert.equal(heatIntensity(5, 0), 1, '退化数据集（max=0）命中即最热')
  assert.equal(heatIntensity(0, 0), 0, '无命中恒 0')
  assert.equal(heatCss(5, 0), 'rgb(226,84,84)')
})

test('数据集 max 单源：maxHeatCount 空集=0，取最大值', () => {
  assert.equal(maxHeatCount(new Map()), 0)
  assert.equal(maxHeatCount(new Map([['中国', 12], ['美国', 1204]])), 1204)
})

test('图例渐变单源：七档阶梯排布，首档=底色、末档=亮红（图例不得手写渐变）', () => {
  const ramp = heatRampGradientCss()
  assert.match(ramp, /^linear-gradient\(90deg, /)
  assert.ok(ramp.includes('rgb(44,66,96) 0%'), '首档=陆地底色')
  assert.ok(ramp.includes('rgb(226,84,84) 100%'), '末档=亮红')
  assert.equal(ramp.split('rgb(').length - 1, 7, '七档（底色 + 3 锚点 + 3 中点插值）')
})

test('A 热力指纹：相同输入 true，计数/长度/重复键变化 false', () => {
  const prev = new Map<string, number>([['中国', 12], ['美国', 5]])
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 12 }, { name: '美国', count: 5 }]), true)
  assert.equal(heatEntriesEqual(prev, [{ name: '美国', count: 5 }, { name: '中国', count: 12 }]), true, '顺序无关')
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 13 }, { name: '美国', count: 5 }]), false)
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 12 }]), false, '长度变化必须视为变化')
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 12 }, { name: '中国', count: 12 }]), false, '重复键不可当相等')
  assert.equal(heatEntriesEqual(new Map(), []), true)
  assert.equal(heatEntriesEqual(new Map(), [{ name: '中国', count: 0 }]), false)
})

test('B 弧线端点：终点跟随当前本站坐标（构造期常量即失效）', () => {
  const origin: [number, number] = [116.4, 39.9]
  const first = arcEndpoints([104.19, 35.86], origin)
  assert.deepEqual(first, { startLat: 39.9, startLng: 116.4, endLat: 35.86, endLng: 104.19 })
  // setServer 到纽约：同一归属地的新弧线终点必须变为新坐标
  const second = arcEndpoints([-74.0, 40.71], origin)
  assert.deepEqual(second, { startLat: 39.9, startLng: 116.4, endLat: 40.71, endLng: -74.0 })
  assert.notEqual(first.endLat, second.endLat)
})

// 台湾归一/短名/计数合并此前零断言——热力、命中、下钻三处都靠它们。
// 失效时台湾点阵不与大陆同色、下钻/命中回退 FALLBACK_CENTROID（中太平洋），
// 且没有任何测试会拦住。
test('台湾归一：Taiwan/台湾 → 中国，其他国名原样（用户裁定 2026-10-18）', () => {
  assert.equal(normalizeCountryName('Taiwan'), '中国')
  assert.equal(normalizeCountryName('台湾'), '中国')
  assert.equal(normalizeCountryName('中国'), '中国')
  assert.equal(normalizeCountryName('日本'), '日本')
  assert.equal(normalizeCountryName(''), '')
})

test('计数合并：台湾计数并入中国，其他键保持独立（热力/hover 单源）', () => {
  const merged = aggregateCountryCounts([
    { name: '中国', count: 3 },
    { name: 'Taiwan', count: 4 },
    { name: '台湾', count: 5 },
    { name: '美国', count: 7 },
  ])
  assert.equal(merged.get('中国'), 12)
  assert.equal(merged.get('美国'), 7)
  assert.equal(merged.has('Taiwan'), false, '台湾不得残留独立键（点阵按中国染色）')
  assert.equal(merged.size, 2)
})

test('省短名代表形态：长后缀优先匹配，非行政后缀不动', () => {
  assert.equal(adminShortName('广西壮族自治区'), '广西')
  assert.equal(adminShortName('宁夏回族自治区'), '宁夏')
  assert.equal(adminShortName('新疆维吾尔自治区'), '新疆')
  assert.equal(adminShortName('内蒙古自治区'), '内蒙古')
  assert.equal(adminShortName('香港特别行政区'), '香港')
  assert.equal(adminShortName('广东省'), '广东')
  assert.equal(adminShortName('北京市'), '北京')
  // 无后缀/后缀即全名时不得截成空串
  assert.equal(adminShortName('California'), 'California')
  assert.equal(adminShortName('省'), '省')
})

test('省短名单源：34 省数据的 short 必须等于剥后缀函数输出', () => {
  for (const province of CHINA_PROVINCES) {
    assert.equal(
      province.short,
      adminShortName(province.name),
      `${province.name} 的省短名与 adminShortName 分叉——地球标签/下钻查找用的是数据侧 short，点阵键用的是函数`,
    )
  }
})

test('剥后缀表与后端 ip2RegionDisplaySuffixes 逐项相等（长后缀优先序一致）', () => {
  const body = member(code('src/utils/threatShared.ts'), 'export function adminShortName(')
  const frontTable = /const suffixes = \[([^\]]*)\]/.exec(body)?.[1]
  assert.ok(frontTable, 'adminShortName 的 suffixes 表被改形——本对表钉需同步')
  const front = [...frontTable.matchAll(/'([^']+)'/g)].map((match) => match[1])
  const goTable = /var ip2RegionDisplaySuffixes = \[\]string\{([^}]*)\}/.exec(repoCode('internal/handlers/security.go'))?.[1]
  assert.ok(goTable, 'security.go 缺 ip2RegionDisplaySuffixes 声明')
  const go = [...goTable.matchAll(/"([^"]+)"/g)].map((match) => match[1])
  assert.deepEqual(front, go, '两端后缀表必须同集同序——后端事件 province 短名与前端点阵键靠它对齐')
})

test('省级统计边界：仅中国有省级数据源，海外下钻必须显示「无省级统计」', () => {
  assert.equal(hasProvinceStats('中国'), true)
  assert.equal(hasProvinceStats('美国'), false)
  assert.equal(hasProvinceStats(''), false)
})

test('下钻续体作废：seq 过期或已销毁一律丢弃（双引擎共用判定）', () => {
  assert.equal(drillCommitAllowed(3, 3, false), true)
  assert.equal(drillCommitAllowed(2, 3, false), false, '复位/返回递增 seq 后迟到续体必须丢弃')
  assert.equal(drillCommitAllowed(3, 3, true), false, '退出大屏后不得再操作已销毁引擎')
})

// 省点阵 bbox 预筛钉测——预筛只是跳点优化，产出必须与无预筛
// 形态逐点一致（宽幅国家下 34 省 × 全网格直接 pointInPolys 是首次下钻长任务，
// 与 threatScene.ts 省级 bbox 预筛同构）。
import { provinceDotGrid } from '../src/utils/threatShared.ts'
import { pointInPolys } from '../src/utils/threatShared.ts'
import { WORLD_COUNTRIES } from '../src/utils/worldBorders.ts'
import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { CHINA_PROVINCES } from '../src/utils/chinaProvinces.ts'

function rectPoly(minLon: number, minLat: number, maxLon: number, maxLat: number): number[][][] {
  return [[[minLon, minLat, maxLon, minLat, maxLon, maxLat, minLon, maxLat, minLon, minLat]]]
}

/** 无预筛参照实现：与 provinceDotGrid 同网格语义，但逐格点对全部省份做射线判定。 */
function provinceDotGridNoPrefilter(
  source: readonly { name: string; polys: number[][][] }[],
  step: number,
): { lat: number; lng: number; key: string }[] {
  let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
  for (const pv of source) {
    for (const poly of pv.polys) for (const ring of poly) for (let k = 0; k + 1 < ring.length; k += 2) {
      if (ring[k] < minLon) minLon = ring[k]
      if (ring[k] > maxLon) maxLon = ring[k]
      if (ring[k + 1] < minLat) minLat = ring[k + 1]
      if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
    }
  }
  const dots: { lat: number; lng: number; key: string }[] = []
  let row = 0
  for (let lat = minLat; lat <= maxLat; lat += step, row++) {
    const offset = row % 2 === 1 ? step / 2 : 0
    for (let lon = minLon + offset; lon <= maxLon; lon += step) {
      for (const pv of source) {
        if (!pointInPolys(lon, lat, pv.polys)) continue
        dots.push({ lat, lng: lon, key: adminShortName(pv.name) })
        break
      }
    }
  }
  return dots
}

test('省点阵 bbox 预筛与无预筛形态产出逐点一致（宽幅/远距/多边形组）', () => {
  const source = [
    // 宽幅省：横跨大部分经度域（预筛几乎不跳点，回归形状）
    { name: '宽幅省', polys: rectPoly(-170, 40, 170, 60) },
    // 远距小省：绝大部分格点被 bbox 预筛跳过（目标形状）
    { name: '小岛省', polys: rectPoly(10, -20, 12.5, -17.5) },
    // 多边形组省：两段分离多边形（畸形形状：bbox 大于实际覆盖）
    { name: '双片省', polys: [...rectPoly(-60, -40, -55, -35), ...rectPoly(60, 0, 65, 5)] },
  ]
  for (const step of [2.5, 5]) {
    assert.deepEqual(
      provinceDotGrid(source, step),
      provinceDotGridNoPrefilter(source, step),
      `step=${step} 预筛产出必须与无预筛一致`,
    )
  }
  // 键名走共享短名口径
  const dots = provinceDotGrid([{ name: '广东省', polys: rectPoly(110, 20, 112, 22) }], 1)
  assert.ok(dots.length > 0)
  assert.equal(dots[0].key, '广东')
})

test('真实国界孔洞：莱索托不计入南非，南非本土仍命中', () => {
  const southAfrica = WORLD_COUNTRIES.find((country) => country.name === '南非')
  const lesotho = WORLD_COUNTRIES.find((country) => country.name === '莱索托')
  assert.ok(southAfrica)
  assert.ok(lesotho)
  assert.equal(pointInPolys(28.23, -29.58, southAfrica.polys), false)
  assert.equal(pointInPolys(28.23, -29.58, lesotho.polys), true)
  assert.equal(pointInPolys(25.0, -28.0, southAfrica.polys), true)
})

test('真实省界孔洞：维也纳不计入下奥地利州，州内其他点仍命中', () => {
  const provinces = ADMIN1_PROVINCES['奥地利']
  assert.ok(provinces)
  const lowerAustria = provinces.find((province) => province.name === 'Niederösterreich')
  const vienna = provinces.find((province) => province.name === 'Wien')
  assert.ok(lowerAustria)
  assert.ok(vienna)
  assert.equal(pointInPolys(16.37, 48.21, lowerAustria.polys), false)
  assert.equal(pointInPolys(16.37, 48.21, vienna.polys), true)
  assert.equal(pointInPolys(15.6, 48.4, lowerAustria.polys), true)
})

test('中国省界回归：北京与天津不被河北孔洞吸收，河北本土仍命中', () => {
  const beijing = CHINA_PROVINCES.find((province) => province.name === '北京市')
  const tianjin = CHINA_PROVINCES.find((province) => province.name === '天津市')
  const hebei = CHINA_PROVINCES.find((province) => province.name === '河北省')
  assert.ok(beijing)
  assert.ok(tianjin)
  assert.ok(hebei)
  assert.equal(pointInPolys(116.4, 39.9, beijing.polys), true)
  assert.equal(pointInPolys(116.4, 39.9, hebei.polys), false)
  assert.equal(pointInPolys(117.35, 39.28, tianjin.polys), true)
  assert.equal(pointInPolys(117.35, 39.28, hebei.polys), false)
  assert.equal(pointInPolys(114.5, 38.0, hebei.polys), true)
})

test('国家网格：候选收敛、远海空集、键夹紧', () => {
  // 两个矩形国家：东经 100-110 北纬 20-30；西经 10-0 北纬 40-50
  const box = (minLon: number, maxLon: number, minLat: number, maxLat: number): number[][][] => [
    [[minLon, minLat, maxLon, minLat, maxLon, maxLat, minLon, maxLat, minLon, minLat]],
  ]
  const countries = [
    { name: 'A', polys: box(100, 110, 20, 30) },
    { name: 'B', polys: box(-10, 0, 40, 50) },
  ]
  const { grid, bounds } = buildCountryCellGrid(countries)
  assert.equal(bounds.length, 2)
  assert.deepEqual(bounds[0], { minLon: 100, maxLon: 110, minLat: 20, maxLat: 30 })
  // 命中单元格只含对应国家（5° 网格 -> 105,25 = x57 y23）
  assert.deepEqual(grid.get(countryGridCell(105, 25)), [0])
  assert.deepEqual(grid.get(countryGridCell(-5, 45)), [1])
  // 远海（南大西洋）无候选
  assert.deepEqual(grid.get(countryGridCell(-30, -30)) ?? [], [])
  // 同一单元格不会被重复登记同一个国家（矩形只登记一次）
  const counts = [...grid.values()].flat().filter((ci) => ci === 0).length
  assert.equal(counts, Math.ceil(10 / 5 + 1) * Math.ceil(10 / 5 + 1))
  // 键夹紧：极值不越界（0..35 行、0..71 列）
  assert.equal(countryGridCell(-180, -90), 0)
  assert.equal(countryGridCell(180, 90), 35 * 100 + 71)
})

// 消费侧接线钉：parseIpLocation 的唯一生产消费点是威胁光流的地域键/
// 端点省派生——被绕过时表现为「光流地域键与端点省漂移」，纯函数用例不会红。
test('parseIpLocation 接线：threatShared 经它派生国家与省份', () => {
  const shared = code('src/utils/threatShared.ts')
  assert.match(shared, /import \{ parseIpLocation \} from '\.\/ipLocationParts\.ts'/, '必须复用单源解析器')
  assert.match(shared, /parseIpLocation\(ipLocation\)/, '光流地域派生必须经 parseIpLocation')
})
