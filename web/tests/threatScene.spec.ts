// 威胁大屏 v16 确定性验收单测（node --test，纯数学+数据级断言，无框架依赖）：
//   ① 2D 投影往返：worldToScreen→screenToLonLat 误差 < 1e-9°（5×5 网格+中心+角点）
//   ② 360° 环绕：panBy 横向平移后中心拾取正确（wrap 归一）；纵向钳制生效
//   ③ 省板包含：10 国省级 bbox ⊆ 国家 bbox ±18°（数据级，含中国高精度省界）
//   ④ 缩放锚点：zoomAt 指针锚定（锚点地理坐标缩放前后不变）
//   ⑤ 下钻取景一致性：俄/中/美/法/沙特 占屏比例方差 < 0.12（v14⑤a 2D 口径）
//   ⑤b 反日界线 unwrap：俄罗斯主环 bbox 不跨全宽
//
// 运行：cd web && node --test tests/threatScene.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  LAT_TOP,
  WORLD_D,
  worldToScreen,
  screenToLonLat,
  panBy,
  zoomAt,
  fitDrillZoom,
  principalBounds,
  type Cam2D,
} from '../src/utils/threatProjection.ts'
import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { CHINA_PROVINCES } from '../src/utils/chinaProvinces.ts'
import { WORLD_COUNTRIES } from '../src/utils/worldBorders.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')

// ---- 固定相机（1600×900 视口，zoom=3，本站 (108.9,34) 居中） ----
const W = 1600
const H = 900
const SITE: [number, number] = [108.9, 34]
const CAM: Cam2D = {
  camX: SITE[0],
  camY: LAT_TOP - SITE[1],
  zoom: 3,
  width: W,
  height: H,
}

test('①2D 投影往返：worldToScreen→screenToLonLat 误差 < 1e-9°', () => {
  const points: [number, number][] = []
  for (let gx = 0; gx <= 4; gx++) {
    for (let gy = 0; gy <= 4; gy++) {
      points.push([-140 + (gx / 4) * 280, -40 + (gy / 4) * 110])
    }
  }
  points.push([SITE[0], SITE[1]], [-175, 70], [178, -50])
  let maxErr = 0
  for (const [lon, lat] of points) {
    const p = worldToScreen(lon, lat, CAM)
    const back = screenToLonLat(p.x, p.y, CAM)
    const dLon = Math.abs(back.lon - lon)
    const dLat = Math.abs(back.lat - lat)
    maxErr = Math.max(maxErr, dLon, dLat)
  }
  assert.ok(maxErr < 1e-9, `往返最大误差 ${maxErr}° 超限`)
})

test('④拾取语义：中心=相机中心、上缘更高纬、左右等距对称', () => {
  const center = screenToLonLat(W / 2, H / 2, CAM)
  assert.ok(Math.abs(center.lon - SITE[0]) < 1e-9, `中心 lon=${center.lon}`)
  assert.ok(Math.abs(center.lat - SITE[1]) < 1e-9, `中心 lat=${center.lat}`)

  const up = screenToLonLat(W / 2, H / 2 - 100, CAM)
  assert.ok(up.lat > center.lat, '上缘纬度应更高')

  const l = screenToLonLat(W / 2 - 200, H / 2, CAM)
  const r = screenToLonLat(W / 2 + 200, H / 2, CAM)
  assert.ok(
    Math.abs(Math.abs(l.lon - center.lon) - Math.abs(r.lon - center.lon)) < 1e-9,
    `左右不对称: ${l.lon} vs ${r.lon}`,
  )
})

test('②360° 环绕：panBy 横向平移后中心拾取正确；纵向钳制生效', () => {
  // 向左拖 480px（zoom3 → 160°），中心经度应西移 160° 并 wrap
  const panned = panBy(CAM, -480, 0)
  const center = screenToLonLat(W / 2, H / 2, { ...CAM, camX: panned.camX, camY: panned.camY })
  const expected = -91.1 // 向左拖 480px=指针位移 -480 → camX +160 → wrap 至 -91.1
  assert.ok(Math.abs(center.lon - expected) < 1e-6, `平移后中心 lon=${center.lon}, want ${expected}`)
  // 纵向越界拖动被钳在世界内
  const clamped = panBy(CAM, 0, -100000)
  const centerY = LAT_TOP - center.lat
  assert.ok(clamped.camY >= 0 && clamped.camY <= WORLD_D, `camY 越界: ${clamped.camY}`)
  void centerY
})

test('④b 缩放锚点：zoomAt 后锚点地理坐标不变（放大后仍局部视图）', () => {
  const anchor = { x: 1100, y: 500 }
  const start = { ...CAM, zoom: 6 }
  const before = screenToLonLat(anchor.x, anchor.y, start)
  const next = zoomAt(start, anchor.x, anchor.y, 1.5, 1, 200)
  const after = screenToLonLat(anchor.x, anchor.y, next)
  assert.ok(Math.abs(before.lon - after.lon) < 1e-9, `锚点经度漂移 ${before.lon} → ${after.lon}`)
  assert.ok(Math.abs(before.lat - after.lat) < 1e-9, `锚点纬度漂移 ${before.lat} → ${after.lat}`)
  assert.ok(next.zoom > CAM.zoom, 'zoom 应放大')
})

// ---- 数据级：省板包含断言（逐行解析三个静态模块） ----

interface BBox {
  minLon: number
  maxLon: number
  minLat: number
  maxLat: number
}

/** 解析 admin1Provinces：行首 `"国家": [{ name: "省", …` → 国家键 → 聚合 bbox。 */
function countryKeyBBoxes(src: string): Map<string, BBox> {
  const map = new Map<string, BBox>()
  for (const line of src.split('\n')) {
    const keyM = line.match(/^  "([^"]+)": \[\{ name:/)
    if (!keyM) continue
    const b = lineBBox(line)
    if (!b) continue
    map.set(keyM[1], b)
  }
  return map
}

/** 解析「每行一个条目」的模块：`name: "…"` 行 → 全部坐标对的聚合 bbox。 */
function lineBBoxes(src: string): Map<string, BBox> {
  const map = new Map<string, BBox>()
  for (const line of src.split('\n')) {
    const nameM = line.match(/name: "([^"]+)"/)
    if (!nameM) continue
    const b = lineBBox(line)
    if (!b) continue
    map.set(nameM[1], b)
  }
  return map
}

/** 单行数字 → bbox。 */
function lineBBox(line: string): BBox | null {
  const nums = line.match(/-?\d+(?:\.\d+)?/g)?.map(Number) ?? []
  let minLon = 1e9
  let maxLon = -1e9
  let minLat = 1e9
  let maxLat = -1e9
  for (let k = 0; k + 1 < nums.length; k += 2) {
    minLon = Math.min(minLon, nums[k])
    maxLon = Math.max(maxLon, nums[k])
    minLat = Math.min(minLat, nums[k + 1])
    maxLat = Math.max(maxLat, nums[k + 1])
  }
  if (minLon === 1e9) return null
  return { minLon, maxLon, minLat, maxLat }
}

function within(inner: BBox, outer: BBox, tol: number): boolean {
  return (
    inner.minLon >= outer.minLon - tol && inner.maxLon <= outer.maxLon + tol &&
    inner.minLat >= outer.minLat - tol && inner.maxLat <= outer.maxLat + tol
  )
}

test('③省板包含：10 国省级 bbox ⊆ 国家 bbox ±18°（拦截生成/映射错位）', () => {
  // 容差基准：10m 省界含离岛/群岛（110m 国家板系统性省略），实测最大偏离
  // 16°（阿留申远端 15.7°、特林达迪 4.6°、西南诸岛 6.1°、设得兰 2.2°）——
  // 统一 ±18°：覆盖全部源数据离岛噪声，仍拦截生成/映射类缺陷（度弧混淆/
  // 镜像/坐标轴互换的错位量级 ≥ 30°，国家尺度）。
  const TOL = 18
  const admin1Src = readFileSync(join(ROOT, 'src/utils/admin1Provinces.ts'), 'utf8')
  const worldSrc = readFileSync(join(ROOT, 'src/utils/worldBorders.ts'), 'utf8')
  const chinaSrc = readFileSync(join(ROOT, 'src/utils/chinaProvinces.ts'), 'utf8')

  const world = lineBBoxes(worldSrc)
  assert.ok(world.size >= 150, `worldBorders 国家数 ${world.size} < 150`)

  // 中国高精度省界：逐省 bbox ⊆ 中国国家板 ± 18°
  const chinaCountry = world.get('中国')
  assert.ok(chinaCountry, 'worldBorders 缺「中国」')
  let chinaChecked = 0
  for (const line of chinaSrc.split('\n')) {
    const nameM = line.match(/\{ name: "([^"]+)"/)
    if (!nameM) continue
    // datav 南海诸岛为示意要素（南至 lat≈4°，内嵌于海南省多边形），NE 国界不含——豁免
    if (nameM[1] === '南海诸岛' || nameM[1] === '海南省') continue
    const b = lineBBox(line)
    if (!b) continue
    chinaChecked++
    assert.ok(
      within(b, chinaCountry, TOL),
      `中国省界 ${nameM[1]} 越出国家板 ±${TOL}°: ${JSON.stringify(b)} vs ${JSON.stringify(chinaCountry)}`,
    )
  }
  assert.ok(chinaChecked >= 30, `中国省界校验 ${chinaChecked} < 30`)

  // 9 国（admin1 聚合 bbox ⊆ 国家板 bbox ±18°）。选样排除海外领地成建制国家
  // （美/法/西/葡的 10m admin1 含 DOM-TOM/领地，110m 板不含——跨洋级源数据
  // 语义差非映射缺陷）；俄罗斯跨 ±180：110m 板 bbox 即全幅，包含恒成立。
  const admin1 = countryKeyBBoxes(admin1Src)
  assert.ok(admin1.size >= 200, `admin1 国家数 ${admin1.size} < 200`)
  const targets = ['俄罗斯', '德国', '英国', '日本', '巴西', '印度', '澳大利亚', '意大利', '瑞典']
  let checked9 = 0
  for (const target of targets) {
    const country = world.get(target)
    assert.ok(country, `worldBorders 缺 ${target}`)
    const aggr = admin1.get(target)
    assert.ok(aggr, `admin1Provinces 缺 ${target}`)
    assert.ok(
      within(aggr, country, TOL),
      `${target} 省板越出国家板 ±${TOL}°: ${JSON.stringify(aggr)} vs ${JSON.stringify(country)}`,
    )
    checked9++
  }
  assert.ok(checked9 === 9, `9 国校验 ${checked9} ≠ 9`)

  // 导入自检：三个模块的运行时导出可用（单测加载链与 vite 同源）
  assert.ok(ADMIN1_PROVINCES && typeof ADMIN1_PROVINCES === 'object')
  assert.ok(Array.isArray(CHINA_PROVINCES) && CHINA_PROVINCES.length >= 30)
  assert.ok(Array.isArray(WORLD_COUNTRIES) && WORLD_COUNTRIES.length >= 150)
})

test('⑤下钻取景一致性：俄/中/美/法/沙特 占屏比例方差 < 0.12（2D 线性）', () => {
  // 新加坡不在 NE 110m 数据（SKIP 披露，非取景缺陷）
  const names = ['俄罗斯', '中国', '美国', '法国', '沙特阿拉伯']
  const doms: number[] = []
  for (const name of names) {
    const c = WORLD_COUNTRIES.find((x) => x.name === name)
    assert.ok(c, `worldBorders 缺 ${name}`)
    const b = principalBounds(c.polys)
    const bboxW = b.maxLon - b.minLon
    const bboxH = b.maxLat - b.minLat
    const zoom = fitDrillZoom(bboxW, bboxH, W, H, 1)
    const fw = (bboxW * zoom) / W
    const fh = (bboxH * zoom) / H
    const dom = Math.max(fw, fh)
    doms.push(dom)
    assert.ok(dom >= 0.7 && dom <= 1.0, `${name} 主导占屏 ${dom.toFixed(2)} 超出 [0.70, 1.00]`)
  }
  const mean = doms.reduce((a, b) => a + b, 0) / doms.length
  const std = Math.sqrt(doms.reduce((a, b) => a + (b - mean) ** 2, 0) / doms.length)
  assert.ok(std < 0.12, `五国占屏比例 stddev ${std.toFixed(3)} >= 0.12`)
})

test('⑤b 反日界线 unwrap：俄罗斯主环 bbox 不再跨全宽', () => {
  const c = WORLD_COUNTRIES.find((x) => x.name === '俄罗斯')
  assert.ok(c)
  const b = principalBounds(c.polys)
  const span = b.maxLon - b.minLon
  assert.ok(span < 180, `俄罗斯主环 bbox span ${span.toFixed(1)}° 仍≈全宽（unwrap 失效）`)
})
