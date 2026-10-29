// 威胁大屏确定性验收单测（node --test，纯数学+数据级断言，无框架依赖）：
//   ① 2D 投影往返：worldToScreen→screenToLonLat 误差 < 1e-9°（5×5 网格+中心+角点）
//   ② 360° 环绕：panBy 横向平移后中心拾取正确（wrap 归一）；纵向钳制生效
//   ③ 省板包含：10 国省级 bbox ⊆ 国家 bbox ±18°（数据级，含中国高精度省界）
//   ④ 下钻口径：统一倍率常量 / 主环取景中心 / 南界钳制（已退役的按国自适应
//      fitDrillZoom 不再有生产消费方——v2.3.8 用户裁定统一倍率）
//   ④b/⑤ 反日界线：俄罗斯主环 bbox 不跨全宽（数据已包裹）；合成环驱动 unwrap 分支见 ⑤b
//   ⑥ 地球球面逆投影往返：sphereSurfacePoint(正投影 NDC) 还原经纬度（含西半球
//      wrap、高纬极区与背向射线 null）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  LAT_TOP,
  LAT_BOTTOM,
  WORLD_D,
  latToY,
  DRILL_UNIFIED_ZOOM,
  worldToScreen,
  screenToLonLat,
  panBy,
  principalBounds,
  sphereSurfacePoint,
  type Cam2D,
} from '../src/utils/threatProjection.ts'
import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { CHINA_PROVINCES } from '../src/utils/chinaProvinces.ts'
import { WORLD_COUNTRIES } from '../src/utils/worldBorders.ts'
import { code, member, stripComments } from './_helpers.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')

// ---- 固定相机（1600×900 视口，zoom=3，本站 (108.9,34) 居中） ----
const W = 1600
const H = 900
const SITE: [number, number] = [108.9, 34]
const CAM: Cam2D = {
  camX: SITE[0],
  camY: latToY(SITE[1]),
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
  // 纵向越界拖动被钳在世界内（钉精确钳制值，替代恒真区间断言与
  // 死代码 centerY——总览 zoom=3 下 visH=300 ≥ WORLD_D，相机恒居中）
  const clamped = panBy(CAM, 0, -100000)
  assert.ok(Math.abs(clamped.camY - WORLD_D / 2) < 1e-9, `总览纵向应钉在 WORLD_D/2: ${clamped.camY}`)
  const clampedDown = panBy(CAM, 0, 100000)
  assert.ok(Math.abs(clampedDown.camY - WORLD_D / 2) < 1e-9, `总览下拖同样钉在 WORLD_D/2: ${clampedDown.camY}`)
})

test('④下钻口径：统一倍率=9、主环取景中心为 bbox 中心、南界 -55 钳制', () => {
  // v2.3.8 用户裁定：任意国家统一下钻倍率（按 bbox 自适应的 fitDrillZoom 已退役，
  // 生产零消费方——见本文件 ⑥ 后的断言）
  assert.equal(DRILL_UNIFIED_ZOOM, 9, '下钻统一倍率必须为 9')
  // 主环取景中心：五国 bbox 中心落在各自经纬范围内（取景落点不漂移到邻国）
  const names = ['俄罗斯', '中国', '美国', '法国', '沙特阿拉伯']
  for (const name of names) {
    const c = WORLD_COUNTRIES.find((x) => x.name === name)
    assert.ok(c, `worldBorders 缺 ${name}`)
    const b = principalBounds(c.polys)
    // 独立算出每环 bbox 做对表：principalBounds 必须选「面积最大的环」（本土），
    // 纬度边界与之逐值相等（纬度不参与 ±180 unwrap）。此前的「中心落在 bbox
    // 内」是代数恒真，不构成任何拦截。
    const ringBoxes = c.polys.flatMap((poly) => poly.map((ring) => {
      let minLon = 180
      let maxLon = -180
      let minLat = 90
      let maxLat = -90
      for (let i = 0; i + 1 < ring.length; i += 2) {
        const lon = ring[i]
        const lat = ring[i + 1]
        if (lon < minLon) minLon = lon
        if (lon > maxLon) maxLon = lon
        if (lat < minLat) minLat = lat
        if (lat > maxLat) maxLat = lat
      }
      return { ring, minLon, maxLon, minLat, maxLat, area: (maxLon - minLon) * (maxLat - minLat) }
    }))
    const largest = ringBoxes.reduce((a, x) => (x.area > a.area ? x : a))
    assert.equal(b.minLat, largest.minLat, `${name} 取景 bbox 纬度南界不是最大环`)
    assert.equal(b.maxLat, largest.maxLat, `${name} 取景 bbox 纬度北界不是最大环`)
    // ±180 unwrap 契约：经度跨度必须收敛（海外属地跨日界线时不得报全宽）
    assert.ok(b.maxLon - b.minLon <= 180, `${name} 取景 bbox 经度跨度 ${b.maxLon - b.minLon} 超过 180（unwrap 失效）`)
    // 经度边界必须与最大环的经度边界同余（差值是 360 的整数倍）——unwrap 选中
    // 错平移窗（例如把俄罗斯主环中心放到 -180 附近）在此变红。
    const normalizeLon = (value: number): number => ((value + 540) % 360) - 180
    assert.ok(
      Math.abs(normalizeLon(b.minLon) - normalizeLon(largest.minLon)) < 1e-9,
      `${name} 取景经度西界 ${b.minLon} 与最大环 ${largest.minLon} 不同余`,
    )
    assert.ok(
      Math.abs(normalizeLon(b.maxLon) - normalizeLon(largest.maxLon)) < 1e-9,
      `${name} 取景经度东界 ${b.maxLon} 与最大环 ${largest.maxLon} 不同余`,
    )
    // 独立从最大环重算 unwrap 中心，不能用输出 bbox 的平均值自证。
    let expectedMinLon = largest.minLon
    let expectedMaxLon = largest.maxLon
    if (expectedMaxLon - expectedMinLon > 180) {
      expectedMinLon = 720
      expectedMaxLon = -720
      for (let i = 0; i + 1 < largest.ring.length; i += 2) {
        const lon = largest.ring[i] < 0 ? largest.ring[i] + 360 : largest.ring[i]
        expectedMinLon = Math.min(expectedMinLon, lon)
        expectedMaxLon = Math.max(expectedMaxLon, lon)
      }
    }
    const expectedCenter = (expectedMinLon + expectedMaxLon) / 2
    const actualCenter = (b.minLon + b.maxLon) / 2
    assert.ok(Math.abs(actualCenter - expectedCenter) < 1e-9, `${name} 取景中心 ${actualCenter} ≠ 最大环独立中心 ${expectedCenter}`)
  }
  // 南界：投影域裁到 -55（南极洲无业务流量）——世界高与相机纵向钳制同源。
  // 总览 zoom 下可视高 ≥ 世界高 → 相机恒居中；下钻倍率下越界拖动被钳在
  // [visH/2, WORLD_D - visH/2]，画面永不越出 -55° 南界。
  assert.equal(LAT_BOTTOM, -55)
  // Mercator：世界高不再是纬度差，而是投影后高度（高纬纵向展开）。
  assert.ok(Math.abs(WORLD_D - (latToY(LAT_BOTTOM) - latToY(LAT_TOP))) < 1e-9, 'WORLD_D 与 latToY 投影不同源')
  const overviewCam = { camX: 0, camY: WORLD_D - 1, zoom: 3, width: W, height: H }
  assert.ok(H / 3 >= WORLD_D)
  assert.equal(panBy(overviewCam, 0, -100000).camY, WORLD_D / 2, '世界完整可见时相机必须纵向居中')
  const drillCam = { camX: 0, camY: 0, zoom: DRILL_UNIFIED_ZOOM, width: W, height: H }
  const visH = H / DRILL_UNIFIED_ZOOM
  const panned = panBy(drillCam, 0, -100000)
  assert.ok(Math.abs(panned.camY - (WORLD_D - visH / 2)) < 1e-9, `下钻相机下缘未钳制: camY=${panned.camY}`)
  assert.ok(panned.camY + visH / 2 <= WORLD_D + 1e-9, '相机下缘越出世界高（-55° 钳制失效）')
})

test('④c 已退役取景辅助零生产消费方（fitDrillZoom / zoomAt）', () => {
  const srcDir = join(ROOT, 'src')
  const offenders: string[] = []
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      if (!/\.(ts|vue)$/.test(entry.name)) continue
      // 先剥注释：注释里的历史说明不构成生产消费（否则维护者只能删说明或
      // 放宽扫描正则，两者都会削弱绊线）。
      if (/\b(fitDrillZoom|zoomAt)\b/.test(stripComments(code(relative(ROOT, full))))) offenders.push(full)
    }
  }
  walk(srcDir)
  assert.deepEqual(offenders, [], `已退役取景辅助仍有生产消费方: ${offenders.join(', ')}`)
})

test('④d 死代码扫描忽略注释：注释提及不构成消费，真实引用仍检出', () => {
  const commentOnly = '// fitDrillZoom 已退役\n/* zoomAt 旧实现 */\nconst keep = 1'
  assert.doesNotMatch(stripComments(commentOnly), /\b(fitDrillZoom|zoomAt)\b/, '注释中的符号名不得算作生产消费')
  const realCall = 'const camera = zoomAt(view, 2)'
  assert.match(stripComments(realCall), /\bzoomAt\b/, '真实调用必须仍被扫描命中')
})

// ---- 地球球面逆投影往返辅助（与 threatGlobe 相机基向量同构） ----
type Vec3 = [number, number, number]

function vecSub(a: Vec3, b: Vec3): Vec3 {
  return [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

function vecDot(a: Vec3, b: Vec3): number {
  return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

function vecCross(a: Vec3, b: Vec3): Vec3 {
  return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]
}

function vecNorm(a: Vec3): Vec3 {
  const len = Math.hypot(a[0], a[1], a[2])
  return [a[0] / len, a[1] / len, a[2] / len]
}

/** 经纬度 → 球面笛卡尔（three-globe polar2Cartesian 约定）。 */
function sphereXyz(lat: number, lng: number, radius: number): Vec3 {
  const phi = ((90 - lat) * Math.PI) / 180
  const a = ((90 - lng) * Math.PI) / 180
  const rho = radius * Math.sin(phi)
  return [rho * Math.cos(a), radius * Math.cos(phi), rho * Math.sin(a)]
}

/** 相机基向量（俯视球心）与正投影（球面点 → NDC）；背向相机返回 null。 */
function cameraAt(lat: number, lng: number, altitudeRatio: number, radius: number, aspect = 16 / 9) {
  const origin = sphereXyz(lat, lng, radius * (1 + altitudeRatio))
  const dir = vecNorm([-origin[0], -origin[1], -origin[2]])
  const right = vecNorm(vecCross(dir, [0, 1, 0]))
  const up = vecCross(right, dir)
  const fovHalf = (45 * Math.PI) / 360
  const cam = { origin, dir, right, up, fovHalf, aspect }
  const project = (lat2: number, lng2: number): { ndcX: number; ndcY: number } | null => {
    const v = vecSub(sphereXyz(lat2, lng2, radius), origin)
    const a = vecDot(v, dir)
    if (a <= 0) return null
    const tan = Math.tan(fovHalf)
    return { ndcX: vecDot(v, right) / a / (tan * aspect), ndcY: vecDot(v, up) / a / tan }
  }
  return { cam, project }
}

test('⑥地球球面逆投影往返：正投影的 NDC → 经纬度误差 < 1e-6°', () => {
  const R = 100 * 1.005
  let checked = 0
  // 覆盖东半球/西半球（美加 lng<-90 曾整片 miss）与高纬（俄/加）
  for (const [clat, clng] of [[35, 116], [38, -97], [60, 90], [-30, 140]] as const) {
    const { cam, project } = cameraAt(clat, clng, 1.2, R)
    for (const dLat of [-12, 0, 12]) {
      for (const dLng of [-15, 0, 15]) {
        const lat = clat + dLat
        const lng = clng + dLng
        const ndc = project(lat, lng)
        assert.ok(ndc, `目标 (${lat},${lng}) 应在相机前方`)
        const picked = sphereSurfacePoint(cam, ndc.ndcX, ndc.ndcY, R)
        assert.ok(picked, `拾取失败 (${lat},${lng})`)
        assert.ok(Math.abs(picked.lat - lat) < 1e-6, `纬度往返误差 ${picked.lat} vs ${lat}`)
        const dLon = Math.abs((((picked.lng - lng) % 360) + 540) % 360 - 180)
        assert.ok(dLon < 1e-6, `经度往返误差 ${picked.lng} vs ${lng}`)
        checked++
      }
    }
  }
  assert.equal(checked, 36)
  // 西半球经度必须还原为负值（原逆变换域 (-90°,270°] 未 wrap 时的回归形状）
  const west = cameraAt(0, -120, 1, R)
  const westNdc = west.project(0, -120)
  assert.ok(westNdc)
  const pickedWest = sphereSurfacePoint(west.cam, westNdc.ndcX, westNdc.ndcY, R)
  assert.ok(pickedWest)
  assert.ok(Math.abs(pickedWest.lng + 120) < 1e-6)
})

test('⑥b地球拾取：射线背向球面/未命中返回 null', () => {
  const R = 100
  const away = {
    origin: [0, 0, 3 * R] as Vec3,
    dir: [0, 0, 1] as Vec3,
    right: [1, 0, 0] as Vec3,
    up: [0, 1, 0] as Vec3,
    fovHalf: (45 * Math.PI) / 360,
    aspect: 1,
  }
  assert.equal(sphereSurfacePoint(away, 0, 0, R), null)
  // 正上方（+y）俯视球心命中北极
  const down = { ...away, origin: [0, 3 * R, 0] as Vec3, dir: [0, -1, 0] as Vec3, up: [0, 0, -1] as Vec3 }
  const hit = sphereSurfacePoint(down, 0, 0, R)
  assert.ok(hit)
  assert.ok(Math.abs(hit.lat - 90) < 1e-6, `北极拾取纬度 ${hit.lat}`)
})

test('⑦地图/地球引擎修复契约', () => {
  const mapSrc = code('src/utils/threatScene.ts')
  const globeSrc = code('src/utils/threatGlobe.ts')
  assert.match(mapSrc, /POINTY_TOP_HEX_VERTICES/, '地图点阵必须消费六边形顶点，而非圆弧')
  assert.doesNotMatch(mapSrc, /path\.arc\(x, y, r|ctx2\.arc\(x, y, r/)
  assert.match(mapSrc, /drillCountryAllowed\(opts\?\.drillCountries, country\)/, '地图必须执行下钻白名单')
  for (const src of [mapSrc, globeSrc]) {
    assert.doesNotMatch(src, /\baddArc\(origin: Centroid\)|\bsetControlsEnabled\(|\bpickCountryAt\(/, '零消费诊断 API 必须移除')
  }
  assert.doesNotMatch(mapSrc, /sawServerConfig/, 'setServer 不得只接受首次配置')
  assert.match(mapSrc, /server = \[centroid\[0\], centroid\[1\]\]/)
  // 两引擎的省级 hover 都必须按数据能力边界标注，不得把「无省级
  // 数据源」渲染成「该省 0 次攻击」——地图侧在此钉住，地球侧由
  // threatGlobe.spec（同断言归属地）承担，避免同一文本钉两处。
  assert.match(mapSrc, /hasProvinceStats\(/, '省级统计边界必须走共享判定')
  assert.match(mapSrc, /无省级统计/, '海外下钻浮签必须显式标注无省级统计')
})

// ---- 数据级：省板包含断言（消费运行时导出的真实数据） ----
// 原实现按「一实体一行 + 两空格缩进」逐行正则解析三个数据
// 模块源码——纯格式化（换行/缩进）即假红，结构重排则可能命中错误行（假绿）。
// 三个模块本身已 import 为本测试的运行时导出，直接对数据结构求 bbox 即可；
// 源码文本只保留「静态字面量、零运行时抓取」的构建期契约交叉校验。

interface BBox {
  minLon: number
  maxLon: number
  minLat: number
  maxLat: number
}

/** 多边形组（polygons → rings → 扁平 [lon,lat,…]）的聚合 bbox；无有效点 → null。 */
function polysBBox(polys: readonly number[][][]): BBox | null {
  let minLon = Infinity
  let maxLon = -Infinity
  let minLat = Infinity
  let maxLat = -Infinity
  for (const poly of polys) {
    for (const ring of poly) {
      for (let i = 0; i + 1 < ring.length; i += 2) {
        const lon = ring[i]
        const lat = ring[i + 1]
        if (lon < minLon) minLon = lon
        if (lon > maxLon) maxLon = lon
        if (lat < minLat) minLat = lat
        if (lat > maxLat) maxLat = lat
      }
    }
  }
  return Number.isFinite(minLon) ? { minLon, maxLon, minLat, maxLat } : null
}

/** 一组省级行（每行自身含 polys）的聚合 bbox。 */
function rowsBBox(rows: readonly { polys: readonly number[][][] }[]): BBox | null {
  let box: BBox | null = null
  for (const row of rows) {
    const b = polysBBox(row.polys)
    if (!b) continue
    box = box === null
      ? b
      : {
          minLon: Math.min(box.minLon, b.minLon),
          maxLon: Math.max(box.maxLon, b.maxLon),
          minLat: Math.min(box.minLat, b.minLat),
          maxLat: Math.max(box.maxLat, b.maxLat),
        }
  }
  return box
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
  const countryBox = new Map<string, BBox>()
  for (const country of WORLD_COUNTRIES) {
    const box = polysBBox(country.polys)
    if (box) countryBox.set(country.name, box)
  }
  assert.ok(countryBox.size >= 150, `worldBorders 国家数 ${countryBox.size} < 150`)

  // 中国高精度省界：逐省 bbox ⊆ 中国国家板 ± 18°
  const chinaCountry = countryBox.get('中国')
  assert.ok(chinaCountry, 'worldBorders 缺「中国」')
  let chinaChecked = 0
  for (const province of CHINA_PROVINCES) {
    // datav 南海诸岛为示意要素（南至 lat≈4°，内嵌于海南省多边形），NE 国界不含——豁免
    if (province.name === '南海诸岛' || province.name === '海南省') continue
    const b = polysBBox(province.polys)
    if (!b) continue
    chinaChecked++
    assert.ok(
      within(b, chinaCountry, TOL),
      `中国省界 ${province.name} 越出国家板 ±${TOL}°: ${JSON.stringify(b)} vs ${JSON.stringify(chinaCountry)}`,
    )
  }
  assert.ok(chinaChecked >= 30, `中国省界校验 ${chinaChecked} < 30`)

  // 9 国（admin1 聚合 bbox ⊆ 国家板 bbox ±18°）。选样排除海外领地成建制国家
  // （美/法/西/葡的 10m admin1 含 DOM-TOM/领地，110m 板不含——跨洋级源数据
  // 语义差非映射缺陷）；俄罗斯跨 ±180：110m 板 bbox 即全幅，包含恒成立。
  assert.ok(Object.keys(ADMIN1_PROVINCES).length >= 200, `admin1 国家数 ${Object.keys(ADMIN1_PROVINCES).length} < 200`)
  const targets = ['俄罗斯', '德国', '英国', '日本', '巴西', '印度', '澳大利亚', '意大利', '瑞典']
  let checked9 = 0
  for (const target of targets) {
    const country = countryBox.get(target)
    assert.ok(country, `worldBorders 缺 ${target}`)
    const rows = ADMIN1_PROVINCES[target]
    assert.ok(rows && rows.length > 0, `admin1Provinces 缺 ${target}`)
    const aggr = rowsBBox(rows)
    assert.ok(aggr, `${target} 省板无有效坐标`)
    assert.ok(
      within(aggr, country, TOL),
      `${target} 省板越出国家板 ±${TOL}°: ${JSON.stringify(aggr)} vs ${JSON.stringify(country)}`,
    )
    checked9++
  }
  assert.ok(checked9 === 9, `9 国校验 ${checked9} ≠ 9`)

  // 构建期契约（唯一保留的源码文本校验）：三个数据模块必须是静态字面量导出，
  // 运行时不抓取外部数据（零 CDN/零请求是威胁大屏的设计约束）。
  for (const [relative, exportPattern] of [
    ['src/utils/worldBorders.ts', /export const WORLD_COUNTRIES: CountryBorders\[\] = \[/],
    ['src/utils/admin1Provinces.ts', /export const ADMIN1_PROVINCES: Record<string, Admin1Province\[\]> = \{/],
    ['src/utils/chinaProvinces.ts', /export const CHINA_PROVINCES: ChinaProvince\[\] = \[/],
  ] as const) {
    const src = code(relative)
    assert.match(src, exportPattern, `${relative} 必须导出静态字面量`)
    assert.doesNotMatch(src, /\bfetch\(|XMLHttpRequest/, `${relative} 不得运行时抓取数据`)
  }
})

test('⑤反日界线：数据本身已包裹——俄罗斯主环 span<180 与 unwrap 分支无关', () => {
  const c = WORLD_COUNTRIES.find((x) => x.name === '俄罗斯')
  assert.ok(c)
  const b = principalBounds(c.polys)
  const span = b.maxLon - b.minLon
  assert.ok(span < 180, `俄罗斯主环 bbox span ${span.toFixed(1)}° 仍≈全宽`)
})

test('⑤b 合成跨日界线环：principalBounds 的 ±180 unwrap 分支真正生效', () => {
  // 生产数据里没有任何业务国家的主环跨 ±180（唯一跨界的南极洲已剔出
  // THREAT_COUNTRIES），所以 ⑤ 的 span<180 是数据已包裹的结果，不能当作
  // 「unwrap 已验证」的证据。这里用合成环驱动该分支：未经 unwrap 的 bbox 是
  // -170..170（span 340），unwrap 后应是 170..190（span 20）。
  const ring = [170, 60, -170, 60, -170, 65, 170, 65]
  const b = principalBounds([[ring]])
  assert.equal(b.minLon, 170, '负经度 +360 平移后西界应为 170')
  assert.equal(b.maxLon, 190, '东界应为 190（=-170+360）')
  assert.equal(b.maxLon - b.minLon, 20, 'span 必须收敛到真实宽度（未 unwrap 时为 340）')
  assert.equal(b.minLat, 60)
  assert.equal(b.maxLat, 65)
  // 取景中心落在 unwrap 窗内（180±10），不得被甩到 0 附近的对侧
  assert.equal((b.minLon + b.maxLon) / 2, 180)
})
test('2D 引擎 dispose 后不再排帧（tick/startLoop 双守卫）', () => {
  const src = code('src/utils/threatScene.ts')
  // tick 首行必须先查 disposed 再 requestAnimationFrame：dispose 后仍可能有一帧
  // 已入队（cancelAnimationFrame 只撤已排队回调，撤不掉 dispose 后 startLoop 的
  // 重排）——无守卫时 tick 自我续排，引擎销毁后 rAF 链永不停止。
  const tick = member(src, 'const tick = (): void => {')
  assert.match(tick, /^[\s\S]*?\{\s*if \(disposed\) \{\s*rafId = 0\s*return\s*\}/, 'tick 首行必须先查 disposed 并清 rafId，再排下一帧')
  // startLoop 是 dispose 后唯一能重新入队 tick 的入口（setTraffic/setPaused 等
  // 都经它），同样必须带 disposed 短路。
  const startLoop = member(src, 'const startLoop = (): void => {')
  assert.match(startLoop, /if \(disposed\) return/, 'startLoop 在 dispose 后必须直接短路')
})

test('2D 光流池满时拒绝新弧线，不淘汰已开始动画', () => {
  const src = code('src/utils/threatScene.ts')
  const start = src.indexOf('function spawnArc(')
  const end = src.indexOf('function spawnRipple(', start)
  assert.ok(start >= 0 && end > start, 'spawnArc 缺失')
  const spawn = src.slice(start, end)
  assert.match(spawn, /if \(arcs\.length >= MAX_ACTIVE_ARCS\) return/, '满池必须拒绝新弧线')
  assert.doesNotMatch(spawn, /arcs\.shift\(\)/, 'spawnArc 不得淘汰已开始弧线')
})


test('2D 拖拽捕获指针并在取消或捕获丢失时清理手势', () => {
  const src = code('src/utils/threatScene.ts')
  const down = src.slice(src.indexOf('function onPointerDown('), src.indexOf('function onPointerMove('))
  assert.match(down, /canvas\.setPointerCapture\(event\.pointerId\)/, '拖出画布后仍须持续接收同一指针事件')
  for (const type of ['pointercancel', 'lostpointercapture']) {
    assert.match(src, new RegExp(`canvas\\.addEventListener\\('${type}', onPointerUp\\)`), `${type} 必须清理拖拽态`)
    assert.match(src, new RegExp(`canvas\\.removeEventListener\\('${type}', onPointerUp\\)`), `${type} 监听必须随 dispose 摘除`)
  }
})
