// 威胁大屏 2D 地图投影/相机数学（v16：Canvas 2D 平面引擎单源，node:test 可直接验证）。
//
// 坐标系：
//   - 世界：等距圆柱平铺，lon∈[-180,180] 平铺（X 无限环绕，1°=1 单位），
//     lat∈[LAT_BOTTOM, LAT_TOP]（Y 向下递增，y = LAT_TOP - lat）
//   - 屏幕：CSS 像素，原点左上；sx = cw/2 + (lon - camX)×zoom，
//     sy = ch/2 + (y - camY)×zoom
//   - 相机：camX（中心经度，任意实数，绘制按 360° 就近副本）、camY（中心 y，
//     纵向钳制在世界高内）、zoom（CSS 像素/度，恒定纵横比=永不变形）

export const LAT_TOP = 83
// v2.3.8：投影域南界 -60→-55——南极洲无业务流量（用户裁定剔除），回收
// 底部占位带宽；-55 保留南美/新西兰最南端（合恩角 ~-56 以点阵粒度可忽略）。
export const LAT_BOTTOM = -55
export const WORLD_W = 360

// 点阵扫描纬度域（两引擎共用）：由投影域派生 + 上下余量，改投影域时点阵覆盖
// 自动跟随。历史实现两引擎各自写死 84 / -54.5，与 LAT_TOP/LAT_BOTTOM 脱钩——
// 调投影域时会出现「地图裁掉了但球面还在布点」的漂移。
export const DOT_LAT_TOP = LAT_TOP + 1
export const DOT_LAT_BOTTOM = LAT_BOTTOM + 0.5

// Web Mercator：x 仍为 1°/单位；y 按 Mercator 展开，赤道处 1°=1 单位，
// 高纬纵向拉开——解决等距圆柱映射下高纬国家被横向拉扁的问题。
// WORLD_D 不再是纬度差，而是投影后的世界高度。
const MERCATOR_R = 180 / Math.PI
const mercator = (lat: number): number => Math.log(Math.tan(Math.PI / 4 + (lat * Math.PI) / 360))
const Y_TOP = mercator(LAT_TOP)
const Y_BOTTOM = mercator(LAT_BOTTOM)
export const WORLD_D = (Y_TOP - Y_BOTTOM) * MERCATOR_R

export function wrapDeg(delta: number): number {
  return (((delta % 360) + 540) % 360) - 180
}

export function wrapLon(lon: number): number {
  return wrapDeg(lon)
}

export function latToY(lat: number): number {
  const clamped = Math.max(LAT_BOTTOM, Math.min(LAT_TOP, lat))
  return (Y_TOP - mercator(clamped)) * MERCATOR_R
}

export function yToLat(y: number): number {
  const m = Y_TOP - y / MERCATOR_R
  return ((2 * Math.atan(Math.exp(m)) - Math.PI / 2) * 180) / Math.PI
}

export interface Cam2D {
  camX: number
  camY: number
  zoom: number
  width: number
  height: number
}

/** 世界（平铺经度取就近副本） → 屏幕 CSS 像素。 */
export function worldToScreen(lon: number, lat: number, cam: Cam2D): { x: number; y: number } {
  const base = cam.camX + wrapDeg(lon - cam.camX)
  return {
    x: cam.width / 2 + (base - cam.camX) * cam.zoom,
    y: cam.height / 2 + (latToY(lat) - cam.camY) * cam.zoom,
  }
}

/** 屏幕 CSS 像素 → 地理经纬（经度归一 [-180,180)）。 */
export function screenToLonLat(px: number, py: number, cam: Cam2D): { lon: number; lat: number } {
  const lon = cam.camX + (px - cam.width / 2) / cam.zoom
  const y = cam.camY + (py - cam.height / 2) / cam.zoom
  return { lon: wrapLon(lon), lat: yToLat(y) }
}

/** 拖动平移：屏幕像素位移 → 相机位移（横向自由、纵向钳制返回值）。 */
export function panBy(cam: Cam2D, dxPx: number, dyPx: number): { camX: number; camY: number } {
  const camX = cam.camX - dxPx / cam.zoom
  const visH = cam.height / cam.zoom
  let camY = cam.camY - dyPx / cam.zoom
  if (visH >= WORLD_D) camY = WORLD_D / 2
  else camY = Math.min(WORLD_D - visH / 2, Math.max(visH / 2, camY))
  return { camX, camY }
}

/** 下钻统一视角倍率（用户裁定 2026-10-17）：任意国家一致，配合拖动查看。
 *  单源常量放在此模块——引擎与确定性单测同源消费（原置于 threatScene 内，
 *  只能源文本断言）。 */
export const DRILL_UNIFIED_ZOOM = 9

/** 球面相机基向量（正交归一；球心=原点、半径=radius 的世界坐标系）。 */
interface SpherePickCamera {
  readonly origin: readonly [number, number, number]
  readonly dir: readonly [number, number, number]
  readonly right: readonly [number, number, number]
  readonly up: readonly [number, number, number]
  /** 纵向半视角（弧度）。 */
  readonly fovHalf: number
  readonly aspect: number
}

/**
 * 地球引擎自研拾取的逆投影单源：NDC 坐标 + 相机基向量 → 射线 ∩
 * 半径 radius 的球面 → three-globe 球面约定经纬度（经度 wrap 到 [-180,180)）。
 * 原实现内嵌在 threatGlobe 闭包里（依赖 three/globe 实例），无法确定性断言；
 * 抽成纯数学后可经「正投影→逆投影」往返验证西半球 wrap 与高纬极区。
 * 射线背向球面/未命中返回 null。
 */
export function sphereSurfacePoint(
  cam: SpherePickCamera,
  ndcX: number,
  ndcY: number,
  radius: number,
): { lat: number; lng: number } | null {
  const tx = ndcX * Math.tan(cam.fovHalf) * cam.aspect
  const ty = ndcY * Math.tan(cam.fovHalf)
  let rx = cam.dir[0] + cam.right[0] * tx + cam.up[0] * ty
  let ry = cam.dir[1] + cam.right[1] * tx + cam.up[1] * ty
  let rz = cam.dir[2] + cam.right[2] * tx + cam.up[2] * ty
  const len = Math.hypot(rx, ry, rz)
  if (!(len > 0)) return null
  rx /= len
  ry /= len
  rz /= len
  // 射线 ∩ 球（球心原点）：|o + t·d|² = r²
  const b = cam.origin[0] * rx + cam.origin[1] * ry + cam.origin[2] * rz
  const c = cam.origin[0] ** 2 + cam.origin[1] ** 2 + cam.origin[2] ** 2 - radius * radius
  const disc = b * b - c
  if (disc < 0) return null
  const t = -b - Math.sqrt(disc)
  if (t < 0) return null
  const px = cam.origin[0] + rx * t
  const py = cam.origin[1] + ry * t
  const pz = cam.origin[2] + rz * t
  const lat = 90 - (Math.acos(Math.max(-1, Math.min(1, py / radius))) * 180) / Math.PI
  // three-globe 球面约定（polar2Cartesian 逆变换）产出域 (-90°, 270°]，
  // 必须 wrap 到 [-180,180)：西半球（美/加等 lng<-90）曾整片 hover/点击 miss。
  const lng = wrapDeg(90 - (Math.atan2(pz, px) * 180) / Math.PI)
  return { lat, lng }
}

interface BoundsBox {
  minLon: number
  maxLon: number
  minLat: number
  maxLat: number
}

/**
 * 主环取景 bbox：只用最大环（本土）bbox，跨 ±180 时负经度 +360 unwrap 重算
 * （消除「lon 范围≈全宽」的伪 bbox）。引擎取景与确定性单测共用此实现。
 */
export function principalBounds(polys: number[][][]): BoundsBox {
  let best: (BoundsBox & { area: number; ring: number[] }) | null = null
  for (const poly of polys) {
    for (const ring of poly) {
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
      const area = (maxLon - minLon) * (maxLat - minLat)
      if (!best || area > best.area) best = { minLon, maxLon, minLat, maxLat, area, ring }
    }
  }
  if (!best) return { minLon: 0, maxLon: 0, minLat: 0, maxLat: 0 }
  if (best.maxLon - best.minLon > 180) {
    // 第二遍只遍历选中的最大环（契约「只用最大环」）：海外领地环不得并入
    // unwrap 窗——主环跨界+领地环时并入会把取景 bbox 拉偏到对侧。
    let minLon = 720
    let maxLon = -720
    const ring = best.ring
    for (let i = 0; i + 1 < ring.length; i += 2) {
      const lon = ring[i] < 0 ? ring[i] + 360 : ring[i]
      if (lon < minLon) minLon = lon
      if (lon > maxLon) maxLon = lon
    }
    if (maxLon - minLon < best.maxLon - best.minLon) {
      return { minLon, maxLon, minLat: best.minLat, maxLat: best.maxLat }
    }
  }
  return { minLon: best.minLon, maxLon: best.maxLon, minLat: best.minLat, maxLat: best.maxLat }
}
