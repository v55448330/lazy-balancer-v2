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
export const WORLD_D = LAT_TOP - LAT_BOTTOM

export function wrapDeg(delta: number): number {
  return (((delta % 360) + 540) % 360) - 180
}

export function wrapLon(lon: number): number {
  return wrapDeg(lon)
}

export function latToY(lat: number): number {
  return LAT_TOP - lat
}

export function yToLat(y: number): number {
  return LAT_TOP - y
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

/**
 * 视口经度范围 → 覆盖的 12° 分桶键序列（去重、按世界带归一）。
 *
 * 世界点阵按 `Math.floor(lon / 12)` 分桶（lon∈[-180,180) → 键 -15..14）。
 * 下钻态横向拖动跨日界线时 minLon/maxLon 会越出世界带（camX 自由实数），
 * 直接 floor 得到的键不在桶表中 → 整段点阵消失。此处把每个键按
 * `((b + 15) % 30) - 15` 归一，与渲染公式 `wrapDeg` 同源。
 */
export function wrappedBucketKeys(minLon: number, maxLon: number, bucketSize = 12): number[] {
  const count = Math.round(WORLD_W / bucketSize)
  const first = Math.floor(minLon / bucketSize)
  const last = Math.floor(maxLon / bucketSize)
  const half = count / 2
  const keys: number[] = []
  const seen = new Set<number>()
  for (let b = first; b <= last; b++) {
    const key = (((b + half) % count) + count) % count - half
    if (seen.has(key)) continue
    seen.add(key)
    keys.push(key)
  }
  return keys
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
  let best: (BoundsBox & { area: number }) | null = null
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
      if (!best || area > best.area) best = { minLon, maxLon, minLat, maxLat, area }
    }
  }
  if (!best) return { minLon: 0, maxLon: 0, minLat: 0, maxLat: 0 }
  if (best.maxLon - best.minLon > 180) {
    let minLon = 720
    let maxLon = -720
    for (const poly of polys) {
      for (const ring of poly) {
        for (let i = 0; i + 1 < ring.length; i += 2) {
          const lon = ring[i] < 0 ? ring[i] + 360 : ring[i]
          if (lon < minLon) minLon = lon
          if (lon > maxLon) maxLon = lon
        }
      }
    }
    if (maxLon - minLon < best.maxLon - best.minLon) {
      return { minLon, maxLon, minLat: best.minLat, maxLat: best.maxLat }
    }
  }
  return { minLon: best.minLon, maxLon: best.maxLon, minLat: best.minLat, maxLat: best.maxLat }
}
