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

/** 滚轮缩放（锚点=指针）：返回新 camX/camY/zoom。 */
export function zoomAt(cam: Cam2D, px: number, py: number, factor: number, minZoom: number, maxZoom: number): Cam2D {
  // v26：lon/camX 环绕（缩放漂移至 ±180 外时归一）
  const lon = wrapDeg(cam.camX + (px - cam.width / 2) / cam.zoom)
  const y = cam.camY + (py - cam.height / 2) / cam.zoom
  const zoom = Math.min(maxZoom, Math.max(minZoom, cam.zoom * factor))
  const camX = wrapDeg(lon - (px - cam.width / 2) / zoom)
  let camY = y - (py - cam.height / 2) / zoom
  const visH = cam.height / zoom
  if (visH >= WORLD_D) camY = WORLD_D / 2
  else camY = Math.min(WORLD_D - visH / 2, Math.max(visH / 2, camY))
  return { ...cam, camX, camY, zoom }
}

/**
 * 下钻取景（v14⑤a 2D 口径）：包围盒宽高分别适配视口取较小 zoom
 * （2D 中 zoom 小=看得多），钳 [minZoom, 24]；unwrap 后中心经度归一主带。
 */
export function fitDrillZoom(
  bboxW: number,
  bboxH: number,
  width: number,
  height: number,
  minZoom: number,
): number {
  const zoomW = width / (bboxW * 1.15)
  const zoomH = height / (bboxH * 1.35)
  return Math.min(200, Math.max(minZoom, Math.min(zoomW, zoomH)))
}

export interface BoundsBox {
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
