// 威胁大屏共享视觉/几何单源（v2.3.8 审计 R1-R5 收口）：地图/地球两引擎共用，
// 杜绝热力阶梯与点内判定算法双实现漂移（此前靠人工复制保持一致）。
export type Rgb = [number, number, number]

/** 热力四段阶梯（与后端口径无关，纯前端视觉）：底色→暗红→红→亮红。 */
export const HEAT_LADDER: Rgb[] = [
  [27, 42, 65], // 底色 #1b2a41
  [150, 74, 60], // #964a3c
  [194, 85, 61], // #c2553d
  [226, 84, 84], // #e25454
]

export const DOT_LAND = 'rgb(27,42,65)'

/** 热力色（log10 计数 1→1000 三段线性插值；count≤0=底色）。 */
export function heatColor(count: number): Rgb {
  const t = Math.min(1, Math.max(0, Math.log10(Math.max(1, count)) / 3))
  const seg = t < 1 / 3 ? 0 : t < 2 / 3 ? 1 : 2
  const local = t * 3 - seg
  const a = HEAT_LADDER[seg]
  const b = HEAT_LADDER[seg + 1]
  return [
    Math.round(a[0] + (b[0] - a[0]) * local),
    Math.round(a[1] + (b[1] - a[1]) * local),
    Math.round(a[2] + (b[2] - a[2]) * local),
  ]
}

export function heatCss(count: number): string {
  const [r, g, b] = heatColor(count)
  return `rgb(${r},${g},${b})`
}

/** 经纬度是否落在任一扁平多边形组内（ray-casting；两引擎 hover/点击共用）。 */
export function pointInPolys(lon: number, lat: number, polys: number[][][]): boolean {
  for (const poly of polys) {
    for (const ring of poly) {
      let inside = false
      for (let i = 0, j = ring.length - 2; i < ring.length; j = i, i += 2) {
        const xi = ring[i], yi = ring[i + 1], xj = ring[j], yj = ring[j + 1]
        if (yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside
      }
      if (inside) return true
    }
  }
  return false
}

/** 行政区名去后缀（广西壮族自治区→广西；两引擎+事件流标签共用）。 */
export function adminShortName(name: string): string {
  const suffixes = ['壮族自治区', '回族自治区', '维吾尔自治区', '自治区', '特别行政区', '省', '市']
  for (const suf of suffixes) {
    if (name.endsWith(suf) && name.length > suf.length) return name.slice(0, -suf.length)
  }
  return name
}
