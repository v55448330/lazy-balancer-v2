// 威胁大屏共享视觉/几何单源（v2.3.8 审计 R1-R5 收口）：地图/地球两引擎共用，
// 杜绝热力阶梯与点内判定算法双实现漂移（此前靠人工复制保持一致）。
type Rgb = [number, number, number]

/** 热力四段阶梯（与后端口径无关，纯前端视觉）：底色→暗红→红→亮红。 */
const HEAT_LADDER: Rgb[] = [
  [27, 42, 65], // 底色 #1b2a41
  [150, 74, 60], // #964a3c
  [194, 85, 61], // #c2553d
  [226, 84, 84], // #e25454
]

export const DOT_LAND = 'rgb(27,42,65)'

/** 热力色（log10 计数 1→1000 三段线性插值；count≤0=底色）。 */
function heatColor(count: number): Rgb {
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

/**
 * 热力数据指纹比较（第 78 轮 U15-F07 纯函数层）：引擎 setCountries/setProvinces
 * 每 30s 轮询重放同一份计数——长度 + 逐键计数浅比较，无变化时调用方跳过
 * 静态层重建（原恒置脏位 → 每轮全量栅格化整幅离屏画布）。
 * 重复键视为变化（Map 语义下后者覆盖，指纹不可当相等）。
 */
export function heatEntriesEqual(prev: ReadonlyMap<string, number>, next: readonly { name: string; count: number }[]): boolean {
  if (prev.size !== next.length) return false
  const seen = new Set<string>()
  for (const entry of next) {
    if (seen.has(entry.name)) return false
    seen.add(entry.name)
    if (prev.get(entry.name) !== entry.count) return false
  }
  return true
}

/**
 * 地球弧线端点（第 78 轮 L07-F03 纯函数接缝）：起点=归属地质心，终点=本站。
 * 本站坐标是可变状态（配置到达后 setServer），弧线对象必须按当前值快照——
 * 抽成纯函数后可由 node:test 断言「终点随 server 更新」，防止退回构造期常量。
 */
export function arcEndpoints(
  self: readonly [number, number],
  origin: readonly [number, number],
): { startLat: number; startLng: number; endLat: number; endLng: number } {
  return { startLat: origin[1], startLng: origin[0], endLat: self[1], endLng: self[0] }
}
