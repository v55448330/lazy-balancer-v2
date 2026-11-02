// 威胁大屏共享视觉/几何单源（v2.3.8 审计收口）：地图/地球两引擎共用，
// 杜绝热力阶梯与点内判定算法双实现漂移（此前靠人工复制保持一致）。
import { CHINA_PROVINCES } from './chinaProvinces.ts'
import { COUNTRY_CENTROIDS, FALLBACK_CENTROID, type Centroid } from './countryCentroids.ts'
import { hasOwn } from './hasOwn.ts'
import { parseIpLocation } from './ipLocationParts.ts'
import { THREAT_COUNTRIES } from './worldBorders.ts'

type Rgb = [number, number, number]

/** 陆地底色（未命中/底色）：热力阶梯首色与未命中国家点阵同源——
 *  原首色 #1b2a41 比点阵底色 #2c4260 更暗，导致「命中 1 次」比 0 次更暗。 */
const LAND_BASE_RGB: Rgb = [44, 66, 96]

/** 强度整形 gamma（>1）：对数标尺的原始强度对低段过于慷慨（max=100k 时
 *  count=100 已到 40% 强度），视觉上「100 上下一过就红透」。t^1.5 把低段
 *  压回蓝域、给高段让出分辨空间；heatIntensity 保持纯对数（图例刻度/外部
 *  语义不变），整形只发生在查色路径。 */
const HEAT_GAMMA = 1.5

/** Oklab 控制点（感知均匀设计，v2.4.x 用户裁定）：低段蓝→青蓝压缩（少量
 *  攻击≈底色语义），中段经 暖灰→琥珀→橙 过渡到红（用户裁定：中间色用橙
 *  不用紫——紫与前后红/蓝亮度相近、区分度弱，橙的热力语义更直觉），
 *  高段 橙红→亮红 逐级拉开。插值在 Oklab 空间折线进行（不穿 RGB 暗浊带），
 *  出界色度按比例收缩回 sRGB 色域。 */
type OklabStop = { t: number; L: number; a: number; b: number }

function srgbToLinear(c: number): number {
  const v = c / 255
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
}

function linearToSrgb(v: number): number {
  const s = v <= 0.0031308 ? v * 12.92 : 1.055 * v ** (1 / 2.4) - 0.055
  return Math.min(1, Math.max(0, s))
}

function srgbToOklab(rgb: Rgb): { L: number; a: number; b: number } {
  const [r, g, b] = rgb.map(srgbToLinear)
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
  return {
    L: 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    a: 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    b: 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  }
}

function oklabToSrgb(L: number, a: number, b: number): Rgb {
  // 出界色度收缩：高色度红/紫超 sRGB 色域时按比例降 a/b 重投（至多 8 次迭代）。
  let ca = a
  let cb = b
  for (let i = 0; i < 8; i++) {
    const l_ = L + 0.3963377774 * ca + 0.2158037573 * cb
    const m_ = L - 0.1055613458 * ca - 0.0638541728 * cb
    const s_ = L - 0.0894841775 * ca - 1.291485548 * cb
    const lr = l_ ** 3
    const mg = m_ ** 3
    const sb = s_ ** 3
    const r = +4.0767416621 * lr - 3.3077115913 * mg + 0.2309699292 * sb
    const g = -1.2684380046 * lr + 2.6097574011 * mg - 0.3413193965 * sb
    const bl = -0.0041960863 * lr - 0.7034186147 * mg + 1.707614701 * sb
    const overflow = Math.max(0, r - 1, g - 1, bl - 1, -r, -g, -bl)
    if (overflow <= 0) {
      return [Math.round(linearToSrgb(r) * 255), Math.round(linearToSrgb(g) * 255), Math.round(linearToSrgb(bl) * 255)]
    }
    ca *= 0.92
    cb *= 0.92
  }
  return [Math.round(linearToSrgb(0) * 255), Math.round(linearToSrgb(0) * 255), Math.round(linearToSrgb(0) * 255)]
}

const BASE_OKLAB = srgbToOklab(LAND_BASE_RGB)
const HEAT_STOPS: readonly OklabStop[] = [
  { t: 0.0, ...BASE_OKLAB },       // 深蓝底（0 命中）
  { t: 0.14, L: 0.47, a: -0.045, b: -0.095 },  // 钢蓝
  { t: 0.3, L: 0.56, a: -0.055, b: -0.105 },   // 青蓝
  { t: 0.44, L: 0.6, a: 0.0, b: 0.03 },        // 暖灰过渡（蓝→橙的桥，亮度抬升防浊）
  { t: 0.58, L: 0.64, a: 0.09, b: 0.13 },      // 琥珀
  { t: 0.7, L: 0.66, a: 0.15, b: 0.14 },       // 橙
  { t: 0.84, L: 0.675, a: 0.18, b: 0.125 },    // 橙红（提亮，与头部拉开明度差）
  { t: 1.0, L: 0.6, a: 0.235, b: 0.115 },      // 亮红（数据集头部；加深压亮保近 max 对可辨）
]

/** 强度 → Oklab 折线插值 → sRGB。 */
function heatRgb(t: number): Rgb {
  const shaped = Math.min(1, Math.max(0, t))
  let seg = 0
  while (seg < HEAT_STOPS.length - 2 && shaped > HEAT_STOPS[seg + 1].t) seg++
  const a = HEAT_STOPS[seg]
  const b = HEAT_STOPS[seg + 1]
  const local = (shaped - a.t) / (b.t - a.t)
  return oklabToSrgb(
    a.L + (b.L - a.L) * local,
    a.a + (b.a - a.a) * local,
    a.b + (b.b - a.b) * local,
  )
}

// 地图/地球未命中国家点阵同色、同不透明度（用户裁定：沿用地图原透明度）。
export const DOT_LAND = `rgb(${LAND_BASE_RGB[0]},${LAND_BASE_RGB[1]},${LAND_BASE_RGB[2]})`

/** pointy-top 六边形单位顶点（地图点阵复用；避免逐点三角函数计算）。 */
export const POINTY_TOP_HEX_VERTICES: readonly (readonly [number, number])[] = [
  [0, -1],
  [Math.sqrt(3) / 2, -0.5],
  [Math.sqrt(3) / 2, 0.5],
  [0, 1],
  [-Math.sqrt(3) / 2, 0.5],
  [-Math.sqrt(3) / 2, -0.5],
]

/** 国家是否允许下钻；缺省不限，显式空列表表示全部禁止。 */
export function drillCountryAllowed(allowed: readonly string[] | undefined, country: string): boolean {
  return allowed === undefined || allowed.includes(country)
}

/** 对数热力标尺（两引擎/图例单源）：强度 = log10(1+count) / log10(1+max) ∈ [0,1]，
 *  max=当前数据集最大命中数（自适应，不写死 1000）——幂律攻击量下 1/10/100/1k/10k+
 *  每个数量级占等宽色段，头部国家不再全部饱和、长尾国家不再不可辨。
 *  count≤0=无命中恒 0（底色）；max≤0 的退化数据集（count>0 已保证）按命中即最热。 */
export function heatIntensity(count: number, maxCount: number): number {
  if (count <= 0) return 0
  const denom = Math.log10(maxCount + 1)
  if (!(denom > 0)) return 1
  return Math.min(1, Math.log10(count + 1) / denom)
}

/** 色阶查找表：强度 0..1 均分 256 档，模块加载时一次预计算（Oklab 插值 +
 *  gamma 整形在预计算期一次完成）——渲染路径只做一次 log10 + 一次查表，
 *  不逐帧重算插值；表与 max 无关，无需按数据集缓存。 */
const HEAT_LUT_SIZE = 256
const HEAT_LUT: readonly string[] = Array.from({ length: HEAT_LUT_SIZE }, (_, i) => {
  const [r, g, b] = heatRgb((i / (HEAT_LUT_SIZE - 1)) ** HEAT_GAMMA)
  return `rgb(${r},${g},${b})`
})

/** 热力色（count=数据集内命中数，maxCount=数据集最大命中数；count≤0=底色）。
 *  gamma 整形已烘焙进 LUT 构建期，查表按纯对数强度索引（勿在此二次整形）。 */
export function heatCss(count: number, maxCount: number): string {
  return HEAT_LUT[Math.round(heatIntensity(count, maxCount) * (HEAT_LUT_SIZE - 1))]
}

/** 数据集最大命中数（对数标尺的自适应 max；空集=0）。 */
export function maxHeatCount(counts: ReadonlyMap<string, number>): number {
  let max = 0
  for (const value of counts.values()) {
    if (value > max) max = value
  }
  return max
}

/** 图例渐变单源：Oklab 控制点按强度位排布成 CSS 渐变——大屏图例与两引擎
 *  同源（同一 HEAT_STOPS/LUT 口径），防漂移。 */
export function heatRampGradientCss(): string {
  const stops = HEAT_STOPS.map((stop) => {
    const [r, g, b] = heatRgb(stop.t ** HEAT_GAMMA)
    const percent = Number((stop.t * 100).toFixed(1))
    return `rgb(${r},${g},${b}) ${percent}%`
  })
  return `linear-gradient(90deg, ${stops.join(', ')})`
}

/** 图例刻度单源（对数标尺动态化）：三档位置 0/50/100%，值 = 10^(f·log10(1+max))−1
 *  取整——与 heatIntensity 同一对数标尺，刻度随数据集 max 自适应（原写死
 *  1/100/10k+ 只在万级数据集近似成立，小火/百万级数据集刻度全部错位）。
 *  0 位显式为 1（最小有意义命中数，与原图例文案一致）；max≤0 的空数据集
 *  回退历史静态三档（版面不塌缩）。标签 <1000 直接数字、≥1000 用 k 缩写
 *  （10200→10.2k，与原图例 10k+ 同族文案）。 */
export function heatLegendTicks(maxHeatCount: number): { pos: number; label: string }[] {
  if (!(maxHeatCount > 0)) {
    return [{ pos: 0, label: '1' }, { pos: 50, label: '100' }, { pos: 100, label: '10k+' }]
  }
  const span = Math.log10(1 + maxHeatCount)
  return [0, 0.5, 1].map((f) => {
    const value = f === 0 ? 1 : Math.max(1, Math.round(10 ** (f * span) - 1))
    return { pos: f * 100, label: heatLegendTickLabel(value) }
  })
}

/** 刻度值 → 图例文案：<1000 直接数字；≥1000 除以 1000 后缀 k（一位小数按需，
 *  整数不带小数点）。 */
function heatLegendTickLabel(value: number): string {
  if (value < 1000) return String(value)
  const k = Math.round((value / 1000) * 10) / 10
  return `${Number.isInteger(k) ? k : k.toFixed(1)}k`
}

/** 热力颜色过渡动画器（v2.4.x 用户裁定「按建议处理」可选加项）：数据轮询
 *  刷新时国家颜色向目标色指数平滑收敛（τ=100ms，约 0.4~0.5s 视觉收敛），消除
 *  max 变化引发的全屏跳色。首帧吸附目标色（无渐入残影）；收敛后 advance
 *  恒 false（引擎停止重绘，热路径零开销）。两引擎各持一个实例，键=国家名。 */
export interface HeatColorTransition {
  setTargets: (targets: ReadonlyMap<string, string>) => void
  advance: (dtMs: number) => boolean
  cssFor: (key: string, fallback: string) => string
}

export function createHeatColorTransition(tauMs = 100): HeatColorTransition {
  type RgbState = [number, number, number]
  const current = new Map<string, RgbState>()
  const targets = new Map<string, RgbState>()
  let active = false

  const parse = (css: string): RgbState => {
    const m = css.match(/^rgb\((\d+),(\d+),(\d+)\)$/)
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : [44, 66, 96]
  }
  const css = (s: RgbState): string => `rgb(${s[0]},${s[1]},${s[2]})`

  return {
    setTargets(next: ReadonlyMap<string, string>): void {
      let changed = next.size !== targets.size
      // 掉键清理：数据集不再包含的键必须从动画状态删除——cssFor 对残留键恒
      // 返回旧热力色，盖掉引擎传入的底色 fallback（数据集收窄/清空后的幽灵
      // 热点）。掉键必然伴随键集差：键集变大时 size 比较已置 changed；等量
      // 换键时下方遍历对不在 current 里的新键置 changed。
      for (const key of current.keys()) {
        if (!next.has(key)) current.delete(key)
      }
      targets.clear()
      for (const [key, cssColor] of next) {
        const t = parse(cssColor)
        targets.set(key, t)
        const cur = current.get(key)
        if (!cur || cur[0] !== t[0] || cur[1] !== t[1] || cur[2] !== t[2]) changed = true
      }
      if (!changed) return
      if (current.size === 0) {
        // 首帧吸附（无旧色可动画），避免初始渐入残影；此后任何变更走过渡。
        for (const [key, t] of targets) current.set(key, [...t] as RgbState)
        active = true
        return
      }
      active = true
    },
    advance(dtMs: number): boolean {
      if (!active) return false
      const k = 1 - Math.exp(-Math.max(0, dtMs) / tauMs)
      let settled = true
      for (const [key, t] of targets) {
        const cur = current.get(key)
        if (!cur) {
          current.set(key, [...t] as RgbState)
          continue
        }
        let done = true
        for (let i = 0; i < 3; i++) {
          const delta = t[i] - cur[i]
          if (Math.abs(delta) > 1) {
            cur[i] += delta * k
            done = false
          } else if (delta !== 0) {
            cur[i] = t[i]
          }
        }
        if (!done) settled = false
      }
      if (settled) active = false
      return true
    },
    cssFor(key: string, fallback: string): string {
      const cur = current.get(key)
      return cur ? css(cur) : fallback
    },
  }
}

/** 经纬度是否落在任一扁平多边形组内（ray-casting；两引擎 hover/点击共用）。 */
export function pointInPolys(lon: number, lat: number, polys: number[][][]): boolean {
  for (const poly of polys) {
    let inside = false
    for (const ring of poly) {
      for (let i = 0, j = ring.length - 2; i < ring.length; j = i, i += 2) {
        const xi = ring[i], yi = ring[i + 1], xj = ring[j], yj = ring[j + 1]
        if (yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside
      }
    }
    if (inside) return true
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

interface PolysBounds {
  minLon: number
  maxLon: number
  minLat: number
  maxLat: number
}

/** 扁平多边形组外包框（网格构建与省点阵预筛的模块内单源）。 */
function polysBounds(polys: number[][][]): PolysBounds {
  let minLon = 180
  let maxLon = -180
  let minLat = 90
  let maxLat = -90
  for (const poly of polys) {
    for (const ring of poly) {
      for (let k = 0; k + 1 < ring.length; k += 2) {
        if (ring[k] < minLon) minLon = ring[k]
        if (ring[k] > maxLon) maxLon = ring[k]
        if (ring[k + 1] < minLat) minLat = ring[k + 1]
        if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
      }
    }
  }
  return { minLon, maxLon, minLat, maxLat }
}

/**
 * 国家级 bbox 空间网格（两引擎点阵构建共用）：5° 网格把 pointInPolys 候选
 * 从 239 国全表压到个位数。地图侧原已实现，地球侧仍逐点全表扫描——两引擎
 * 首开耗时不对称的根因，抽到共享层单源。
 */
const COUNTRY_GRID_DEG = 5
const COUNTRY_GRID_MAX_X = 71
const COUNTRY_GRID_MAX_Y = 35

/** 经纬度 → 网格键（y*100+x；越界夹紧到扫描域边界）。 */
export const countryGridCell = (lon: number, lat: number): number => {
  const x = Math.min(COUNTRY_GRID_MAX_X, Math.max(0, Math.floor((lon + 180) / COUNTRY_GRID_DEG)))
  const y = Math.min(COUNTRY_GRID_MAX_Y, Math.max(0, Math.floor((lat + 90) / COUNTRY_GRID_DEG)))
  return y * 100 + x
}

/**
 * 国家 bbox 覆盖的网格 → 候选国家索引列表。bounds 可传入已算好的外包框
 * （引擎侧 hover/点击命中已缓存 bbox 时避免重复扫描多边形）。
 */
export function buildCountryCellGrid(
  countries: readonly { name: string; polys: number[][][] }[],
  bounds?: readonly PolysBounds[],
): { grid: Map<number, number[]>; bounds: PolysBounds[] } {
  const cellBounds = countries.map((c, i) => bounds?.[i] ?? polysBounds(c.polys))
  const grid = new Map<number, number[]>()
  for (let ci = 0; ci < countries.length; ci++) {
    const b = cellBounds[ci]
    const x0 = Math.min(COUNTRY_GRID_MAX_X, Math.max(0, Math.floor((b.minLon + 180) / COUNTRY_GRID_DEG)))
    const x1 = Math.min(COUNTRY_GRID_MAX_X, Math.max(0, Math.floor((b.maxLon + 180) / COUNTRY_GRID_DEG)))
    const y0 = Math.min(COUNTRY_GRID_MAX_Y, Math.max(0, Math.floor((b.minLat + 90) / COUNTRY_GRID_DEG)))
    const y1 = Math.min(COUNTRY_GRID_MAX_Y, Math.max(0, Math.floor((b.maxLat + 90) / COUNTRY_GRID_DEG)))
    for (let y = y0; y <= y1; y++) {
      for (let x = x0; x <= x1; x++) {
        const key = y * 100 + x
        const list = grid.get(key)
        if (list) list.push(ci)
        else grid.set(key, [ci])
      }
    }
  }
  return { grid, bounds: cellBounds }
}

/** 国家 bbox 覆盖网格（只读视图）：grid/bounds 仅供消费，调用方不得改写
 *  （改写会污染另一引擎的候选预筛）。类型不外泄——消费方经函数返回值推断。 */
interface ThreatCountryGrid {
  grid: ReadonlyMap<number, readonly number[]>
  bounds: readonly PolysBounds[]
}

let threatCountryGridCache: ThreatCountryGrid | null = null

/**
 * 国家 bbox 覆盖网格单例（懒初始化）：两个引擎共享同一份构建期缓存——原
 * 地图/地球每引擎每实例各自 `buildCountryCellGrid(THREAT_COUNTRIES)`，同一份
 * 国界扫两遍。相机高度（flyAltitudeFor）与命中预筛同取此处的 bounds。
 */
export function threatCountryGrid(): ThreatCountryGrid {
  threatCountryGridCache ??= buildCountryCellGrid(THREAT_COUNTRIES)
  return threatCountryGridCache
}

interface ProvinceGridDot {
  lat: number
  lng: number
  key: string
}

/** 布点行（纬度 + 错列经度偏移）。 */
export interface ProvinceDotRow {
  lat: number
  lonOffset: number
}

/**
 * 下钻省点阵：错列经纬网格 × 省多边形命中（首个命中省取色键=行政短名）。
 * 省级 bbox 预筛（与 threatScene 省级预筛同构）：34 省 × 全网格
 * 直接 pointInPolys 在宽幅国家首次下钻产生明显长任务；先按省 bbox 排除绝
 * 大多数省份，再对候选做射线判定。bbox 是命中判定的保守超集，预筛不改变
 * 产出点集。
 *
 * 行迭代器参数化：默认等纬度步长（地球引擎口径）；地图引擎传 Mercator
 * 投影 y 步长的行集（两引擎的有意分歧点），bbox 预筛 + 射线命中 + 首中省
 * 取色的主体在此单源。
 */
export function provinceDotGrid(
  source: readonly { name: string; polys: number[][][] }[],
  step: number,
  rows: (minLat: number, maxLat: number) => readonly ProvinceDotRow[] = (minLat, maxLat) => {
    const equalLatRows: ProvinceDotRow[] = []
    let row = 0
    for (let lat = minLat; lat <= maxLat; lat += step, row++) {
      equalLatRows.push({ lat, lonOffset: row % 2 === 1 ? step / 2 : 0 })
    }
    return equalLatRows
  },
): ProvinceGridDot[] {
  let minLon = 180
  let maxLon = -180
  let minLat = 90
  let maxLat = -90
  const bounds = source.map((pv) => {
    const b = polysBounds(pv.polys)
    if (b.minLon < minLon) minLon = b.minLon
    if (b.maxLon > maxLon) maxLon = b.maxLon
    if (b.minLat < minLat) minLat = b.minLat
    if (b.maxLat > maxLat) maxLat = b.maxLat
    return b
  })
  const dots: ProvinceGridDot[] = []
  for (const { lat, lonOffset } of rows(minLat, maxLat)) {
    for (let lon = minLon + lonOffset; lon <= maxLon; lon += step) {
      for (let pi = 0; pi < source.length; pi++) {
        const b = bounds[pi]
        if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
        if (!pointInPolys(lon, lat, source[pi].polys)) continue
        dots.push({ lat, lng: lon, key: adminShortName(source[pi].name) })
        break
      }
    }
  }
  return dots
}

/**
 * 热力数据指纹比较：引擎 setCountries/setProvinces
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
 * 地球弧线端点：起点=归属地质心，终点=本站。
 * 本站坐标是可变状态（配置到达后 setServer），弧线对象必须按当前值快照——
 * 抽成纯函数后可由 node:test 断言「终点随 server 更新」，防止退回构造期常量。
 */
export function arcEndpoints(
  self: readonly [number, number],
  origin: readonly [number, number],
): { startLat: number; startLng: number; endLat: number; endLng: number } {
  return { startLat: origin[1], startLng: origin[0], endLat: self[1], endLng: self[0] }
}

/** 归属地文本 → 光流起点（中国精确到省质心，其余国家质心，未知走兜底点）。
 *  地图/地球两引擎共用，避免省/国家查找与回退规则双实现漂移。
 *  国家名先经 normalizeCountryName（台湾→中国），与热力/正常光流口径一致。 */
export function arcOriginForLocation(ipLocation: string): Centroid {
  const { country: rawCountry, province } = parseIpLocation(ipLocation)
  if (!rawCountry) return FALLBACK_CENTROID
  const country = normalizeCountryName(rawCountry)
  if (country === '中国' && province) {
    const pv = CHINA_PROVINCES.find((x) => x.short === province || x.name === province)
    if (pv) return [pv.centroid[0], pv.centroid[1]]
  }
  const centroid = hasOwn(COUNTRY_CENTROIDS, country) ? COUNTRY_CENTROIDS[country] : undefined
  return centroid ?? FALLBACK_CENTROID
}

/** 中国领土口径：世界边界数据中 Taiwan 为独立条目，但威胁大屏按中国的一部分
 *  展示/高亮/下钻（用户裁定 2026-10-18）。所有国家名消费点在查表前归一到
 *  中国，计数在写入时合并。 */
export function normalizeCountryName(name: string): string {
  return name === 'Taiwan' || name === '台湾' ? '中国' : name
}

/** 正常流光流的国家 → 弧线起点：先归一（台湾→中国，见 normalizeCountryName）
 *  再查质心表，未知走兜底点。地图/地球两引擎 setTraffic 共用——原各自
 *  `COUNTRY_CENTROIDS[key] ?? FALLBACK` 且未归一（「台湾」落太平洋兜底点，
 *  与热力「计数并入中国」口径不一致）。 */
export function trafficOriginForCountry(name: string): Centroid {
  const country = normalizeCountryName(name)
  const centroid = hasOwn(COUNTRY_CENTROIDS, country) ? COUNTRY_CENTROIDS[country] : undefined
  return centroid ?? FALLBACK_CENTROID
}

/**
 * 该下钻国家是否有省级统计源：后端 `threatLocationParts` 只对中国
 * 从归属地串取省，`china_provinces` 也只聚合中国省——海外下钻的省板是纯几何，
 * UI 必须显示「无省级统计」而不是 0，避免把缺失当成「该省 0 次攻击」。
 */
export function hasProvinceStats(country: string): boolean {
  return country === '中国'
}

/**
 * 异步下钻续体的提交判定：`seq` 已被返回/复位/销毁递增，或引擎已
 * 销毁 → 丢弃加载结果。地图/地球共用，防止一侧补了作废逻辑另一侧漏（原地球
 * 的 zoomOut/resetView 不递增 drillSeq，迟到的 chunk 会把用户刚做的复位覆盖）。
 */
export function drillCommitAllowed(seq: number, currentSeq: number, disposed: boolean): boolean {
  return seq === currentSeq && !disposed
}

/**
 * 下钻态点击手势意图（两引擎单源）：下钻中命中国=当前下钻国 → 'stay'（保持），
 * 命中他国 → 'switch'，空白 → 'world'（返回世界）；总览态命中 → 'drill'，
 * 空白 → 'none'。
 *
 * 历史：地图引擎 onClick 缺 'stay' 分支——下钻后单击国境内任意处都会重新下钻
 * （清 hover + 全量重建省点阵 + 把用户拖动后的取景拉回国土中心），与地球引擎
 * 「本省保持」相反。手势语义必须在共享层单源，避免一侧补了一侧漏。
 */
export function drillClickIntent(hit: string | null, drilled: string | null): 'none' | 'drill' | 'stay' | 'switch' | 'world' {
  if (!drilled) return hit ? 'drill' : 'none'
  if (!hit) return 'world'
  return hit === drilled ? 'stay' : 'switch'
}

/** 国家计数归一+合并：台湾计数并入中国，避免 hover 中国时台湾计数缺失。 */
export function aggregateCountryCounts(entries: readonly { name: string; count: number }[]): Map<string, number> {
  const out = new Map<string, number>()
  for (const e of entries) {
    const key = normalizeCountryName(e.name)
    out.set(key, (out.get(key) ?? 0) + e.count)
  }
  return out
}
