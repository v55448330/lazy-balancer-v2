import {
  LAT_TOP,
  LAT_BOTTOM,
  DOT_LAT_TOP,
  DOT_LAT_BOTTOM,
  WORLD_W,
  WORLD_D,
  DRILL_UNIFIED_ZOOM,
  latToY,
  yToLat,
  wrapDeg,
  wrapLon,
  worldToScreen,
  screenToLonLat,
  panBy,
  principalBounds,
  type Cam2D,
} from '@/utils/threatProjection'
import { THREAT_COUNTRIES } from '@/utils/worldBorders'
import { hasOwn } from '@/utils/hasOwn'
import { CHINA_PROVINCES } from '@/utils/chinaProvinces'
import { heatCss, heatEntriesEqual, pointInPolys as sharedPointInPolys, adminShortName as sharedShortName, DOT_LAND as SHARED_DOT_LAND, normalizeCountryName, aggregateCountryCounts, buildCountryCellGrid, countryGridCell, POINTY_TOP_HEX_VERTICES, drillCountryAllowed, arcOriginForLocation, hasProvinceStats, drillCommitAllowed, drillClickIntent, polysBounds, trafficOriginForCountry } from '@/utils/threatShared'
import type { Centroid } from '@/utils/countryCentroids'
import { loadAdmin1Tables } from '@/utils/admin1Loader'
import { FLOW_ATTACK_COLOR as ATTACK_COLOR, FLOW_NORMAL_COLOR as NORMAL_COLOR, FLOW_FLIGHT_MS, FLOW_HOVER_TIP_COLOR, FLOW_RIPPLE_SECONDS, FLOW_RIPPLE_START_RADIUS, FLOW_RIPPLE_GROWTH_RADIUS, FLOW_RIPPLE_LINE_WIDTH, FLOW_RIPPLE_ALPHA, easeOutCubic, flowArcLabel, flowArcTierWidth, type FlowArcTier } from '@/utils/threatTheme'
import { planFlowArcs } from '@/utils/threatFlowRules'

// 威胁大屏 2D 平面地图引擎（v16 终版：Canvas 2D，参考 Radware/Check Point 平面风格）。
//
// v16 终审裁定弃 3D：等距圆柱平铺、等比缩放永不变形、DPR 原生渲染、线宽恒
// 1 物理像素。分层渲染：静态层（陆地+国家点阵热力）按 zoom/数据缓存离屏 canvas，
// 拖动=blit（360° 环绕三份拼接）；动态层（弧线/涟漪/扫掠/信标/hover/下钻省层）
// 每帧矢量叠绘。对外接口与 3D 版完全一致（ThreatScreen.vue 零改动）。
//
// 热力=绝对标尺（1→1000 命中，log10 归一），砖红三档 #964a3c/#c2553d/#e25454，
// 低命中向陆地底色 #2c4260 插值（与未命中点阵同源，命中 1 次不得更暗）；
// 无挤出无悬浮无双层——纯平面。
// 交互：左键拖动平移（横向 360° 无缝环绕、纵向钳制）、**滚轮不参与缩放**（用户
// 裁定 2026-10-17：缩放仅经点击下钻/返回流程控制）、hover=国家提亮+浮签、
// 点击国家下钻省级平面、点击空白返回、ESC 语义在 Vue 层。

const MAX_PIXEL_RATIO = 2
const MAX_ACTIVE_ARCS = 60
const ARC_FLIGHT_SECONDS = FLOW_FLIGHT_MS / 1000
const ARC_FLIGHT_GAP = 0.22
const ARC_FLIGHT_PARTICLES = 12
const ZOOM_SECONDS = 0.6
const RIPPLE_POOL = 12
// 静态层离屏位图宽度上限（物理像素）。总览 zoom 随视口宽度增长（width×2/360），
// 4K 屏可达 ~14，叠加 DPR 2 后宽度 >1 万物理像素（≈160MB）——超过上限时
// 按上限分配、由 blit 放大（极端屏轻微软化，换取内存有界；
// 明确要求把 dpr 计入本判定）。
const MAX_STATIC_WIDTH = 4096
// 绝对热力标尺（log10(命中)/3 → 0..1），砖红三档，首段向底色插值

export interface CountryHeat {
  name: string
  count: number
}

export interface ThreatSceneOptions {
  serverCentroid?: Centroid | null
  /** 未配置站点坐标时隐藏本站信标与弹道，避免画出一个假站点。 */
  siteConfigured?: boolean
  /** 允许下钻的国家（缺省不限）；用于禁止无省级数据的海外下钻。 */
  drillCountries?: string[]
  onDrillChange?: (name: string | null) => void
  /** 省界数据按需加载失败（视图层 toast 一次；引擎按「无省层」降级不白屏）。 */
  onProvinceLoadError?: () => void
}

export interface ThreatScene {
  addArcForLocation(ipLocation: string, weight?: number, tier?: FlowArcTier): void
  /** 正常请求光流（固定青色；逐请求事件流消费）。 */
  addNormalArcForLocation(ipLocation: string, weight?: number, tier?: FlowArcTier): void
  setCountries(entries: CountryHeat[]): void
  setProvinces(entries: CountryHeat[]): void
  setTraffic(entries: CountryHeat[]): void
  setServer(centroid: Centroid | null): void
  zoomOut(): void
  /** 复位视角（总览/本站居中，600ms）。 */
  resetView(): void
  /** 相机状态（诊断；cx/cy 为地理坐标中心）。 */
  cameraState(): { zoom: number; cx: number; cy: number; dist: number; pos: [number, number, number] }
  setPaused(paused: boolean): void
  dispose(): void
}

interface Centroid2D {
  x: number
  y: number
}

interface Arc2D {
  from: Centroid
  elapsed: number
  flightT: number
  pulsed: boolean
  normal: boolean
  weight: number
  tier: FlowArcTier
  label?: string
}

interface Ripple2D {
  age: number
  color: string
}



function easeInOutCubic(t: number): number {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2
}

function pointInPolys(lon: number, lat: number, polys: number[][][]): boolean {
  return sharedPointInPolys(lon, lat, polys)
}

/** 世界坐标点阵路径（x=lon+180, y=latToY(lat)，半径按世界单位）→ 屏幕的
 *  仿射变换 + 经度裁剪窗。
 *
 * （悬停高亮每帧重建 Path2D）：路径按国家/省在世界坐标缓存一次，
 *  绘制只做 setTransform；相机平移/缩放不再触发路径重建。
 *  三份世界拷贝（±360°×zoom）覆盖环绕显示；裁剪窗宽=360°×zoom、居中于相机
 *  经度，保证每个点只在「最近副本」上出现一次（与旧逐点 wrapDeg 定位等价，
 *  且在画布宽于一个世界时不会重复提亮）。 */
interface HoverLayerTransform {
  /** 世界单位 → CSS 像素。 */
  scale: number
  /** 世界拷贝 0（路径坐标直接落屏）的屏幕平移。 */
  tx: number
  ty: number
  /** 一份世界拷贝的屏幕宽度（±360° 环绕的平移量）。 */
  worldPx: number
  /** 最近副本经度窗（CSS 像素；宽 360°×zoom，居中于相机经度）。 */
  clipX: number
  clipWidth: number
}

export function hoverLayerTransform(cam: Cam2D): HoverLayerTransform {
  const baseLon = wrapLon(cam.camX)
  return {
    scale: cam.zoom,
    tx: cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom,
    ty: cam.height / 2 - cam.camY * cam.zoom,
    worldPx: WORLD_W * cam.zoom,
    clipX: cam.width / 2 - (WORLD_W / 2) * cam.zoom,
    clipWidth: WORLD_W * cam.zoom,
  }
}

function makeLabelElement(text: string, color: string): HTMLDivElement {
  // 悬停浮签（引擎自管 DOM）：样式内联单源——scoped CSS 无法作用于引擎
  // 动态创建的节点（原 `.label-layer div` 选择器零匹配），背景/内边距/圆角
  // 此前完全缺失（深色底图上白字无底衬）。地球版 hoverTip 同视觉。
  const div = document.createElement('div')
  div.className = 'ts-label'
  div.textContent = text
  div.style.cssText = 'position:absolute;z-index:6;pointer-events:none;padding:5px 10px;background:rgba(4,12,32,.92);border:1px solid rgba(80,170,255,.45);border-radius:2px;color:' + color + ';font:12px "Noto Sans SC","PingFang SC",sans-serif;white-space:nowrap'
  return div
}

export function createThreatScene(container: HTMLElement, opts?: ThreatSceneOptions): ThreatScene {
  const onDrillChange = opts?.onDrillChange
  let siteConfigured = opts?.siteConfigured ?? !!opts?.serverCentroid
  let server: Centroid = opts?.serverCentroid ?? [0, (LAT_TOP + LAT_BOTTOM) / 2]

  // ---- 基建 ----
  const canvas = document.createElement('canvas')
  canvas.style.width = '100%'
  canvas.style.height = '100%'
  canvas.style.display = 'block'
  canvas.style.cursor = 'grab'
  container.appendChild(canvas)
  const ctx = canvas.getContext('2d')!

  // 标签层（CSS2D 等价：绝对定位 DOM）
  const labelLayer = document.createElement('div')
  labelLayer.style.position = 'absolute'
  labelLayer.style.inset = '0'
  labelLayer.style.overflow = 'hidden'
  labelLayer.style.pointerEvents = 'none'
  container.appendChild(labelLayer)

  // 静态层（世界：陆地+染色+国界；zoom/数据变化时重建，拖动=blit）
  const staticCanvas = document.createElement('canvas')
  const staticCtx = staticCanvas.getContext('2d')!

  let dpr = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)
  let minZoom = 1

  const cam: Cam2D = { camX: 0, camY: 0, zoom: 2, width: 1, height: 1 }
  // v26：总览按宽高双适配（取较小 zoom）——顶栏/底部卡片占位后上下留边，
  // 国家不再贴边无法点选。
  // v2.3.8 三轮放大（用户裁定）：高度项 = 可视高 90%（上下各留 5%），
  // 宽度项 = 视口宽 ×2 / 世界宽——2 倍宽度只保证横向 180° 可见（360° 环绕
  // 冗余可裁），所以 16:9 等宽屏下恒由高度项主导；窄/竖屏容器才可能由宽度项
  // 主导（可见经度多于 180°）。
  const overviewZoom = (): number => Math.max(minZoom, Math.min((cam.width * 2) / WORLD_W, (cam.height * 0.9) / WORLD_D))

  // ---- 数据 ----
  let countryCounts = new Map<string, number>()
  let provinceCounts = new Map<string, number>()
  let serverPos: Centroid2D = { x: 0, y: 0 }
  let userInteracted = false

  let drillLayerCountry = ''
  let drillProvinceData: { name: string; polys: number[][][]; centroid?: [number, number] }[] = []
  let hoverName: string | null = null
  let hoverScreen: Centroid2D | null = null
  let pendingHover: Centroid2D | null = null

  // 悬停高亮路径：按国家/省在世界坐标缓存一次（绘制只 setTransform），
  // 不再随相机平移/缩放逐帧重建 Path2D（原 hoverCacheKey 含 camX/camY，
  // 拖动每帧全量重放上千条六边形子路径是主线程热点）。
  // 下钻省点阵的路径缓存随省层销毁（clearProvinceLayer）。
  let drillHoverPathByKey: Map<string, Path2D> | null = null

  // ---- DOM 标签 ----
  const hoverTip = makeLabelElement('', FLOW_HOVER_TIP_COLOR)
  hoverTip.style.display = 'none'
  labelLayer.appendChild(hoverTip)

  function shortName(name: string): string {
    return sharedShortName(name)
  }

  // ---- 绘制辅助 ----
  /** 世界坐标（就近副本）→ 屏幕 CSS 像素。 */
  function toScreen(lon: number, lat: number): Centroid2D {
    return worldToScreen(lon, lat, cam)
  }

  /** 多边形 path（按就近副本平移，杜绝跨界撕裂）。 */

  // ---- 点阵网格（v2.3.8：与地球版六边形瓦片同视觉语言；一次栅格化缓存） ----
  /** 六边形瓦片路径（pointy-top，与 globe.gl hexbin 同款——用户裁定
   * 2026-10-17：地图点阵改成地球页面的六边形样式，替代圆点）。
   *  只提供 Path2D 版本：静态层/下钻层/悬停层全部按色聚合后一次 fill，
   *  逐点 beginPath+fill 的 ctx 版本已退役（1.3 万次绘制调用是重建热点）。 */
  function dotSubPath(path: CanvasRenderingContext2D | Path2D, x: number, y: number, r: number): void {
    const first = POINTY_TOP_HEX_VERTICES[0]
    path.moveTo(x + first[0] * r, y + first[1] * r)
    for (let i = 1; i < POINTY_TOP_HEX_VERTICES.length; i++) {
      const vertex = POINTY_TOP_HEX_VERTICES[i]
      path.lineTo(x + vertex[0] * r, y + vertex[1] * r)
    }
    path.closePath()
  }
  interface Dot { lon: number; lat: number; key: string }

  /**
   * 国家命中测试（hover/click 单源）：先用构建期缓存的共享 bbox 网格取候选，
   * 再对候选国做 bbox + 多边形射线。点击曾对全部国家逐条射线，与 hover 的
   * 预筛分叉——多环国家（俄/美/加）上点击反馈可感知停顿。网格候选按国家
   * 索引升序（构建顺序），因此「首个命中」与全表扫描同结果。
   */
  function countryHitIndex(lon: number, lat: number, exclude?: string): number {
    const candidates = sharedCountryGrid.grid.get(countryGridCell(lon, lat)) ?? []
    for (const ci of candidates) {
      const b = bboxOf(ci)
      // bbox 跨日界线（如俄/美）时 minLon>maxLon 不可能（当前聚合取原始值），
      // 宽 bbox 只损失预筛收益，不会误杀。
      if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
      if (exclude && normalizeCountryName(THREAT_COUNTRIES[ci].name) === exclude) continue
      if (pointInPolys(lon, lat, THREAT_COUNTRIES[ci].polys)) return ci
    }
    return -1
  }

  let worldDots: Dot[] | null = null
  let provinceDots: Dot[] | null = null
  // 与地球版同源：0.95° 错列网格、加大点径以匹配地球 5px/10px 的视觉尺寸。
  const DOT_STEP = 0.95
  // Mercator 总览 zoom 约 2.79；半径按原等距投影 zoom4.57 的比例折算，
  // 保持「点径/间距」与原地图一致，避免点互相粘连成色块。
  const DOT_R = 0.18
  const DOT_LAND = SHARED_DOT_LAND
  // 国家 bbox 预筛缓存（外包框由共享网格构建一并算出，hover/点击与点阵共用）
  const sharedCountryGrid = buildCountryCellGrid(THREAT_COUNTRIES)
  const countryBboxes = THREAT_COUNTRIES.map((c, i) => ({ name: c.name, ...sharedCountryGrid.bounds[i], polys: c.polys }))
  const bboxOf = (i: number): { minLon: number; maxLon: number; minLat: number; maxLat: number } => countryBboxes[i]

  function buildWorldDots(): void {
    if (worldDots) return
    const dots: Dot[] = []
    const grid = sharedCountryGrid.grid
    let rowIdx = 0
    // Mercator 下按「投影后 y」等距布点，而不是按纬度等距：等纬度步长
    // 会在高纬被拉稀、低纬挤密（用户实测：上方稀、下方密、南半球显小）。
    // 扫描域由投影域派生（DOT_LAT_TOP/BOTTOM 单源），不再写死 84/-54.5。
    const topY = latToY(DOT_LAT_TOP)
    const bottomY = latToY(DOT_LAT_BOTTOM)
    for (let y = topY; y < bottomY; y += DOT_STEP, rowIdx++) {
      const lat = yToLat(y)
      const lonOffset = rowIdx % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = -179.5 + lonOffset; lon < 180; lon += DOT_STEP) {
        const candidates = grid.get(countryGridCell(lon, lat)) ?? []
        for (const ci of candidates) {
          const b = bboxOf(ci)
          if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
          if (pointInPolys(lon, lat, THREAT_COUNTRIES[ci].polys)) {
            dots.push({ lon, lat, key: normalizeCountryName(THREAT_COUNTRIES[ci].name) })
            break
          }
        }
      }
    }
    worldDots = dots
  }

  /** 下钻省点阵（进入下钻时重建；省级命中按 short 名染色）。 */
  function buildProvinceDots(): void {
    if (!drillProvinceData.length) { provinceDots = null; return }
    let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
    for (const pv of drillProvinceData) {
      const b = polysBounds(pv.polys)
      minLon = Math.min(minLon, b.minLon); maxLon = Math.max(maxLon, b.maxLon)
      minLat = Math.min(minLat, b.minLat); maxLat = Math.max(maxLat, b.maxLat)
    }
    const dots: Dot[] = []
    // 省级 bbox 预筛：34 省 × 全网格点直接 pointInPolys 会在首次下钻产生
    // 明显长任务；先按 bbox 排除绝大多数省份，再对候选做射线判定。
    const provinceBounds = drillProvinceData.map((pv) => polysBounds(pv.polys))
    let pRow = 0
    // 与世界层同一 Mercator 投影 y 步长/错列，避免下钻后密度随纬度变化。
    const pTopY = latToY(maxLat)
    const pBottomY = latToY(minLat)
    for (let y = pTopY; y <= pBottomY; y += DOT_STEP, pRow++) {
      const lat = yToLat(y)
      const lonOffset = pRow % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = minLon + lonOffset; lon <= maxLon; lon += DOT_STEP) {
        for (let pi = 0; pi < drillProvinceData.length; pi++) {
          const b = provinceBounds[pi]
          if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
          if (!pointInPolys(lon, lat, drillProvinceData[pi].polys)) continue
          dots.push({ lon, lat, key: shortName(drillProvinceData[pi].name) })
          break
        }
      }
    }
    provinceDots = dots
  }

  // 世界点阵按国家缓存的 Path2D：点坐标与画布缩放无关，路径只需构建一次。
  // 原实现每次静态层重建（首屏 ResizeObserver + 数据到达可触发多次）都重新
  // 构造 1.4 万条六边形子路径，是地图首开长任务的主因。
  let worldDotPathByKey: Map<string, Path2D> | null = null
  function ensureWorldDotPaths(): Map<string, Path2D> {
    if (worldDotPathByKey) return worldDotPathByKey
    const paths = new Map<string, Path2D>()
    if (worldDots) {
      for (const d of worldDots) {
        let path = paths.get(d.key)
        if (!path) {
          path = new Path2D()
          paths.set(d.key, path)
        }
        dotSubPath(path, d.lon + WORLD_W / 2, latToY(d.lat), DOT_R * 1.35)
      }
    }
    worldDotPathByKey = paths
    return paths
  }


  // ---- 静态层 ----
  let staticDirty = true

  function rebuildStaticLayer(): void {
    // DPR 计入离屏分配：原按 CSS 像素分配、blit 时放回 CSS
    // 尺寸 → Retina 下静态层被 2× 下采样（点阵发虚/边缘糊）。现按
    // zoom×dpr 分配并以同倍率变换绘制，blit 目标仍是 CSS 尺寸（1:1 物理像素）。
    const scale = Math.min(cam.zoom * dpr, MAX_STATIC_WIDTH / WORLD_W)
    const w = Math.ceil(WORLD_W * scale)
    const h = Math.ceil(WORLD_D * scale)
    // 尺寸不变时不要重写 width/height（会强制重分配后备存储，4K 下每次
    // 数据刷新可产生数十 MB 分配/GC）；仅 clear 后重绘。
    if (staticCanvas.width !== w || staticCanvas.height !== h) {
      staticCanvas.width = w
      staticCanvas.height = h
    }
    staticCtx.setTransform(1, 0, 0, 1, 0, 0)
    staticCtx.clearRect(0, 0, w, h)
    // v27 修复（用户实测「中国画在美洲」根因）：原 transform 平移 (WORLD_W/2)*zoom
    // 与 x=lon+180 叠加 → 整幅地图平移 360°（半世界错位：渲染与拾取相差 180°，
    // hover 中国=视觉美洲）。平移移除，x=lon+180 单独承担。
    staticCtx.setTransform(scale, 0, 0, scale, 0, 0)
    staticCtx.lineJoin = 'round'
    // 陆地衬底退役（用户裁定：单层点阵自表意，海洋即背景）
    // 点阵：普通陆地暗点，命中国家按热力染色（log10 计数标尺与地球版同源）
    buildWorldDots()
    if (worldDots) {
      // 路径缓存按国家复用：只有热力色分组/填充是每次重建的成本，不再逐点
      // 重新构造六边形子路径（原首屏多次重建的主线程热点）。
      const byKey = ensureWorldDotPaths()
      const land = new Path2D()
      const byFill = new Map<string, Path2D>()
      for (const [key, path] of byKey) {
        const cnt = countryCounts.get(key) ?? 0
        if (cnt <= 0) {
          land.addPath(path)
          continue
        }
        const fill = heatCss(cnt)
        let group = byFill.get(fill)
        if (!group) {
          group = new Path2D()
          byFill.set(fill, group)
        }
        group.addPath(path)
      }
      staticCtx.fillStyle = DOT_LAND
      staticCtx.fill(land)
      for (const [fill, path] of byFill) {
        staticCtx.fillStyle = fill
        staticCtx.fill(path)
      }
    }
    // 国界描边退役（v2.3.8 用户裁定：点阵已表意，无需分隔线）
    staticDirty = false
  }

  /** 静态层重建请求：下钻态使用独立世界坐标层（drillWorldCanvas），
   *  不使用世界静态层。 */
  function requestStaticLayer(): void {
    if (drillLayerCountry) {
      staticDirty = false
      return
    }
    if (staticDirty) rebuildStaticLayer()
  }

  /** 复用缓存的世界坐标路径绘制悬停提亮：只 setTransform + 最近副本裁剪。
   *  路径坐标与世界层点阵同源（x=lon+180, y=latToY(lat), 半径=世界单位），
   *  因此拖动/缩放期间零路径重建。 */
  function fillHoverWorldPath(path: Path2D, color: string): void {
    const layer = hoverLayerTransform(cam)
    ctx.save()
    // 最近副本经度窗（宽=360°×zoom，居中于相机经度）：每个点只出现一次，
    // 与旧逐点 wrapDeg 定位等价；画布宽于一个世界时不会重复提亮。
    ctx.beginPath()
    ctx.rect(layer.clipX, 0, layer.clipWidth, cam.height)
    ctx.clip()
    ctx.fillStyle = color
    ctx.globalAlpha = 0.9
    for (const copy of [-layer.worldPx, 0, layer.worldPx]) {
      const dx = layer.tx + copy
      if (dx > cam.width || dx + layer.worldPx < 0) continue
      ctx.setTransform(dpr * layer.scale, 0, 0, dpr * layer.scale, dpr * dx, dpr * layer.ty)
      ctx.fill(path)
    }
    ctx.restore()
  }

  /** 下钻省点阵按短名的世界坐标路径（悬停层专用；随省层销毁）。 */
  function ensureDrillHoverPaths(): Map<string, Path2D> {
    if (drillHoverPathByKey) return drillHoverPathByKey
    const paths = new Map<string, Path2D>()
    for (const d of provinceDots ?? []) {
      let path = paths.get(d.key)
      if (!path) {
        path = new Path2D()
        paths.set(d.key, path)
      }
      dotSubPath(path, d.lon + WORLD_W / 2, latToY(d.lat), DOT_R * 1.35)
    }
    drillHoverPathByKey = paths
    return paths
  }

  /** 下钻悬浮点高亮（只画命中省的点；路径按省短名世界坐标缓存一次，
   *  绘制只 setTransform——原实现按 hover+相机键逐帧重建）。 */
  function drawDrillHover(): void {
    if (!hoverName) return
    let path = provinceDots ? ensureDrillHoverPaths().get(shortName(hoverName)) : undefined
    if (!path) {
      // 下钻态悬停其他国家（暗度衬底）：提亮该国世界点阵（同一坐标口径）。
      buildWorldDots()
      path = ensureWorldDotPaths().get(hoverName)
    }
    if (!path) return
    fillHoverWorldPath(path, 'rgba(143, 230, 255, 0.55)')
  }

  // 下钻世界暗度衬底：复用世界点阵按国缓存的 Path2D，一次性 addPath 成
  // 单一暗色路径。旧实现在新离屏 canvas 上重建 1.4 万条六边形（已删除），
  // 是首次下钻卡顿的主要来源。
  let dimWorldPath: Path2D | null = null
  function ensureDimWorldPath(): Path2D | null {
    if (dimWorldPath) return dimWorldPath
    buildWorldDots()
    const byKey = ensureWorldDotPaths()
    const path = new Path2D()
    for (const sub of byKey.values()) path.addPath(sub)
    dimWorldPath = path
    return path
  }

  // 下钻世界坐标离屏层：按目标下钻 zoom 只构建一次，动画/拖动期间只做
  // drawImage，不再随相机重建（原屏幕空间缓存 120ms 重建一次仍造成动画卡顿）。
  const drillWorldCanvas = document.createElement('canvas')
  const drillWorldCtx = drillWorldCanvas.getContext('2d')!
  let drillDirty = true
  let drillWorldTargetZoom = DRILL_UNIFIED_ZOOM
  let drillWorldScale = 0
  function rebuildDrillWorldLayer(): void {
    buildWorldDots()
    if (!worldDots || !provinceDots) return
    // 下钻层用于背景衬底，实际显示会再缩放；2048px 宽足以保持点阵连贯，
    // 同时把首次下钻的 Path2D/栅格化成本压到可接受范围。
    const scale = Math.min(Math.max(1, drillWorldTargetZoom * dpr), MAX_STATIC_WIDTH / WORLD_W, 2048 / WORLD_W)
    const w = Math.ceil(WORLD_W * scale)
    const h = Math.ceil(WORLD_D * scale)
    if (drillWorldCanvas.width !== w || drillWorldCanvas.height !== h) {
      drillWorldCanvas.width = w
      drillWorldCanvas.height = h
    }
    drillWorldCtx.setTransform(scale, 0, 0, scale, 0, 0)
    drillWorldCtx.clearRect(0, 0, WORLD_W, WORLD_D)
    const dimPath = ensureDimWorldPath()
    if (dimPath) {
      drillWorldCtx.globalAlpha = 0.22
      drillWorldCtx.fillStyle = DOT_LAND
      drillWorldCtx.fill(dimPath)
      drillWorldCtx.globalAlpha = 1
    }
    const byColor = new Map<string, Path2D>()
    for (const d of provinceDots) {
      const cnt = provinceCounts.get(d.key) ?? 0
      const color = cnt > 0 ? heatCss(cnt) : DOT_LAND
      let path = byColor.get(color)
      if (!path) {
        path = new Path2D()
        byColor.set(color, path)
      }
      dotSubPath(path, d.lon + WORLD_W / 2, latToY(d.lat), DOT_R * 1.35)
    }
    drillWorldCtx.globalAlpha = 0.9
    for (const [color, path] of byColor) {
      drillWorldCtx.fillStyle = color
      drillWorldCtx.fill(path)
    }
    drillWorldCtx.globalAlpha = 1
    drillWorldScale = scale
    drillDirty = false
  }

  // ---- 交互 ----
  let dragging = false
  let dragMoved = false
  let dragLast: Centroid2D | null = null
  let dragStart: Centroid2D | null = null

  // 画布屏幕原点缓存：pointermove 每帧 getBoundingClientRect 会强制同步布局
  // （拖拽期间逐帧付一次）。矩形只随画布尺寸/位置变化——applySize 在
  // ResizeObserver/window resize 时刷新；按下手势时再刷新一次，兜住页面
  // 滚动/布局位移而无尺寸变化的场景。
  let canvasLeft = 0
  let canvasTop = 0
  function refreshCanvasOrigin(): void {
    const rect = canvas.getBoundingClientRect()
    canvasLeft = rect.left
    canvasTop = rect.top
  }

  function canvasPoint(event: { clientX: number; clientY: number }): Centroid2D {
    return { x: event.clientX - canvasLeft, y: event.clientY - canvasTop }
  }

  function onPointerDown(event: PointerEvent): void {
    if (event.button !== 0) return
    refreshCanvasOrigin()
    dragging = true
    dragMoved = false
    dragLast = canvasPoint(event)
    dragStart = dragLast
    canvas.style.cursor = 'grabbing'
  }

  function onPointerMove(event: PointerEvent): void {
    const p = canvasPoint(event)
    if (dragging && dragLast) {
      const dx = p.x - dragLast.x
      const dy = p.y - dragLast.y
      if (Math.abs(p.x - (dragStart?.x ?? 0)) + Math.abs(p.y - (dragStart?.y ?? 0)) > 4) dragMoved = true
      userInteracted = true
      const next = panBy(cam, dx, dy)
      cam.camX = next.camX
      cam.camY = next.camY
      dragLast = p
      return
    }
    if (!pendingHover || Math.abs(pendingHover.x - p.x) > 2 || Math.abs(pendingHover.y - p.y) > 2) pendingHover = p
  }

  function onPointerUp(): void {
    dragging = false
    dragLast = null
    canvas.style.cursor = 'grab'
  }

  function onClick(event: MouseEvent): void {
    if (dragMoved) {
      dragMoved = false
      return
    }
    const p = canvasPoint(event)
    const geo = screenToLonLat(p.x, p.y, cam)
    const hit = countryHitIndex(geo.lon, geo.lat)
    if (hit >= 0) {
      const country = THREAT_COUNTRIES[hit]
      const intent = drillClickIntent(normalizeCountryName(country.name), drillLayerCountry || null)
      // 'stay'：下钻态单击当前下钻国自身 = 保持（与地球引擎「本省保持」同语义）。
      // 缺这行时每次单击国境都会重钻：清 hover、全量重建省点阵、把用户拖动后
      // 的取景拉回国土中心。
      if (intent === 'stay') return
      if (intent === 'drill' || intent === 'switch') void drillToCountry(normalizeCountryName(country.name))
      return
    }
    if (drillLayerCountry) returnToWorld()
  }

  function onWheel(event: WheelEvent): void {
    // v2.3.8（用户裁定 2026-10-17）：滚轮不参与缩放——地图尺寸由总览/下钻
    // 视图固定，缩放仅经点击下钻/返回流程控制。
    event.preventDefault()
  }

  // 指针移出画布即清悬停态+浮签（对齐地球引擎 pointerleave 清理）——
  // 原实现移入右侧 HUD/底部图区后最后国家的提示框与提亮长期残留。
  function onPointerLeave(): void {
    hoverName = null
    hoverScreen = null
    pendingHover = null
    hoverTip.style.display = 'none'
    canvas.style.cursor = 'grab'
  }

  canvas.addEventListener('pointerdown', onPointerDown)
  canvas.addEventListener('pointermove', onPointerMove)
  canvas.addEventListener('pointerleave', onPointerLeave)
  window.addEventListener('pointerup', onPointerUp)
  canvas.addEventListener('click', onClick)
  canvas.addEventListener('wheel', onWheel, { passive: false })

  // ---- 下钻 ----
  function clearProvinceLayer(): void {
    drillProvinceData = []
    provinceDots = null
    // 省层重建后旧世界坐标路径失效（路径只含省点阵几何）。
    drillHoverPathByKey = null
    drillLayerCountry = ''
    // 进入/退出下钻时清掉上一视图的国家 hover——否则 drawDrillHover 会把
    // 整个中国点阵当「悬停国」再提亮一层，出现整块青色（实测）。
    hoverName = null
    hoverScreen = null
    pendingHover = null
    hoverTip.style.display = 'none'
    drillDirty = true
  }

  // 省界数据按需加载 ----
  // admin1Provinces 是 1.9MB 静态表——顶栏首屏不需要它（仅下钻时消费）。
  // 共享加载器动态 import：Vite 切出独立 chunk，总览首屏零下载；加载失败按
  // 「无省层」降级（不白屏、不进下钻），并经 onProvinceLoadError 让视图 toast。
  async function loadProvinceRows(country: string): Promise<{ name: string; polys: number[][][]; centroid?: [number, number] }[] | null> {
    if (country === '中国') {
      return CHINA_PROVINCES.map((pv) => ({ name: pv.name, polys: pv.polys, centroid: [pv.centroid[0], pv.centroid[1]] }))
    }
    const tables = await loadAdmin1Tables()
    if (!tables) {
      opts?.onProvinceLoadError?.()
      return null
    }
    // 表是普通对象且国家名来自点击/事件数据：原型键直接下标会拿到函数
    // （非省表数组），必须走自有属性守卫。
    return hasOwn(tables, country) ? tables[country] ?? [] : []
  }

  function buildProvinceLayer(country: string, provinces: { name: string; polys: number[][][]; centroid?: [number, number] }[], zoom: number): void {
    clearProvinceLayer()
    drillProvinceData = provinces
    drillLayerCountry = country
    drillWorldTargetZoom = zoom
    drillDirty = true
    buildProvinceDots()
  }

  function returnToWorld(): void {
    drillSeq += 1 // 作废在途省界加载（加载完成后不得再进入下钻）
    clearProvinceLayer()
    flyToOverview()
    if (onDrillChange) onDrillChange(null)
  }

  let drillSeq = 0
  // 销毁标记——省界 chunk 在途时退出大屏，续体不得再操作已卸载视图
  let disposed = false

  async function drillToCountry(country: string): Promise<void> {
    country = normalizeCountryName(country)
    if (!drillCountryAllowed(opts?.drillCountries, country)) return
    const c = THREAT_COUNTRIES.find((x) => x.name === country)
    if (!c) return
    const seq = ++drillSeq
    const b = principalBounds(c.polys)
    const clon0 = (b.minLon + b.maxLon) / 2
    const clon = clon0 > 180 ? clon0 - 360 : clon0
    const clat = (b.minLat + b.maxLat) / 2
    // v2.3.8（用户裁定）：下钻统一放大倍率——按国家 bbox 自适应曾对美/俄
    // 等超幅员国家产生过高 zoom（显示不全/跳动）；统一倍率+拖动自由探索。
    const zoom = DRILL_UNIFIED_ZOOM
    // 目标 camY 预钳制（俄罗斯质心 61°N 越上界——动画落点被 tick 钳制 snap
    // 上跳，与「复位下坠」同款根因）
    const visH = cam.height / zoom
    const targetY = visH >= WORLD_D
      ? WORLD_D / 2
      : Math.min(WORLD_D - visH / 2, Math.max(visH / 2, latToY(clat)))
    // 中国走内置高精度表（无需异步）；其余国家按需加载省界 chunk。
    const provinces = await loadProvinceRows(country)
    // 加载期间又点击了别国/返回/退出大屏 → 丢弃（与地球引擎共用判定单源）
    if (!drillCommitAllowed(seq, drillSeq, disposed)) return
    // 无省层数据（含加载失败）：不进入下钻、不切换提示/返回按钮——
    // 原实现先 flyTo+onDrillChange 再发现无数据，画面成「被选国家空洞」。
    if (!provinces || provinces.length === 0) return
    buildProvinceLayer(country, provinces, zoom)
    flyTo(clon, targetY, zoom)
    if (onDrillChange) onDrillChange(country)
  }

  // ---- 相机动画 ----
  interface CamAnim {
    from: { camX: number; camY: number; zoom: number }
    to: { camX: number; camY: number; zoom: number }
    elapsed: number
  }
  let camAnim: CamAnim | null = null

  /** 相机落点归一（tick 末尾同口径）：camX wrap、camY 按可视高钳制。 */
  function applyCamTarget(camX: number, camY: number, zoom: number): void {
    cam.camX = wrapDeg(camX)
    cam.zoom = zoom
    const visH = cam.height / zoom
    cam.camY = visH >= WORLD_D
      ? WORLD_D / 2
      : Math.min(WORLD_D - visH / 2, Math.max(visH / 2, camY))
    staticDirty = true
    serverPos = toScreen(server[0], server[1])
  }

  function flyTo(camX: number, camY: number, zoom: number): void {
    const fromX = cam.camX
    const toX = fromX + wrapDeg(camX - fromX)
    // 暂停态无动画帧驱动（rafId=0）：直接落点并补绘一帧，否则「复位视角/返回
    // 世界/下钻」在暂停中静默无反应。
    if (paused) {
      applyCamTarget(toX, camY, zoom)
      renderOnce()
      return
    }
    camAnim = {
      from: { camX: fromX, camY: cam.camY, zoom: cam.zoom },
      to: { camX: toX, camY, zoom },
      elapsed: 0,
    }
  }

  function flyToOverview(): void {
    // v2.3.8 修复「复位后地图整体向下」：目标 camY 先按总览 zoom 的可视高
    // 钳制——原目标=本站纬度（动画中 camY 合法），tick 末尾归一钳制再把它
    // 拉回 WORLD_D 中心，观感即动画结束后整幅下坠。
    const z = overviewZoom()
    const visH = cam.height / z
    const targetY = visH >= WORLD_D
      ? WORLD_D / 2
      : Math.min(WORLD_D - visH / 2, Math.max(visH / 2, latToY(server[1])))
    flyTo(server[0], targetY, z)
  }

  /**
   * 返回世界视口单源（zoomOut / resetView 共用）：作废在途省界加载、清空省层、
   * 飞回总览并确保渲染循环运行。暂停态下 startLoop 为空操作（flyToOverview 已
   * 直接落点并补绘），运行态 rafId 非 0 同样不入循环——两处调用语义一致。
   */
  function returnToWorldView(): void {
    drillSeq += 1
    clearProvinceLayer()
    flyToOverview()
    startLoop()
  }

  // ---- 特效 ----
  const arcs: Arc2D[] = []
  const ripples: Ripple2D[] = []
  let sweepAngle = 0

  function spawnArc(origin: Centroid, normal: boolean, weight = 1, tier: FlowArcTier = 'thin'): void {
    if (!siteConfigured) return
    // 正常/攻击共用容量：满池时拒绝新弧线，已开始的动画完整播完。
    if (arcs.length >= MAX_ACTIVE_ARCS) return
    // 聚合弧显示 ×N；逐条弧不显示，避免把采样还原值误读成聚合组。
    const label = flowArcLabel(weight, tier !== 'thin')
    arcs.push({ from: origin, elapsed: 0, flightT: 0, pulsed: false, normal, weight, tier, label })
  }

  function spawnRipple(color: string): void {
    if (ripples.length >= RIPPLE_POOL) ripples.shift()
    ripples.push({ age: 0, color })
  }

  function bezierX(p0: Centroid2D, p1: Centroid2D, p2: Centroid2D, t: number): number {
    const u = 1 - t
    return u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x
  }

  function bezierY(p0: Centroid2D, p1: Centroid2D, p2: Centroid2D, t: number): number {
    const u = 1 - t
    return u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y
  }

  // 弧线渐变缓存：端点按 0.5px 量化后作键（视觉无差），相机静止时复用，
  // 无界增长防护=超过上限整体清空（弧线池上限 60，键数天然有界）。
  const arcGradients = new Map<string, CanvasGradient>()
  function arcGradient(from: Centroid2D, to: Centroid2D, color: string): CanvasGradient {
    const key = `${Math.round(from.x * 2)},${Math.round(from.y * 2)},${Math.round(to.x * 2)},${Math.round(to.y * 2)},${color}`
    const cached = arcGradients.get(key)
    if (cached) return cached
    if (arcGradients.size > MAX_ACTIVE_ARCS * 4) arcGradients.clear()
    const gradient = ctx.createLinearGradient(from.x, from.y, to.x, to.y)
    gradient.addColorStop(0, 'rgba(0,0,0,0)')
    gradient.addColorStop(1, color)
    arcGradients.set(key, gradient)
    return gradient
  }

  function drawArcs(delta: number): void {
    for (let i = arcs.length - 1; i >= 0; i--) {
      const arc = arcs[i]
      arc.elapsed += delta
      arc.flightT += delta
      const life = ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP
      if (arc.flightT >= ARC_FLIGHT_SECONDS) {
        if (!arc.pulsed) {
          arc.pulsed = true
          spawnRipple(arc.normal ? NORMAL_COLOR : ATTACK_COLOR)
        }
        if (arc.flightT >= ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP) {
          arcs.splice(i, 1)
          continue
        }
      }
      // 屏幕空间二次贝塞尔（质心→本站，控制点居中抬高）
      const from = toScreen(arc.from[0], arc.from[1])
      const to = { x: serverPos.x, y: serverPos.y }
      const dist = Math.hypot(to.x - from.x, to.y - from.y)
      if (dist < 2 || dist > Math.max(cam.width, cam.height) * 1.2) continue
      const ctrl = { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 - dist * 0.28 }
      const head = easeOutCubic(Math.min(1, arc.flightT / ARC_FLIGHT_SECONDS))
      const color = arc.normal ? NORMAL_COLOR : ATTACK_COLOR
      const segments = 64
      ctx.beginPath()
      let hasPath = false
      for (let s = 0; s <= segments * head; s++) {
        const t = s / segments
        const x = bezierX(from, ctrl, to, t)
        const y = bezierY(from, ctrl, to, t)
        if (!hasPath) ctx.moveTo(x, y)
        else ctx.lineTo(x, y)
        hasPath = true
      }
      // 渐变发光描边（头亮尾隐）。渐变只由（起点,终点,颜色）决定，相机静止
      // 时逐帧重建 60 个 createLinearGradient 纯属浪费——按量化后的端点缓存，
      // 相机移动/越界时整体失效重建。
      if (hasPath) {
        const gradient = arcGradient(from, to, color)
        ctx.strokeStyle = gradient
        ctx.lineWidth = flowArcTierWidth(arc.tier)
        ctx.globalAlpha = Math.min(1, Math.max(0.05, (life - arc.elapsed) / 0.4))
        ctx.stroke()
        ctx.globalAlpha = 1
        if (arc.label) {
          ctx.font = '11px ui-monospace, monospace'
          ctx.fillStyle = arc.normal ? NORMAL_COLOR : ATTACK_COLOR
          ctx.textBaseline = 'middle'
          ctx.fillText(arc.label, from.x + 8, from.y - 8)
        }
      }
      // 亮头粒子拖尾（正常/攻击同一规则）
      if (head < 1) {
        for (let p = 0; p < ARC_FLIGHT_PARTICLES; p++) {
          const t = Math.max(0, head - p * (0.16 / ARC_FLIGHT_PARTICLES))
          ctx.beginPath()
          ctx.arc(bezierX(from, ctrl, to, t), bezierY(from, ctrl, to, t), 1.8, 0, Math.PI * 2)
          ctx.fillStyle = color
          ctx.globalAlpha = 0.85 * (1 - p / ARC_FLIGHT_PARTICLES)
          ctx.fill()
        }
        ctx.globalAlpha = 1
      }
    }
  }

  function drawRipples(delta: number): void {
    for (let i = ripples.length - 1; i >= 0; i--) {
      const ripple = ripples[i]
      ripple.age += delta
      const t = ripple.age / FLOW_RIPPLE_SECONDS
      if (t >= 1) {
        ripples.splice(i, 1)
        continue
      }
      const r = FLOW_RIPPLE_START_RADIUS + t * FLOW_RIPPLE_GROWTH_RADIUS
      ctx.beginPath()
      ctx.arc(serverPos.x, serverPos.y, r, 0, Math.PI * 2)
      ctx.strokeStyle = ripple.color
      ctx.lineWidth = FLOW_RIPPLE_LINE_WIDTH
      ctx.globalAlpha = FLOW_RIPPLE_ALPHA * (1 - t)
      ctx.stroke()
      ctx.globalAlpha = 1
    }
  }

  function drawSiteMarker(): void {
    if (!siteConfigured) return
    // 十字标
    ctx.strokeStyle = '#e2e8f0'
    ctx.lineWidth = 1.4
    ctx.globalAlpha = 0.95
    ctx.beginPath()
    ctx.moveTo(serverPos.x - 7, serverPos.y)
    ctx.lineTo(serverPos.x - 2.5, serverPos.y)
    ctx.moveTo(serverPos.x + 2.5, serverPos.y)
    ctx.lineTo(serverPos.x + 7, serverPos.y)
    ctx.moveTo(serverPos.x, serverPos.y - 7)
    ctx.lineTo(serverPos.x, serverPos.y - 2.5)
    ctx.moveTo(serverPos.x, serverPos.y + 2.5)
    ctx.lineTo(serverPos.x, serverPos.y + 7)
    ctx.stroke()
    // 外圈
    ctx.beginPath()
    ctx.arc(serverPos.x, serverPos.y, 5, 0, Math.PI * 2)
    ctx.stroke()
    // 本站文字（画布内绘制，图标右侧 14px 垂直居中）
    ctx.font = '11px "Noto Sans SC", "PingFang SC", sans-serif'
    ctx.fillStyle = '#8ea7d6'
    ctx.textBaseline = 'middle'
    ctx.fillText('本站', serverPos.x + 14, serverPos.y)
    // 顶部光点
    ctx.beginPath()
    ctx.arc(serverPos.x, serverPos.y - 11, 2.4, 0, Math.PI * 2)
    ctx.fillStyle = '#e2e8f0'
    ctx.fill()
    ctx.globalAlpha = 1
  }

  // v27 恢复（用户裁定加回）：本站雷达扫掠光线——旋转扇形光束，低透明度
  // 不与热力色块/弧线打架（旧 conic 大扇退役原因），扫过全屏半径以内。
  let sweepGrad: CanvasGradient | null = null
  let sweepGradAngle = -1
  let sweepGradX = -1
  let sweepGradY = -1
  function drawSiteSweep(): void {
    if (!siteConfigured) return
    // 角度由 tick 统一推进（每帧 delta*0.9 rad/s）；此处只消费不复位/不自增
    const r = Math.hypot(cam.width, cam.height) / 2 + 40
    // createConicGradient 是下钻/放大态的高开销调用：角度变化 <0.05rad 或
    // 站点未移动时复用上一帧渐变（约 20Hz 更新，视觉足够平滑）。
    if (!sweepGrad || Math.abs(sweepAngle - sweepGradAngle) > 0.05 ||
      Math.abs(serverPos.x - sweepGradX) > 0.5 || Math.abs(serverPos.y - sweepGradY) > 0.5) {
      sweepGrad = ctx.createConicGradient ? ctx.createConicGradient(sweepAngle, serverPos.x, serverPos.y) : null
      if (sweepGrad) {
        // stop 只在新渐变上设置一次；复用期间重复 addColorStop 会持续膨胀。
        sweepGrad.addColorStop(0, 'rgba(120,190,255,0.22)')
        sweepGrad.addColorStop(0.14, 'rgba(120,190,255,0.05)')
        sweepGrad.addColorStop(1, 'rgba(120,190,255,0)')
      }
      sweepGradAngle = sweepAngle
      sweepGradX = serverPos.x
      sweepGradY = serverPos.y
    }
    const grad = sweepGrad
    if (!grad) return
    ctx.save()
    ctx.beginPath()
    ctx.moveTo(serverPos.x, serverPos.y)
    ctx.arc(serverPos.x, serverPos.y, r, sweepAngle, sweepAngle + 0.9)
    ctx.closePath()
    ctx.fillStyle = grad
    ctx.fill()
    ctx.restore()
  }

  function drawHoverHighlight(): void {
    if (!hoverName) return
    // 与地球模式统一：不铺半透明多边形，直接把命中该国的点阵提亮（地球是
    // 直接改 hex 颜色）。路径复用静态层的按国世界坐标缓存（每国只构建一次），
    // 绘制只 setTransform——拖动/缩放不再逐帧重放六边形子路径。
    buildWorldDots()
    const path = ensureWorldDotPaths().get(hoverName)
    if (!path) return
    fillHoverWorldPath(path, '#8fe6ff')
  }

  // ---- 主循环 ----
  let rafId = 0
  let paused = false
  let lastTime = performance.now()

  function updateHoverTip(): void {
    if (hoverName && hoverScreen) {
      hoverTip.style.display = 'block'
      hoverTip.style.transform = `translate(${(hoverScreen.x + 14).toFixed(1)}px, ${(hoverScreen.y - 8).toFixed(1)}px)`
    } else {
      hoverTip.style.display = 'none'
    }
  }

  /** 单帧合成（tick 与暂停补绘共用）：静态层 + hover +
   *  下钻省层 + 全部动态层（弧线/涟漪/信标/扫掠/浮签）。暂停帧传 delta=0：
   *  画面元素在位但动画不推进——原 renderOnce 只画静态层+浮签，暂停后弧线/
   *  信标/扫掠整层消失。 */
  function paintComposite(delta: number): void {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, cam.width, cam.height)
    const dw = WORLD_W * cam.zoom
    const dh = WORLD_D * cam.zoom
    if (drillLayerCountry) {
      // 下钻世界坐标层：动画与稳定态都只 blit；相机变化不再触发点阵重建。
      if (drillDirty || drillWorldScale === 0) rebuildDrillWorldLayer()
      const baseLon = wrapLon(cam.camX)
      const sx = cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom
      const sy = cam.height / 2 - cam.camY * cam.zoom
      for (const offset of [-dw, 0, dw]) {
        if (sx + offset > cam.width || sx + offset + dw < 0) continue
        ctx.drawImage(drillWorldCanvas, sx + offset, sy, dw, dh)
      }
      drawDrillHover()
    } else {
      const baseLon = wrapLon(cam.camX)
      const sx = cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom
      const sy = cam.height / 2 - cam.camY * cam.zoom
      for (const offset of [-dw, 0, dw]) {
        if (sx + offset > cam.width || sx + offset + dw < 0) continue
        ctx.drawImage(staticCanvas, sx + offset, sy, dw, dh)
      }
    }
    // 世界 hover 提亮；下钻态 hover 由 drawDrillHover 只画命中省。
    if (!drillLayerCountry) drawHoverHighlight()
    drawArcs(delta)
    drawRipples(delta)
    drawSiteMarker()
    drawSiteSweep()
    updateHoverTip()
  }

  const tick = (): void => {
    rafId = requestAnimationFrame(tick)
    const now = performance.now()
    const delta = Math.min(0.1, (now - lastTime) / 1000)
    lastTime = now
    sweepAngle += delta * 0.9
    serverPos = toScreen(server[0], server[1])

    // 相机飞行
    if (camAnim) {
      camAnim.elapsed += delta
      const t = Math.min(1, camAnim.elapsed / ZOOM_SECONDS)
      const e = easeInOutCubic(t)
      cam.camX = camAnim.from.camX + (camAnim.to.camX - camAnim.from.camX) * e
      cam.camY = camAnim.from.camY + (camAnim.to.camY - camAnim.from.camY) * e
      cam.zoom = camAnim.from.zoom + (camAnim.to.zoom - camAnim.from.zoom) * e
      // 动画期间不重建静态层（原每帧 staticDirty=true → 每帧重分配整幅离屏
      // 画布并逐点重绘，0.6s 动画≈36 次全量栅格化）。blit 本身已按当前 zoom
      // 缩放旧位图（短暂软化可接受）；动画结束补一次重建保证清晰度。
      if (t >= 1) {
        camAnim = null
        staticDirty = true
      }
    }

    // hover 拾取（帧内一次）
    if (pendingHover) {
      hoverScreen = pendingHover
      const geo = screenToLonLat(pendingHover.x, pendingHover.y, cam)
      hoverName = null
      if (drillLayerCountry) {
        // 下钻态：先测省（选中国家内），未命中再测其他国家（暗度衬底同样
        // 可 hover——用户裁定 2026-10-17）
        for (const pv of drillProvinceData) {
          if (pointInPolys(geo.lon, geo.lat, pv.polys)) {
            hoverName = pv.name
            const short = shortName(pv.name)
            // 省级统计只覆盖中国（后端 threatLocationParts 仅对中国
            // 取省）；海外下钻不得把「无数据源」渲染成「该省 0 次攻击」。
            hoverTip.textContent = hasProvinceStats(drillLayerCountry)
              ? `${short} ${provinceCounts.get(short) ?? provinceCounts.get(pv.name) ?? 0}`
              : `${short} 无省级统计`
            break
          }
        }
        if (!hoverName) {
          const ci = countryHitIndex(geo.lon, geo.lat, drillLayerCountry)
          if (ci >= 0) {
            hoverName = normalizeCountryName(THREAT_COUNTRIES[ci].name)
            hoverTip.textContent = `${hoverName} ${countryCounts.get(hoverName) ?? 0}`
          }
        }
      } else {
        const ci = countryHitIndex(geo.lon, geo.lat)
        if (ci >= 0) {
          hoverName = normalizeCountryName(THREAT_COUNTRIES[ci].name)
          hoverTip.textContent = `${hoverName} ${countryCounts.get(hoverName) ?? 0}`
        }
      }
      canvas.style.cursor = hoverName ? 'pointer' : 'grab'
      pendingHover = null
    }

    requestStaticLayer()
    paintComposite(delta)

    // v27 终修（tick 末尾）：camX 每帧归一 + camY 钳制——必须放在 camAnim 插值
    // 之后：动画目标未 wrap 时每帧插值会把 camX 写脏（用户实测 cx=684.4），
    // 开头归一无效。末尾归一保证下一帧渲染/拾取/信标全体消费端一致。
    cam.camX = wrapDeg(cam.camX)
    const visHFrame = cam.height / cam.zoom
    if (visHFrame >= WORLD_D) cam.camY = WORLD_D / 2
    else cam.camY = Math.min(WORLD_D - visHFrame / 2, Math.max(visHFrame / 2, cam.camY))
  }

  const startLoop = (): void => {
    if (!rafId && !paused) {
      lastTime = performance.now()
      rafId = requestAnimationFrame(tick)
    }
  }

  /** 暂停态单帧补绘（尺寸变化/复位/暂停切换共用；与 tick 同合成路径）。 */
  const renderOnce = (): void => {
    if (rafId || !paused) return
    serverPos = toScreen(server[0], server[1])
    requestStaticLayer()
    paintComposite(0)
  }

  // ---- 尺寸 ----
  const applySize = (): void => {
    const w = container.clientWidth || 1
    const h = container.clientHeight || 1
    // 尺寸/布局变化后拾取原点缓存失效（pointermove 不再逐帧读布局）。
    refreshCanvasOrigin()
    const prevDpr = dpr
    const prevZoom = cam.zoom
    const nextDpr = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)
    const sizeChanged = w !== cam.width || h !== cam.height || nextDpr !== prevDpr
    dpr = nextDpr
    const pixelW = Math.round(w * dpr)
    const pixelH = Math.round(h * dpr)
    if (canvas.width !== pixelW) canvas.width = pixelW
    if (canvas.height !== pixelH) canvas.height = pixelH
    cam.width = w
    cam.height = h
    // v26 修复：minZoom 固定 0.35——原 Math.max(h/WORLD_D, 0.35) 强制地图高≥视口，
    // 总览缩小（宽高双适配留边）从未生效，顶/底国家恒贴边不可选（用户实测实锤）。
    minZoom = 0.35
    // v27 修复（初始地图偏高）：ResizeObserver 在布局落定后二次触发 applySize，
    // 但 zoom 仍是旧尺寸算的总览值——用户未交互且未下钻时随尺寸刷新总览。
    if (!userInteracted && !drillLayerCountry && !camAnim) cam.zoom = overviewZoom()
    // ResizeObserver 在首屏可能多次回调；尺寸与总览 zoom 都没变时不得置脏，
    // 否则每次回调都全量重绘静态层（用户实测地图刚打开卡顿）。
    if (sizeChanged || cam.zoom !== prevZoom) staticDirty = true
    // 暂停态无 tick 驱动：尺寸变化后必须补绘一帧，否则画布是新尺寸的空白
    // （尺寸/相机变化后暂停态仍需主动渲染）。
    if (paused) renderOnce()
  }
  const resizeObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(applySize) : null
  resizeObserver?.observe(container)
  window.addEventListener('resize', applySize)
  applySize()
  cam.camX = server[0]
  cam.camY = latToY(server[1])
  cam.zoom = overviewZoom()
  startLoop()

  // 下钻暗层按需构建（首次下钻时 rebuildDrillWorldLayer 内部 ensure）；
  // 不在首屏 idle 预构建，避免地图刚打开后的秒级长任务（用户实测卡顿）。

  return {
    addArcForLocation(ipLocation: string, weight = 1, tier: FlowArcTier = 'thin'): void {
      if (!ipLocation) return
      spawnArc(arcOriginForLocation(ipLocation), false, weight, tier)
      startLoop()
    },
    addNormalArcForLocation(ipLocation: string, weight = 1, tier: FlowArcTier = 'thin'): void {
      if (!ipLocation) return
      spawnArc(arcOriginForLocation(ipLocation), true, weight, tier)
      startLoop()
    },
    setCountries(entries: CountryHeat[]): void {
      // 30s 轮询同数据不得触发整幅静态层重建：长度+逐键
      // 浅比较，无变化直接返回（原恒 staticDirty=true → 每轮全量栅格化）。
      const nextCounts = aggregateCountryCounts(entries)
      if (heatEntriesEqual(countryCounts, [...nextCounts].map(([name, count]) => ({ name, count })))) return
      countryCounts = nextCounts
      staticDirty = true
      // 暂停态无 tick 驱动：数据到达即补绘（否则热力染色停在上一次暂停帧）
      if (paused) renderOnce()
    },
    setProvinces(entries: CountryHeat[]): void {
      if (heatEntriesEqual(provinceCounts, entries)) return
      provinceCounts = new Map(entries.map((e) => [e.name, e.count]))
      drillDirty = true
      if (paused) renderOnce()
    },
    setTraffic(entries: CountryHeat[]): void {
      // 正常/攻击共用出弧计划：1-3 逐条、4-8 合并、>8 更粗；weight 决定线宽。
      const plan = planFlowArcs(entries.filter((e) => e.count > 0).map((e) => ({ key: e.name, count: e.count, weight: e.count })))
      for (const item of plan) {
        spawnArc(trafficOriginForCountry(item.key), true, item.weight, item.tier)
      }
      startLoop()
    },
    setServer(centroid: Centroid | null): void {
      if (!centroid) return
      const changed = !siteConfigured || server[0] !== centroid[0] || server[1] !== centroid[1]
      siteConfigured = true
      server = [centroid[0], centroid[1]]
      // 与地球引擎一致：每次坐标变更都更新信标/弧线/返回视角；总览随新站
      // 坐标居中，下钻态保持用户当前取景。相同坐标重放不重置平移视角。
      if (changed && !drillLayerCountry) {
        cam.camX = server[0]
        cam.camY = latToY(server[1])
        staticDirty = true
      }
      if (paused) renderOnce()
      else startLoop()
    },
    zoomOut(): void {
      returnToWorldView()
    },
    resetView(): void {
      returnToWorldView()
    },
    cameraState(): { zoom: number; cx: number; cy: number; dist: number; pos: [number, number, number] } {
      return {
        zoom: Number(cam.zoom.toFixed(2)),
        cx: Number(wrapLon(cam.camX).toFixed(1)),
        cy: Number(yToLat(cam.camY).toFixed(1)),
        dist: Number((1000 / cam.zoom).toFixed(0)),
        pos: [Number(wrapLon(cam.camX).toFixed(1)), Number(cam.zoom.toFixed(2)), Number(cam.camY.toFixed(1))],
      }
    },
    setPaused(value: boolean): void {
      if (paused === value) return
      paused = value
      if (value) {
        cancelAnimationFrame(rafId)
        rafId = 0
        renderOnce()
      } else {
        startLoop()
      }
    },
    dispose(): void {
      // 作废在途下钻（drillToCountry 的 await 后继体检查 disposed）
      disposed = true
      drillSeq += 1
      cancelAnimationFrame(rafId)
      rafId = 0
      resizeObserver?.disconnect()
      window.removeEventListener('resize', applySize)
      window.removeEventListener('pointerup', onPointerUp)
      canvas.removeEventListener('pointerdown', onPointerDown)
      canvas.removeEventListener('pointermove', onPointerMove)
      canvas.removeEventListener('pointerleave', onPointerLeave)
      canvas.removeEventListener('click', onClick)
      canvas.removeEventListener('wheel', onWheel)
      hoverTip.remove()
      // 提前释放离屏位图后备存储（GC 前即可归还内存）
      drillHoverPathByKey = null
      staticCanvas.width = 0
      staticCanvas.height = 0
      drillWorldCanvas.width = 0
      drillWorldCanvas.height = 0
      dimWorldPath = null
      canvas.remove()
      labelLayer.remove()
    },
  }
}
