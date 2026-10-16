import {
  LAT_TOP,
  LAT_BOTTOM,
  WORLD_W,
  WORLD_D,
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
import { WORLD_COUNTRIES } from '@/utils/worldBorders'

// v2.3.8：南极洲剔除（无业务流量，用户裁定）——全部渲染/命中路径消费此表
const RENDER_COUNTRIES = WORLD_COUNTRIES.filter((c) => c.name !== 'Antarctica')
import { CHINA_PROVINCES } from '@/utils/chinaProvinces'
import { ADMIN1_PROVINCES } from '@/utils/admin1Provinces'
import { heatCss, pointInPolys as sharedPointInPolys, adminShortName as sharedShortName, DOT_LAND as SHARED_DOT_LAND } from '@/utils/threatShared'
import { COUNTRY_CENTROIDS, FALLBACK_CENTROID, type Centroid } from '@/utils/countryCentroids'

// 威胁大屏 2D 平面地图引擎（v16 终版：Canvas 2D，参考 Radware/Check Point 平面风格）。
//
// v16 终审裁定弃 3D：等距圆柱平铺、等比缩放永不变形、DPR 原生渲染、线宽恒
// 1 物理像素。分层渲染：静态层（陆地块+染中国+国界）按 zoom 缓存离屏 canvas，
// 拖动=blit（360° 环绕两份拼接）；动态层（弧线/涟漪/扫掠/信标/hover/下钻省层）
// 每帧矢量叠绘。对外接口与 3D 版完全一致（ThreatScreen.vue 零改动）。
//
// 热力=绝对标尺（1→1000 命中，log10 归一），砖红三档 #964a3c/#c2553d/#e25454，
// 低命中向底色 #1b2a41 插值；无挤出无悬浮无双层——纯平面。
// 交互：左键拖动平移（横向 360° 无缝环绕、纵向钳制）、滚轮缩放（锚点=指针）、
// hover=国家提亮+浮签、点击国家下钻省级平面、点击空白返回、ESC 语义在 Vue 层。

const MAX_PIXEL_RATIO = 2
const MAX_ACTIVE_ARCS = 30
const ARC_FLIGHTS = 3
const ARC_FLIGHT_SECONDS = 0.95
const ARC_FLIGHT_GAP = 0.22
const ARC_FLIGHT_PARTICLES = 12
const ZOOM_SECONDS = 0.6
const FPS_FLOOR = 30
const RIPPLE_POOL = 12
const MAX_STATIC_WIDTH = 8192
// 下钻统一视角倍率（用户裁定 2026-10-17）：任意国家一致，配合拖动查看
const DRILL_UNIFIED_ZOOM = 9
// 绝对热力标尺（log10(命中)/3 → 0..1），砖红三档，首段向底色插值

const ATTACK_COLOR = '#e25454'
const NORMAL_COLOR = '#38bdf8'

export interface CountryHeat {
  name: string
  count: number
}

export interface ThreatSceneOptions {
  serverCentroid?: Centroid | null
  onDrillChange?: (name: string | null) => void
}

export interface ThreatScene {
  addArc(origin: Centroid): void
  addArcForLocation(ipLocation: string, weight?: number): void
  setCountries(entries: CountryHeat[]): void
  setProvinces(entries: CountryHeat[]): void
  setTraffic(entries: CountryHeat[]): void
  setServer(centroid: Centroid | null): void
  zoomOut(): void
  /** 复位视角（总览/本站居中，600ms）。 */
  resetView(): void
  /** 程序化启停交互（验证接缝；禁用时点击拾取仍工作）。 */
  setControlsEnabled(enabled: boolean): void
  /** 拾取诊断：屏幕坐标 → 命中国家（null=未命中）。 */
  pickCountryAt(clientX: number, clientY: number): string | null
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
  flight: number
  flightT: number
  pulsed: boolean
  normal: boolean
  w: number
}

interface Ripple2D {
  age: number
}



function easeInOutCubic(t: number): number {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2
}

function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3)
}

function polysBounds(polys: number[][][]): { minLon: number; maxLon: number; minLat: number; maxLat: number } {
  let minLon = 180
  let maxLon = -180
  let minLat = 90
  let maxLat = -90
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
  return { minLon, maxLon, minLat, maxLat }
}


function pointInPolys(lon: number, lat: number, polys: number[][][]): boolean {
  return sharedPointInPolys(lon, lat, polys)
}

function makeLabelElement(text: string, color: string): HTMLDivElement {
  const div = document.createElement('div')
  div.className = 'ts-label'
  div.textContent = text
  div.style.color = color
  return div
}

export function createThreatScene(container: HTMLElement, opts?: ThreatSceneOptions): ThreatScene {
  const onDrillChange = opts?.onDrillChange
  let sawServerConfig = !!opts?.serverCentroid
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
  // v2.3.8 三轮放大（用户裁定）：高度满格（留 8px 缓冲）；宽度系数 1.15
  // （360° 环绕冗余可裁）让高度主导——世界高≈面板 98%。
  const overviewZoom = (): number => Math.max(minZoom, Math.min((cam.width * 2) / WORLD_W, (cam.height * 0.9) / WORLD_D))

  // ---- 数据 ----
  let countryCounts = new Map<string, number>()
  let provinceCounts = new Map<string, number>()
  let topCountries: { name: string; count: number; lon: number; lat: number }[] = []
  let serverPos: Centroid2D = { x: 0, y: 0 }
  let userInteracted = false

  let drillLayerCountry = ''
  let drillProvinceData: { name: string; polys: number[][][]; centroid?: [number, number] }[] = []
  let hoverName: string | null = null
  let hoverScreen: Centroid2D | null = null
  let pendingHover: Centroid2D | null = null

  // ---- DOM 标签 ----
  const topLabelEls = new Map<string, HTMLDivElement>()
  const provinceLabelEls: { el: HTMLDivElement; lon: number; lat: number }[] = []
  const hoverTip = makeLabelElement('', '#e2e8f0')
  hoverTip.style.display = 'none'
  labelLayer.appendChild(hoverTip)


  function rebuildTopLabels(): void {
    // v2.3.8：Top 国家 DOM 标签退役（用户裁定）——热度光斑动画+热力点阵已
    // 表达国家命中，标签长期「跑位」观感问题随层移除。
    for (const [, el] of topLabelEls) el.remove()
    topLabelEls.clear()
  }

  function rebuildProvinceLabels(): void {
    // v2.3.8：固定省标签退役（用户裁定，与国家标签同款）——高倍视图下东部
    // 省份标签挤叠成簇观感即「错乱」；省名由 hover 高亮+提示准确承载。
    for (const item of provinceLabelEls) item.el.remove()
    provinceLabelEls.length = 0
  }

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
   * 2026-10-17：地图点阵改成地球页面的六边形样式，替代圆点）。 */
  function hexPath(ctx2: CanvasRenderingContext2D, x: number, y: number, r: number): void {
    ctx2.beginPath()
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 180) * (60 * i - 30)
      const px = x + r * Math.cos(a)
      const py = y + r * Math.sin(a)
      if (i === 0) ctx2.moveTo(px, py)
      else ctx2.lineTo(px, py)
    }
    ctx2.closePath()
  }
  interface Dot { lon: number; lat: number; key: string }
  let worldDots: Dot[] | null = null
  /** 经度分桶（12°/桶）：下钻衬底每帧只遍历视口命中桶（原全量 ~1.3 万点/帧）。 */
  let worldDotBuckets: Map<number, Dot[]> | null = null
  let provinceDots: Dot[] | null = null
  const DOT_STEP = 1.1
  const DOT_R = 0.3
  const DOT_LAND = SHARED_DOT_LAND
  // 国家 bbox 预筛缓存
  const countryBboxes = RENDER_COUNTRIES.map((c) => ({ name: c.name, minLon: 0, maxLon: 0, minLat: 0, maxLat: 0, polys: c.polys, computed: false }))
  function bboxOf(i: number): { minLon: number; maxLon: number; minLat: number; maxLat: number } {
    const b = countryBboxes[i]
    if (!b.computed) {
      let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
      for (const poly of b.polys) for (const ring of poly) for (let k = 0; k + 1 < ring.length; k += 2) {
        if (ring[k] < minLon) minLon = ring[k]
        if (ring[k] > maxLon) maxLon = ring[k]
        if (ring[k + 1] < minLat) minLat = ring[k + 1]
        if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
      }
      Object.assign(b, { minLon, maxLon, minLat, maxLat, computed: true })
    }
    return b
  }

  function buildWorldDots(): void {
    if (worldDots) return
    const dots: Dot[] = []
    let rowIdx = 0
    for (let lat = -54.5; lat < 84; lat += DOT_STEP, rowIdx++) {
      const lonOffset = rowIdx % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = -179.5 + lonOffset; lon < 180; lon += DOT_STEP) {
        for (let ci = 0; ci < RENDER_COUNTRIES.length; ci++) {
          const b = bboxOf(ci)
          if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
          if (pointInPolys(lon, lat, RENDER_COUNTRIES[ci].polys)) {
            dots.push({ lon, lat, key: RENDER_COUNTRIES[ci].name })
            break
          }
        }
      }
    }
    worldDots = dots
    const buckets = new Map<number, Dot[]>()
    for (const d of dots) {
      const b = Math.floor(d.lon / 12)
      const arr = buckets.get(b)
      if (arr) arr.push(d)
      else buckets.set(b, [d])
    }
    worldDotBuckets = buckets
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
    let pRow = 0
    for (let lat = minLat; lat <= maxLat; lat += DOT_STEP * 0.7, pRow++) {
      const lonOffset = pRow % 2 === 1 ? DOT_STEP * 0.35 : 0
      for (let lon = minLon + lonOffset; lon <= maxLon; lon += DOT_STEP * 0.7) {
        for (const pv of drillProvinceData) {
          if (!pointInPolys(lon, lat, pv.polys)) continue
          dots.push({ lon, lat, key: shortName(pv.name) })
          break
        }
      }
    }
    provinceDots = dots
  }

  // ---- 静态层 ----
  let staticDirty = true

  /** 视口可见世界范围（经度 wrap 归一、纬度截断）。 */
  function visibleWorldBox(): { minLon: number; maxLon: number; minLat: number; maxLat: number } {
    const halfW = cam.width / 2 / cam.zoom
    const halfH = cam.height / 2 / cam.zoom
    return {
      minLon: cam.camX - halfW,
      maxLon: cam.camX + halfW,
      minLat: Math.max(LAT_BOTTOM, yToLat(cam.camY + halfH)),
      maxLat: Math.min(LAT_TOP, yToLat(cam.camY - halfH)),
    }
  }

  function rebuildStaticLayer(): void {
    // v16：超大 zoom（下钻小国）放弃全幅离屏（宽度超限），tick 走直绘分支
    if (WORLD_W * cam.zoom > MAX_STATIC_WIDTH) {
      staticCtx.setTransform(1, 0, 0, 1, 0, 0)
      staticCtx.clearRect(0, 0, staticCanvas.width, staticCanvas.height)
      staticDirty = false
      return
    }
    const w = Math.ceil(WORLD_W * cam.zoom)
    const h = Math.ceil(WORLD_D * cam.zoom)
    staticCanvas.width = w
    staticCanvas.height = h
    staticCtx.setTransform(1, 0, 0, 1, 0, 0)
    staticCtx.clearRect(0, 0, w, h)
    // v27 修复（用户实测「中国画在美洲」根因）：原 transform 平移 (WORLD_W/2)*zoom
    // 与 x=lon+180 叠加 → 整幅地图平移 360°（半世界错位：渲染与拾取相差 180°，
    // hover 中国=视觉美洲）。平移移除，x=lon+180 单独承担。
    staticCtx.setTransform(cam.zoom, 0, 0, cam.zoom, 0, 0)
    staticCtx.lineJoin = 'round'
    // 陆地衬底退役（用户裁定：单层点阵自表意，海洋即背景）
    // 点阵：普通陆地暗点，命中国家按热力染色（log10 计数标尺与地球版同源）
    buildWorldDots()
    if (worldDots) {
      const heatCache = new Map<string, string>()
      staticCtx.beginPath()
      for (const d of worldDots) {
        let fill = heatCache.get(d.key)
        if (fill === undefined) {
          const cnt = countryCounts.get(d.key) ?? 0
          fill = cnt > 0 ? heatCss(cnt) : DOT_LAND
          heatCache.set(d.key, fill)
        }
        staticCtx.fillStyle = fill
        hexPath(staticCtx, d.lon + WORLD_W / 2, LAT_TOP - d.lat, DOT_R * 1.35)
        staticCtx.fill()
      }
    }
    // 国界描边退役（v2.3.8 用户裁定：点阵已表意，无需分隔线）
    staticDirty = false
  }

  /** 下钻省层直接矢量绘（每帧；省数有界，视口外 bbox 剔除）。 */
  function drawDrillDirect(): void {
    const view = visibleWorldBox()
    for (const pv of drillProvinceData) {
      const pb = polysBounds(pv.polys)
      if (pb.maxLon < view.minLon || pb.minLon > view.maxLon || pb.maxLat < view.minLat || pb.minLat > view.maxLat) continue
    }
    // 省点阵（命中省热力染色；hover 省=放大提亮高亮——用户裁定 2026-10-17）
    if (provinceDots) {
      const hoverShort = hoverName ? shortName(hoverName) : null
      const r = DOT_R * 0.7 * cam.zoom
      for (const d of provinceDots) {
        if (d.lon < view.minLon - 1 || d.lon > view.maxLon + 1 || d.lat < view.minLat - 1 || d.lat > view.maxLat + 1) continue
        const hovered = hoverShort !== null && d.key === hoverShort
        const cnt = provinceCounts.get(d.key) ?? 0
        ctx.fillStyle = hovered ? 'rgba(143, 230, 255, 0.55)' : cnt > 0 ? heatCss(cnt) : DOT_LAND
        ctx.globalAlpha = 0.9
        hexPath(ctx, cam.width / 2 + wrapDeg(d.lon - cam.camX) * cam.zoom, cam.height / 2 + ((LAT_TOP - d.lat) - cam.camY) * cam.zoom, hovered ? r * 1.6 : r * 1.1)
        ctx.fill()
      }
      ctx.globalAlpha = 1
    }
  }

  /** 超大 zoom 直绘世界（视口外国家 bbox 剔除；国界 1 物理像素）。 */
  /** 下钻态世界衬底：全陆地点阵 22% 暗度（未命中色），视口剔除。 */
  function drawWorldDotsDim(): void {
    buildWorldDots()
    if (!worldDots || !worldDotBuckets) return
    const view = visibleWorldBox()
    const hoverCountry = hoverName && drillProvinceData.every((pv) => pv.name !== hoverName) ? hoverName : null
    // 经度分桶视口剔除（v2.3.8 性能：每帧只遍历命中桶，替代全量 1.3 万点）
    const b0 = Math.floor((view.minLon - 1) / 12)
    const b1 = Math.floor((view.maxLon + 1) / 12)
    ctx.fillStyle = DOT_LAND
    for (let b = b0; b <= b1; b++) {
      const arr = worldDotBuckets.get(b)
      if (!arr) continue
      for (const d of arr) {
        if (d.lat < view.minLat - 1 || d.lat > view.maxLat + 1) continue
        const hovered = hoverCountry !== null && d.key === hoverCountry
        const cnt = countryCounts.get(d.key) ?? 0
        ctx.globalAlpha = hovered ? 0.65 : 0.22
        ctx.fillStyle = hovered ? (cnt > 0 ? heatCss(cnt) : '#8fe6ff') : DOT_LAND
        hexPath(ctx, cam.width / 2 + wrapDeg(d.lon - cam.camX) * cam.zoom, cam.height / 2 + ((LAT_TOP - d.lat) - cam.camY) * cam.zoom, DOT_R * 1.35 * cam.zoom)
        ctx.fill()
      }
    }
    ctx.globalAlpha = 1
  }

  function drawStaticDirect(): void {
    const view = visibleWorldBox()
    // 点阵主视觉（视口剔除；与静态层/地球版同源）
    buildWorldDots()
    if (worldDots) {
      const r = DOT_R * cam.zoom
      for (const d of worldDots) {
        if (d.lon < view.minLon - 1 || d.lon > view.maxLon + 1 || d.lat < view.minLat - 1 || d.lat > view.maxLat + 1) continue
        const cnt = countryCounts.get(d.key) ?? 0
        ctx.fillStyle = cnt > 0 ? heatCss(cnt) : DOT_LAND
        hexPath(ctx, cam.width / 2 + wrapDeg(d.lon - cam.camX) * cam.zoom, cam.height / 2 + ((LAT_TOP - d.lat) - cam.camY) * cam.zoom, r * 1.1)
        ctx.fill()
      }
    }
    for (const country of RENDER_COUNTRIES) {
      const pb = polysBounds(country.polys)
      // 就近副本距离（bbox 中心）
      const centerShift = wrapDeg((pb.minLon + pb.maxLon) / 2 - cam.camX)
      const nearCenter = cam.camX + centerShift
      const halfSpan = (pb.maxLon - pb.minLon) / 2 + 2
      if (nearCenter + halfSpan < view.minLon || nearCenter - halfSpan > view.maxLon) continue
      if (pb.maxLat < view.minLat || pb.minLat > view.maxLat) continue
    }
  }

  // ---- 交互 ----
  let controlsEnabled = true
  let dragging = false
  let dragMoved = false
  let dragLast: Centroid2D | null = null
  let dragStart: Centroid2D | null = null

  function canvasPoint(event: { clientX: number; clientY: number }): Centroid2D {
    const rect = canvas.getBoundingClientRect()
    return { x: event.clientX - rect.left, y: event.clientY - rect.top }
  }

  function onPointerDown(event: PointerEvent): void {
    if (!controlsEnabled || event.button !== 0) return
    dragging = true
    dragMoved = false
    dragLast = canvasPoint(event)
    dragStart = dragLast
    canvas.style.cursor = 'grabbing'
  }

  function onPointerMove(event: PointerEvent): void {
    const p = canvasPoint(event)
    if (dragging && dragLast && controlsEnabled) {
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
    pendingHover = p
  }

  function onPointerUp(): void {
    dragging = false
    dragLast = null
    canvas.style.cursor = 'grab'
  }

  function onClick(event: MouseEvent): void {
    if (!controlsEnabled || dragMoved) {
      dragMoved = false
      return
    }
    const p = canvasPoint(event)
    const geo = screenToLonLat(p.x, p.y, cam)
    for (const country of RENDER_COUNTRIES) {
      if (pointInPolys(geo.lon, geo.lat, country.polys)) {
        drillToCountry(country.name)
        return
      }
    }
    if (drillLayerCountry) returnToWorld()
  }

  function onWheel(event: WheelEvent): void {
    // v2.3.8（用户裁定 2026-10-17）：禁止滚轮缩放——地图尺寸由总览/下钻
    // 视图固定，缩放仅经点击下钻/返回流程控制。
    if (!controlsEnabled) return
    event.preventDefault()
  }

  canvas.addEventListener('pointerdown', onPointerDown)
  canvas.addEventListener('pointermove', onPointerMove)
  window.addEventListener('pointerup', onPointerUp)
  canvas.addEventListener('click', onClick)
  canvas.addEventListener('wheel', onWheel, { passive: false })

  // ---- 下钻 ----
  function clearProvinceLayer(): void {
    drillProvinceData = []
    provinceDots = null
    drillLayerCountry = ''
    for (const item of provinceLabelEls) item.el.remove()
    provinceLabelEls.length = 0
  }

  function buildProvinceLayer(country: string): void {
    clearProvinceLayer()
    let provinces: { name: string; polys: number[][][]; centroid?: [number, number] }[] | undefined
    if (country === '中国') provinces = CHINA_PROVINCES.map((pv) => ({ name: pv.name, polys: pv.polys, centroid: [pv.centroid[0], pv.centroid[1]] }))
    else provinces = ADMIN1_PROVINCES[country]
    if (!provinces || provinces.length === 0) return
    drillProvinceData = provinces
    drillLayerCountry = country
    buildProvinceDots()
    rebuildProvinceLabels()
  }

  function returnToWorld(): void {
    clearProvinceLayer()
    flyToOverview()
    if (onDrillChange) onDrillChange(null)
  }

  function drillToCountry(country: string): void {
    const c = RENDER_COUNTRIES.find((x) => x.name === country)
    if (!c) return
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
    buildProvinceLayer(country)
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

  function flyTo(camX: number, camY: number, zoom: number): void {
    const fromX = cam.camX
    camAnim = {
      from: { camX: fromX, camY: cam.camY, zoom: cam.zoom },
      to: { camX: fromX + wrapDeg(camX - fromX), camY, zoom },
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

  // ---- 特效 ----
  const arcs: Arc2D[] = []
  const ripples: Ripple2D[] = []
  let rippleCursor = 0
  let sweepAngle = 0

  function spawnArc(origin: Centroid, normal: boolean, weight = 1): void {
    if (arcs.length >= MAX_ACTIVE_ARCS) arcs.shift()
    // 同源聚合权重 → 弧宽（log 标尺上限钳 4：百次/秒下视觉可控）
    const w = Math.min(4, 0.6 + Math.log10(Math.max(1, weight)))
    arcs.push({ from: origin, elapsed: 0, flight: 0, flightT: 0, pulsed: false, normal, w })
  }

  function spawnRipple(): void {
    if (ripples.length >= RIPPLE_POOL) ripples.shift()
    ripples.push({ age: 0 })
    void rippleCursor
  }

  function bezierPoint(p0: Centroid2D, p1: Centroid2D, p2: Centroid2D, t: number): Centroid2D {
    const u = 1 - t
    return {
      x: u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
      y: u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
    }
  }

  function drawArcs(delta: number): void {
    for (let i = arcs.length - 1; i >= 0; i--) {
      const arc = arcs[i]
      arc.elapsed += delta
      arc.flightT += delta
      const life = arc.normal
        ? ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP
        : ARC_FLIGHTS * (ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP)
      if (arc.flightT >= ARC_FLIGHT_SECONDS) {
        if (!arc.pulsed) {
          arc.pulsed = true
          if (!arc.normal) spawnRipple()
        }
        if (arc.flightT >= ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP) {
          if (arc.normal || arc.flight + 1 >= ARC_FLIGHTS) {
            arcs.splice(i, 1)
            continue
          }
          arc.flight += 1
          arc.flightT = 0
          arc.pulsed = false
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
      let last: Centroid2D | null = null
      for (let s = 0; s <= segments * head; s++) {
        const pt = bezierPoint(from, ctrl, to, s / segments)
        if (!last) ctx.moveTo(pt.x, pt.y)
        else ctx.lineTo(pt.x, pt.y)
        last = pt
      }
      // 渐变发光描边（头亮尾隐）
      if (last) {
        const gradient = ctx.createLinearGradient(from.x, from.y, to.x, to.y)
        gradient.addColorStop(0, 'rgba(0,0,0,0)')
        gradient.addColorStop(1, color)
        ctx.strokeStyle = gradient
        ctx.lineWidth = arc.normal ? 1.2 : 2 * arc.w
        ctx.globalAlpha = arc.normal ? 0.5 : Math.min(1, Math.max(0.05, (life - arc.elapsed) / 0.4))
        ctx.stroke()
        ctx.globalAlpha = 1
      }
      // 亮头粒子拖尾
      if (head < 1 || !arc.normal) {
        for (let p = 0; p < ARC_FLIGHT_PARTICLES; p++) {
          const t = Math.max(0, head - p * (0.16 / ARC_FLIGHT_PARTICLES))
          const pt = bezierPoint(from, ctrl, to, t)
          const r = arc.normal ? 1.1 : 2 - p * 0.12
          ctx.beginPath()
          ctx.arc(pt.x, pt.y, Math.max(0.4, r), 0, Math.PI * 2)
          ctx.fillStyle = color
          ctx.globalAlpha = (arc.normal ? 0.5 : 0.9) * (1 - p / ARC_FLIGHT_PARTICLES)
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
      const t = ripple.age / 1.8
      if (t >= 1) {
        ripples.splice(i, 1)
        continue
      }
      const r = 3 + t * 26
      ctx.beginPath()
      ctx.arc(serverPos.x, serverPos.y, r, 0, Math.PI * 2)
      ctx.strokeStyle = ATTACK_COLOR
      ctx.lineWidth = 1.5
      ctx.globalAlpha = 0.85 * (1 - t)
      ctx.stroke()
      ctx.globalAlpha = 1
    }
  }

  function drawSweep(): void {
    // v27（用户多轮实测反馈收敛）：扫掠扇退役——大半径 conic 渐变扇在地图上
    // 反复被误读为「色块层/攻击扇/国家高亮错位」，且与信标点视觉打架。
    // 本站标记保留：十字标+同心圆+光点（drawSiteMarker）。
  }



  function drawSiteMarker(): void {
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
  function drawSiteSweep(delta: number): void {
    sweepAngle = (sweepAngle + delta * 0.00055) % (Math.PI * 2)
    const r = Math.hypot(cam.width, cam.height) / 2 + 40
    const grad = ctx.createConicGradient
      ? ctx.createConicGradient(sweepAngle, serverPos.x, serverPos.y)
      : null
    if (!grad) return
    // 前缘亮、尾缘淡的单束扫掠（0~0.9rad 扇区）
    grad.addColorStop(0, 'rgba(120,190,255,0.22)')
    grad.addColorStop(0.14, 'rgba(120,190,255,0.05)')
    grad.addColorStop(1, 'rgba(120,190,255,0)')
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
    const country = RENDER_COUNTRIES.find((x) => x.name === hoverName)
    if (!country) return
    // v27 修复（用户实测 hover 高亮脱离地图）：原 tracePoly 以「屏幕中心」为
    // 国家中心且无相机 Y 偏移 → 高亮恒在屏幕中上部。改为完整相机投影：
    // sx = width/2 + wrapDeg(lon-camX)·z，sy = height/2 + (worldY-camY)·z。
    ctx.beginPath()
    for (const poly of country.polys) {
      const c = polysBounds([poly])
      const base = cam.camX + wrapDeg((c.minLon + c.maxLon) / 2 - cam.camX)
      for (const ring of poly) {
        for (let i = 0; i + 1 < ring.length; i += 2) {
          const sx = cam.width / 2 + (base + wrapDeg(ring[i] - base) - cam.camX) * cam.zoom
          const sy = cam.height / 2 + ((LAT_TOP - ring[i + 1]) - cam.camY) * cam.zoom
          if (i === 0) ctx.moveTo(sx, sy)
          else ctx.lineTo(sx, sy)
        }
        ctx.closePath()
      }
    }
    ctx.fillStyle = 'rgba(255,255,255,0.07)'
    ctx.fill()
  }

  // ---- 主循环 ----
  let rafId = 0
  let paused = false
  let lastTime = performance.now()
  let elapsedTotal = 0
  let degraded = false
  let lowFpsSeconds = 0
  const frameDurations: number[] = []

  function updateLabels(): void {
    const place = (el: HTMLDivElement, lon: number, lat: number, offsetX = 0, offsetY = 0): void => {
      const p = toScreen(lon, lat)
      if (p.x < -80 || p.x > cam.width + 80 || p.y < -40 || p.y > cam.height + 40) {
        el.style.display = 'none'
        return
      }
      el.style.display = 'block'
      el.style.transform = `translate(${(p.x + offsetX).toFixed(1)}px, ${(p.y + offsetY).toFixed(1)}px) translate(-50%, -100%)`
    }
    for (const [name, el] of topLabelEls) {
      const entry = topCountries.find((t) => t.name === name)
      if (entry) place(el, entry.lon, entry.lat)
    }
    for (const item of provinceLabelEls) place(item.el, item.lon, item.lat, 0, -6)

    if (hoverName && hoverScreen) {
      hoverTip.style.display = 'block'
      hoverTip.style.transform = `translate(${(hoverScreen.x + 14).toFixed(1)}px, ${(hoverScreen.y - 8).toFixed(1)}px)`
    } else {
      hoverTip.style.display = 'none'
    }
  }

  const tick = (): void => {
    rafId = requestAnimationFrame(tick)
    const now = performance.now()
    const delta = Math.min(0.1, (now - lastTime) / 1000)
    lastTime = now
    elapsedTotal += delta
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
      staticDirty = true
      if (t >= 1) camAnim = null
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
            hoverTip.textContent = `${shortName(pv.name)} ${provinceCounts.get(shortName(pv.name)) ?? provinceCounts.get(pv.name) ?? 0}`
            break
          }
        }
        if (!hoverName) {
          for (const country of RENDER_COUNTRIES) {
            if (country.name === drillLayerCountry) continue
            if (pointInPolys(geo.lon, geo.lat, country.polys)) {
              hoverName = country.name
              hoverTip.textContent = `${country.name} ${countryCounts.get(country.name) ?? 0}`
              break
            }
          }
        }
      } else {
        for (const country of RENDER_COUNTRIES) {
          if (pointInPolys(geo.lon, geo.lat, country.polys)) {
            hoverName = country.name
            hoverTip.textContent = `${hoverName} ${countryCounts.get(hoverName) ?? 0}`
            break
          }
        }
      }
      canvas.style.cursor = hoverName ? 'pointer' : 'grab'
      pendingHover = null
    }

    if (staticDirty) rebuildStaticLayer()

    // ---- 合成 ----
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, cam.width, cam.height)
    // 静态层：常规=离屏 blit（环绕三份拼接）；超大 zoom=直接矢量绘
    const dw = WORLD_W * cam.zoom
    const dh = WORLD_D * cam.zoom
    if (drillLayerCountry) {
      // 下钻态：其他国家暗度衬底（用户裁定：仍显示但变暗突出选中国家）
      drawWorldDotsDim()
    } else if (dw > MAX_STATIC_WIDTH) {
      drawStaticDirect()
    } else {
      const baseLon = wrapLon(cam.camX)
      const sx = cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom
      const sy = cam.height / 2 - cam.camY * cam.zoom
      for (const offset of [-dw, 0, dw]) {
        if (sx + offset > cam.width || sx + offset + dw < 0) continue
        ctx.drawImage(staticCanvas, sx + offset, sy, dw, dh)
      }
    }
    // 世界 hover 提亮（下钻态改为提亮省）
    if (!drillLayerCountry) drawHoverHighlight()
    // 下钻省层（直接矢量绘）
    if (drillLayerCountry) drawDrillDirect()
    // 动态层
    // v2.3.8：国家热点光斑层（一度退役后恢复）——光斑是 Top 国家标签的
    // 视觉锚点：无光斑时标签悬浮于真实坐标上方，观感即「标签跑位」。
    // 光斑层退役（用户裁定）：国家命中由点阵自身热力染色表达

    drawSweep()
    drawArcs(delta)
    drawRipples(delta)
    drawSiteMarker()
    drawSiteSweep(delta)
    updateLabels()

    // 帧率看门狗
    if (!degraded) {
      frameDurations.push(delta)
      if (frameDurations.length > 90) frameDurations.shift()
      if (frameDurations.length === 90) {
        const avgFps = frameDurations.length / frameDurations.reduce((a, b) => a + b, 0)
        lowFpsSeconds = avgFps < FPS_FLOOR ? lowFpsSeconds + delta : 0
        if (lowFpsSeconds >= 3) degraded = true
      }
    }
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

  const renderOnce = (): void => {
    if (rafId || !paused) return
    if (staticDirty) rebuildStaticLayer()
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, cam.width, cam.height)
    const dw = WORLD_W * cam.zoom
    const dh = WORLD_D * cam.zoom
    if (drillLayerCountry) {
      // 下钻态：其他国家暗度衬底（用户裁定：仍显示但变暗突出选中国家）
      drawWorldDotsDim()
    } else if (dw > MAX_STATIC_WIDTH) {
      drawStaticDirect()
    } else {
      const baseLon = wrapLon(cam.camX)
      const sx = cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom
      const sy = cam.height / 2 - cam.camY * cam.zoom
      for (const offset of [-dw, 0, dw]) {
        if (sx + offset > cam.width || sx + offset + dw < 0) continue
        ctx.drawImage(staticCanvas, sx + offset, sy, dw, dh)
      }
    }
    updateLabels()
  }

  // ---- 尺寸 ----
  const applySize = (): void => {
    const w = container.clientWidth || 1
    const h = container.clientHeight || 1
    dpr = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)
    canvas.width = Math.round(w * dpr)
    canvas.height = Math.round(h * dpr)
    cam.width = w
    cam.height = h
    // v26 修复：minZoom 固定 0.35——原 Math.max(h/WORLD_D, 0.35) 强制地图高≥视口，
    // 总览缩小（宽高双适配留边）从未生效，顶/底国家恒贴边不可选（用户实测实锤）。
    minZoom = 0.35
    staticDirty = true
    // v27 修复（初始地图偏高）：ResizeObserver 在布局落定后二次触发 applySize，
    // 但 zoom 仍是旧尺寸算的总览值——用户未交互且未下钻时随尺寸刷新总览。
    if (!userInteracted && !drillLayerCountry && !camAnim) cam.zoom = overviewZoom()
  }
  const resizeObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(applySize) : null
  resizeObserver?.observe(container)
  window.addEventListener('resize', applySize)
  applySize()
  cam.camX = server[0]
  cam.camY = latToY(server[1])
  cam.zoom = overviewZoom()
  startLoop()

  function recomputeTops(): void {
    topCountries = [...countryCounts.entries()]
      .map(([name, count]) => {
        const c = COUNTRY_CENTROIDS[name] ?? FALLBACK_CENTROID
        return { name, count, lon: c[0], lat: c[1] }
      })
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
      .slice(0, 5)
  }

  return {
    addArc(origin: Centroid): void {
      spawnArc(origin, false)
      startLoop()
    },
    addArcForLocation(ipLocation: string, weight = 1): void {
      if (!ipLocation) return
      const [country, province] = ipLocation.split('·')
      if (!country) return
      if (country === '中国') {
        const pv = province ? CHINA_PROVINCES.find((x) => x.short === province || x.name === province) : undefined
        const c: Centroid = pv ? [pv.centroid[0], pv.centroid[1]] : COUNTRY_CENTROIDS['中国']
        spawnArc(c, false, weight)
        startLoop()
        return
      }
      spawnArc(COUNTRY_CENTROIDS[country] ?? FALLBACK_CENTROID, false, weight)
      startLoop()
    },
    setCountries(entries: CountryHeat[]): void {
      countryCounts = new Map(entries.map((e) => [e.name, e.count]))
      recomputeTops()
      rebuildTopLabels()
      staticDirty = true
    },
    setProvinces(entries: CountryHeat[]): void {
      provinceCounts = new Map(entries.map((e) => [e.name, e.count]))
      if (drillLayerCountry) rebuildProvinceLabels()
    },
    setTraffic(entries: CountryHeat[]): void {
      const sorted = [...entries].sort((a, b) => b.count - a.count).slice(0, 8)
      for (const entry of sorted) {
        if (entry.count <= 0) continue
        spawnArc(COUNTRY_CENTROIDS[entry.name] ?? FALLBACK_CENTROID, true)
      }
      startLoop()
    },
    setServer(centroid: Centroid | null): void {
      if (centroid && !sawServerConfig) {
        sawServerConfig = true
        server = [centroid[0], centroid[1]]
        cam.camX = server[0]
        cam.camY = latToY(server[1])
        startLoop()
      }
    },
    zoomOut(): void {
      clearProvinceLayer()
      flyToOverview()
      startLoop()
    },
    resetView(): void {
      clearProvinceLayer()
      flyToOverview()
    },
    setControlsEnabled(enabled: boolean): void {
      controlsEnabled = enabled
      if (!enabled) {
        dragging = false
        dragLast = null
      }
    },
    pickCountryAt(clientX: number, clientY: number): string | null {
      const rect = canvas.getBoundingClientRect()
      const geo = screenToLonLat(clientX - rect.left, clientY - rect.top, cam)
      for (const country of RENDER_COUNTRIES) {
        if (pointInPolys(geo.lon, geo.lat, country.polys)) return country.name
      }
      return null
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
      cancelAnimationFrame(rafId)
      rafId = 0
      resizeObserver?.disconnect()
      window.removeEventListener('resize', applySize)
      window.removeEventListener('pointerup', onPointerUp)
      canvas.removeEventListener('pointerdown', onPointerDown)
      canvas.removeEventListener('pointermove', onPointerMove)
      canvas.removeEventListener('click', onClick)
      canvas.removeEventListener('wheel', onWheel)
      for (const [, el] of topLabelEls) el.remove()
      for (const item of provinceLabelEls) item.el.remove()
      hoverTip.remove()
      canvas.remove()
      labelLayer.remove()
    },
  }
}
