// 威胁大屏「地球模式」引擎（v2.3.8）：globe.gl(three.js) 旋转地球 + 垂直扫描
// 特效。与 threatScene.ts（360°地图+雷达扫掠）实现同一 ThreatScene 接口——
// ThreatScreen.vue 按设置 threat_screen_mode 二选一装载，数据管线/UI 完全复用。
// 渲染：实心多边形国家板（choropleth 热力，可点击下钻）→ 下钻态换该国
// 一级行政区板（中国=chinaProvinces 34 省高精度；其余=admin1Provinces）；
// 攻击弧线/本站涟漪/扫描光带。扫描 shader 移植自参考实现（threat-wall，
// 用户友人制作，授权改造）。
import Globe from 'globe.gl'
import type { GlobeInstance } from 'globe.gl'
import * as THREE from 'three'
import type { Centroid } from '@/utils/countryCentroids'
import { COUNTRY_CENTROIDS, FALLBACK_CENTROID } from '@/utils/countryCentroids'
import { THREAT_COUNTRIES } from '@/utils/worldBorders'
import { CHINA_PROVINCES } from '@/utils/chinaProvinces'
import type { Admin1Province } from '@/utils/admin1Provinces'
import { loadAdmin1Tables, loadedAdmin1Tables } from '@/utils/admin1Loader'
import { heatCss, pointInPolys as sharedPointInPolys, arcEndpoints } from '@/utils/threatShared'
import type { ThreatScene, ThreatSceneOptions, CountryHeat } from '@/utils/threatScene'

interface GeoFeature {
  type: 'Feature'
  properties: { name: string; count: number }
  geometry: { type: 'MultiPolygon'; coordinates: [number, number][][][] }
}

interface ArcDatum {
  startLat: number
  startLng: number
  endLat: number
  endLng: number
  color: string[]
  strokeW: number
  born: number
}

const LAND_DARK = 'rgb(27,42,65)'
const MAX_ARCS = 30
const ARC_TTL = 4200

/** 扁平多边形组（[lon,lat,…] 环）→ GeoJSON MultiPolygon（环首点闭合）。 */
function toMultiPolygon(polys: number[][][]): [number, number][][][] {
  return polys.map((poly) =>
    poly.map((flat) => {
      const coords: [number, number][] = []
      for (let i = 0; i + 1 < flat.length; i += 2) coords.push([flat[i], flat[i + 1]])
      const first = coords[0]
      const last = coords[coords.length - 1]
      if (first && last && (first[0] !== last[0] || first[1] !== last[1])) coords.push([first[0], first[1]])
      return coords
    }),
  )
}

/** 国家层 FeatureCollection（count 预置 0，热力随 setCountries 更新重建）。
 *  国家全集消费 THREAT_COUNTRIES（南极洲已剔除——第 78 轮 U15-F12 单源）。 */
function buildCountryFeatures(counts: Map<string, number>): GeoFeature[] {
  return THREAT_COUNTRIES.map((c) => ({
    type: 'Feature',
    properties: { name: c.name, count: counts.get(c.name) ?? 0 },
    geometry: { type: 'MultiPolygon', coordinates: toMultiPolygon(c.polys) },
  }))
}

/** 下钻态：国家一级行政区 FeatureCollection（中国走高精度 34 省表）。
 *  tables 为按需加载的省界表（未加载时由调用方保证已 await）。 */
function buildProvinceFeatures(country: string, counts: Map<string, number>, tables: Record<string, Admin1Province[]>): GeoFeature[] {
  if (country === '中国') {
    return CHINA_PROVINCES.map((p) => ({
      type: 'Feature',
      properties: { name: p.short, count: counts.get(p.name) ?? counts.get(p.short) ?? 0 },
      geometry: { type: 'MultiPolygon', coordinates: toMultiPolygon(p.polys) },
    }))
  }
  const provinces = tables[country]
  if (!provinces) return []
  return provinces.map((p) => ({
    type: 'Feature',
    properties: { name: p.name, count: counts.get(p.name) ?? 0 },
    geometry: { type: 'MultiPolygon', coordinates: toMultiPolygon(p.polys) },
  }))
}

/** 垂直扫描 shader（参考实现移植）：纬度带自北极向南极往返扫掠。 */
const FRESNEL_VS = `
varying vec3 vN; varying vec3 vV; varying vec3 vP;
void main(){
  vN = normalize(normalMatrix * normal);
  vec4 mv = modelViewMatrix * vec4(position, 1.0);
  vV = normalize(-mv.xyz);
  vP = position;
  gl_Position = projectionMatrix * mv;
}`
const SCAN_FS = `
uniform vec3 uColor; uniform float uTime, uR;
varying vec3 vN; varying vec3 vV; varying vec3 vP;
void main(){
  float y = vP.y / uR;
  float c = sin(uTime * 0.32) * 1.05;
  float band = 1.0 - smoothstep(0.0, 0.035, abs(y - c));
  float tail = (1.0 - smoothstep(0.0, 0.28, abs(y - c))) * 0.18;
  float facing = max(dot(vN, vV), 0.0);
  gl_FragColor = vec4(uColor, (band * 0.32 + tail * 0.7) * (0.3 + 0.7 * facing));
}`

/** 国家板块跨度（度）→ 相机高度：大国产远、小国产近，钳制 0.55-2.2。 */
function flyAltitudeFor(name: string): number {
  const c = THREAT_COUNTRIES.find((x) => x.name === name)
  if (!c) return 1.4
  let minLat = 90, maxLat = -90, minLon = 180, maxLon = -180
  for (const poly of c.polys) {
    for (const flat of poly) {
      for (let i = 0; i + 1 < flat.length; i += 2) {
        if (flat[i] < minLon) minLon = flat[i]
        if (flat[i] > maxLon) maxLon = flat[i]
        if (flat[i + 1] < minLat) minLat = flat[i + 1]
        if (flat[i + 1] > maxLat) maxLat = flat[i + 1]
      }
    }
  }
  const span = Math.max(maxLat - minLat, Math.min(maxLon - minLon, 180)) / 2
  return Math.min(2.2, Math.max(0.55, span / 45 + 0.35))
}

export function createThreatGlobe(container: HTMLElement, opts?: ThreatSceneOptions): ThreatScene {
  // 第 78 轮 L07-F03：本站坐标是可变状态——构造期常量会让 setServer 只改
  // 环/点，弧线终点与返回视角仍指向旧坐标（本变量由 setServer/返回视角消费）。
  let server: Centroid = opts?.serverCentroid ?? COUNTRY_CENTROIDS['中国'] ?? [104, 35]
  let countryCounts = new Map<string, number>()
  let provinceCounts = new Map<string, number>()
  let drilledName: string | null = null
  const arcs: ArcDatum[] = []
  let disposed = false
  let paused = false
  const onDrillChange = opts?.onDrillChange

  // 构造（v2.3.8）：width/height 默认窗口尺寸（地球右偏）——事后同步容器
  // 实测尺寸（渲染器+相机 aspect 均更新）。库内 hexPolygon 射线拾取在本
  // 组合下不可用（多轮实证：hover/click 永不触发且无错误），交互改为引擎
  // 自研：canvas click → 相机射线 ∩ 球面 → 经纬度（three-globe 球面约定）
  // → 点内多边形判定（ray-casting），数学确定、零依赖库内事件。
  // 两段式构造（v2.3.8 定稿）：自研射线交互不依赖库内拾取，两段式无副作用；
  // animateIn:false 必须经配置传入（new 形态 props 不透传——「右下角飘入」
  // 在 new 形态下持续存在的根因）；width/height 同步容器实测尺寸。
  const globe = (Globe as unknown as (config: Record<string, unknown>) => (el: HTMLElement) => GlobeInstance)({
    rendererConfig: { antialias: true, alpha: true },
    width: container.clientWidth || 800,
    height: container.clientHeight || 600,
    animateIn: false,
  })(container)


  // 海洋球面深海军蓝（纯黑不合理——用户裁定 2026-10-17）
  const gMat = globe.globeMaterial() as THREE.MeshPhongMaterial
  if (gMat && gMat.color) gMat.color.set('#0a1e42')
  globe
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true)
    .atmosphereColor('#3ad1ff')
    .atmosphereAltitude(0.16)
    .hexPolygonsData(buildCountryFeatures(countryCounts))
    .hexPolygonResolution(3)
    .hexPolygonMargin(0.25)
    .hexPolygonUseDots(false)
    .hexPolygonColor((f: object) => {
      const props = f && 'properties' in f ? (f as GeoFeature & { properties: { hover?: boolean; dim?: boolean } }).properties : null
      if (!props) return LAND_DARK
      if (props.hover) return '#8fe6ff'
      // 下钻态他国暗度衬底（与地图版 22% 同语义；命中国仍全亮热力）
      if (props.dim) return 'rgba(27, 42, 65, 0.4)'
      return heatCss(props.count)
    })
    .hexPolygonsTransitionDuration(0)
    .ringsData([{ lat: server[1], lng: server[0] }])
    .ringLat('lat')
    .ringLng('lng')
    .ringColor(() => (t: number) => `rgba(226,232,240,${Math.max(0, 1 - t)})`)
    .ringMaxRadius(3)
    .ringPropagationSpeed(1.1)
    .ringRepeatPeriod(900)
    .arcsData(arcs)
    .arcStartLat('startLat')
    .arcStartLng('startLng')
    .arcEndLat('endLat')
    .arcEndLng('endLng')
    .arcColor('color')
    .arcAltitudeAutoScale(0.4)
    .arcStroke('strokeW' as never)
    .arcDashLength(0.45)
    .arcDashGap(2)
    .arcDashAnimateTime(2200)
    .pointsData([{ lat: server[1], lng: server[0], size: 0.45 }])
    .pointLat('lat')
    .pointLng('lng')
    .pointColor((d: object) => ((d as { color?: string }).color) ?? '#e2e8f0')
    .pointAltitude(0.012)
    .pointRadius('size')
    .pointsTransitionDuration(0)

  globe.controls().autoRotate = true
  globe.controls().autoRotateSpeed = 0.45
  // 滚轮不参与缩放（用户裁定：两页面交互一致，缩放仅经下钻/返回）
  globe.controls().enableZoom = false
  globe.pointOfView({ lat: server[1], lng: server[0], altitude: 2.4 }, 0)

  // ---- 自研拾取：屏幕点 → 相机射线 ∩ 球面 → 经纬度 → 国家/省份 ----
  function screenToLatLng(px: number, py: number): { lat: number; lng: number } | null {
    const cam = globe.camera() as THREE.PerspectiveCamera
    const r = container.getBoundingClientRect()
    const ndcX = ((px - r.left) / r.width) * 2 - 1
    const ndcY = -(((py - r.top) / r.height) * 2 - 1)
    cam.updateMatrixWorld()
    const fovHalf = (cam.fov * Math.PI) / 360
    const dir = new THREE.Vector3()
    cam.getWorldDirection(dir)
    const right = new THREE.Vector3().crossVectors(dir, cam.up).normalize()
    const up = new THREE.Vector3().crossVectors(right, dir).normalize()
    const ray = dir
      .add(right.multiplyScalar(ndcX * Math.tan(fovHalf) * cam.aspect))
      .add(up.multiplyScalar(ndcY * Math.tan(fovHalf)))
      .normalize()
    const origin = new THREE.Vector3().setFromMatrixPosition(cam.matrixWorld)
    const R = globe.getGlobeRadius()
    // 射线 ∩ 球（球心原点）：|o + t·d|² = R²
    const b = origin.dot(ray)
    const c = origin.dot(origin) - R * R
    const disc = b * b - c
    if (disc < 0) return null
    const t = -b - Math.sqrt(disc)
    if (t < 0) return null
    const p = origin.clone().add(ray.clone().multiplyScalar(t))
    // three-globe 球面约定（polar2Cartesian 逆变换）——逆变换产出域为
    // (-90°, 270°]，必须 wrap 到 [-180,180]：西半球国家（美/加等 lng<-90）
    // 曾整片 hover/点击 miss（v2.3.8-beta 实测）。
    const lat = 90 - (Math.acos(p.y / R) * 180) / Math.PI
    const lng = ((((90 - (Math.atan2(p.z, p.x) * 180) / Math.PI) + 540) % 360) - 180)
    return { lat, lng }
  }

  
  /** 共享点内判定的批量包装（国家/省多边形组命中）。 */
  function pointInEntries(lon: number, lat: number, entries: { polys: number[][][] }[]): boolean {
    return entries.some((e) => sharedPointInPolys(lon, lat, e.polys))
  }

  let provincePolysCache: { polys: number[][][] }[] = []

  /** 下钻省数据源（中国走内置高精度表；其余取按需加载表，未加载=空）。 */
  function provinceSource(country: string): { name: string; polys: number[][][]; short?: string }[] {
    if (country === '中国') return CHINA_PROVINCES
    return loadedAdmin1Tables()?.[country] ?? []
  }

  let drillSeq = 0

  /** 下钻某国（第 78 轮 L07-F18：下钻态点击他国与地图版一致=切换下钻）。
   *  无省层数据（含 admin1 chunk 加载失败）时不进入下钻——原实现直接
   *  drilledName+flyTo，省板为空（被选国家成空洞）。 */
  async function drillCountry(name: string): Promise<void> {
    const seq = ++drillSeq
    if (name !== '中国') {
      const tables = await loadAdmin1Tables()
      if (seq !== drillSeq) return
      if (!tables) {
        opts?.onProvinceLoadError?.()
        return
      }
      if (!tables[name]?.length) return
    }
    drilledName = name
    const c2 = COUNTRY_CENTROIDS[name] ?? FALLBACK_CENTROID
    globe.pointOfView({ lat: c2[1], lng: c2[0], altitude: flyAltitudeFor(name) }, 700)
    globe.controls().autoRotate = false
    applyLayer()
    onDrillChange?.(name)
  }

  async function handleCanvasClick(ev: MouseEvent): Promise<void> {
    const geo = screenToLatLng(ev.clientX, ev.clientY)
    if (!geo) return
    if (drilledName) {
      // 本省（选中国家内）：保持
      if (pointInEntries(geo.lng, geo.lat, provincePolysCache)) return
      // 命中其他国家：切换下钻（手势语义与地图版统一）
      const other = THREAT_COUNTRIES.find((c) => c.name !== drilledName && pointInEntries(geo.lng, geo.lat, [c]))
      if (other) {
        await drillCountry(other.name)
        return
      }
      // 空白：返回世界
      drillSeq += 1
      drilledName = null
      globe.pointOfView({ lat: server[1], lng: server[0], altitude: 2.4 }, 700)
      globe.controls().autoRotate = !paused
      applyLayer()
      onDrillChange?.(null)
      return
    }
    const hit = THREAT_COUNTRIES.find((c) => pointInEntries(geo.lng, geo.lat, [c]))
    if (!hit) return
    await drillCountry(hit.name)
  }

  // ---- hover：国家/省 hex 标记重着色 + 悬浮名（与地图版同构：pointermove 只
  // 记坐标，帧内拾取一次——原实现每个 pointermove 事件全量扫描 177 国多边形，
  // 快速移动时同帧多次射线拾取，hover 明显滞后（第 78 轮 L07-F14）。 ----
  const hoverTipEl = document.createElement('div')
  hoverTipEl.style.cssText = 'position:absolute;z-index:6;pointer-events:none;display:none;padding:5px 10px;background:rgba(4,12,32,.92);border:1px solid rgba(80,170,255,.45);color:#e2ecff;font:12px "Noto Sans SC","PingFang SC",sans-serif;white-space:nowrap;border-radius:2px'
  container.appendChild(hoverTipEl)
  let hoverKeyCache: string | null = null
  let pendingMove: { x: number; y: number } | null = null
  /** 当前 hex 特征数组（稳定对象引用——hover 只替换属性变化的特征对象）。 */
  let hexFeatures: (GeoFeature & { properties: { hover?: boolean; dim?: boolean } })[] = []

  function setHexHover(name: string | null): void {
    let changed = false
    const arr = hexFeatures.map((feature) => {
      const want = feature.properties.name === name
      if (feature.properties.hover === want) return feature
      changed = true
      // 逐特征属性差量：只替换属性变化的那几个对象（hover 名称切换=2 个）
      return { ...feature, properties: { ...feature.properties, hover: want } } as typeof feature
    })
    if (!changed) return
    hexFeatures = arr
    globe.hexPolygonsData(arr)
  }

  /** 帧内 hover 拾取（每帧最多一次）。 */
  function processHover(): void {
    const move = pendingMove
    if (!move) return
    pendingMove = null
    const geo = screenToLatLng(move.x, move.y)
    if (!geo) {
      if (hoverKeyCache !== null) {
        hoverKeyCache = null
        hoverTipEl.style.display = 'none'
        setHexHover(null)
      }
      return
    }
    let name: string | null = null
    let count = 0
    if (drilledName) {
      for (const pv of provinceSource(drilledName)) {
        if (pointInEntries(geo.lng, geo.lat, [{ polys: pv.polys }])) {
          name = 'short' in pv && pv.short ? String(pv.short) : String(pv.name)
          count = provinceCounts.get(name) ?? 0
          break
        }
      }
      if (!name) {
        const other = THREAT_COUNTRIES.find((c) => c.name !== drilledName && pointInEntries(geo.lng, geo.lat, [c]))
        if (other) { name = other.name; count = countryCounts.get(name) ?? 0 }
      }
    } else {
      const hit = THREAT_COUNTRIES.find((c) => pointInEntries(geo.lng, geo.lat, [c]))
      if (hit) { name = hit.name; count = countryCounts.get(name) ?? 0 }
    }
    if (name !== hoverKeyCache) {
      hoverKeyCache = name
      setHexHover(name)
    }
    if (name) {
      const r = container.getBoundingClientRect()
      hoverTipEl.style.display = 'block'
      hoverTipEl.textContent = `${name} ${count}`
      hoverTipEl.style.left = `${move.x - r.left + 14}px`
      hoverTipEl.style.top = `${move.y - r.top - 6}px`
    } else {
      hoverTipEl.style.display = 'none'
    }
  }

  function onCanvasMove(ev: PointerEvent): void {
    pendingMove = { x: ev.clientX, y: ev.clientY }
  }

  function onPointerLeave(): void {
    pendingMove = null
    hoverKeyCache = null
    hoverTipEl.style.display = 'none'
    setHexHover(null)
  }

  /** 板块层重建：世界=国家六边形板（热力）；下钻=省板（全亮）+他国板（暗度
   * 衬底，与地图版下钻同视觉——用户裁定 2026-10-17）。 */
  function applyLayer(): void {
    if (drilledName) {
      type HexF = GeoFeature & { properties: { hover?: boolean; dim?: boolean } }
      const provinces = buildProvinceFeatures(drilledName, provinceCounts, loadedAdmin1Tables() ?? {}) as HexF[]
      const others = buildCountryFeatures(countryCounts)
        .filter((f) => f.properties.name !== drilledName)
        .map((f) => ({ ...f, properties: { ...f.properties, dim: true } }) as HexF)
      hexFeatures = [...provinces, ...others]
      globe.hexPolygonsData(hexFeatures)
      provincePolysCache = provinceSource(drilledName).map((p) => ({ polys: p.polys }))
    } else {
      hexFeatures = buildCountryFeatures(countryCounts) as (GeoFeature & { properties: { hover?: boolean; dim?: boolean } })[]
      globe.hexPolygonsData(hexFeatures)
      provincePolysCache = []
    }
  }

  // click 处理为 async（按需加载省界）——命名包装器承担 add/removeEventListener
  // 同一引用；void 丢弃 Promise 是刻意的（内部处理全部失败分支）。
  const onCanvasClick = (ev: MouseEvent): void => { void handleCanvasClick(ev) }
  const cv = container.querySelector('canvas')
  if (cv) {
    cv.addEventListener('click', onCanvasClick)
    cv.addEventListener('pointermove', onCanvasMove)
    cv.addEventListener('pointerleave', onPointerLeave)
  }

  // 尺寸重试同步（构造竞态：容器 0×0 时双 RAF 单次尝试会静默失败）
  const syncSize = (): void => {
    const w = container.clientWidth
    const h = container.clientHeight
    if (w > 0 && h > 0 && (globe.width() !== w || globe.height() !== h)) globe.width(w).height(h)
  }
  let syncTries = 0
  const syncTimer = window.setInterval(() => {
    syncSize()
    syncTries++
    const done = globe.width() === container.clientWidth && container.clientWidth > 0
    if (done || syncTries > 60) clearInterval(syncTimer)
  }, 250)
  window.addEventListener('resize', syncSize)

  // 垂直扫描带（移植 shader）+ 帧驱动
  let scanMat: THREE.ShaderMaterial | null = null
  const clock = { t: 0 }
  globe.onGlobeReady(() => {
    if (disposed) return
    const scene = globe.scene()
    if (!scene) return
    const R = 100
    scanMat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: { uColor: { value: new THREE.Color('#5fe1ff') }, uTime: { value: 0 }, uR: { value: R * 1.012 } },
      vertexShader: FRESNEL_VS,
      fragmentShader: SCAN_FS,
    })
    const scan = new THREE.Mesh(new THREE.SphereGeometry(R * 1.012, 96, 64), scanMat)
    // 扫描壳包在板块层之外，必须退出射线检测——否则吞掉国家点击
    scan.raycast = () => {}
    scan.scale.setScalar(globe.getGlobeRadius() / R)
    scene.add(scan)
  })

  // 调试句柄（与地图版 __threatScene 同位约定；无功能依赖）
  ;(window as unknown as Record<string, unknown>).__threatGlobe = globe

  let last = performance.now()
  const frame = (): void => {
    if (disposed) return
    rafId = requestAnimationFrame(frame)
    const now = performance.now()
    const dt = now - last
    last = now
    // hover 拾取每帧最多一次（pointermove 只记坐标——第 78 轮 L07-F14）
    processHover()
    if (!paused) {
      clock.t += dt / 1000
      if (scanMat) scanMat.uniforms.uTime.value = clock.t
      // 弧线老化淘汰（队首=最旧；保持其余对象次序稳定，动画相位不重排）
      if (arcs.length > 0 && now - arcs[0].born > ARC_TTL) {
        arcs.shift()
        globe.arcsData([...arcs])
      }
    }
  }
  let rafId = requestAnimationFrame(frame)

  /** 热点光点：命中国家 log10 计数定尺寸（与地图版信标同语义），叠加本站点。 */
  function applyHotspots(): void {
    const hot: { lat: number; lng: number; size: number; color?: string }[] = [
      { lat: server[1], lng: server[0], size: 0.45, color: '#e2e8f0' },
    ]
    for (const [name, count] of countryCounts) {
      if (count <= 0) continue
      const c = COUNTRY_CENTROIDS[name]
      if (!c) continue
      hot.push({ lat: c[1], lng: c[0], size: 0.25 + Math.min(1, Math.log10(count) / 3) * 0.85, color: '#ff4d4d' })
    }
    globe.pointsData(hot)
  }

  function spawnArc(from: Centroid, normal: boolean, weight = 1): void {
    // v2.3.8 弧线中断修复：新弧线 append 到队尾、淘汰从队首移除——原 unshift
    // 到队头使全部弧线对象次序重排，globe.gl 按次序分配 dash 动画相位 →
    // 每来一条新弧，其余光流全部跳变（用户实测「光流被打断」）。
    if (arcs.length >= MAX_ARCS) arcs.shift()
    arcs.push({
      ...arcEndpoints(server, from),
      color: normal ? ['rgba(61,220,132,0.1)', 'rgba(61,220,132,0.85)'] : ['rgba(255,122,47,0.1)', 'rgba(255,77,77,0.95)'],
      strokeW: Math.min(3, 0.5 + Math.log10(Math.max(1, weight))),
      born: performance.now(),
    })
    globe.arcsData([...arcs])
  }

  return {
    addArc(origin: Centroid): void {
      spawnArc(origin, false)
    },
    addArcForLocation(ipLocation: string, weight = 1): void {
      if (!ipLocation) return
      const country = ipLocation.split('·')[0]
      if (!country) return
      spawnArc(COUNTRY_CENTROIDS[country] ?? FALLBACK_CENTROID, false, weight)
    },
    setCountries(entries: CountryHeat[]): void {
      countryCounts = new Map(entries.map((e) => [e.name, e.count]))
      applyHotspots()
      if (!drilledName) applyLayer()
    },
    setProvinces(entries: CountryHeat[]): void {
      provinceCounts = new Map(entries.map((e) => [e.name, e.count]))
      if (drilledName === '中国') applyLayer()
    },
    setTraffic(entries: CountryHeat[]): void {
      for (const entry of entries.slice(0, 4)) {
        if (entry.count > 0) spawnArc(COUNTRY_CENTROIDS[entry.name] ?? FALLBACK_CENTROID, true)
      }
    },
    setServer(centroid: Centroid | null): void {
      if (!centroid) return
      // 第 78 轮 L07-F03：状态化本站坐标——热光点、弧线终点（spawnArc 每次
      // 读 server）、返回世界视角（zoomOut/resetView）随之更新；原实现只改
      // 环/点数据，server 常量让后续弧线仍飞向旧坐标。
      server = [centroid[0], centroid[1]]
      globe.ringsData([{ lat: server[1], lng: server[0] }])
      applyHotspots()
      if (!drilledName) globe.pointOfView({ lat: server[1], lng: server[0], altitude: 2.4 }, 600)
    },
    zoomOut(): void {
      drilledName = null
      globe.controls().autoRotate = !paused
      globe.pointOfView({ lat: server[1], lng: server[0], altitude: 2.4 }, 600)
      applyLayer()
    },
    resetView(): void {
      drilledName = null
      globe.controls().autoRotate = !paused
      globe.pointOfView({ lat: server[1], lng: server[0], altitude: 2.4 }, 600)
      applyLayer()
    },
    setControlsEnabled(enabled: boolean): void {
      globe.controls().enabled = enabled
    },
    pickCountryAt(): string | null {
      return null
    },
    cameraState(): { zoom: number; cx: number; cy: number; dist: number; pos: [number, number, number] } {
      const pov = globe.pointOfView()
      return { zoom: 1, cx: pov.lng, cy: pov.lat, dist: pov.altitude, pos: [pov.lng, 1, pov.lat] }
    },
    setPaused(p: boolean): void {
      paused = p
      globe.controls().autoRotate = !p && !drilledName
    },
    dispose(): void {
      disposed = true
      window.removeEventListener('resize', syncSize)
      clearInterval(syncTimer)
      const cvd = container.querySelector('canvas')
      if (cvd) {
        cvd.removeEventListener('click', onCanvasClick)
        cvd.removeEventListener('pointermove', onCanvasMove)
        cvd.removeEventListener('pointerleave', onPointerLeave)
      }
      cancelAnimationFrame(rafId)
      globe.pauseAnimation()
      globe.hexPolygonsData([])
      globe.arcsData([])
      globe.ringsData([])
      globe.pointsData([])
      if (scanMat) {
        scanMat.dispose()
        scanMat = null
      }
      // WebGL/three 资源释放（第 78 轮 L07-F13）：原仅清数据 + innerHTML，
      // renderer/几何/纹理驻留 → 反复进出大屏堆内存与 WebGL 上下文持续增长。
      const destructible = globe as unknown as { _destructor?: () => void; renderer?: () => THREE.WebGLRenderer }
      try {
        destructible.renderer?.().dispose()
        destructible.renderer?.().forceContextLoss()
        destructible._destructor?.()
      } catch (error) {
        console.warn('threat globe teardown failed', error)
      }
      delete (window as unknown as Record<string, unknown>).__threatGlobe
      container.innerHTML = ''
    },
  }
}
