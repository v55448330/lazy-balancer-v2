// 威胁大屏双引擎（2D 地图 / 3D 地球）行为对齐契约。
//
// 两个引擎实现同一 ThreatScene 接口，历史多次出现「一侧修了另一侧没同步」
// （下钻手势、暂停补绘、拾取预筛），差异只在运行时可见。可求值的语义用纯函数
// 断言；引擎接线（DOM/WebGL 依赖，node:test 无法装载）沿用 threatGlobe.spec
// 的源码契约断言先例。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { drillClickIntent } from '../src/utils/threatShared.ts'
import { LAT_TOP, LAT_BOTTOM, DOT_LAT_TOP, DOT_LAT_BOTTOM } from '../src/utils/threatProjection.ts'
import { member, code } from './_helpers.ts'

const sceneSrc = code('src/utils/threatScene.ts')
const globeSrc = code('src/utils/threatGlobe.ts')

test('下钻点击手势：命中国=当前下钻国保持、他国切换、空白返回世界、总览态下钻', () => {
  // 下钻态
  assert.equal(drillClickIntent('中国', '中国'), 'stay', '点击当前下钻国自身必须保持（不得重钻回弹）')
  assert.equal(drillClickIntent('美国', '中国'), 'switch', '命中他国必须切换下钻')
  assert.equal(drillClickIntent(null, '中国'), 'world', '下钻态空白必须返回世界')
  // 总览态
  assert.equal(drillClickIntent('中国', null), 'drill')
  assert.equal(drillClickIntent(null, null), 'none')
})

test('两个引擎的点击处理都必须走共享手势判定（单源，不得各写一套）', () => {
  const sceneClick = member(sceneSrc, 'function onClick(')
  assert.match(sceneClick, /drillClickIntent\(/, '2D 地图点击必须走共享手势判定')
  assert.match(sceneClick, /intent === 'stay'\)\s*return/, '2D 地图必须对「当前下钻国自身」直接返回（不重钻）')

  const globeClick = member(globeSrc, 'async function handleCanvasClick(')
  assert.match(globeClick, /drillClickIntent\(/, '3D 地球点击必须走共享手势判定')
  // 不得再有「排除选择国后另找一个国家」的平行实现
  assert.doesNotMatch(globeClick, /THREAT_COUNTRIES\.find\(/, '地球点击不得再写平行命中逻辑')
})

test('点阵扫描纬度域由投影常量派生（两引擎单源）', () => {
  assert.equal(DOT_LAT_TOP, LAT_TOP + 1)
  assert.equal(DOT_LAT_BOTTOM, LAT_BOTTOM + 0.5)
  assert.match(sceneSrc, /latToY\(DOT_LAT_TOP\)/)
  assert.match(sceneSrc, /latToY\(DOT_LAT_BOTTOM\)/)
  assert.match(globeSrc, /DOT_LAT_BOTTOM; lat < DOT_LAT_TOP/)
  for (const [src, name] of [[sceneSrc, '地图'], [globeSrc, '地球']] as const) {
    assert.doesNotMatch(src, /latToY\(84\)|let lat = -54\.5|let lat = 84/, `${name}引擎不得再写死点阵纬度域`)
  }
})

test('暂停态数据/坐标 setter 必须补绘一帧（地球与地图同口径）', () => {
  // 地图：三个 setter 均已补绘（既有实现，防回退）
  const sceneStart = sceneSrc.indexOf('return {\n    addArcForLocation')
  const sceneApi = sceneSrc.slice(sceneStart)
  for (const name of ['setCountries', 'setProvinces', 'setServer']) {
    const marker = name === 'setServer' ? `${name}(centroid: Centroid | null): void {` : `${name}(entries: CountryHeat[]): void {`
    const body = member(sceneApi, marker)
    assert.match(body, /if \(paused\) renderOnce\(\)/, `地图 ${name} 暂停态必须补绘`)
  }
  // 地球：三个 setter 同样必须补绘（原实现只有下钻/返回视角补绘）
  const globeStart = globeSrc.indexOf('return {\n    addArcForLocation')
  const globeApi = globeSrc.slice(globeStart)
  for (const name of ['setCountries', 'setProvinces', 'setServer']) {
    const marker = name === 'setServer' ? `${name}(centroid: Centroid | null): void {` : `${name}(entries: CountryHeat[]): void {`
    const body = member(globeApi, marker)
    assert.match(body, /if \(paused\) renderOnce\(\)/, `地球 ${name} 暂停态必须补绘`)
  }
})

test('地球 hover/click 命中必须复用点阵 bbox 预筛，且静止态不再反复拾取', () => {
  const hit = member(globeSrc, 'function countryHit(')
  assert.match(hit, /sharedCountryGrid\.grid\.get\(countryGridCell\(/, '命中候选必须复用共享 5° 网格（与地图引擎同源）')
  assert.match(hit, /dotBboxes\[i\]/, '命中测试必须先用 bbox 预筛')
  assert.match(hit, /lng < b\.minLon \|\| lng > b\.maxLon/, '预筛必须同时约束经度')
  assert.doesNotMatch(hit, /i < THREAT_COUNTRIES\.length/, '不得再全表逐国扫描')
  const hover = member(globeSrc, 'function processHover(')
  assert.match(hover, /countryHit\(/, 'hover 拾取必须走预筛单源')
  assert.doesNotMatch(hover, /THREAT_COUNTRIES\.find\(/, 'hover 不得再全表逐个射线')
  assert.match(hover, /const autoRotate = globe\.controls\(\)\.autoRotate/, '读自转状态')
  // 「仅自转时复测静止指针」的三个条件与复测间隔分开判：把三元表达式整串钉死会让
  // 调换条件顺序、提取间隔常量、改注释都假红，而语义（自转 ∧ 有指针 ∧ 距上次复测
  // 超过间隔）没变。间隔本身只判量级——复测是渲染节拍级的去抖，不该被钉成魔法数。
  const flat = hover.replace(/\s+/g, ' ')
  for (const condition of ['autoRotate', 'hoverPoint', 'now - lastHoverPick >=']) {
    assert.ok(flat.includes(condition), `静止指针复测守卫缺少条件：${condition}`)
  }
  const repick = /now - lastHoverPick >= (\d+)/.exec(flat)
  assert.ok(repick !== null, '复测间隔必须存在')
  const repickMs = Number(repick[1])
  assert.ok(repickMs >= 16 && repickMs <= 500, `复测间隔必须是渲染节拍级的去抖（实际 ${repickMs}ms）`)
})

test('下钻态点击的手势输入集与地图一致：不得排除下钻国', () => {
  // 地图：countryHitIndex 不排除，同国命中 → drillClickIntent=stay。
  const sceneClick = member(sceneSrc, 'function onClick(')
  assert.match(sceneClick, /countryHitIndex\(geo\.lon, geo\.lat\)/, '地图点击不得排除下钻国')
  // 地球：原实现排除下钻国，国境内落在省多边形空档时被判空白 → 强制退出下钻。
  const globeClick = member(globeSrc, 'async function handleCanvasClick(')
  assert.match(globeClick, /countryHit\(geo\.lng, geo\.lat\)/, '地球点击不得排除下钻国')
  assert.doesNotMatch(globeClick, /countryHit\(geo\.lng, geo\.lat, drilledName/, '排除下钻国会让省界空档被误判为空白')
})

test('返回世界视口在两引擎内各自单源（zoomOut/resetView 不得各写一份）', () => {
  for (const [src, name] of [[sceneSrc, '地图'], [globeSrc, '地球']] as const) {
    for (const method of ['zoomOut', 'resetView']) {
      const body = member(src, `${method}(): void {`)
      assert.match(body, /returnToWorldView\(/, `${name} ${method} 必须走返回世界视口单源`)
    }
    const helper = member(src, 'function returnToWorldView(')
    assert.match(helper, /drillSeq \+= 1/, `${name} 返回世界视口必须作废在途加载`)
    assert.ok(
      helper.indexOf('drillSeq += 1') < helper.indexOf('enterWorldView(') ||
      helper.indexOf('drillSeq += 1') < helper.indexOf('flyToOverview()'),
      `${name} 必须先作废在途加载再复位视口`,
    )
  }
})

test('地球点色更新用单次局部缓存（不得跨 30s 轮询累积）', () => {
  const update = member(globeSrc, 'function updateDotColors(')
  assert.doesNotMatch(globeSrc, /const heatColorCache = new Map/, '全局按计数缓存必须退役（慢泄漏）')
  assert.match(update, /const colorCache = new Map<number, THREE\.Color>\(\)/, '每次更新使用局部缓存')
  assert.match(update, /const colorFor = \(count: number\)/, '颜色复用局部 colorFor')
})

test('热力对数标尺两引擎同源：各引擎按当前数据集 max 归一（自适应，禁写死分母）', () => {
  const rebuild = member(sceneSrc, 'function rebuildStaticLayer(')
  assert.match(rebuild, /const heatMax = maxHeatCount\(countryCounts\)/, '世界层 max=国家计数数据集')
  assert.match(rebuild, /heatCss\(cnt, heatMax\)/, '世界层不得回退单参调用')
  const drill = member(sceneSrc, 'function rebuildDrillWorldLayer(')
  assert.match(drill, /const heatMax = maxHeatCount\(provinceCounts\)/, '下钻层 max=省计数数据集')
  assert.match(drill, /heatCss\(cnt, heatMax\)/, '下钻层不得回退单参调用')
  const update = member(globeSrc, 'function updateDotColors(')
  assert.match(update, /const heatMax = maxHeatCount\(activeCounts\)/, '球面 max=当前点集数据集（世界/下钻随切换）')
  assert.match(update, /heatCss\(count, heatMax\)/, '球面不得回退单参调用')
})

test('地图静态层复用国家 Path2D 后按色批量填充', () => {
  const rebuild = member(sceneSrc, 'function rebuildStaticLayer(')
  assert.match(rebuild, /const byKey = ensureWorldDotPaths\(\)/, '必须复用国家点阵路径缓存')
  assert.match(rebuild, /const byFill = new Map<string, Path2D>\(\)/)
  assert.match(rebuild, /staticCtx\.fill\(path\)/, '必须逐色一次 fill')
  assert.doesNotMatch(rebuild, /dotPath\(/, '逐点 beginPath+fill 必须退役')
  const cache = member(sceneSrc, 'function ensureWorldDotPaths(')
  assert.match(cache, /dotSubPath\(path/, '路径缓存只在首次构建时逐点生成')
  // 弧线渐变同样必须缓存（相机静止时无逐帧 createLinearGradient）
  const arcs = member(sceneSrc, 'function drawArcs(')
  assert.doesNotMatch(arcs, /createLinearGradient\(/, 'drawArcs 不得逐帧逐弧重建渐变')
  assert.match(arcs, /arcGradient\(from, to, color\)/)
})

test('地球光流投影与点阵共用 DOT_ALTITUDE 壳层', () => {
  assert.match(globeSrc, /getCoords\(lat, lng, DOT_ALTITUDE\)/)
  assert.doesNotMatch(globeSrc, /getCoords\(lat, lng, 0\.005\)/)
})

test('地图光流只保留单航次状态，不含不可达的多航次分支', () => {
  assert.doesNotMatch(sceneSrc, /ARC_FLIGHTS|arc\.flight\b|flight: 0/)
  const arcs = member(sceneSrc, 'function drawArcs(')
  assert.match(arcs, /arc\.flightT >= ARC_FLIGHT_SECONDS \+ ARC_FLIGHT_GAP[\s\S]*arcs\.splice\(i, 1\)/)
})

test('地球光流叠加层复用地图的像素线宽/尾迹/粒子口径', () => {
  const overlay = member(globeSrc, 'function drawFlowOverlay(')
  assert.match(overlay, /flowArcTierWidth\(arc\.tier\)/, '3D 光流线宽必须沿用显式三档')
  // 尾迹必须尾隐头亮：把实现里的 alpha 表达式**求值**再判两点（尾≈0.05·alpha、
  // 头=alpha）与单调性。整串公式钉在改常量、换成查表或重排括号时即假红，而这条
  // 可见效果没变；求值判据只对「尾隐头亮」这一语义负责。
  const trailExprs = [...overlay.matchAll(/ctx\.globalAlpha\s*=\s*alpha\s*\*\s*([^\n;]+)/g)]
    .map((match) => match[1].trim())
    .filter((expr) => /\bratio\b/.test(expr))
  assert.equal(trailExprs.length, 1, '尾迹 alpha 必须只有一处按 ratio 渐变')
  const alphaAt = (ratio: number): number => Number(new Function('alpha', 'ratio', `return ${trailExprs[0]}`)(1, ratio))
  const atTail = alphaAt(0)
  const atMid = alphaAt(0.5)
  const atHead = alphaAt(1)
  assert.ok(Math.abs(atTail - 0.05) < 1e-9, `尾端应几乎透明（实际 ${atTail}）——否则弧尾拖成实线`)
  assert.ok(Math.abs(atHead - 1) < 1e-9, `头部必须完全不透明（实际 ${atHead}）`)
  assert.ok(atTail < atMid && atMid < atHead, `沿弧长必须单调变亮（实际 ${atTail} → ${atMid} → ${atHead}）`)
  assert.match(overlay, /FLOW_PARTICLES/, '必须绘制同地图亮头粒子')
  assert.doesNotMatch(globeSrc, /arcStroke\('strokeW'/, '3D tube 弧线必须退役，避免双套样式')
})

test('地球聚合标签与到站脉冲跟地图同色', () => {
  assert.match(globeSrc, /labelColor\(\(d: object\) => \(\(d as \{ color\?: string \}\)\.color\)/, '标签必须随弧线颜色（不得固定黄）')
  assert.match(globeSrc, /syncArcLabels[\s\S]*color: a\.color/, 'labelsData 必须携带颜色')
  assert.match(globeSrc, /arc\.pulsed = true/, '一个航次只允许触发一次到站脉冲')
  assert.match(globeSrc, /spawnFlowRipple\(arc\.color\)/, '脉冲颜色必须使用弧线颜色')
  assert.match(globeSrc, /ripple\.age \/ FLOW_RIPPLE_SECONDS/, '涟漪寿命必须走 threatTheme 单源（1.8s）')
})

test('缓动/涟漪/浮签字色四组跨引擎重复实现收敛到 threatTheme', () => {
  const theme = code('src/utils/threatTheme.ts')
  // 单源定义在本文件，两引擎只导入
  assert.match(theme, /export function easeOutCubic\(/)
  assert.match(theme, /export const FLOW_HOVER_TIP_COLOR = '#/)
  assert.match(theme, /export const FLOW_RIPPLE_SECONDS = 1\.8/)
  assert.match(theme, /export const FLOW_RIPPLE_START_RADIUS = 3/)
  assert.match(theme, /export const FLOW_RIPPLE_GROWTH_RADIUS = 26/)
  assert.match(theme, /export const FLOW_RIPPLE_LINE_WIDTH = 1\.5/)
  assert.match(theme, /export const FLOW_RIPPLE_ALPHA = 0\.85/)
  for (const [src, name] of [[sceneSrc, '地图'], [globeSrc, '地球']] as const) {
    assert.match(src, /easeOutCubic,/, `${name}引擎必须导入共享缓动`)
    assert.doesNotMatch(src, /function easeOutCubic\(/, `${name}引擎不得再自写缓动`)
    assert.match(src, /FLOW_RIPPLE_SECONDS/, `${name}引擎涟漪寿命必须走单源`)
    assert.match(src, /FLOW_RIPPLE_START_RADIUS \+ t \* FLOW_RIPPLE_GROWTH_RADIUS/, `${name}引擎涟漪半径公式必须走单源常量`)
    assert.doesNotMatch(src, /const t = ripple\.age \/ 1\.8/, `${name}引擎不得写死 1.8`)
    assert.match(src, /FLOW_HOVER_TIP_COLOR/, `${name}引擎浮签字色必须走单源`)
  }
  assert.doesNotMatch(globeSrc, /color:#e2ecff/, '地球浮签不得写死字色')
})

test('帧率脚手架已删（两档恒等常量与交互时间窗不再伪装成自适应）', () => {
  assert.doesNotMatch(globeSrc, /IDLE_FRAME_INTERVAL|ACTIVE_FRAME_INTERVAL|ACTIVE_WINDOW|lastInteraction/,
    '恒等的两档帧率与交互时间窗是死脚手架')
  assert.match(globeSrc, /const FRAME_INTERVAL\s*=\s*1000\s*\/\s*60/)
})

// 拦截页回落文案归 securityStagesModel.spec（按 buildStageModel 行为断言，比源码文本
// 钉更强），且与「双引擎对齐」主题无关，此处不再重复。
