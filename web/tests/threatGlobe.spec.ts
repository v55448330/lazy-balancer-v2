// 威胁大屏地球引擎契约守卫。
//
// threatGlobe 依赖 globe.gl/three 的 WebGL 实例与 DOM，node:test 无法装载；
// 其可确定性验证的数学已抽到 threatProjection（sphereSurfacePoint 往返见
// threatScene.spec ⑥/⑥b）。此处沿用 threatScene.spec ⑦ 的源码契约断言先例，
// 钉住「引擎接线」本身——这些修复全是单行接线，缺一行不会有编译错误，只能靠
// 契约断言守住。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { member, code } from './_helpers.ts'

const globeSrc = code('src/utils/threatGlobe.ts')

// member() 的可判定前置：切片必须真的包含嵌套块。缩进启发式会在函数内第一个
// 内层块收尾处截断，块内 banned 标记的 doesNotMatch 断言会假绿——这里先证明
// helper 对该形态取到完整函数体。
test('member() 按花括号配对：嵌套块完整保留，块内 doesNotMatch 才有鉴别力', () => {
  const sample = [
    'function withNested(): void {',
    '  if (ready) {',
    '    banned()',
    '  }',
    '  allowed()',
    '}',
    'const after = 1',
  ].join('\n')
  const body = member(sample, 'function withNested(')
  assert.match(body, /banned\(\)/, '嵌套内层块必须在切片内')
  assert.match(body, /allowed\(\)/, '外层收尾语句必须在切片内')
  assert.doesNotMatch(body, /const after/, '切片不得越过函数收尾')
})

test('member() 跳过字符串/模板量/注释中的大括号：字面量不参与配对', () => {
  const sample = [
    'function withLiterals(): void {',
    "  const close = '}'",
    '  // 孤立 { 注释',
    '  /* 另一处 } */',
    '  const tpl = `} ${ { a: 1 }.a }`',
    '  done()',
    '}',
    'const after = 1',
  ].join('\n')
  const body = member(sample, 'function withLiterals(')
  // 字符串/注释里的 } 不得提前收尾：体内收尾语句必须仍在切片内。
  assert.match(body, /done\(\)/, '字面量中的 } 不得让切片提前收尾')
  // 注释里的 { 不得让切片越界吞下相邻声明。
  assert.doesNotMatch(body, /const after/, '字面量/注释中的 { 不得使切片越界')
})

// member() 的基础形状自测（缺 marker / 单表达式箭头 / 括号不平衡）单源在
// tests/helpersStripComments.spec.ts（该文件是 helper 自己的 spec）。这里只钉本
// 文件依赖的增量形态：顶层 `;` 声明不是成员体、声明头里的注释与模板量不参与配对。
test('member() 声明边界：顶层 ; 声明不是成员体，声明头注释/模板量不参与配对', () => {
  // 顶层 `;` 结束的声明：左花括号属于对象字面量，不是成员体——若当成块体会截出
  // 一段「看起来有内容」的切片，后续 doesNotMatch 假绿。
  assert.throws(
    () => member(['const cfg = { a: 1 };', 'function next(): void {', '  done()', '}'].join('\n'), 'const cfg = '),
    /has no block body/,
  )
  // 声明头里的 // 注释、块注释、模板量都不参与配对，仍须取到完整函数体
  const header = [
    'function withHeader(',
    '  a: string, // 参数注释里有 }',
    '  /* 块注释里有 { 和 } */ b: `tpl}`,',
    '): void {',
    '  done()',
    '}',
    'const after = 1',
  ].join('\n')
  const body = member(header, 'function withHeader(')
  assert.match(body, /done\(\)/, '声明头注释/模板量不得吞掉函数体')
  assert.doesNotMatch(body, /const after/, '声明头注释/模板量不得让切片越界')
})

test('复位/返回必须作废在途省界加载（与地图引擎同源）', () => {
  for (const name of ['zoomOut', 'resetView']) {
    const body = member(globeSrc, `${name}(): void {`)
    assert.match(body, /returnToWorldView\(600\)/, `${name} 必须走返回世界视口单源`)
    assert.doesNotMatch(body, /enterWorldView\(/, `${name} 不得再各自实现复位（两份实现会静默分叉）`)
  }
  const helper = member(globeSrc, 'function returnToWorldView(')
  const seqIdx = helper.indexOf('drillSeq += 1')
  const viewIdx = helper.indexOf('enterWorldView(')
  assert.ok(seqIdx >= 0, '返回世界视口必须递增 drillSeq')
  assert.ok(viewIdx > seqIdx, '必须先作废在途加载再返回世界视角')
  // 续体判定必须走共享纯函数（地图/地球同一口径）
  assert.match(globeSrc, /drillCommitAllowed\(seq, drillSeq, disposed\)/)
})

test('暂停态相机变更必须直接落点并补绘一帧', () => {
  assert.match(globeSrc, /paused \? 0 : 700/, '下钻 pointOfView 必须按暂停态取 0 时长')
  const enter = member(globeSrc, 'function enterWorldView(')
  assert.match(enter, /paused \? 0 : duration/, '返回世界视角必须按暂停态取 0 时长')
  assert.match(enter, /if \(paused\) renderOnce\(\)/, '暂停态无自循环，必须手动补绘')
  assert.match(globeSrc, /threeRenderer\.render\(scene, cam\)/, 'renderOnce 必须真正渲染一帧')
})

test('下钻衬底=低透明度世界点阵，hover 他国只提亮点，且不再有 H3 死配置', () => {
  // 与 2D 地图同规则：非下钻国家降透明度点阵，不再使用国家多边形色块。
  assert.match(globeSrc, /worldDots\.filter\(\(d\) => d\.key !== drilledName\)/)
  assert.match(globeSrc, /DRILL_BACKDROP_OPACITY = 0\.22/)
  assert.match(globeSrc, /backdropDotsPoints\.visible = !!drilledName/)
  // alphaTest 若高于 opacity 会把低透明度点全部丢弃（本次不可见根因）。
  assert.match(globeSrc, /alphaTest: 0\.05/)
  assert.match(globeSrc, /size: DRILL_DOT_SIZE,\s+color: DRILL_BACKDROP_COLOR/)
  assert.doesNotMatch(globeSrc, /globe\.polygonsData\(|polygonCapColor\(/,
    '国家多边形衬底已退役，非下钻国家必须走暗度点阵')
  assert.doesNotMatch(globeSrc, /\.hexPolygonsData\(|\.hexPolygonResolution\(|\.hexPolygonMargin\(|\.hexPolygonColor\(/,
    'H3 六边形层从未有图元，死配置必须移除（避免再次误以为衬底走 hex）')
  const hover = member(globeSrc, 'function setHexHover(')
  assert.match(hover, /updateHoverDots\(name\)/, '下钻态 hover 他国必须只提亮该国点阵')
  assert.match(globeSrc, /hoverDotsPoints/, '下钻态 hover 需要独立亮色点阵层')
})

test('首帧双 RAF 无条件应用图层（两帧内下钻不得残留世界点阵）', () => {
  // 锚点用代码 token（嵌套 requestAnimationFrame）而非注释文本——注释改写不该假红。
  const start = globeSrc.indexOf('requestAnimationFrame(() => requestAnimationFrame(')
  const end = globeSrc.indexOf('let rafId = requestAnimationFrame(frame)')
  assert.ok(start >= 0 && end > start, '首帧双 RAF 块缺失（单层 RAF 会在球体尺寸就绪前建点阵）')
  const block = globeSrc.slice(start, end)
  // ① 嵌套形状：两个 RAF 才保证首帧已上屏再建点阵
  assert.match(block, /requestAnimationFrame\(\(\) => requestAnimationFrame\(\(\) => \{/, '首帧必须嵌套两层 RAF')
  // ② 卸载守卫：回调可能在卸载后执行，必须直接返回
  assert.match(block, /if \(disposed\) return/, '双 RAF 回调必须复查卸载态（否则对已销毁引擎建点阵）')
  // ③ 应用图层无条件：两帧内已下钻时 applyLayer 不得被 !drilledName 之类的旧守卫拦下
  assert.doesNotMatch(globeSrc, /if \(!drilledName\) applyLayer\(\)/)
  assert.match(block, /^\s*applyLayer\(\)$/m, '双 RAF 回调必须无条件 applyLayer()')
})

test('海外下钻浮签显示「无省级统计」而不是 0', () => {
  assert.match(globeSrc, /hasProvinceStats\(drilledName\)/)
  assert.match(globeSrc, /无省级统计/)
})
test('光流池满时拒绝新弧线，不淘汰已开始动画', () => {
  const spawn = member(globeSrc, 'function spawnArc(')
  assert.match(spawn, /if \(arcs\.length >= MAX_ARCS\) return/, '满池必须拒绝新弧线')
  assert.doesNotMatch(spawn, /arcs\.shift\(\)/, 'spawnArc 不得淘汰已开始弧线')
})

